"""
Non-destructive smoke test of SentinelOne Management Console read APIs.

Purpose
-------
Hit every GET endpoint + a curated allow-list of read-only query POSTs
against the configured tenant and record which ones work on THIS
tenant. Writes two artifacts:

  references/tenant_capabilities.json   (machine-readable)
  references/tenant_capabilities.md     (human-readable)

Guarantees
----------
- Read-only. POST allow-list is hand-curated to endpoints that only
  READ state (validate, count, list-filters, check). Action/mutation
  POSTs are never called.
- Start-state = end-state: no config changes, no agent actions, no
  writes. The only server-side side-effects are load and audit-log
  entries (an API token issuing GETs is already a normal audit event).
- Path-param endpoints are called with IDs pre-fetched from sibling
  list endpoints. If an ID is unavailable on this tenant, the call is
  skipped and recorded as "no_id_available", not failed.

Usage
-----
    python scripts/smoke_test_queries.py                 # full sweep
    python scripts/smoke_test_queries.py --tag Threats   # one tag
    python scripts/smoke_test_queries.py --workers 12    # faster fan-out
    python scripts/smoke_test_queries.py --dry-run       # print plan, no calls
    python scripts/smoke_test_queries.py --no-post       # GETs only

Output
------
Console: per-tag pass/fail rollup + overall summary.
Files:   references/tenant_capabilities.{json,md}
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# skill/scripts -> add skill/scripts to sys.path so `import s1_client` works
SCRIPTS_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client, S1APIError  # noqa: E402

INDEX_PATH = SKILL_DIR / "references" / "endpoint_index.json"
OUT_JSON = SKILL_DIR / "references" / "tenant_capabilities.json"
OUT_MD = SKILL_DIR / "references" / "tenant_capabilities.md"

# --------------------------------------------------------------------- POSTs
# Hand-curated list of read-only query POSTs. Each entry is
# (path, body_factory). body_factory returns the JSON body to send.
# Do NOT add action/mutation POSTs here.
SAFE_POSTS: List[Tuple[str, callable]] = [
    ("/web/api/v2.1/filters", lambda ctx: {"filter": {"scopeLevel": "site"}}),
    ("/web/api/v2.1/filters/dv", lambda ctx: {"filter": {}}),
    ("/web/api/v2.1/xdr/filters", lambda ctx: {}),
    ("/web/api/v2.1/exclusions/validate", lambda ctx: {
        "data": [{"type": "path", "value": "/tmp/nonexistent-smoke-test"}]
    }),
    ("/web/api/v2.1/restrictions/validate", lambda ctx: {
        "data": [{"type": "path", "value": "/tmp/nonexistent-smoke-test"}]
    }),
    ("/web/api/v2.1/cloud-funnel/validate-query", lambda ctx: {"query": "*"}),
    ("/web/api/v2.1/remote-scripts/guardrails/check", lambda ctx: {"data": {"scriptId": "noop"}}),
    ("/web/api/v2.1/xdr/assets/tags/count", lambda ctx: {}),
]

# --------------------------------------------------------------------- params
# For each path parameter name, a (list_path, field) pair telling us how to
# resolve an example ID. Fields are tried in order.
PARAM_RESOLVERS: Dict[str, List[Tuple[str, str, Optional[Dict[str, Any]]]]] = {
    "account_id":  [("/web/api/v2.1/accounts", "id", {"limit": 1})],
    "site_id":     [("/web/api/v2.1/sites", "id", {"limit": 1})],
    "group_id":    [("/web/api/v2.1/groups", "id", {"limit": 1})],
    "user_id":     [("/web/api/v2.1/users", "id", {"limit": 1})],
    "service_user_id": [("/web/api/v2.1/service-users", "id", {"limit": 1})],
    "agent_id":    [("/web/api/v2.1/agents", "id", {"limit": 1})],
    "threat_id":   [("/web/api/v2.1/threats", "id", {"limit": 1})],
    "tag_id":      [("/web/api/v2.1/tags", "id", {"limit": 1})],
    "role_id":     [("/web/api/v2.1/rbac/role", "id", {"limit": 1})],
    "policyId":    [("/web/api/v2.1/policies", "id", {"limit": 1})],
    "workflow_id": [("/web/api/v2.1/hyperautomation/workflows", "id", {"limit": 1})],
    "activity_id": [("/web/api/v2.1/activities", "id", {"limit": 1})],
    "hash":        [("/web/api/v2.1/threats", "fileContentHash", {"limit": 1})],
    # Static / enumerated path params with safe demo values
    "agent_type":  [("__STATIC__", "linux", None)],
    "event_type":  [("__STATIC__", "processcreation", None)],
    "report_format": [("__STATIC__", "pdf", None)],
    "export_format": [("__STATIC__", "csv", None)],
    "firewall_rule_category": [("__STATIC__", "endpoint", None)],
}

# Path params we can't resolve reliably — endpoints using these are skipped
# with "no_id_available" rather than marked failing.
UNRESOLVABLE = {
    "application_id", "applicationId", "applicationCatalogId",
    "report_id", "inventory_id", "profile_id", "package_id",
    "workflow_execution_id", "integrationId", "vcsIntegrationId",
    "version_id", "id",
}

PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


# --------------------------------------------------------------- response hints
def _shape(body: Any) -> Dict[str, Any]:
    """Small fingerprint of the response — what keys, how many items."""
    if not isinstance(body, dict):
        return {"type": type(body).__name__}
    out: Dict[str, Any] = {"keys": sorted(list(body.keys()))[:15]}
    data = body.get("data")
    if isinstance(data, list):
        out["data_type"] = "list"
        out["data_len"] = len(data)
    elif isinstance(data, dict):
        out["data_type"] = "object"
        out["data_keys"] = sorted(list(data.keys()))[:15]
    pag = body.get("pagination")
    if isinstance(pag, dict):
        out["paginated"] = True
        if "totalItems" in pag:
            out["total_items"] = pag["totalItems"]
    return out


# --------------------------------------------------------------------- resolver
class Resolver:
    def __init__(self, client: S1Client):
        self.client = client
        self.cache: Dict[str, Optional[str]] = {}

    def resolve(self, name: str) -> Optional[str]:
        if name in self.cache:
            return self.cache[name]
        if name in UNRESOLVABLE:
            self.cache[name] = None
            return None
        rules = PARAM_RESOLVERS.get(name)
        if not rules:
            self.cache[name] = None
            return None
        for source, field, params in rules:
            if source == "__STATIC__":
                self.cache[name] = field
                return field
            try:
                resp = self.client.get(source, params=params)
            except Exception:
                continue
            items = resp.get("data")
            if isinstance(items, list) and items:
                first = items[0]
            elif isinstance(items, dict) and items:
                first = items
            else:
                continue
            if not isinstance(first, dict):
                continue
            val = first.get(field) or first.get("id")
            if val:
                self.cache[name] = val
                return val
        self.cache[name] = None
        return None

    def substitute(self, path: str) -> Tuple[Optional[str], List[str]]:
        """Replace {params} with resolved values. Returns (final_path or None, missing_names)."""
        missing: List[str] = []
        final = path
        for m in PATH_PARAM_RE.findall(path):
            v = self.resolve(m)
            if v is None:
                missing.append(m)
            else:
                final = final.replace("{" + m + "}", str(v))
        if missing:
            return None, missing
        return final, []


# --------------------------------------------------------------------- runner
# Endpoints that stream or return large payloads. Calling them as part of a
# read-only smoke sweep has high variance (seconds to minutes) and tells us
# nothing we don't already know from the sibling list endpoint. Skip by
# default; `--include-slow` re-includes them.
_SLOW_SUFFIXES = (
    "/export",
    "/download",
    "/fetch-file",
    "/mitigation-report",
    "/whitening-options",
)
_SLOW_SUBSTRINGS = (
    "/dv/events",                    # DV event fetch — paginated bulk reads
    "/dv/fetch-file",
    "/remote-ops/forensics/collection-file-url",
)


def _is_slow_path(path: str) -> bool:
    if any(path.endswith(sfx) for sfx in _SLOW_SUFFIXES):
        return True
    return any(sub in path for sub in _SLOW_SUBSTRINGS)


def plan_gets(index: List[Dict[str, Any]], resolver: Resolver,
              tag_filter: Optional[str], include_slow: bool = False):
    """
    Build the GET call plan. Returns (callable_rows, skipped_rows) where
    callable_rows = [(entry, final_path), ...] and skipped_rows records
    why we skipped an endpoint.
    """
    callable_rows: List[Tuple[Dict[str, Any], str]] = []
    skipped: List[Dict[str, Any]] = []
    for e in index:
        if e["method"] != "GET":
            continue
        if tag_filter and e["tag"] != tag_filter:
            continue
        if not include_slow and _is_slow_path(e["path"]):
            skipped.append({**e, "skip_reason": "slow_endpoint",
                            "missing": []})
            continue
        if "{" in e["path"]:
            final, missing = resolver.substitute(e["path"])
            if not final:
                skipped.append({**e, "skip_reason": "no_id_available",
                                "missing": missing})
                continue
            callable_rows.append((e, final))
        else:
            callable_rows.append((e, e["path"]))
    return callable_rows, skipped


_NO_LIMIT_PATTERNS = ("/export", "/download", "/timeline", "/explore/",
                      "/whitening-options", "/mitigation-report", "/report",
                      "/summary", "/status", "/info", "/notes", "/config",
                      "/settings", "/details", "/blocklist",
                      "/count", "/filters-count", "/filters/count",
                      "/categories", "/sub-categories", "/asset-counts",
                      "/maintenance-windows/export_mw",
                      "/autocomplete",
                      "/graph-explorer/query/builder/",
                      "/available-actions", "/available-options",
                      "/tasks-configuration",
                      "/query-status", "/process-state", "/events",
                      "/applications", "/processes",
                      "/inventory/endpoints", "/risks/cves", "/risks/endpoints",
                      "/risks/export",
                      "/content-updates-inventory",
                      "/tasks-configuration/flexible",
                      "/tasks-configuration/has-explicit-subscope",
                      "/tasks-configuration/explicit-subscopes",
                      "/detection-library/platform-rules",
                      "/detection-library/template-rules",
                      "/detection-library/rules",
                      "/detection-library/platform-rules/settings",
                      "/cnapp/vcs/scanner-policy/max-allowed-priority",
                      "/cnapp/vcs/filters/count",
                      "/upgrade-policy/available-packages",
                      "/upgrade-policy/parent-policies",
                      "/upgrade-policy/policies",
                      "/dv/fetch-file",
                      "/dv/events/pq-ping",
                      "/cloud-funnel/estimator",
                      "/unified-exclusions/available-actions",
                      "/remote-ops/data-exporter/results",
                      "/remote-ops/forensics/task-result",
                      "/remote-ops/forensics/collection-file-url",
                      "/remote-ops/forensics/is-collection-file",
                      "/users/login/sso-saml2",
                      "/users/onboarding/validate-token",
                      "/agent-artifacts/token",
                      "/xdr/graph-explorer/query/builder/metadata/available-options",
                      "/agents/applications",
                      "/agents/processes",
                      "/device-control/export",
                      "/installed-applications/export",
                      "/remote-scripts/status",
                      "/tags",
                      "/saved-searches",
                      "/log-collection/agent-type-count",
                      "/mobile-integration/provisioning/partner-key",
                      "/mobile-integration/provisioning/tenant",
                      "/mobile-integration/provisioning/can-provision-tenant",
                      "/mobile-integration/mssp-provisioning/partner",
                      "/rbac/role",
                      "/threat-intelligence/user-config",
                      "/web/api/v2.1/user",
                      )


# --------------------------------------------------------------- path rules
# Ordered rules: (predicate, params). Applied after the default limit=1.
# A predicate is a callable(path) -> bool, or a string (substring match).
# Later matches overwrite earlier for the same key.
_PATH_RULES: List[Tuple[Any, Dict[str, Any]]] = [
    # CSV/JSON export endpoints need exportFormat
    (lambda p: "/xdr/assets/" in p and p.endswith("/export"),
     {"exportFormat": "csv"}),
    # Autocomplete endpoints need a searchText with min length 2.
    (lambda p: p.endswith("/autocomplete") or p.endswith("/autocomplete/v2"),
     {"text": "ab", "key": "name", "searchText": "ab"}),
    # Tasks configuration needs a valid taskType enum. "UPGRADE" works on most tenants.
    (lambda p: p.startswith("/web/api/v2.1/tasks-configuration"),
     {"taskType": "UPGRADE"}),
    # Scope-aware endpoints need scopeLevel + scopeId
    (lambda p: p in (
        "/web/api/v2.1/agent-artifacts/token",
        "/web/api/v2.1/upgrade-policy/available-packages",
        "/web/api/v2.1/upgrade-policy/parent-policies",
        "/web/api/v2.1/upgrade-policy/policies",
        "/web/api/v2.1/detection-library/rules",
        "/web/api/v2.1/detection-library/platform-rules/settings",
        "/web/api/v2.1/detection-library/platform-rules",
        "/web/api/v2.1/detection-library/template-rules",
        "/web/api/v2.1/cnapp/vcs/filters/count",
        "/web/api/v2.1/cnapp/vcs/scanner-policy/max-allowed-priority",
        "/web/api/v2.1/cnapp/vcs/integrations",
        "/web/api/v2.1/cnapp/vcs/integrations/count",
     ),
     {"scopeLevel": "site", "scope_level": "site",
      "scopeType": "site", "scope_type": "site",
      "osType": "windows"}),
    # /tags needs type
    (lambda p: p == "/web/api/v2.1/tags",
     {"type": "ALL"}),
    # User onboarding token validation
    (lambda p: p.endswith("/users/onboarding/validate-token"),
     {"token": "dummy-smoke-token"}),
    # unified-exclusions/available-actions needs 'create' flag
    (lambda p: p.endswith("/unified-exclusions/available-actions"),
     {"create": "false"}),
    # XDR graph explorer metadata/available-options/v2 needs at least one input
    (lambda p: p.endswith("/xdr/graph-explorer/query/builder/metadata/available-options/v2"),
     {"ctx": "source"}),
    # /xdr/assets/.../filters/autocomplete wants 'key' = asset-specific attribute
    (lambda p: "/xdr/assets/" in p and p.endswith("/filters/autocomplete"),
     {"key": "name", "text": "a"}),
]


def _params_for(path: str, ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Build query params for a GET call. `ctx` carries resolved IDs
    (site_id, agent_id, account_id, etc.) from the resolver.

    The default is `limit=1` for list-like endpoints; endpoints that
    reject limit are matched against _NO_LIMIT_PATTERNS. Endpoints that
    need specific params get them via _PATH_RULES.
    """
    params: Dict[str, Any] = {}
    # Default limit unless endpoint doesn't take one
    if not any(p in path for p in _NO_LIMIT_PATTERNS):
        params["limit"] = 1
    # Apply path rules
    for pred, extra in _PATH_RULES:
        matches = pred(path) if callable(pred) else (pred in path)
        if matches:
            params.update(extra)
    # Bind scopeId to a resolved site_id if available
    if "scopeLevel" in params and ctx.get("site_id"):
        params.setdefault("scopeId", ctx["site_id"])
        params.setdefault("scope_id", ctx["site_id"])
    # agent_id / agentId substitutions for endpoints that need them
    if ctx.get("agent_id"):
        _agent_required = (
            "/web/api/v2.1/content-updates-inventory",
            "/web/api/v2.1/remote-ops/data-exporter/results",
        )
        if any(path == p or path.startswith(p + "?") for p in _agent_required):
            params["agentId"] = ctx["agent_id"]
            params["agentIds"] = ctx["agent_id"]
        # agents/applications, agents/processes need ids= (agent ids, not application ids)
        if path in ("/web/api/v2.1/agents/applications",
                    "/web/api/v2.1/agents/processes"):
            params["ids"] = ctx["agent_id"]
    # Fill applicationIds for application-management if we have one
    if ctx.get("application_id"):
        app_needed = (
            "/web/api/v2.1/application-management/inventory/endpoints",
            "/web/api/v2.1/application-management/inventory/applications",
            "/web/api/v2.1/application-management/risks/cves",
            "/web/api/v2.1/application-management/risks/endpoints",
        )
        if path in app_needed or path.startswith(tuple(a + "/" for a in app_needed)):
            params["applicationIds"] = ctx["application_id"]
            params["ids"] = ctx["application_id"]
    return params or None


def run_gets(client: S1Client, plan, workers: int, ctx: Dict[str, Any],
             progress: bool = True, batch_deadline: float = 45.0):
    """Fan out the GET calls. Params: limit=1 when the endpoint looks like a list.

    ``batch_deadline`` is the hard wall-clock cap per batch. Any future that
    hasn't completed by then is recorded as a timeout and the batch moves on.
    Without this, a single stalled endpoint (slow upstream, half-open socket
    under pool_block=False) can block a whole batch beyond requests' own
    timeout.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTimeout

    calls = []
    for entry, path in plan:
        calls.append((path, _params_for(path, ctx)))
    t0 = time.time()
    # Run in batches so we can print progress and cap total wall time.
    results: List[Dict[str, Any]] = []
    batch_size = max(workers * 4, 40)
    for i in range(0, len(calls), batch_size):
        chunk = calls[i:i + batch_size]
        batch_t0 = time.time()

        # Fan out manually with a hard deadline so one stalled request
        # can't hold up the whole batch.
        batch_results: List[Dict[str, Any]] = [None] * len(chunk)  # type: ignore[list-item]

        def _one(idx: int, path: str, params):
            t = time.time()
            try:
                body = client.request("GET", path, params=params, retries=0)
                return idx, {
                    "path": path, "params": params, "ok": True,
                    "status": 200, "data": body, "error": None,
                    "elapsed_ms": (time.time() - t) * 1000.0,
                }
            except S1APIError as e:
                return idx, {
                    "path": path, "params": params, "ok": False,
                    "status": e.status, "data": None, "error": str(e),
                    "elapsed_ms": (time.time() - t) * 1000.0,
                }
            except Exception as e:
                return idx, {
                    "path": path, "params": params, "ok": False,
                    "status": None, "data": None,
                    "error": f"{type(e).__name__}: {e}",
                    "elapsed_ms": (time.time() - t) * 1000.0,
                }

        ex = ThreadPoolExecutor(max_workers=workers)
        try:
            futs = {ex.submit(_one, j, p, q): j
                    for j, (p, q) in enumerate(chunk)}
            try:
                for f in as_completed(futs, timeout=batch_deadline):
                    idx, r = f.result()
                    batch_results[idx] = r
            except FutTimeout:
                # Mark unfinished calls as timeouts; cancel pending futures.
                for f, j in futs.items():
                    if batch_results[j] is None and not f.done():
                        path, params = chunk[j]
                        batch_results[j] = {
                            "path": path, "params": params, "ok": False,
                            "status": None, "data": None,
                            "error": f"Timeout: exceeded {batch_deadline}s batch deadline",
                            "elapsed_ms": batch_deadline * 1000.0,
                        }
                        f.cancel()
        finally:
            # Non-blocking shutdown. Any in-flight worker whose socket read
            # is wedged continues in the background but we don't wait on it;
            # progress resumes.
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                ex.shutdown(wait=False)

        # Fill any remaining None slots (shouldn't happen, but safe-guard).
        for j, r in enumerate(batch_results):
            if r is None:
                path, params = chunk[j]
                batch_results[j] = {
                    "path": path, "params": params, "ok": False,
                    "status": None, "data": None,
                    "error": "Unknown: never started",
                    "elapsed_ms": 0.0,
                }
        results.extend(batch_results)
        if progress:
            ok = sum(1 for r in batch_results if r["ok"])
            timed_out = sum(1 for r in batch_results
                            if r["error"] and r["error"].startswith("Timeout"))
            extra = f" (timeouts: {timed_out})" if timed_out else ""
            print(f"  batch {i//batch_size + 1}: {len(batch_results)} calls, "
                  f"{ok} ok{extra}, cum {len(results)}/{len(calls)}, "
                  f"{time.time() - t0:.1f}s", flush=True)
    elapsed = time.time() - t0
    # Zip back with plan metadata
    rows = []
    for (entry, path), r in zip(plan, results):
        rows.append({
            "method": "GET",
            "path_template": entry["path"],
            "path_called": path,
            "tag": entry["tag"],
            "operationId": entry.get("operationId"),
            "summary": entry.get("summary"),
            "ok": r["ok"],
            "status": r["status"],
            "error": (r["error"] or "")[:300] if r["error"] else None,
            "elapsed_ms": round(r["elapsed_ms"], 1),
            "shape": _shape(r["data"]) if r["ok"] else None,
        })
    return rows, elapsed


def run_safe_posts(client: S1Client, workers: int):
    rows: List[Dict[str, Any]] = []
    # POSTs vary in body shape; do them sequentially so we can honor a
    # body_factory. They're few and small.
    ctx: Dict[str, Any] = {}
    for path, fac in SAFE_POSTS:
        body = fac(ctx)
        t0 = time.time()
        try:
            resp = client.post(path, json_body=body)
            rows.append({
                "method": "POST",
                "path_template": path,
                "path_called": path,
                "tag": "safe_post",
                "operationId": None,
                "summary": None,
                "ok": True,
                "status": 200,
                "error": None,
                "elapsed_ms": round((time.time() - t0) * 1000, 1),
                "shape": _shape(resp),
            })
        except S1APIError as e:
            rows.append({
                "method": "POST",
                "path_template": path,
                "path_called": path,
                "tag": "safe_post",
                "operationId": None,
                "summary": None,
                "ok": False,
                "status": e.status,
                "error": str(e)[:300],
                "elapsed_ms": round((time.time() - t0) * 1000, 1),
                "shape": None,
            })
        except Exception as e:
            rows.append({
                "method": "POST",
                "path_template": path,
                "path_called": path,
                "tag": "safe_post",
                "operationId": None,
                "summary": None,
                "ok": False,
                "status": None,
                "error": f"{type(e).__name__}: {e}"[:300],
                "elapsed_ms": round((time.time() - t0) * 1000, 1),
                "shape": None,
            })
    return rows


# --------------------------------------------------------------------- report
def _status_bucket(row: Dict[str, Any]) -> str:
    if row["ok"]:
        return "ok"
    s = row["status"]
    err = row.get("error") or ""
    if s == 400:
        return "bad_request"
    if s == 401:
        return "unauthorized"
    if s == 403:
        return "forbidden"
    if s == 404:
        return "not_found"
    if s is None:
        if err.startswith("Timeout"):
            return "timeout"
        return "transport_error"
    return f"http_{s}"


def build_report(rows, skipped, elapsed_total: float, base_url: str):
    total = len(rows) + len(skipped)
    by_status = Counter(_status_bucket(r) for r in rows)
    by_tag: Dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        by_tag[r["tag"]][_status_bucket(r)] += 1
    for s in skipped:
        by_tag[s["tag"]]["no_id_available"] += 1

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base_url": base_url,
        "total_planned": total,
        "total_called": len(rows),
        "total_skipped": len(skipped),
        "elapsed_seconds": round(elapsed_total, 2),
        "by_status": dict(by_status),
        "by_tag": {t: dict(c) for t, c in sorted(by_tag.items())},
    }
    return {
        "summary": summary,
        "rows": rows,
        "skipped": skipped,
    }


def write_markdown(report: Dict[str, Any], out_path: Path):
    s = report["summary"]
    rows = report["rows"]
    skipped = report["skipped"]

    lines: List[str] = []
    lines.append("# Tenant capabilities — auto-generated")
    lines.append("")
    lines.append(f"- Generated at: {s['generated_at']}")
    lines.append(f"- Tenant: `{s['base_url']}`")
    lines.append(f"- Called: {s['total_called']}  |  Skipped (no ID on this tenant): {s['total_skipped']}")
    lines.append(f"- Elapsed: {s['elapsed_seconds']}s")
    lines.append("")
    lines.append("## Status mix")
    lines.append("")
    lines.append("| Bucket | Count |")
    lines.append("|---|---:|")
    for k, v in sorted(s["by_status"].items(), key=lambda x: -x[1]):
        lines.append(f"| {k} | {v} |")
    lines.append("")

    lines.append("## Per-tag rollup")
    lines.append("")
    lines.append("| Tag | ok | forbidden | not_found | bad_request | other | no_id |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for tag, c in s["by_tag"].items():
        other = sum(v for k, v in c.items()
                    if k not in ("ok", "forbidden", "not_found", "bad_request", "no_id_available"))
        lines.append(
            f"| {tag} | {c.get('ok', 0)} | {c.get('forbidden', 0)} | "
            f"{c.get('not_found', 0)} | {c.get('bad_request', 0)} | "
            f"{other} | {c.get('no_id_available', 0)} |"
        )
    lines.append("")

    lines.append("## Endpoints that work on this tenant (status 200)")
    lines.append("")
    ok_rows = [r for r in rows if r["ok"]]
    ok_rows.sort(key=lambda r: (r["tag"], r["path_template"]))
    lines.append("| Method | Path | Tag | Latency (ms) | Shape |")
    lines.append("|---|---|---|---:|---|")
    for r in ok_rows:
        shape = r.get("shape") or {}
        shape_s = ", ".join(f"{k}={v}" for k, v in shape.items()
                            if k in ("data_type", "data_len", "total_items"))
        lines.append(f"| {r['method']} | `{r['path_template']}` | {r['tag']} | "
                     f"{r['elapsed_ms']:.0f} | {shape_s} |")
    lines.append("")

    failed = [r for r in rows if not r["ok"]]
    if failed:
        lines.append("## Endpoints that returned non-2xx")
        lines.append("")
        lines.append("| Method | Path | Tag | Status | Reason |")
        lines.append("|---|---|---|---:|---|")
        for r in sorted(failed, key=lambda r: (r["status"] or 0, r["tag"], r["path_template"])):
            reason = (r.get("error") or "").replace("|", "/").replace("\n", " ")
            lines.append(f"| {r['method']} | `{r['path_template']}` | {r['tag']} | "
                         f"{r['status']} | {reason[:140]} |")
        lines.append("")

    if skipped:
        lines.append("## Skipped — no ID available on this tenant")
        lines.append("")
        lines.append("| Path | Tag | Missing |")
        lines.append("|---|---|---|")
        for r in sorted(skipped, key=lambda r: (r["tag"], r["path"])):
            lines.append(f"| `{r['path']}` | {r['tag']} | {', '.join(r.get('missing', []))} |")
        lines.append("")

    out_path.write_text("\n".join(lines))


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", help="limit to one tag (e.g. Threats)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan; do not call anything")
    ap.add_argument("--no-post", action="store_true",
                    help="skip the safe-POST batch")
    ap.add_argument("--include-slow", action="store_true",
                    help="also call streaming/export endpoints (slower, higher variance)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="per-request timeout seconds (default 10)")
    ap.add_argument("--batch-deadline", type=float, default=45.0,
                    help="hard wall-clock deadline per batch (default 45s); "
                         "unfinished calls are recorded as timeouts")
    ap.add_argument("--out-json", default=str(OUT_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    args = ap.parse_args()

    index = json.loads(INDEX_PATH.read_text())

    # Short timeout + no retries for the smoke test — we want fast signal,
    # not persistence. A slow endpoint is still signal ("this one's slow
    # on this tenant"), not a reason to block the whole sweep.
    client = S1Client(cache_ttl=120, timeout=args.timeout)
    resolver = Resolver(client)

    # Pre-warm common IDs so parallel workers don't thunder the resolver
    for name in ("account_id", "site_id", "group_id", "user_id", "agent_id",
                 "threat_id", "service_user_id"):
        resolver.resolve(name)

    # Resolve an application_id (not in PARAM_RESOLVERS — it's an extra
    # needed by /application-management/*). Best-effort.
    app_id: Optional[str] = None
    try:
        resp = client.get("/web/api/v2.1/application-management/inventory",
                          params={"limit": 1})
        data = resp.get("data") or []
        if isinstance(data, list) and data:
            app_id = data[0].get("id") or data[0].get("applicationId")
    except Exception:
        pass

    ctx: Dict[str, Any] = {
        "account_id": resolver.cache.get("account_id"),
        "site_id": resolver.cache.get("site_id"),
        "group_id": resolver.cache.get("group_id"),
        "user_id": resolver.cache.get("user_id"),
        "agent_id": resolver.cache.get("agent_id"),
        "threat_id": resolver.cache.get("threat_id"),
        "application_id": app_id,
    }

    plan, skipped = plan_gets(index, resolver, args.tag,
                              include_slow=args.include_slow)

    print(f"Plan: {len(plan)} GET calls, {len(skipped)} skipped"
          f" (tag filter: {args.tag or 'all'})")
    if args.dry_run:
        for e, p in plan[:10]:
            print("  GET", p, f"[{e['tag']}]")
        print("  ...")
        return

    t0 = time.time()
    rows, get_elapsed = run_gets(client, plan, args.workers, ctx,
                                 batch_deadline=args.batch_deadline)
    print(f"GETs done: {len(rows)} in {get_elapsed:.1f}s "
          f"({len([r for r in rows if r['ok']])} ok)")

    if not args.no_post:
        post_rows = run_safe_posts(client, args.workers)
        rows.extend(post_rows)
        print(f"Safe POSTs done: {len(post_rows)} "
              f"({len([r for r in post_rows if r['ok']])} ok)")

    elapsed = time.time() - t0
    report = build_report(rows, skipped, elapsed, client.base_url)

    Path(args.out_json).write_text(json.dumps(report, indent=2, default=str))
    write_markdown(report, Path(args.out_md))

    s = report["summary"]
    print()
    print(f"== summary ({s['base_url']}) ==")
    print(f"  called : {s['total_called']}")
    print(f"  skipped: {s['total_skipped']}")
    print(f"  elapsed: {s['elapsed_seconds']}s")
    print("  status :", dict(s["by_status"]))
    print(f"  wrote  : {args.out_json}")
    print(f"  wrote  : {args.out_md}")


if __name__ == "__main__":
    main()
