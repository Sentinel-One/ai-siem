#!/usr/bin/env python3
"""Detection as Code: validate, convert, and sync detection rules to SentinelOne.

This is the one place the logic lives. Every CI platform (GitHub Actions, GitLab
CI, Azure Pipelines) just calls this script, so the behaviour is identical
whether a detection engineer runs it on a laptop or a runner runs it on merge.

What it does
------------
1. Reads detection rule files authored in TOML (the team's standard format).
   JSON and YAML rule files are also accepted so mixed repos keep working.
2. Converts each rule into the SentinelOne Custom Detection Rule API envelope
   ({"data": {...}, "filter": {...}}), applying every confirmed API rule:
     - events        -> s1ql, queryLang 2.0, supports mitigation
     - scheduled      -> scheduledParams, queryLang 2.0, no mitigation
     - correlation    -> correlationParams (entity, matchInOrder, subQueries)
3. Validates locally before any network call (enum checks, required fields,
   the runInterval/lookback relationship, pipe-syntax-in-events guard).
4. Syncs idempotently: POST to create; if a rule with the same name already
   exists in scope, look it up and PUT to update. Re-running is safe.
5. Writes a manifest (deployed_rules.json) so you can audit or roll back.

Modes
-----
    python3 dac_sync.py --lint                 # validate only, no convert/deploy
    python3 dac_sync.py --dry-run              # validate + convert, print, no API
    python3 dac_sync.py --sync                 # validate + convert + deploy
    python3 dac_sync.py --sync --changed-only  # CI: only files changed vs BASE_SHA..HEAD_SHA
    python3 dac_sync.py --rollback deployed_rules.json   # delete listed rules

Scope and auth
--------------
Auth comes from the environment so CI never hardcodes a token:
    S1_CONSOLE_URL        e.g. https://your-tenant.sentinelone.net  (no trailing /web/api)
    S1_CONSOLE_API_TOKEN  an API/service-user token
Scope (where rules deploy) is read per rule from its [scope] block, or supplied
globally with --site / --site-id / --account-id (CLI overrides the file).

Dependencies
------------
- None required. Python 3.11+ reads TOML via stdlib tomllib; this script also
  ships a strict built-in TOML fallback, so it runs on older interpreters with
  nothing installed. YAML rule files are the only thing that need an extra
  package (`pip install pyyaml`); TOML and JSON work out of the box.
- HTTP uses the stdlib (urllib), so no `requests` install is required on runners.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ---- TOML reader -----------------------------------------------------------
# Preference order: stdlib tomllib (Python 3.11+), then tomli if installed,
# then a small strict built-in parser so the tool has ZERO hard dependencies on
# any runner. The built-in parser covers exactly the constructs detection rules
# use (tables, arrays of tables, basic/literal/multiline strings, arrays,
# ints, bools) and raises on anything it does not understand rather than
# guessing, so ambiguous input fails loudly instead of mis-deploying.
def _load_toml(text: str) -> dict:
    try:
        import tomllib  # type: ignore
        return tomllib.loads(text)
    except ModuleNotFoundError:
        pass
    try:
        import tomli  # type: ignore
        return tomli.loads(text)
    except ModuleNotFoundError:
        pass
    return _fallback_parse_toml(text)


def _fallback_parse_toml(text: str) -> dict:
    """Strict, minimal TOML reader for the detection-rule subset. Raises on
    anything outside that subset."""
    root: dict = {}

    def descend_table(path: str) -> dict:
        node = root
        for part in [p.strip() for p in path.split(".")]:
            nxt = node.get(part)
            if nxt is None:
                nxt = {}
                node[part] = nxt
            elif isinstance(nxt, list):  # array-of-tables: use the last element
                nxt = nxt[-1]
            elif not isinstance(nxt, dict):
                raise ValueError(f"TOML: {path} conflicts with a non-table value")
            node = nxt
        return node

    def descend_array(path: str) -> dict:
        parts = [p.strip() for p in path.split(".")]
        node = root
        for part in parts[:-1]:
            nxt = node.get(part)
            if isinstance(nxt, list):
                nxt = nxt[-1]
            elif nxt is None:
                nxt = {}
                node[part] = nxt
            node = nxt
        last = parts[-1]
        arr = node.setdefault(last, [])
        if not isinstance(arr, list):
            raise ValueError(f"TOML: {path} is not an array of tables")
        item: dict = {}
        arr.append(item)
        return item

    def parse_scalar(tok: str):
        tok = tok.strip()
        if tok.startswith('"""') or tok.startswith("'''"):
            raise ValueError("multiline string must be handled before scalar parse")
        if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
            return bytes(tok[1:-1], "utf-8").decode("unicode_escape")
        if tok.startswith("'") and tok.endswith("'") and len(tok) >= 2:
            return tok[1:-1]
        if tok == "true":
            return True
        if tok == "false":
            return False
        try:
            return int(tok)
        except ValueError:
            pass
        try:
            return float(tok)
        except ValueError:
            pass
        raise ValueError(f"TOML: cannot parse value {tok!r}")

    def parse_array(tok: str):
        inner = tok.strip()[1:-1].strip()
        if not inner:
            return []
        elems, buf, depth, q = [], "", 0, None
        for ch in inner:
            if q:
                buf += ch
                if ch == q:
                    q = None
                continue
            if ch in ('"', "'"):
                q = ch
                buf += ch
            elif ch == "[":
                depth += 1
                buf += ch
            elif ch == "]":
                depth -= 1
                buf += ch
            elif ch == "," and depth == 0:
                elems.append(buf.strip())
                buf = ""
            else:
                buf += ch
        if buf.strip():
            elems.append(buf.strip())
        return [parse_scalar(e) for e in elems]

    def strip_inline_comment(s: str) -> str:
        # remove a trailing # comment that is outside any quotes
        q = None
        for idx, ch in enumerate(s):
            if q:
                if ch == q:
                    q = None
            elif ch in ('"', "'"):
                q = ch
            elif ch == "#":
                return s[:idx]
        return s

    lines = text.splitlines()
    i, n = 0, len(lines)
    cur = root
    while i < n:
        raw = lines[i]
        i += 1
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[["):
            cur = descend_array(line[2:line.index("]]")].strip())
            continue
        if line.startswith("["):
            cur = descend_table(line[1:line.index("]")].strip())
            continue
        if "=" not in line:
            raise ValueError(f"TOML: cannot parse line {raw!r}")
        key, val = line.split("=", 1)
        key = key.strip().strip('"').strip("'")
        val = val.strip()
        if val.startswith('"""') or val.startswith("'''"):
            delim = val[:3]
            literal = delim == "'''"
            body = val[3:]
            if body.startswith("\n"):
                body = body[1:]
            if body.endswith(delim) and len(body) >= 3:
                content = body[:-3]
            else:
                buf = [body] if body else []
                closed = False
                while i < n:
                    ln = lines[i]
                    i += 1
                    if delim in ln:
                        buf.append(ln[: ln.index(delim)])
                        closed = True
                        break
                    buf.append(ln)
                if not closed:
                    raise ValueError("TOML: unterminated multiline string")
                content = "\n".join(buf)
            if content.startswith("\n"):
                content = content[1:]
            cur[key] = content if literal else bytes(content, "utf-8").decode("unicode_escape")
            continue
        val = strip_inline_comment(val).strip()
        if val.startswith("["):
            # array may span lines until matching ]
            while val.count("[") > val.count("]") and i < n:
                val += " " + strip_inline_comment(lines[i].strip()).strip()
                i += 1
            cur[key] = parse_array(val)
        else:
            cur[key] = parse_scalar(val)
    return root

# ---- optional YAML reader --------------------------------------------------
try:
    import yaml as _yaml  # type: ignore
except ModuleNotFoundError:
    _yaml = None

API_PATH = "/web/api/v2.1/cloud-detection/rules"

SEVERITIES = {"Low", "Medium", "High", "Critical", "Info"}
STATUSES = {"Draft", "Active", "Disabled"}
QUERY_TYPES = {"events", "scheduled", "correlation"}
EXPIRATION_MODES = {"Permanent", "Temporary"}
TREAT_AS_THREAT = {"UNDEFINED", "Suspicious", "Malicious"}
CORR_ENTITIES = {"user", "process", "ip", "endpoint", "storyline", "custom", "none"}
CORR_WINDOWS = {1, 5, 10, 30, 60, 240, 480, 720}
THRESHOLD_OPS = {"Greater", "Less", "Equal"}

RULE_EXTS = {".toml", ".json", ".yaml", ".yml"}


class RuleError(Exception):
    """A rule that fails validation. Carries the file path for clear CI output."""

    def __init__(self, path: Path, message: str):
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message


# ---------------------------------------------------------------------------
# Loading rule files
# ---------------------------------------------------------------------------
def load_rule_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".toml":
        return _load_toml(text)
    if suffix == ".json":
        return json.loads(text)
    if suffix in (".yaml", ".yml"):
        if _yaml is None:
            raise RuleError(path, "YAML rule file needs `pip install pyyaml`.")
        return _yaml.safe_load(text)
    raise RuleError(path, f"unsupported rule extension {suffix}")


def discover_rule_files(roots: list[str]) -> list[Path]:
    out: list[Path] = []
    for root in roots:
        p = Path(root)
        if p.is_file() and p.suffix.lower() in RULE_EXTS:
            out.append(p)
        elif p.is_dir():
            for ext in RULE_EXTS:
                out.extend(sorted(p.rglob(f"*{ext}")))
    # de-dupe, keep order
    seen, uniq = set(), []
    for f in out:
        rp = f.resolve()
        if rp not in seen:
            seen.add(rp)
            uniq.append(f)
    return uniq


def changed_rule_files(base_sha: str, head_sha: str) -> list[Path]:
    """Files added or modified between two commits (CI on-merge sync)."""
    cmd = ["git", "diff", "--name-only", "--diff-filter=AM", base_sha, head_sha]
    names = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.split()
    return [Path(n) for n in names if Path(n).suffix.lower() in RULE_EXTS and Path(n).exists()]


# ---------------------------------------------------------------------------
# TOML model -> API envelope
# ---------------------------------------------------------------------------
def _get(d: dict, *keys, default=None):
    """Accept snake_case or camelCase keys so JSON/YAML rules also work."""
    for k in keys:
        if k in d:
            return d[k]
    return default


def build_envelope(rule: dict, path: Path, scope_override: dict | None) -> dict:
    """Render one rule dict into the {"data":..., "filter":...} API body."""
    name = _get(rule, "name")
    if not name or not str(name).strip():
        raise RuleError(path, "missing required field: name")

    query_type = _get(rule, "query_type", "queryType", default="events")
    if query_type not in QUERY_TYPES:
        raise RuleError(path, f"query_type must be one of {sorted(QUERY_TYPES)}, got {query_type!r}")

    severity = _get(rule, "severity", default="Low")
    if severity not in SEVERITIES:
        raise RuleError(path, f"severity must be one of {sorted(SEVERITIES)}, got {severity!r}")

    status = _get(rule, "status", default="Draft")
    if status not in STATUSES:
        raise RuleError(path, f"status must be one of {sorted(STATUSES)}, got {status!r}")

    expiration_mode = _get(rule, "expiration_mode", "expirationMode", default="Permanent")
    if expiration_mode not in EXPIRATION_MODES:
        raise RuleError(path, f"expiration_mode must be one of {sorted(EXPIRATION_MODES)}")

    data: dict = {
        "name": str(name),
        "queryType": query_type,
        "severity": severity,
        "status": status,
        "expirationMode": expiration_mode,
    }
    desc = _get(rule, "description")
    if desc:
        if len(str(desc)) > 2000:
            raise RuleError(path, "description exceeds the 2000-character API limit")
        data["description"] = str(desc)

    if expiration_mode == "Temporary":
        exp = _get(rule, "expiration")
        if not exp:
            raise RuleError(path, "expiration_mode = 'Temporary' requires an 'expiration' date-time")
        data["expiration"] = exp

    # cool-off (optional, both rule types)
    cooloff = _get(rule, "cool_off", "coolOffSettings")
    renotify = None
    if isinstance(cooloff, dict):
        renotify = _get(cooloff, "renotify_minutes", "renotifyMinutes")
        if renotify is not None:
            data["coolOffSettings"] = {"renotifyMinutes": int(renotify)}

    # ---- per-type bodies --------------------------------------------------
    if query_type == "events":
        _build_events(rule, path, data)
    elif query_type == "scheduled":
        _build_scheduled(rule, path, data, renotify)
    elif query_type == "correlation":
        _build_correlation(rule, path, data)

    return {"data": data, "filter": resolve_scope(rule, path, scope_override)}


def _build_events(rule: dict, path: Path, data: dict) -> None:
    s1ql = _get(rule, "s1ql", "query")
    if not s1ql or not str(s1ql).strip():
        raise RuleError(path, "events rule requires 's1ql'")
    s1ql = str(s1ql)
    # Events rules take boolean S1QL only. A pipe '|' is PowerQuery syntax and
    # belongs in a scheduled rule; the API rejects a piped events body with
    # HTTP 400 "Don't understand [|]".
    if "|" in s1ql:
        raise RuleError(
            path,
            "events rule body contains a pipe '|' (PowerQuery). Events rules take "
            "boolean S1QL only. Use query_type = 'scheduled' for piped PowerQuery.",
        )
    data["s1ql"] = s1ql
    # All Custom Detection (STAR) rules use queryLang 2.0 (verified live: an events
    # rule creates and is stored with queryLang 2.0).
    data["queryLang"] = "2.0"
    tat = _get(rule, "treat_as_threat", "treatAsThreat", default="UNDEFINED")
    if tat not in TREAT_AS_THREAT:
        raise RuleError(path, f"treat_as_threat must be one of {sorted(TREAT_AS_THREAT)}")
    data["treatAsThreat"] = tat
    data["networkQuarantine"] = bool(_get(rule, "network_quarantine", "networkQuarantine", default=False))


def _build_scheduled(rule: dict, path: Path, data: dict, renotify) -> None:
    sched = _get(rule, "scheduled", "scheduledParams")
    if not isinstance(sched, dict):
        raise RuleError(path, "scheduled rule requires a [scheduled] table")
    query = _get(sched, "query")
    if not query or not str(query).strip():
        raise RuleError(path, "scheduled rule requires scheduled.query (PowerQuery)")
    run_iv = _get(sched, "run_interval_minutes", "runIntervalMinutes")
    lookback = _get(sched, "lookback_window_minutes", "lookbackWindowMinutes")
    if run_iv is None or lookback is None:
        raise RuleError(path, "scheduled rule requires run_interval_minutes and lookback_window_minutes")
    run_iv, lookback = int(run_iv), int(lookback)
    _check_interval(path, run_iv, lookback)

    threshold = _get(sched, "threshold", default={"value": 0, "operator": "Greater"})
    if isinstance(threshold, dict):
        op = _get(threshold, "operator", default="Greater")
        if op not in THRESHOLD_OPS:
            raise RuleError(path, f"threshold.operator must be one of {sorted(THRESHOLD_OPS)}")
        threshold = {"value": int(_get(threshold, "value", default=0)), "operator": op}
    if renotify is not None and renotify % run_iv != 0:
        raise RuleError(
            path,
            f"cool_off.renotify_minutes ({renotify}) must be a multiple of "
            f"run_interval_minutes ({run_iv}) when both are set.",
        )

    data["queryLang"] = "2.0"  # mandatory for scheduled; omitting it is HTTP 400
    # Scheduled rules cannot mitigate; verdict surfaces via severity.
    data["treatAsThreat"] = "UNDEFINED"
    data["networkQuarantine"] = False
    data["scheduledParams"] = {
        "query": str(query),
        "runIntervalMinutes": run_iv,
        "lookbackWindowMinutes": lookback,
        "threshold": threshold,
    }


def _build_correlation(rule: dict, path: Path, data: dict) -> None:
    corr = _get(rule, "correlation", "correlationParams")
    if not isinstance(corr, dict):
        raise RuleError(path, "correlation rule requires a [correlation] table")
    entity = _get(corr, "entity", default="user")
    if entity not in CORR_ENTITIES:
        raise RuleError(path, f"correlation.entity must be one of {sorted(CORR_ENTITIES)}")
    if "match_in_order" not in corr and "matchInOrder" not in corr:
        raise RuleError(path, "correlation rule requires correlation.match_in_order (true/false)")
    match_in_order = bool(_get(corr, "match_in_order", "matchInOrder"))

    subs_in = _get(corr, "subqueries", "subQueries", default=[])
    if not isinstance(subs_in, list) or not subs_in:
        raise RuleError(path, "correlation rule requires at least one [[correlation.subqueries]]")
    if len(subs_in) > 10:
        raise RuleError(path, "correlation rule allows at most 10 subqueries")
    sub_queries = []
    for i, s in enumerate(subs_in, 1):
        sq = _get(s, "sub_query", "subQuery")
        mr = _get(s, "matches_required", "matchesRequired", default=1)
        if not sq or not str(sq).strip():
            raise RuleError(path, f"subquery #{i} missing sub_query")
        mr = int(mr)
        if not (1 <= mr <= 1000):
            raise RuleError(path, f"subquery #{i} matches_required must be 1..1000")
        sub_queries.append({"subQuery": str(sq), "matchesRequired": mr})

    cparams: dict = {"entity": entity, "matchInOrder": match_in_order, "subQueries": sub_queries}
    tw = _get(corr, "time_window", "timeWindow")
    if isinstance(tw, dict):
        wm = _get(tw, "window_minutes", "windowMinutes")
        if wm is not None:
            if int(wm) not in CORR_WINDOWS:
                raise RuleError(path, f"correlation.time_window.window_minutes must be one of {sorted(CORR_WINDOWS)}")
            cparams["timeWindow"] = {"windowMinutes": int(wm)}
    # Correlation rules require queryLang 2.0 (confirmed live: omitting it returns
    # HTTP 400 "query lang must be 2.0"), same as scheduled rules.
    data["queryLang"] = "2.0"
    data["correlationParams"] = cparams
    # Mitigation is configurable on correlation rules; pass through if present.
    tat = _get(rule, "treat_as_threat", "treatAsThreat")
    if tat is not None:
        if tat not in TREAT_AS_THREAT:
            raise RuleError(path, f"treat_as_threat must be one of {sorted(TREAT_AS_THREAT)}")
        data["treatAsThreat"] = tat
    if _get(rule, "network_quarantine", "networkQuarantine") is not None:
        data["networkQuarantine"] = bool(_get(rule, "network_quarantine", "networkQuarantine"))


def _check_interval(path: Path, run_iv: int, lookback: int) -> None:
    if not (1 <= run_iv <= 43200):
        raise RuleError(path, "run_interval_minutes must be 1..43200")
    if not (1 <= lookback <= 43200):
        raise RuleError(path, "lookback_window_minutes must be 1..43200")
    if lookback < 60:
        min_iv = 1
    elif lookback <= 360:
        min_iv = 5
    elif lookback <= 10080:
        min_iv = 15
    else:
        min_iv = 60
    if run_iv < min_iv:
        raise RuleError(
            path,
            f"with lookback_window_minutes={lookback}, run_interval_minutes must be "
            f">= {min_iv} (API constraint).",
        )


def resolve_scope(rule: dict, path: Path, scope_override: dict | None) -> dict:
    """Return the API filter block: {"siteIds":[...]} or {"accountIds":[...]}."""
    if scope_override:
        return scope_override
    scope = _get(rule, "scope", default={})
    site_ids = _get(scope, "site_ids", "siteIds")
    account_ids = _get(scope, "account_ids", "accountIds")
    site_name = _get(scope, "site")
    if site_ids:
        return {"siteIds": list(site_ids)}
    if account_ids:
        return {"accountIds": list(account_ids)}
    if site_name:
        # name needs a live lookup; mark for the syncer to resolve.
        return {"_siteName": site_name}
    raise RuleError(
        path,
        "no scope. Add a [scope] block with site_ids/account_ids/site, or pass "
        "--site / --site-id / --account-id.",
    )


# ---------------------------------------------------------------------------
# SentinelOne API client (stdlib only)
# ---------------------------------------------------------------------------
class S1:
    def __init__(self, base_url: str, token: str, verify_tls: bool = True):
        self.base = base_url.rstrip("/")
        self.token = token
        self._ctx = None
        if not verify_tls:
            import ssl
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _req(self, method: str, path: str, params: dict | None = None, body: dict | None = None) -> dict:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"ApiToken {self.token}")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=60) as r:
                txt = r.read().decode()
                return json.loads(txt) if txt else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {e.code} on {method} {path}: {detail[:600]}") from None

    def get(self, path, params=None):
        return self._req("GET", path, params=params)

    def post(self, path, body):
        return self._req("POST", path, body=body)

    def put(self, path, body):
        return self._req("PUT", path, body=body)

    def delete(self, path, body):
        return self._req("DELETE", path, body=body)

    def resolve_site(self, name: str) -> tuple[str, str]:
        r = self.get("/web/api/v2.1/sites", {"name": name, "limit": 10})
        sites = r.get("data", {}).get("sites", []) or []
        exact = [s for s in sites if s.get("name") == name]
        pick = exact[0] if exact else (sites[0] if sites else None)
        if not pick:
            raise RuntimeError(f"no site matched name {name!r}")
        return pick["id"], pick.get("accountId")

    def find_rule_by_name(self, name: str, scope: dict) -> str | None:
        params = {"isLegacy": "false", "name__contains": name, "limit": 200}
        if "siteIds" in scope:
            params["siteIds"] = ",".join(scope["siteIds"])
        elif "accountIds" in scope:
            params["accountIds"] = ",".join(scope["accountIds"])
        r = self.get(API_PATH, params)
        rules = r.get("data", []) or []
        for rule in rules:
            if rule.get("name") == name:
                return rule.get("id")
        return None


# ---------------------------------------------------------------------------
# Sync (idempotent create-or-update)
# ---------------------------------------------------------------------------
def _materialise_scope(client: S1 | None, envelope: dict, cache: dict) -> tuple[dict, str | None]:
    """Turn a {_siteName: ...} filter into a real siteIds filter via the API."""
    flt = envelope["filter"]
    if "_siteName" not in flt:
        acct = flt.get("accountIds", [None])[0] if "accountIds" in flt else None
        return flt, acct
    name = flt["_siteName"]
    if client is None:
        return {"siteIds": ["<resolve:" + name + ">"]}, None
    if name not in cache:
        cache[name] = client.resolve_site(name)
    site_id, acct = cache[name]
    return {"siteIds": [site_id]}, acct


def sync_rules(envelopes: list[tuple[Path, dict]], client: S1, status_override: str | None) -> list[dict]:
    manifest, cache = [], {}
    for path, env in envelopes:
        scope, acct = _materialise_scope(client, env, cache)
        env["filter"] = scope
        if status_override:
            env["data"]["status"] = status_override
        name = env["data"]["name"]
        existing = client.find_rule_by_name(name, scope)
        try:
            if existing:
                # PUT requires all five data fields plus filter.siteIds and a non-null status.
                env["data"].setdefault("status", "Active")
                resp = client.put(f"{API_PATH}/{existing}", env)
                rid = (resp.get("data") or {}).get("id", existing)
                action = "updated"
            else:
                resp = client.post(API_PATH, env)
                rid = (resp.get("data") or {}).get("id")
                action = "created"
            print(f"  {action}: {name} -> {rid}")
            manifest.append({"name": name, "ruleId": rid, "queryType": env["data"]["queryType"],
                             "action": action, "scope": scope, "accountId": acct, "file": str(path)})
        except RuntimeError as e:
            # If create failed because the name already exists (race or stale lookup), retry as update.
            if "already" in str(e).lower() and not existing:
                rid2 = client.find_rule_by_name(name, scope)
                if rid2:
                    env["data"].setdefault("status", "Active")
                    client.put(f"{API_PATH}/{rid2}", env)
                    print(f"  updated (retry): {name} -> {rid2}")
                    manifest.append({"name": name, "ruleId": rid2, "queryType": env["data"]["queryType"],
                                     "action": "updated", "scope": scope, "accountId": acct, "file": str(path)})
                    continue
            print(f"  FAILED: {name}: {e}", file=sys.stderr)
            raise
    return manifest


def rollback(manifest_path: str, client: S1) -> None:
    items = json.loads(Path(manifest_path).read_text())
    for it in items:
        rid, scope = it.get("ruleId"), it.get("scope", {})
        if not rid:
            continue
        flt = {"ids": [rid]}
        if "siteIds" in scope:
            flt["siteIds"] = scope["siteIds"]
        elif "accountIds" in scope:
            flt["accountIds"] = scope["accountIds"]
        client.delete(API_PATH, {"filter": flt})
        print(f"  deleted: {it.get('name')} ({rid})")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Detection as Code sync for SentinelOne.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--lint", action="store_true", help="validate only")
    mode.add_argument("--dry-run", action="store_true", help="validate + convert + print, no API")
    mode.add_argument("--sync", action="store_true", help="validate + convert + deploy")
    mode.add_argument("--rollback", metavar="MANIFEST", help="delete rules in a manifest")
    ap.add_argument("paths", nargs="*", default=["detections"], help="rule files or dirs (default: detections/)")
    ap.add_argument("--changed-only", action="store_true", help="CI: only files changed in BASE_SHA..HEAD_SHA")
    ap.add_argument("--base-sha", default=os.environ.get("BASE_SHA"))
    ap.add_argument("--head-sha", default=os.environ.get("HEAD_SHA"))
    ap.add_argument("--site", help="scope override: site name (resolved to siteId)")
    ap.add_argument("--site-id", help="scope override: siteId")
    ap.add_argument("--account-id", help="scope override: accountId")
    ap.add_argument("--status", choices=sorted(STATUSES), help="override status on every rule")
    ap.add_argument("--manifest", default="deployed_rules.json", help="where to write the deploy manifest")
    args = ap.parse_args(argv)

    scope_override = None
    if args.site_id:
        scope_override = {"siteIds": [args.site_id]}
    elif args.account_id:
        scope_override = {"accountIds": [args.account_id]}
    elif args.site:
        scope_override = {"_siteName": args.site}

    # rollback short-circuits
    if args.rollback:
        client = _client_from_env()
        rollback(args.rollback, client)
        return 0

    # pick files
    if args.changed_only:
        if not (args.base_sha and args.head_sha):
            print("--changed-only needs --base-sha/--head-sha (or BASE_SHA/HEAD_SHA env).", file=sys.stderr)
            return 2
        files = changed_rule_files(args.base_sha, args.head_sha)
    else:
        files = discover_rule_files(args.paths or ["detections"])

    if not files:
        print("No rule files found. Nothing to do.")
        return 0

    # validate + convert
    envelopes, errors = [], []
    for f in files:
        try:
            rule = load_rule_file(f)
            env = build_envelope(rule, f, scope_override)
            envelopes.append((f, env))
        except (RuleError, json.JSONDecodeError, Exception) as e:
            errors.append(str(e) if isinstance(e, RuleError) else f"{f}: {e}")

    print(f"Parsed {len(envelopes)} rule(s); {len(errors)} error(s).")
    for e in errors:
        print(f"  ERROR {e}", file=sys.stderr)
    if errors:
        return 1

    if args.lint:
        print("Lint OK.")
        return 0

    if args.dry_run:
        for f, env in envelopes:
            print(f"\n# {f}")
            print(json.dumps(env, indent=2))
        return 0

    # sync
    client = _client_from_env()
    print(f"Syncing {len(envelopes)} rule(s) to {client.base} ...")
    manifest = sync_rules(envelopes, client, args.status)
    Path(args.manifest).write_text(json.dumps(manifest, indent=2))
    print(f"\nWrote manifest: {args.manifest} ({len(manifest)} rule(s)).")
    return 0


def _client_from_env() -> S1:
    base = os.environ.get("S1_CONSOLE_URL")
    token = os.environ.get("S1_CONSOLE_API_TOKEN")
    if not base or not token:
        raise SystemExit("Set S1_CONSOLE_URL and S1_CONSOLE_API_TOKEN in the environment.")
    verify = os.environ.get("S1_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
    return S1(base, token, verify_tls=verify)


if __name__ == "__main__":
    sys.exit(main())
