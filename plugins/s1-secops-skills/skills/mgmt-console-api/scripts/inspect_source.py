"""
Source-agnostic schema discovery for SDL data sources.

Uses the LRQ ``LOG`` queryType (the same primitive the Event Search UI
uses for raw-event retrieval). Unlike PowerQuery, a ``LOG`` query
returns every flat attribute the parser emits under
``data.matches[].values``. From that sample we read every attribute
name that appeared, compute populated_frac + cardinality, and
classify each one semantically (principal_user | principal_host |
principal_ip | action | temporal | network | file | process |
grouping_candidate | other). Recommended ``prim_key`` and
``action_key`` are picked from whatever the source actually carries,
not from a hardcoded list.

The point: downstream tools (collectors, dashboards, detections)
should NOT hardcode field names. They should discover the schema,
then build queries from whichever fields actually exist.

Why the ``LOG`` queryType rather than ``| columns`` or bare PQ?

- PQ has no wildcard column projection (``| columns *`` errors).
- A bare ``| limit`` returns only ``timestamp`` + ``message``.
- ``| columns <big-list>`` only catches fields in the hardcoded list.
- ``LOG`` returns the full parsed event as a dict, so every emitted
  attribute is visible -- even source-specific ones like
  ``policyName``, ``promptResponseId``, ``connectorName`` that no
  hardcoded list would have.

CLI:

    python scripts/inspect_source.py --source "Example Source" --window 24h
    python scripts/inspect_source.py --source "Zscaler Internet Access" --window 7d --sample 200
    python scripts/inspect_source.py --list
    python scripts/inspect_source.py --source X --json

Library:

    from inspect_source import discover_schema, pick_keys
    schema = discover_schema(client, "Example Source", hours=24, sample=100)
    prim_key, action_key = pick_keys(schema)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from s1_client import S1Client  # noqa: E402
from pq import list_data_sources, PQError  # noqa: E402


# ---- classification -------------------------------------------------------

PRINCIPAL_USER_RX = re.compile(
    r"(?:^|[._])user(?:\.|$)|username|principal|actor\.name|\.email(?:\b|$)",
    re.IGNORECASE,
)
PRINCIPAL_HOST_RX = re.compile(
    r"(?:^|[._])hostname(?:\b|$)|\.host\.name(?:\b|$)"
    r"|\.device\.name(?:\b|$)|endpoint\.name|\.computer(?:\b|$)"
    r"|^agent\.(?:uuid|id|name)(?:\b|$)|^device\.(?:id|name)(?:\b|$)"
    r"|^endpoint\.(?:id|name|host\.name)(?:\b|$)",
    re.IGNORECASE,
)
PRINCIPAL_IP_RX = re.compile(
    r"\.ip\.address(?:\b|$)|\.ip_addr(?:\b|$)|(?:^|[._])ip(?:\b|$)"
    r"|ipv4|ipv6",
    re.IGNORECASE,
)
NETWORK_RX = re.compile(
    r"\.port(?:\b|$)|\.url(?:\b|$)|\.domain(?:\b|$)|\.dns(?:\b|$)|uri"
    r"|user_agent|http\.|network\.|bytes",
    re.IGNORECASE,
)
FILE_RX = re.compile(
    r"\.file\.|\.sha(?:1|256|512)?(?:\b|$)|\.md5(?:\b|$)"
    r"|\.hash(?:\b|$)|filename|^sha|^md5",
    re.IGNORECASE,
)
PROCESS_RX = re.compile(
    r"\.process\.|cmdline|command_line|\.pid(?:\b|$)",
    re.IGNORECASE,
)
TEMPORAL_RX = re.compile(
    r"(?:^|[._])(?:time|timestamp|date|ts)(?:\b|$|_)",
    re.IGNORECASE,
)
# Exact-name action candidates, in priority order
ACTION_EXACT: Tuple[str, ...] = (
    "action", "event.type", "event.action", "event.category",
    "event.outcome", "event.kind", "outcome", "result", "status",
    "disposition", "verdict", "severity", "severity.name",
    "threat.classification", "rule.name", "activity_name",
    "class_name", "category_name",
)


def classify_field(name: str, distinct: int, populated_frac: float) -> str:
    low = name.lower()
    if TEMPORAL_RX.search(low):
        return "temporal"
    if name in ACTION_EXACT:
        return "action"
    if PRINCIPAL_USER_RX.search(low):
        return "principal_user"
    if PRINCIPAL_HOST_RX.search(low):
        return "principal_host"
    if PRINCIPAL_IP_RX.search(low):
        return "principal_ip"
    if FILE_RX.search(low):
        return "file"
    if PROCESS_RX.search(low):
        return "process"
    if NETWORK_RX.search(low):
        return "network"
    # low-cardinality populated string => viable grouping key
    if populated_frac >= 0.5 and 1 <= distinct <= 15:
        return "grouping_candidate"
    return "other"


# ---- discovery (via LRQ LOG queryType) -----------------------------------
#
# Unlike PQ, the LOG queryType returns the full parsed event dict for
# every match under ``data.matches[].values``. That means every flat
# attribute the parser emits is visible, without needing a candidate
# list. This is how the Event Search UI populates its "Event
# properties" panel.


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_sdl_query(client: Any, log_filter: str, *,
                   hours: float = 24, sample: int = 200,
                   timeout_s: float = 60.0) -> Dict[str, Any]:
    """Sync query against ``/sdl/api/query`` (SDL API).

    Returns ``{matches: [...], estimatedMatchCount: ...}`` where
    ``matches[i].attributes`` is the parsed event dict. Each match:
    ``{session, thread, timestamp, severity, message, attributes:{...}}``.

    This endpoint is synchronous (no poll/cancel) and on bench is
    20-50% faster than the equivalent LRQ LOG query. It is the
    preferred path for schema discovery. Benchmarks (usea1-acme):

    Windows Event Logs 24h: 3.0s vs 5.8s LRQ (-49%)
    SentinelOne 1h:          3.2s vs 4.6s LRQ (-32%)
    Example Source 7d:      3.2s vs 4.0s LRQ (-21%)
    """
    base = client.base_url.rstrip("/")
    jwt = client.api_token
    if not jwt or not base:
        raise PQError("client is missing api_token or base_url")

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(hours=hours)
    body = {
        "filter": log_filter,
        "startTime": _iso(start),
        "endTime": _iso(end),
        "tenant": True,
        "maxCount": max(sample, 50),
    }
    r = requests.post(f"{base}/sdl/api/query",
                      headers={"Authorization": f"Bearer {jwt}",
                               "Content-Type": "application/json"},
                      json=body, timeout=timeout_s)
    if r.status_code != 200:
        raise PQError(
            f"SDL query failed: HTTP {r.status_code} {r.text[:200]}")
    j = r.json()
    if j.get("status") and j["status"] != "success":
        raise PQError(f"SDL query returned status={j['status']} "
                      f"{j.get('message', '')[:200]}")
    matches = j.get("matches") or []
    # Normalize the response shape to match LRQ LOG's (values dict).
    # LRQ uses `values`; SDL uses `attributes`. Downstream code reads
    # `values`, so we alias.
    out: List[Dict[str, Any]] = []
    for m in matches[:sample]:
        if not isinstance(m, dict):
            continue
        attrs = m.get("attributes")
        if isinstance(attrs, dict):
            out.append({"values": attrs,
                        "timestamp": m.get("timestamp"),
                        "severity": m.get("severity")})
    return {"estimatedMatchCount": len(matches), "matches": out}


def _run_lrq_log_query(client: Any, log_filter: str, *,
                       hours: float = 24, sample: int = 100,
                       poll_deadline_s: float = 60.0) -> Dict[str, Any]:
    """Launch a LRQ LOG query, poll to completion, cancel, return data.

    Fallback path when the sync SDL ``/sdl/api/query`` endpoint is
    unavailable. Slower (3-6s typical) than ``_run_sdl_query`` because
    of the async launch+poll+cancel handshake, but more tolerant of
    tenants where the sync endpoint is not exposed.

    Returns ``{matches: [{values, timestamp, severity}...],
    estimatedMatchCount: int}``, same shape as ``_run_sdl_query``.

    ``log.limit`` is the server-side cap. Setting it to the sample
    size drops 24s -> 6s on a 7d Example Source window.
    """
    base = client.base_url.rstrip("/")
    jwt = client.api_token
    if not jwt or not base:
        raise PQError("client is missing api_token or base_url")

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(hours=hours)
    headers = {"Authorization": f"Bearer {jwt}",
               "Content-Type": "application/json"}

    # Server-side cap. `log.limit` is the accepted field name; the
    # more obvious `maxCount`/`limit` on the outer body don't exist.
    body = {
        "queryType": "LOG",
        "tenant": True,
        "startTime": _iso(start),
        "endTime": _iso(end),
        "queryPriority": "HIGH",
        "log": {"filter": log_filter, "limit": max(sample, 50)},
    }
    r = requests.post(f"{base}/sdl/v2/api/queries", headers=headers,
                      json=body, timeout=30)
    if r.status_code != 200:
        raise PQError(
            f"LOG launch failed: HTTP {r.status_code} {r.text[:200]}")
    j = r.json()
    qid = j.get("id")
    ftag = r.headers.get("X-Dataset-Query-Forward-Tag", "")
    poll_headers = dict(headers)
    if ftag:
        poll_headers["X-Dataset-Query-Forward-Tag"] = ftag

    # Fast-poll schedule: most LOG queries finish in <2s, so tight
    # initial intervals shave latency. Fall back to 1s steady-state.
    # Respects the per-user 3 rps rate cap (first 3 polls take 0.9s).
    poll_schedule = [0.25, 0.35, 0.5, 0.75, 1.0]
    deadline = time.time() + poll_deadline_s
    last_seen = 0
    jj = j
    idx = 0
    try:
        while time.time() < deadline:
            wait = poll_schedule[idx] if idx < len(poll_schedule) else 1.0
            time.sleep(wait)
            idx += 1
            pr = requests.get(
                f"{base}/sdl/v2/api/queries/{qid}?lastStepSeen={last_seen}",
                headers=poll_headers, timeout=30)
            if pr.status_code != 200:
                raise PQError(
                    f"LOG poll failed: HTTP {pr.status_code} {pr.text[:200]}")
            jj = pr.json()
            last_seen = int(jj.get("stepsCompleted") or 0)
            total = int(jj.get("stepsTotal") or 0)
            if total > 0 and last_seen >= total:
                break
        else:
            raise PQError(
                f"LOG poll deadline ({poll_deadline_s}s) exceeded for {qid}")
    finally:
        try:
            requests.delete(f"{base}/sdl/v2/api/queries/{qid}",
                            headers=poll_headers, timeout=10)
        except requests.RequestException:
            pass

    data = jj.get("data") or {}
    # Truncate matches to the requested sample for the stats pass.
    matches = (data.get("matches") or [])[:sample]
    return {
        "estimatedMatchCount": data.get("estimatedMatchCount"),
        "matches": matches,
    }


# Module-level switch so repeated calls in a single process skip the
# SDL attempt once we've established it's unreachable on this tenant.
_SDL_AVAILABLE: Optional[bool] = None


def _run_log_query(client: Any, log_filter: str, *,
                   hours: float = 24, sample: int = 200,
                   backend: str = "auto") -> Dict[str, Any]:
    """Dispatch a schema-discovery sample query.

    ``backend``:
      - ``"auto"`` (default): try sync SDL ``/sdl/api/query`` first,
        fall back to async LRQ LOG on HTTP 404 / auth rejection.
        After one 404 we cache the decision for the process lifetime.
      - ``"sdl"``: SDL sync only.
      - ``"lrq"``: LRQ LOG only.

    Returns ``{matches: [...], estimatedMatchCount: int}`` with
    ``matches[i].values`` being the parsed event dict (both backends
    are normalized to this shape).
    """
    global _SDL_AVAILABLE
    if backend == "sdl" or (backend == "auto" and _SDL_AVAILABLE is not False):
        try:
            res = _run_sdl_query(client, log_filter, hours=hours,
                                 sample=sample)
            if _SDL_AVAILABLE is None:
                _SDL_AVAILABLE = True
            return res
        except PQError as e:
            msg = str(e)
            # 404 / auth error => SDL not exposed; flip the switch.
            if backend == "sdl":
                raise
            if "HTTP 404" in msg or "HTTP 401" in msg or "HTTP 403" in msg:
                _SDL_AVAILABLE = False
            else:
                # Non-404 error: bubble up rather than silently masking
                # a real problem. Callers upstream will retry on a new
                # rung if they need to.
                raise
    return _run_lrq_log_query(client, log_filter, hours=hours,
                              sample=sample)


def discover_schema(client: Any, source: str, *, hours: float = 24,
                    sample: int = 150,
                    extra_filter: Optional[str] = None,
                    min_events: int = 50,
                    escalate: bool = True,
                    backend: str = "auto") -> Dict[str, Any]:
    """Sample events from ``source`` via a LOG query and return a
    schema description.

    Parameters
    ----------
    client : S1Client
    source : str
        ``dataSource.name`` value. Single quotes in the value are
        doubled defensively.
    hours : float, default 24
        Sampling window ceiling in hours. With ``escalate=True`` this
        is the MAX window the function is allowed to scan; it starts
        with a much smaller window and widens only as needed.
    sample : int, default 150
        Target sample size. Caps both the server-side ``log.limit``
        and the client-side truncation.
    extra_filter : str, optional
        Additional LOG filter expression appended with AND.
    min_events : int, default 50
        The minimum number of events we want to see before we trust
        the schema. If the narrowest window returns fewer, we widen.
        Set to 1 to stop escalating as soon as any event appears.
    escalate : bool, default True
        If True, attempt narrow windows first (1h, 4h, 24h, capped at
        ``hours``) and stop at the first window that returns at least
        ``min_events`` matches. If False, run a single query at the
        requested ``hours``.
    backend : str, default "auto"
        Which discovery backend to use: "auto" (SDL sync preferred,
        LRQ LOG fallback), "sdl" (sync only), or "lrq" (async only).
        SDL sync is ~30% faster on usea1-acme; LRQ is slightly more
        tolerant of scoping quirks.

    Returns
    -------
    dict with keys:
        source              : str, echo of input
        n_sampled           : int, events returned (0..sample)
        estimated_match     : int, estimatedMatchCount from the server
        effective_hours     : float, the window we actually used
        n_present           : int, distinct attribute names observed
        fields              : dict[field_name -> dict]
            { populated_frac     : float in [0,1],
              distinct_in_sample : int,
              samples            : list[str],
              classified_as      : str }
        error               : str (only when query failed or 0 rows)
    """
    safe = source.replace("'", "''")
    log_filter = f"dataSource.name='{safe}'"
    if extra_filter:
        log_filter = f"{log_filter} {extra_filter}"

    # Escalating window: 1h -> 4h -> 24h -> min(hours, 168)...
    # The earliest narrow window that returns >= min_events wins.
    # Rationale: busy sources (SentinelOne, Windows Event Logs,
    # Zscaler) have thousands of events in 1h, which scans in ~3s.
    # Only sparse sources (Example Source demo, audit logs) need
    # us to widen, which costs another ~3-6s per rung.
    if escalate:
        rungs: List[float] = []
        for r in (1.0, 4.0, 24.0):
            if r < hours and r not in rungs:
                rungs.append(r)
        if hours not in rungs:
            rungs.append(float(hours))
    else:
        rungs = [float(hours)]

    res: Optional[Dict[str, Any]] = None
    used_hours = rungs[0]
    last_err: Optional[str] = None
    for rh in rungs:
        try:
            res = _run_log_query(client, log_filter, hours=rh,
                                 sample=sample, backend=backend)
        except PQError as e:
            last_err = str(e)
            continue
        used_hours = rh
        if len(res.get("matches") or []) >= min_events:
            break

    if res is None:
        return {"source": source, "n_sampled": 0, "estimated_match": 0,
                "effective_hours": used_hours, "n_present": 0,
                "fields": {},
                "error": last_err or "LOG query failed on every rung"}

    matches = res.get("matches") or []
    n = len(matches)
    est = res.get("estimatedMatchCount") or 0
    if n == 0:
        return {"source": source, "n_sampled": 0,
                "estimated_match": int(est),
                "effective_hours": used_hours, "n_present": 0,
                "fields": {},
                "error": f"no events in {used_hours}h window"}

    # Aggregate all attribute names from every event's values dict.
    acc: Dict[str, Dict[str, Any]] = {}
    for m in matches:
        # The LOG response has `values` (parsed event) and top-level
        # metadata (timestamp, severity, sessionId, threadId). We
        # merge timestamp + severity into values so callers see them.
        vals: Dict[str, Any] = {}
        if isinstance(m, dict):
            v = m.get("values")
            if isinstance(v, dict):
                vals.update(v)
            if "timestamp" in m and "timestamp" not in vals:
                vals["timestamp"] = m["timestamp"]
            if "severity" in m and "severity" not in vals:
                vals["severity"] = m["severity"]
        for k, v in vals.items():
            if k not in acc:
                acc[k] = {"populated": 0, "values": set(), "samples": []}
            if v in (None, "", "null", "[]", "{}"):
                continue
            acc[k]["populated"] += 1
            sv = str(v)
            if len(sv) > 200:
                sv = sv[:200] + "..."
            if sv not in acc[k]["values"] and len(acc[k]["values"]) < 100:
                acc[k]["values"].add(sv)
            if len(acc[k]["samples"]) < 3 and sv not in acc[k]["samples"]:
                acc[k]["samples"].append(sv)

    fields: Dict[str, Dict[str, Any]] = {}
    for name, info in acc.items():
        pop = info["populated"]
        if pop == 0:
            continue
        frac = round(pop / n, 3)
        distinct = len(info["values"])
        fields[name] = {
            "populated_frac": frac,
            "distinct_in_sample": distinct,
            "samples": info["samples"],
            "classified_as": classify_field(name, distinct, frac),
        }

    return {
        "source": source,
        "n_sampled": n,
        "estimated_match": int(est),
        "effective_hours": used_hours,
        "n_present": len(fields),
        "fields": fields,
    }


# ---- key selection --------------------------------------------------------

def _best_by_class(schema: Dict[str, Any], cls: str,
                   min_populated: float = 0.5) -> Optional[str]:
    """Pick the best field of a given class: highly populated first,
    then shortest name (so ``user`` wins over ``src.user.name``)."""
    cands = [
        (name, meta) for name, meta in schema["fields"].items()
        if meta["classified_as"] == cls
        and meta["populated_frac"] >= min_populated
    ]
    if not cands:
        return None
    cands.sort(key=lambda kv: (-kv[1]["populated_frac"], len(kv[0])))
    return cands[0][0]


def pick_keys(schema: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(prim_key, action_key)`` picked from a discovered schema.

    prim_key: principal to group per-entity breakdowns by. Preference
        user > hostname > IP, then shortest name (so ``user`` wins
        over ``src.user.name``).
    action_key: low-cardinality categorical to break volume down by.
        Exact-name hits (action, event.type, outcome, ...) win in the
        order listed in ACTION_EXACT; then any discovered
        low-cardinality grouping candidate.
    """
    prim_key = (_best_by_class(schema, "principal_user")
                or _best_by_class(schema, "principal_host")
                or _best_by_class(schema, "principal_ip"))

    action_key: Optional[str] = None
    for name in ACTION_EXACT:
        meta = schema["fields"].get(name)
        if meta and meta["populated_frac"] >= 0.5:
            action_key = name
            break
    if action_key is None:
        action_key = (_best_by_class(schema, "action")
                      or _best_by_class(schema, "grouping_candidate", 0.8))
    return prim_key, action_key


# ---- pretty printing ------------------------------------------------------

_CLS_ORDER = [
    "principal_user", "principal_host", "principal_ip",
    "action", "grouping_candidate",
    "temporal", "network", "file", "process", "other",
]


def format_report(schema: Dict[str, Any]) -> str:
    out: List[str] = []
    src = schema.get("source", "?")
    out.append(f"=== schema discovery: {src} ===")
    if schema.get("error"):
        out.append(f"error: {schema['error']}")
        return "\n".join(out)
    n = schema["n_sampled"]
    est = schema.get("estimated_match", 0)
    n_pres = schema.get("n_present", 0)
    out.append(f"sampled {n} events (of ~{est} estimated in window), "
               f"{n_pres} distinct attributes observed")
    out.append("")

    by_cls: Dict[str, List[Tuple[str, Dict[str, Any]]]] = defaultdict(list)
    for name, meta in schema["fields"].items():
        by_cls[meta["classified_as"]].append((name, meta))

    for cls in _CLS_ORDER:
        fields = by_cls.get(cls, [])
        if not fields:
            continue
        fields.sort(key=lambda kv: (-kv[1]["populated_frac"], kv[0]))
        plural = "s" if len(fields) != 1 else ""
        out.append(f"-- {cls} ({len(fields)} field{plural}) --")
        for name, meta in fields:
            frac = meta["populated_frac"]
            distinct = meta["distinct_in_sample"]
            samples = meta["samples"]
            pct = int(frac * 100)
            samp = ", ".join(samples[:2])
            if len(samp) > 80:
                samp = samp[:80] + "..."
            out.append(f"  {name:40s}  pop={pct:3d}%  card~{distinct:<3d}  "
                       f"e.g. {samp}")
        out.append("")

    prim_key, action_key = pick_keys(schema)
    out.append("=== recommended query keys ===")
    out.append(f"  prim_key   = {prim_key}")
    out.append(f"  action_key = {action_key}")
    out.append("")
    if prim_key or action_key:
        safe_src = src.replace("'", "''")
        base = f"dataSource.name = '{safe_src}'"
        out.append("-- suggested PQs --")
        out.append(f"  {base} | limit 20   # raw rows always work")
        if action_key:
            out.append(f"  {base} | group n=count() by {action_key} "
                       "| sort -n   # volume by action")
        if prim_key:
            out.append(f"  {base} | group n=count() by {prim_key} "
                       "| sort -n | limit 25   # top principals")
        if prim_key and action_key:
            out.append(f"  {base} | group n=count() by {prim_key}, "
                       f"{action_key} | sort -n | limit 60   "
                       "# per-principal action mix")
    return "\n".join(out)


# ---- CLI ------------------------------------------------------------------

def _parse_window(w: str) -> float:
    w = w.strip().lower()
    aliases = {"24h": 24.0, "7d": 168.0, "30d": 720.0, "1h": 1.0, "1d": 24.0}
    if w in aliases:
        return aliases[w]
    m = re.fullmatch(r"(\d+)([hdw])", w)
    if not m:
        raise ValueError(f"bad window '{w}' (expected e.g. 24h, 7d, 2w)")
    n = int(m.group(1))
    unit = m.group(2)
    return float({"h": n, "d": 24 * n, "w": 24 * 7 * n}[unit])


def main() -> int:
    ap = argparse.ArgumentParser(description=(
        "Discover the schema of an SDL data source by sampling raw "
        "events with a universal-attribute projection. Use BEFORE "
        "writing queries against a source so you don't hardcode "
        "field names that aren't there."))
    ap.add_argument("--source",
                    help="dataSource.name (e.g. 'Example Source')")
    ap.add_argument("--window", default="24h",
                    help="Sampling window. e.g. 24h, 7d, 30d. Default 24h.")
    ap.add_argument("--sample", type=int, default=50,
                    help="Max events to sample. Default 50.")
    ap.add_argument("--extra-filter", default="",
                    help="Additional LOG filter expression appended to "
                         "the dataSource.name filter, e.g. "
                         "'severity > 1' or 'site.id = \"123\"'.")
    ap.add_argument("--backend", choices=("auto", "sdl", "lrq"),
                    default="auto",
                    help=("Which schema-discovery backend to use. "
                          "'auto' (default) tries sync SDL first, falls "
                          "back to async LRQ. 'sdl' forces sync "
                          "/sdl/api/query. 'lrq' forces async "
                          "/sdl/v2/api/queries (LOG queryType)."))
    ap.add_argument("--no-escalate", action="store_true",
                    help=("Disable the 1h -> 4h -> 24h escalation and "
                          "run a single query at the requested --window. "
                          "Useful for benchmarking."))
    ap.add_argument("--list", action="store_true",
                    help="List all data sources on the tenant and exit.")
    ap.add_argument("--json", action="store_true",
                    help="Machine-readable JSON output.")
    args = ap.parse_args()

    client = S1Client()

    if args.list:
        try:
            sources = list_data_sources(client, hours=24, limit=200)
        except PQError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(sources, indent=2, default=str))
        else:
            print(f"{'dataSource.name':35s}  {'category':20s}  count (24h)")
            for r in sources:
                name = str(r.get("dataSource.name", ""))[:35]
                cat = str(r.get("dataSource.category", ""))[:20]
                ct = r.get("ct", "")
                print(f"{name:35s}  {cat:20s}  {ct}")
        return 0

    if not args.source:
        ap.error("--source is required unless --list is passed")

    try:
        hours = _parse_window(args.window)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    extra_filter = args.extra_filter.strip() or None

    schema = discover_schema(client, args.source, hours=hours,
                             sample=args.sample,
                             extra_filter=extra_filter,
                             escalate=not args.no_escalate,
                             backend=args.backend)
    if args.json:
        print(json.dumps(schema, indent=2, default=str))
    else:
        print(format_report(schema))
    return 0 if schema.get("n_sampled", 0) > 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
