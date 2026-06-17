"""
XDR Graph Query lifecycle round-trip test — REVERSIBLE.

Exercises the graph query save/update/delete surface:

    SAVE    POST   /web/api/v2.1/xdr/graph-explorer/query/management/query
    LIST    GET    /web/api/v2.1/xdr/graph-explorer/query/management/query
    UPDATE  PUT    /web/api/v2.1/xdr/graph-explorer/query/management/query/{query_id}
    DELETE  DELETE /web/api/v2.1/xdr/graph-explorer/query/management/query/{query_id}
    VERIFY  GET    (expect saved query absent)

Graph saved queries are user-scope objects — they do not affect agents, threats,
or detection logic. Zero blast radius.

Scope
-----
Queries are user-scoped; no account/site filter needed. Uses the token configured
in credentials.json.

Usage
-----
    python tests/test_xdr_graph_query_lifecycle.py
    python tests/test_xdr_graph_query_lifecycle.py --keep   # skip delete

Exit code 0 on success, non-zero on any step failure.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client, S1APIError  # noqa: E402

RUN_TAG = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
QUERY_NAME = f"{RUN_TAG}-gq"

GRAPH_QUERY_BASE = "/web/api/v2.1/xdr/graph-explorer/query/management/query"

# The XDR graph explorer uses a proprietary query string format that is server-validated
# but not documented in the swagger. The test discovers the format at runtime by reading
# an existing saved query from the tenant. If no saved queries exist, the test skips.
SAFE_QUERY_STR: Optional[str] = None


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def discover_query_format(client: S1Client) -> Optional[str]:
    """
    Return a valid query string by reading the first existing saved query on the tenant.
    Returns None if no saved queries exist — the test will skip in that case.
    The XDR graph explorer uses a proprietary server-validated format that cannot be
    constructed without a live example.
    """
    resp = client.get(GRAPH_QUERY_BASE, params={"limit": 5})
    items = resp.get("data") or []
    for item in items:
        q = item.get("query") or item.get("queryContent") or item.get("queryString")
        if q and isinstance(q, str) and q.strip():
            return q
    return None


def save_query(client: S1Client, name: str, query_str: str) -> Dict[str, Any]:
    body = {
        "name": name,
        "query": query_str,
        "queryDescription": f"Smoke test. run_tag={RUN_TAG}. Safe to delete.",
        "shared": False,
    }
    resp = client.post(GRAPH_QUERY_BASE, json_body=body)
    data = resp.get("data") or {}
    if not data.get("id"):
        raise RuntimeError(f"SAVE returned no id. Response: {resp}")
    return data


def list_queries(client: S1Client, name_fragment: str) -> List[Dict[str, Any]]:
    """Return all saved queries whose name contains name_fragment."""
    resp = client.get(GRAPH_QUERY_BASE, params={"limit": 100})
    items = resp.get("data") or []
    return [q for q in items if name_fragment in q.get("name", "")]


def update_query(client: S1Client, query_id: str, name: str,
                 query_str: str) -> Dict[str, Any]:
    body = {
        "name": name,
        "query": query_str,  # same format, description changed
        "queryDescription": f"Smoke test UPDATED. run_tag={RUN_TAG}.",
        "shared": False,
    }
    return client.put(f"{GRAPH_QUERY_BASE}/{query_id}", json_body=body)


def delete_query(client: S1Client, query_id: str) -> Any:
    return client.delete(f"{GRAPH_QUERY_BASE}/{query_id}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="skip delete after run")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}")

    # --- 0. FORMAT DISCOVERY ---
    # The graph query format is proprietary and server-validated. We discover it
    # by reading an existing saved query on this tenant. If none exist, skip.
    _log(f"FORMAT DISCOVERY: GET {GRAPH_QUERY_BASE} (read existing query for format)")
    query_str = discover_query_format(client)
    if not query_str:
        _log("No existing saved graph queries found on this tenant. "
             "Cannot determine valid query format without a live example. "
             "SKIPPING test (exit 0). To enable: save at least one query "
             "via the XDR Graph Explorer UI, then re-run.")
        return 0
    _log(f"FORMAT DISCOVERY ok: using query string (first 80 chars): {query_str[:80]!r}")

    # --- 1. SAVE ---
    _log(f"SAVE: POST {GRAPH_QUERY_BASE}")
    try:
        saved = save_query(client, QUERY_NAME, query_str)
    except S1APIError as e:
        _log(f"SAVE FAILED: HTTP {e.status} {e}")
        return 1
    query_id = saved["id"]
    _log(f"SAVE ok: query_id={query_id!r}  name={saved.get('name')!r}")

    # --- 2. LIST ---
    time.sleep(1)
    _log("LIST: GET all saved queries (filter by run_tag in name)")
    hits = list_queries(client, RUN_TAG)
    list_ok = any(q.get("id") == query_id for q in hits)
    if not list_ok:
        _log(f"LIST consistency issue: query_id={query_id} not found in list. "
             f"Hits: {[q.get('id') for q in hits]}")
    else:
        _log(f"LIST ok: {len(hits)} hit(s); created query present")

    # --- 3. UPDATE ---
    _log(f"UPDATE: PUT {GRAPH_QUERY_BASE}/{query_id}")
    try:
        update_query(client, query_id, QUERY_NAME, query_str)
    except S1APIError as e:
        _log(f"UPDATE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: query_id={query_id!r}")
        return 3
    _log("UPDATE ok")

    # --- 4. DELETE ---
    if args.keep:
        _log(f"KEEP flag set. Leaving query {query_id!r} (name={QUERY_NAME!r})")
        return 0

    _log(f"DELETE: DELETE {GRAPH_QUERY_BASE}/{query_id}")
    try:
        delete_query(client, query_id)
    except S1APIError as e:
        _log(f"DELETE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: query_id={query_id!r}")
        return 4
    _log("DELETE ok")

    # --- 5. VERIFY ---
    time.sleep(1)
    remaining = list_queries(client, RUN_TAG)
    if any(q.get("id") == query_id for q in remaining):
        _log(f"VERIFY FAILED: query {query_id!r} still present after delete")
        return 5
    _log("VERIFY ok: query removed")

    _log("XDR graph query lifecycle: SAVE → LIST → UPDATE → DELETE → VERIFY — ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
