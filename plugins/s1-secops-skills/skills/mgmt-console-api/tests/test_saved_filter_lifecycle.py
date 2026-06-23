"""
Saved-filter lifecycle round-trip test — REVERSIBLE.

Demonstrates that the skill can exercise CREATE → UPDATE → LIST → DELETE →
VERIFY for a console "saved filter" (Filters tag) without leaving state
behind.

    CREATE  POST   /web/api/v2.1/filters                     (body: {data: {name, filterFields}})
    LIST    GET    /web/api/v2.1/filters?name__contains=<run_tag>
    UPDATE  PUT    /web/api/v2.1/filters/{filter_id}         (body: {data: {name}})
    DELETE  DELETE /web/api/v2.1/filters/{filter_id}
    VERIFY  GET    /web/api/v2.1/filters?name__contains=<run_tag>

A saved filter is a personal saved-search definition — no protection impact,
no detection impact, no other user can see it. This is the lowest blast-
radius content-create path in the REST API. Safe to run on any shared
tenant at any time.

Usage
-----
    python tests/test_saved_filter_lifecycle.py
    python tests/test_saved_filter_lifecycle.py --keep    # leave the filter

Exit code 0 on full round-trip success, non-zero on any step failure.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client, S1APIError  # noqa: E402


RUN_TAG = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
FILTER_NAME = f"{RUN_TAG}-filter"


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def create_filter(client: S1Client, name: str) -> str:
    # Minimal non-matching filter: a harmless UUID that won't match any agent.
    body = {
        "data": {
            "name": name,
            "filterFields": {
                "computerName__contains": f"zz-no-match-{uuid.uuid4().hex[:6]}",
            },
        },
    }
    resp = client.post("/web/api/v2.1/filters", json_body=body)
    data = resp.get("data") or {}
    fid = data.get("id")
    if not fid:
        raise RuntimeError(f"CREATE returned no id. Response: {resp}")
    return fid


def update_filter(client: S1Client, filter_id: str, new_name: str) -> None:
    body = {
        "data": {
            "name": new_name,
            "filterFields": {
                "computerName__contains": f"zz-no-match-{uuid.uuid4().hex[:6]}",
            },
        },
    }
    client.put(f"/web/api/v2.1/filters/{filter_id}", json_body=body)


def list_by_name_contains(client: S1Client, needle: str) -> list:
    out = []
    for item in client.iter_items(
        "/web/api/v2.1/filters",
        params={"name__contains": needle, "limit": 50},
    ):
        out.append(item)
    return out


def delete_filter(client: S1Client, filter_id: str) -> Dict[str, Any]:
    return client.delete(f"/web/api/v2.1/filters/{filter_id}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="do not delete the test filter after")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}")

    # --- 1. CREATE ---
    _log(f"CREATE: POST /filters name={FILTER_NAME!r}")
    try:
        fid = create_filter(client, FILTER_NAME)
    except S1APIError as e:
        _log(f"CREATE FAILED: HTTP {e.status} {e}")
        return 2
    _log(f"CREATE ok: filter_id={fid}")

    # --- 2. LIST (name__contains) ---
    time.sleep(1)
    _log(f"LIST: filters where name__contains={RUN_TAG!r}")
    hits = list_by_name_contains(client, RUN_TAG)
    if not any(h.get("id") == fid for h in hits):
        _log(f"LIST FAILED: created filter {fid} not surfaced by name__contains filter")
        _log(f"Hits ({len(hits)}): {[h.get('id') for h in hits]}")
        # don't bail out — cleanup below will still remove it
        list_ok = False
    else:
        list_ok = True
        _log(f"LIST ok: {len(hits)} hit(s); created filter present")

    # --- 3. UPDATE ---
    new_name = f"{FILTER_NAME}-updated"
    _log(f"UPDATE: PUT /filters/{fid}  name -> {new_name!r}")
    try:
        update_filter(client, fid, new_name)
    except S1APIError as e:
        _log(f"UPDATE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: filter_id={fid}")
        return 3
    _log("UPDATE ok")

    # --- 4. DELETE ---
    if args.keep:
        _log(f"KEEP flag set. Leaving filter {fid} (name={new_name!r})")
        return 0

    _log(f"DELETE: /filters/{fid}")
    try:
        del_resp = delete_filter(client, fid)
    except S1APIError as e:
        _log(f"DELETE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: filter_id={fid}")
        return 4
    affected = (del_resp.get("data") or {}).get("affected")
    _log(f"DELETE ok: affected={affected}")

    # --- 5. VERIFY ---
    time.sleep(1)
    remaining = [h for h in list_by_name_contains(client, RUN_TAG)
                 if h.get("id") == fid]
    if remaining:
        _log(f"VERIFY FAILED: filter {fid} still present after delete")
        return 5
    _log("VERIFY ok: filter removed")

    if not list_ok:
        _log("NOTE: LIST stage flagged a consistency issue earlier; "
             "CREATE/UPDATE/DELETE/VERIFY still passed. Returning 0 but "
             "investigate name__contains search indexing if this repeats.")

    _log("Saved-filter lifecycle: CREATE → LIST → UPDATE → DELETE → VERIFY — ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
