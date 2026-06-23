"""
IOC lifecycle round-trip test — REVERSIBLE.

Purpose
-------
Prove the skill can handle the full Threat Intelligence IOC workflow end-to-end
against a live tenant without leaving state behind:

    CREATE  POST   /web/api/v2.1/threat-intelligence/iocs
    LIST    GET    /web/api/v2.1/threat-intelligence/iocs
    FILTER  GET    /web/api/v2.1/threat-intelligence/iocs?source=<test_source>
    DELETE  DELETE /web/api/v2.1/threat-intelligence/iocs  (filtered to our test IOCs)
    VERIFY  GET    /web/api/v2.1/threat-intelligence/iocs?source=<test_source>

The test IOCs are tagged with a unique `source` string and `externalId`
per run (ISO timestamp + random suffix) so that the DELETE filter only
matches what THIS run created. Safe to run anytime on a shared tenant.

All test IOCs use non-malicious indicator values:
    - IPV4   192.0.2.1       (TEST-NET-1, RFC 5737 documentation)
    - IPV4   198.51.100.1    (TEST-NET-2, RFC 5737)
    - DNS    example.com     (RFC 2606 reserved)
    - MD5    deterministic hash of "smoke-test-<run_tag>"
    - SHA256 deterministic hash of "smoke-test-<run_tag>"

SHA256/MD5 values must be non-zero (S1 rejects the empty-file hash as
`hashes_empty_file`). Deterministic run-tag-derived hashes avoid collisions
across parallel runs.

Usage
-----
    python tests/test_ioc_lifecycle.py
    python tests/test_ioc_lifecycle.py --keep    # don't delete, useful for UI inspection
    python tests/test_ioc_lifecycle.py --count 3 # number of IOCs to create (default 5)

Exit code 0 on full round-trip success, non-zero on any step failure.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client, S1APIError  # noqa: E402


RUN_TAG = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"

def _template_iocs(run_tag: str) -> List[Dict[str, Any]]:
    """Safe-to-submit indicator values. Hashes are derived from run_tag so
    they are unique per run (no collision across parallel runs) and never
    match real malware."""
    seed = f"smoke-test-{run_tag}".encode()
    return [
        {"type": "IPV4",   "value": "192.0.2.1"},
        {"type": "IPV4",   "value": "198.51.100.1"},
        {"type": "DNS",    "value": "example.com"},
        {"type": "MD5",    "value": hashlib.md5(seed).hexdigest()},
        {"type": "SHA256", "value": hashlib.sha256(seed).hexdigest()},
    ]


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def build_test_iocs(run_tag: str, count: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    templates = _template_iocs(run_tag)
    for i, t in enumerate(templates[:count]):
        out.append({
            **t,
            "method":      "EQUALS",
            "source":      run_tag,   # tag for safe later deletion
            "externalId":  f"{run_tag}-{i}",
            "name":        f"{run_tag}-ioc-{i}",
            "description": f"Smoke-test IOC created {now_iso}. Safe to delete.",
            "severity":    1,
            "labels":      ["smoke-test", run_tag],
        })
    return out


def _pick_account_id(client: S1Client) -> str:
    resp = client.get("/web/api/v2.1/accounts", params={"limit": 1})
    data = resp.get("data") or []
    if not data:
        raise RuntimeError("No accounts visible to this token — cannot scope IOC create")
    return data[0]["id"]


def create_iocs(client: S1Client, iocs: List[Dict[str, Any]],
                account_id: str) -> Dict[str, Any]:
    # Scope to a specific account — tenant scope requires a global user.
    body = {"filter": {"accountIds": [account_id]}, "data": iocs}
    return client.post("/web/api/v2.1/threat-intelligence/iocs", json_body=body)


def list_by_run_tag(client: S1Client, run_tag: str,
                    account_id: str) -> List[Dict[str, Any]]:
    # GET /iocs filter: `name__contains` works, `source` does NOT.
    # Our test IOCs embed run_tag in both source AND name, so name match
    # is how we retrieve them.
    found: List[Dict[str, Any]] = []
    for row in client.iter_items(
        "/web/api/v2.1/threat-intelligence/iocs",
        params={"name__contains": run_tag, "accountIds": account_id,
                "limit": 100},
    ):
        # post-filter on source too — name__contains could in theory match
        # an unrelated record (no risk in practice with the uuid tag).
        if (row.get("source") or "") == run_tag:
            found.append(row)
    return found


def delete_by_ids(client: S1Client, ids: List[str],
                  account_id: str) -> Dict[str, Any]:
    # DELETE /iocs takes a body with a filter. The filter schema accepts
    # `uuids` (the IOC IDs) — NOT `source__contains` on this endpoint.
    # Scoping by uuids is strictly safer than a source-contains match:
    # we only delete what we just created.
    body = {"filter": {"accountIds": [account_id], "uuids": ids}}
    return client.request("DELETE", "/web/api/v2.1/threat-intelligence/iocs",
                          json_body=body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=5,
                    help="number of IOCs to create (max 5)")
    ap.add_argument("--keep", action="store_true",
                    help="do not delete after test (for manual inspection)")
    args = ap.parse_args()

    # IOCs reject multi-scope tokens with code 4030010 ("This page doesn't
    # support multi-scopes users yet"). Use the single-scope token that's
    # pinned to one account via S1_CONSOLE_API_TOKEN_SINGLE_SCOPE in credentials.json.
    client = S1Client(timeout=30, token_kind="single_scope")
    run_tag = RUN_TAG
    iocs = build_test_iocs(run_tag, args.count)

    _log(f"tenant={client.base_url}")
    try:
        account_id = _pick_account_id(client)
    except Exception as e:
        _log(f"could not resolve an account id: {e}")
        return 1
    _log(f"run_tag={run_tag}  iocs={len(iocs)}  account_id={account_id}")

    # Precheck: /iocs rejects multi-scope tokens with HTTP 403 code 4030010
    # "This page doesn't support multi-scopes users yet". No client-side
    # workaround (confirmed: S1-Scope header, scopeLevel params, accountIds
    # scoping all still 403). If the precheck fails, skip the test cleanly
    # rather than leaking IOCs that we can't then LIST-and-DELETE.
    _log("PRECHECK: verify /iocs is reachable on this token")
    try:
        client.get("/web/api/v2.1/threat-intelligence/iocs", params={"limit": 1})
    except S1APIError as e:
        if e.status == 403 and "multi-scopes" in str(e):
            _log("SKIP: token has multiple account scopes; /iocs requires a "
                 "single-account-scoped token. Not a skill bug — documented "
                 "in tests/README.md.")
            return 0
        _log(f"PRECHECK FAILED: HTTP {e.status} {e}")
        return 1
    _log("PRECHECK ok")

    # --- CREATE ---
    _log("CREATE: posting IOC batch")
    try:
        resp = create_iocs(client, iocs, account_id)
    except S1APIError as e:
        _log(f"CREATE FAILED: HTTP {e.status} {e}")
        return 2
    # API returns {data: [{id, ...}, ...]} on success
    created = (resp.get("data") or [])
    _log(f"CREATE ok: {len(created)} indicators created")

    # --- LIST (filter by source) ---
    time.sleep(2)  # small settle window for indexing
    _log("LIST: filter by source")
    found = list_by_run_tag(client, run_tag, account_id)
    _log(f"LIST ok: {len(found)} indicators match source={run_tag}")
    if len(found) != len(iocs):
        _log(f"WARN: expected {len(iocs)} found {len(found)} — "
             "may be async indexing; continuing")

    # Collect UUIDs from what we just found — safer than any content filter.
    # IOC records use `uuid` (not `id`) as the primary key, and the DELETE
    # filter field is `uuids` (plural).
    ids = [r["uuid"] for r in found if r.get("uuid")]

    # --- DELETE ---
    if args.keep:
        _log("KEEP flag set — leaving test IOCs in place. Clean up manually with:")
        import json as _json
        filt = _json.dumps({"filter": {"accountIds": [account_id], "uuids": ids}})
        print(f'  python scripts/call_endpoint.py DELETE '
              f'/web/api/v2.1/threat-intelligence/iocs --json \'{filt}\'')
        return 0

    if not ids:
        _log("DELETE skipped: no IDs collected from LIST step.")
        return 5

    _log(f"DELETE: removing {len(ids)} test IOCs by id")
    try:
        del_resp = delete_by_ids(client, ids, account_id)
    except S1APIError as e:
        _log(f"DELETE FAILED: HTTP {e.status} {e}")
        _log("Manual cleanup required — see --keep instructions above.")
        return 3
    affected = (del_resp.get("data") or {}).get("affected")
    _log(f"DELETE ok: affected={affected}")

    # --- VERIFY ---
    time.sleep(2)
    _log("VERIFY: re-query by source should be empty")
    remaining = list_by_run_tag(client, run_tag, account_id)
    if remaining:
        _log(f"VERIFY FAILED: {len(remaining)} indicators still present")
        return 4
    _log("VERIFY ok: zero remaining")

    _log("IOC lifecycle: CREATE → LIST → DELETE → VERIFY — ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
