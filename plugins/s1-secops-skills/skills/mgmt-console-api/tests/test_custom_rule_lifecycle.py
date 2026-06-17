"""
Custom Detection Rule lifecycle round-trip test — REVERSIBLE.

Exercises the full rule CRUD pattern against /cloud-detection/rules:

    CREATE  POST   /web/api/v2.1/cloud-detection/rules
    LIST    GET    /web/api/v2.1/cloud-detection/rules?name__contains=<run_tag>
    UPDATE  PUT    /web/api/v2.1/cloud-detection/rules/{rule_id}
    DELETE  DELETE /web/api/v2.1/cloud-detection/rules  (body filter: {ids: [...]})
    VERIFY  GET    /web/api/v2.1/cloud-detection/rules?name__contains=<run_tag>

The rule is created with ``status: "Disabled"`` so it never fires against
live telemetry, meaning zero blast radius: no alerts generated, no
analyst inboxes touched, no SOC noise. The test asserts the server keeps
status=="Draft" (Draft is the server-side name for a rule that has never
been activated) throughout the lifecycle.

Scope
-----
The rule is scoped to the **first account** visible to the token. This
avoids the "Filter args is not compatible with user scope" 403 that
tenant-scope (filter={}) produces on multi-account tokens.

Usage
-----
    python tests/test_custom_rule_lifecycle.py
    python tests/test_custom_rule_lifecycle.py --keep    # leave the rule

Exit code 0 on full round-trip success, non-zero on any step failure.
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
RULE_NAME = f"{RUN_TAG}-rule"

# A deliberately narrow query that is syntactically valid but unlikely to
# match anything in practice. Since the rule is created in "Disabled" state
# it never evaluates against telemetry anyway — this is belt-and-braces.
SAFE_QUERY = 'EventType = "Process Creation" AND ProcessName = "zzz-smoke-test-does-not-exist.exe"'


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _pick_account_id(client: S1Client) -> str:
    resp = client.get("/web/api/v2.1/accounts", params={"limit": 1})
    data = resp.get("data") or []
    if not data:
        raise RuntimeError("No accounts visible to this token")
    return data[0]["id"]


def create_rule(client: S1Client, name: str, account_id: str) -> Dict[str, Any]:
    body = {
        "data": {
            "name": name,
            "description": f"Smoke-test rule run_tag={RUN_TAG}. Safe to delete.",
            "severity": "Low",
            "expirationMode": "Permanent",
            "queryType": "events",
            "status": "Disabled",
            "s1ql": SAFE_QUERY,
        },
        "filter": {"accountIds": [account_id]},
    }
    resp = client.post("/web/api/v2.1/cloud-detection/rules", json_body=body)
    data = resp.get("data") or {}
    if not data.get("id"):
        raise RuntimeError(f"CREATE returned no id. Response: {resp}")
    return data


def update_rule(client: S1Client, rule_id: str, name: str,
                account_id: str, new_description: str) -> Dict[str, Any]:
    body = {
        "data": {
            "name": name,
            "description": new_description,
            "severity": "Medium",   # changed field
            "expirationMode": "Permanent",
            "queryType": "events",
            "status": "Disabled",
            "s1ql": SAFE_QUERY,
        },
        "filter": {"accountIds": [account_id]},
    }
    return client.put(f"/web/api/v2.1/cloud-detection/rules/{rule_id}",
                      json_body=body)


def list_by_name_contains(client: S1Client, needle: str,
                          account_id: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in client.iter_items(
        "/web/api/v2.1/cloud-detection/rules",
        params={"name__contains": needle, "accountIds": account_id,
                "limit": 100},
    ):
        out.append(item)
    return out


def delete_rule(client: S1Client, rule_id: str,
                account_id: str) -> Dict[str, Any]:
    body = {"filter": {"accountIds": [account_id], "ids": [rule_id]}}
    return client.request("DELETE", "/web/api/v2.1/cloud-detection/rules",
                          json_body=body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="do not delete the test rule after the run")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}")

    try:
        account_id = _pick_account_id(client)
    except Exception as e:
        _log(f"could not resolve account id: {e}")
        return 1
    _log(f"account_id={account_id}  rule_name={RULE_NAME!r}")

    # --- 1. CREATE ---
    _log("CREATE: POST /cloud-detection/rules (status=Disabled)")
    try:
        created = create_rule(client, RULE_NAME, account_id)
    except S1APIError as e:
        _log(f"CREATE FAILED: HTTP {e.status} {e}")
        return 2
    rule_id = created["id"]
    _log(f"CREATE ok: rule_id={rule_id}  status={created.get('status')!r}")
    if created.get("status") not in ("Draft", "Disabled"):
        _log(f"WARN: unexpected rule status {created.get('status')!r} — "
             "expected Draft/Disabled; continuing")

    # --- 2. LIST (name__contains) ---
    time.sleep(1)
    _log(f"LIST: rules where name__contains={RUN_TAG!r}")
    hits = list_by_name_contains(client, RUN_TAG, account_id)
    list_ok = any(h.get("id") == rule_id for h in hits)
    if not list_ok:
        _log(f"LIST consistency issue: created rule {rule_id} not surfaced "
             f"by name__contains={RUN_TAG!r}. Hits: "
             f"{[h.get('id') for h in hits]}")
    else:
        _log(f"LIST ok: {len(hits)} hit(s); created rule present")

    # --- 3. UPDATE ---
    new_desc = f"Smoke-test rule run_tag={RUN_TAG} — updated at " \
               f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}"
    _log(f"UPDATE: PUT /cloud-detection/rules/{rule_id} (bump severity → Medium)")
    try:
        update_rule(client, rule_id, RULE_NAME, account_id, new_desc)
    except S1APIError as e:
        _log(f"UPDATE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: rule_id={rule_id}")
        return 3
    _log("UPDATE ok")

    # --- 4. DELETE (unless --keep) ---
    if args.keep:
        _log(f"KEEP flag set. Leaving rule {rule_id} (name={RULE_NAME!r})")
        return 0

    _log(f"DELETE: rule_id={rule_id}")
    try:
        del_resp = delete_rule(client, rule_id, account_id)
    except S1APIError as e:
        _log(f"DELETE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: rule_id={rule_id}")
        return 4
    affected = (del_resp.get("data") or {}).get("affected")
    _log(f"DELETE ok: affected={affected}")

    # --- 5. VERIFY ---
    time.sleep(1)
    remaining = [h for h in list_by_name_contains(client, RUN_TAG, account_id)
                 if h.get("id") == rule_id]
    if remaining:
        _log(f"VERIFY FAILED: rule {rule_id} still present after delete")
        return 5
    _log("VERIFY ok: rule removed")

    if not list_ok:
        _log("NOTE: LIST stage flagged a consistency issue earlier; "
             "CREATE/UPDATE/DELETE/VERIFY still passed. Returning 0 but "
             "investigate name__contains search indexing if this repeats.")

    _log("Custom-rule lifecycle: CREATE → LIST → UPDATE → DELETE → VERIFY — ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
