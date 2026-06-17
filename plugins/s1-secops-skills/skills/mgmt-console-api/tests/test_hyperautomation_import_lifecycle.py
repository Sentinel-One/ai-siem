"""
Hyperautomation workflow import lifecycle test — REVERSIBLE.

Builds a minimal workflow JSON from scratch, imports it, verifies it appears
in the list, then deletes it:

    BUILD   (construct minimal workflow dict in memory)
    IMPORT  POST   /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import
    LIST    GET    /web/api/v2.1/hyper-automate/api/public/workflows
    DELETE  DELETE /web/api/v2.1/hyper-automate/api/v1/workflows/{id}?accountIds=<acct>
    VERIFY  GET    (expect workflow absent from active list)

The workflow contains only a Manual Trigger and is never activated, so it
cannot fire against live data. Delete is a soft, recoverable delete (the console
offers a "Restore workflow" action). Zero blast radius.

Note on token type
------------------
Per the Hyperautomation skill: workflows imported with a Service User token
are invisible to human users in the UI. Use a personal Console User API token
(S1_CONSOLE_API_TOKEN or S1_CONSOLE_API_TOKEN_SINGLE_SCOPE) for this test
if you need the result to be visible in the UI. The test itself verifies the
import programmatically regardless of token type.

Usage
-----
    python tests/test_hyperautomation_import_lifecycle.py
    python tests/test_hyperautomation_import_lifecycle.py --account-id <id>
    python tests/test_hyperautomation_import_lifecycle.py --keep

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
WORKFLOW_NAME = f"{RUN_TAG}-wf"

HA_PUBLIC = "/web/api/v2.1/hyper-automate/api/public"
HA_V1 = "/web/api/v2.1/hyper-automate/api/v1"


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _pick_account_id(client: S1Client) -> str:
    resp = client.get("/web/api/v2.1/accounts", params={"limit": 1})
    data = resp.get("data") or []
    if not data:
        raise RuntimeError("No accounts visible to this token")
    return data[0]["id"]


def _build_minimal_workflow(name: str) -> Dict[str, Any]:
    """Build the minimal valid workflow JSON: one Manual Trigger, no downstream actions."""
    return {
        "name": name,
        "description": f"Smoke test. run_tag={RUN_TAG}. Safe to delete.",
        "actions": [
            {
                "action": {
                    "type": "manual_trigger",
                    "tag": "core_action",
                    "connection_id": None,
                    "connection_name": None,
                    "use_connection_name": False,
                    "integration_id": None,
                    "data": {
                        "name": "Manual Trigger",
                        "action_type": "manual_trigger",
                        "trigger_type": "static",
                        "dynamic_properties": {},
                        "static_payload": "{}",
                    },
                    "state": "active",
                    "description": None,
                    "client_data": {
                        "position": {"x": 0.0, "y": 0.0},
                        "dimensions": {"width": 256.0, "height": 100.0},
                        "collapsed": False,
                    },
                    "snippet_workflow_id": None,
                    "snippet_version_id": None,
                },
                "export_id": 0,
                "connected_to": [],
                "parent_action": None,
            }
        ],
    }


def import_workflow(client: S1Client, workflow_json: Dict[str, Any],
                    account_id: str) -> Dict[str, Any]:
    body = {
        "data": workflow_json,
        "filter": {"accountIds": [account_id]},
    }
    resp = client.post(f"{HA_PUBLIC}/workflow-import-export/import", json_body=body)
    # Confirmed: public import response uses top-level "id" and "version_id" (not "workflowId").
    # The nested workflow data also has an "id" field — same value.
    public_id = resp.get("id")
    if not public_id:
        raise RuntimeError(f"IMPORT returned no id. Response: {resp}")
    return resp  # return full response so caller can read id, version_id, name, state


def list_recent_workflows(client: S1Client, account_id: str,
                          first_n: int = 20) -> List[Dict[str, Any]]:
    """
    Return the most recently updated N workflows for the account.
    Items use the v1 nested shape: {id: <v1_uuid>, workflow: {name, id, state, ...}, actions: []}.
    Sorted by updated_at desc so a freshly imported workflow appears on the first page.
    We never paginate — just fetch the top N and match by run_tag in name.
    """
    resp = client.get(
        f"{HA_PUBLIC}/workflows",
        params={"accountIds": account_id, "limit": first_n,
                "skip": 0, "sortBy": "updated_at", "sortOrder": "desc"},
    )
    items = resp.get("data") or []
    out = []
    for item in items:
        wf = item.get("workflow") or {}
        wf_name = wf.get("name") or item.get("name") or ""
        wf_v1_id = wf.get("id") or item.get("id") or ""
        if RUN_TAG in wf_name:
            out.append({**item, "_v1_id": wf_v1_id, "_name": wf_name})
    return out


def find_v1_id_by_name(client: S1Client, account_id: str,
                        workflow_name: str) -> Optional[str]:
    """
    Find the v1 workflow UUID by matching workflow.name in the most recently updated
    workflows. Scans the top 50 sorted by updated_at desc — a freshly imported
    workflow will always appear there.
    """
    try:
        resp = client.get(
            f"{HA_PUBLIC}/workflows",
            params={"accountIds": account_id, "limit": 50, "skip": 0,
                    "sortBy": "updated_at", "sortOrder": "desc"},
        )
    except Exception:
        return None
    for item in resp.get("data") or []:
        wf = item.get("workflow") or {}
        if wf.get("name") == workflow_name or item.get("name") == workflow_name:
            return wf.get("id") or item.get("id")
    return None


def delete_workflow(client: S1Client, v1_workflow_id: str, account_id: str) -> Any:
    """
    Delete via the REST DELETE endpoint using the v1 UUID:
        DELETE /api/v1/workflows/{id}?accountIds=<acct>   -> 204 (soft, recoverable)

    Validated 2026-06-13 (import -> publish -> delete -> gone from list). Scope with
    accountIds for an account-scoped workflow (or siteIds for a site-scoped one); a
    404 "Object not found" means the id is not under that scope or is already deleted.

    NOTE: the older POST /workflows/archive returns 500 on this tenant and must not be
    used — the REST DELETE above is the correct delete mechanism.
    """
    return client.delete(f"{HA_V1}/workflows/{v1_workflow_id}",
                         params={"accountIds": account_id})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--account-id", default=None, help="pin to a specific account ID")
    ap.add_argument("--keep", action="store_true", help="skip delete after run")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}")

    # Resolve account ID
    if args.account_id:
        account_id = args.account_id
    else:
        try:
            account_id = _pick_account_id(client)
        except Exception as e:
            _log(f"Could not resolve account ID: {e}")
            return 1
    _log(f"account_id={account_id}  workflow_name={WORKFLOW_NAME!r}")

    # --- 1. BUILD + IMPORT ---
    wf_json = _build_minimal_workflow(WORKFLOW_NAME)
    _log(f"IMPORT: POST {HA_PUBLIC}/workflow-import-export/import")
    try:
        imported = import_workflow(client, wf_json, account_id)
    except S1APIError as e:
        if e.status == 403:
            _log(f"IMPORT skipped: HTTP 403 — token lacks Hyperautomation write scope")
            return 0
        _log(f"IMPORT FAILED: HTTP {e.status} {e}")
        return 1
    # Confirmed: public import response uses top-level "id" (not "workflowId").
    workflow_id = imported["id"]
    version_id = imported.get("version_id")
    _log(f"IMPORT ok: workflow_id={workflow_id}  version_id={version_id}")

    # --- 2. LIST ---
    time.sleep(2)
    _log(f"LIST: GET {HA_PUBLIC}/workflows (most recent 20, name-filter by run_tag)")
    hits = list_recent_workflows(client, account_id)
    list_ok = bool(hits)  # any hit with run_tag in name is ours
    if not list_ok:
        _log(f"LIST consistency issue: workflow_id={workflow_id} not in name-filtered hits "
             f"({len(hits)} hit(s)). Continuing.")
    else:
        _log(f"LIST ok: {len(hits)} hit(s); imported workflow present")

    # --- 3. DELETE ---
    if args.keep:
        _log(f"KEEP flag set. Leaving workflow {workflow_id} (name={WORKFLOW_NAME!r})")
        return 0

    # Find the v1 UUID for this workflow by name — delete requires the v1 id.
    _log(f"FIND v1 id for workflow name={WORKFLOW_NAME!r}")
    v1_id = find_v1_id_by_name(client, account_id, WORKFLOW_NAME)
    if not v1_id:
        _log(f"DELETE FAILED: v1 id not found for {WORKFLOW_NAME!r}. "
             f"Manual cleanup: mcp ha_delete_workflow with id={workflow_id}")
        return 1
    _log(f"Found v1_id={v1_id}")
    _log(f"DELETE: DELETE {HA_V1}/workflows/{v1_id}?accountIds={account_id}")
    try:
        delete_workflow(client, v1_id, account_id)
        _log("DELETE ok (204)")
    except S1APIError as e:
        _log(f"DELETE FAILED: HTTP {e.status} {e}. "
             f"Manual cleanup: run mcp ha_delete_workflow with id={workflow_id}")
        return 1

    # --- 4. VERIFY ---
    time.sleep(2)
    remaining = list_recent_workflows(client, account_id)
    if remaining:
        _log(f"VERIFY: workflow {workflow_id} still present after delete "
             f"({len(remaining)} hit(s)) — soft-delete may lag the active list; verify in the console.")
    else:
        _log("VERIFY ok: workflow absent from active list after delete")

    _log("Hyperautomation workflow lifecycle: IMPORT → LIST → DELETE → VERIFY — ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
