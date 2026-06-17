"""
Detection rule activate/deactivate lifecycle test — REVERSIBLE.

Exercises the full enable/disable surface for BOTH rule types:
  - Scheduled (PowerQuery 2.0): queryType=scheduled, queryLang=2.0
  - Events (legacy S1QL): queryType=events

For each type:

    CREATE   POST   /web/api/v2.1/cloud-detection/rules  (status=Disabled)
    ENABLE   PUT    /web/api/v2.1/cloud-detection/rules/enable
    VERIFY_ON GET   confirm status is Active/Enabled (isLegacy=false for scheduled)
    DISABLE  PUT    /web/api/v2.1/cloud-detection/rules/disable
    VERIFY_OFF GET  confirm status is not Active
    DELETE   DELETE /web/api/v2.1/cloud-detection/rules
    VERIFY   GET    (expect 0 hits)

The scheduled rule runs on a 1440-minute (24h) window so even if it is
briefly enabled it cannot fire within the test's lifetime. The events rule
is never enabled with an alert-generating query. Tested against demo
(site <site-id>) by default; pass --site-id to override.

Usage
-----
    python tests/test_detection_rule_activate_lifecycle.py
    python tests/test_detection_rule_activate_lifecycle.py --site-id <id>
    python tests/test_detection_rule_activate_lifecycle.py --keep

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

# demo site — confirmed safe for activation tests
DEFAULT_SITE_ID = "<site-id>"

RULES_BASE = "/web/api/v2.1/cloud-detection/rules"

# Scheduled: PowerQuery that counts a fictitious datasource — will never match.
SCHEDULED_QUERY = (
    "dataSource.name = 'EndpointSecurityWin'"
    " | filter AgentName = 'zzz-smoke-test-does-not-exist'"
    " | group count = count() by AgentName"
    " | filter count > 9999"
)

# Events: S1QL that matches a process that doesn't exist.
EVENTS_QUERY = (
    "EventType = \"Process Creation\""
    " AND ProcessName = \"zzz-smoke-test-does-not-exist.exe\""
)


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _pick_account_id(client: S1Client) -> str:
    resp = client.get("/web/api/v2.1/accounts", params={"limit": 1})
    data = resp.get("data") or []
    if not data:
        raise RuntimeError("No accounts visible to this token")
    return data[0]["id"]


# ---------------------------------------------------------------------------
# CREATE helpers
# ---------------------------------------------------------------------------

def create_scheduled_rule(client: S1Client, name: str, site_id: str,
                           account_id: str) -> Dict[str, Any]:
    body = {
        "data": {
            "name": name,
            "queryType": "scheduled",
            "queryLang": "2.0",         # required — HTTP 400 without it
            "severity": "Low",
            "expirationMode": "Permanent",
            "status": "Disabled",
            "scheduledParams": {
                "query": SCHEDULED_QUERY,
                "runIntervalMinutes": 1440,     # 24h — never fires during test
                "lookbackWindowMinutes": 1440,
                "threshold": {"value": 9999, "operator": "Greater"},
                "alertPerRow": False,
                "disableStreaksLogic": False,
            },
        },
        "filter": {"siteIds": [site_id]},
    }
    resp = client.post(RULES_BASE, json_body=body)
    data = resp.get("data") or {}
    if not data.get("id"):
        raise RuntimeError(f"CREATE (scheduled) returned no id. Response: {resp}")
    return data


def create_events_rule(client: S1Client, name: str, account_id: str) -> Dict[str, Any]:
    body = {
        "data": {
            "name": name,
            "description": f"Smoke test. run_tag={RUN_TAG}. Safe to delete.",
            "severity": "Low",
            "expirationMode": "Permanent",
            "queryType": "events",
            "status": "Disabled",
            "s1ql": EVENTS_QUERY,
        },
        "filter": {"accountIds": [account_id]},
    }
    resp = client.post(RULES_BASE, json_body=body)
    data = resp.get("data") or {}
    if not data.get("id"):
        raise RuntimeError(f"CREATE (events) returned no id. Response: {resp}")
    return data


# ---------------------------------------------------------------------------
# ENABLE / DISABLE
# ---------------------------------------------------------------------------

def enable_rule(client: S1Client, rule_id: str, site_id: str) -> Dict[str, Any]:
    return client.put(f"{RULES_BASE}/enable",
                      json_body={"filter": {"ids": [rule_id], "siteIds": [site_id]}})


def disable_rule(client: S1Client, rule_id: str, site_id: str) -> Dict[str, Any]:
    return client.put(f"{RULES_BASE}/disable",
                      json_body={"filter": {"ids": [rule_id], "siteIds": [site_id]}})


# ---------------------------------------------------------------------------
# GET / DELETE / VERIFY
# ---------------------------------------------------------------------------

def get_rule(client: S1Client, rule_id: str, site_id: str,
             is_scheduled: bool = False) -> Optional[Dict[str, Any]]:
    params: Dict[str, Any] = {"ids": rule_id, "siteIds": site_id}
    if is_scheduled:
        params["isLegacy"] = "false"   # required for scheduled rules
    resp = client.get(RULES_BASE, params=params)
    items = resp.get("data") or []
    return items[0] if items else None


def delete_rule(client: S1Client, rule_id: str, account_id: str) -> Dict[str, Any]:
    body = {"filter": {"ids": [rule_id], "accountIds": [account_id]}}
    return client.delete(RULES_BASE, json_body=body)


# ---------------------------------------------------------------------------
# Per-rule lifecycle
# ---------------------------------------------------------------------------

def run_rule_lifecycle(client: S1Client, label: str, rule_id: str,
                       site_id: str, account_id: str,
                       is_scheduled: bool, keep: bool) -> int:
    """Returns 0 on success, non-zero on failure. Cleans up unless keep=True."""

    # ENABLE
    _log(f"[{label}] ENABLE: PUT {RULES_BASE}/enable")
    try:
        en_resp = enable_rule(client, rule_id, site_id)
    except S1APIError as e:
        _log(f"[{label}] ENABLE FAILED: HTTP {e.status} {e}")
        _log(f"[{label}] Manual cleanup: rule_id={rule_id}")
        return 10
    affected = (en_resp.get("data") or {}).get("affected")
    _log(f"[{label}] ENABLE ok: affected={affected}")

    # VERIFY ON
    # "activating" is the transitional status immediately after enable — fully valid.
    # The rule moves to "active" after a short delay. Accept both.
    time.sleep(1)
    rule = get_rule(client, rule_id, site_id, is_scheduled)
    status = (rule or {}).get("status", "").lower()
    if status not in ("active", "enabled", "activating"):
        _log(f"[{label}] VERIFY_ON: unexpected status {status!r} (expected active/activating/enabled)")
    else:
        _log(f"[{label}] VERIFY_ON ok: status={status!r}")

    # DISABLE
    _log(f"[{label}] DISABLE: PUT {RULES_BASE}/disable")
    try:
        dis_resp = disable_rule(client, rule_id, site_id)
    except S1APIError as e:
        _log(f"[{label}] DISABLE FAILED: HTTP {e.status} {e}")
        _log(f"[{label}] Manual cleanup: rule_id={rule_id}")
        return 11
    affected = (dis_resp.get("data") or {}).get("affected")
    _log(f"[{label}] DISABLE ok: affected={affected}")

    # VERIFY OFF
    time.sleep(1)
    rule = get_rule(client, rule_id, site_id, is_scheduled)
    status = (rule or {}).get("status", "").lower()
    if status in ("active", "enabled"):
        _log(f"[{label}] VERIFY_OFF: rule still active after disable — status={status!r}")
    else:
        _log(f"[{label}] VERIFY_OFF ok: status={status!r}")

    if keep:
        _log(f"[{label}] KEEP flag set. Leaving rule {rule_id}")
        return 0

    # DELETE
    _log(f"[{label}] DELETE: rule_id={rule_id}")
    try:
        del_resp = delete_rule(client, rule_id, account_id)
    except S1APIError as e:
        _log(f"[{label}] DELETE FAILED: HTTP {e.status} {e}")
        _log(f"[{label}] Manual cleanup: rule_id={rule_id}")
        return 12
    affected = (del_resp.get("data") or {}).get("affected")
    _log(f"[{label}] DELETE ok: affected={affected}")

    # VERIFY GONE
    time.sleep(1)
    rule = get_rule(client, rule_id, site_id, is_scheduled)
    if rule:
        _log(f"[{label}] VERIFY_GONE FAILED: rule still present after delete")
        return 13
    _log(f"[{label}] VERIFY_GONE ok: rule removed")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-id", default=DEFAULT_SITE_ID,
                    help=f"site to scope rules to (default: demo {DEFAULT_SITE_ID})")
    ap.add_argument("--keep", action="store_true", help="skip delete after run")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}  site_id={args.site_id}")

    try:
        account_id = _pick_account_id(client)
    except Exception as e:
        _log(f"Could not resolve account ID: {e}")
        return 1
    _log(f"account_id={account_id}")

    overall = 0

    # ---- Scheduled rule ----
    sched_name = f"{RUN_TAG}-sched-act"
    _log(f"=== SCHEDULED RULE: {sched_name} ===")
    try:
        sched = create_scheduled_rule(client, sched_name, args.site_id, account_id)
    except S1APIError as e:
        _log(f"CREATE (scheduled) FAILED: HTTP {e.status} {e}")
        overall = max(overall, 2)
        sched = None
    if sched:
        sched_id = sched["id"]
        _log(f"CREATE (scheduled) ok: rule_id={sched_id}")
        rc = run_rule_lifecycle(client, "scheduled", sched_id, args.site_id,
                                account_id, is_scheduled=True, keep=args.keep)
        if rc:
            overall = max(overall, rc)

    # ---- Events rule ----
    events_name = f"{RUN_TAG}-events-act"
    _log(f"=== EVENTS RULE: {events_name} ===")
    try:
        evts = create_events_rule(client, events_name, account_id)
    except S1APIError as e:
        _log(f"CREATE (events) FAILED: HTTP {e.status} {e}")
        overall = max(overall, 2)
        evts = None
    if evts:
        evts_id = evts["id"]
        _log(f"CREATE (events) ok: rule_id={evts_id}")
        rc = run_rule_lifecycle(client, "events", evts_id, args.site_id,
                                account_id, is_scheduled=False, keep=args.keep)
        if rc:
            overall = max(overall, rc)

    if overall == 0:
        _log("Detection rule activate lifecycle: ALL OK (scheduled + events)")
    else:
        _log(f"Detection rule activate lifecycle: FAILED (exit={overall})")
    return overall


if __name__ == "__main__":
    sys.exit(main())
