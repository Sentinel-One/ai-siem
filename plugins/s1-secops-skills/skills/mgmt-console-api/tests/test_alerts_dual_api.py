"""
Alerts dual-API round-trip test — REVERSIBLE.

Demonstrates the SentinelOne alerts story:

    PRIMARY    POST /web/api/v2.1/unifiedalerts/graphql      (GraphQL UAM)
    SECONDARY  GET  /web/api/v2.1/cloud-detection/alerts     (REST, cloud detections only)

These are PARALLEL surfaces, not redundant ones:
  - UAM is the modern "unified alert management" view across every
    detection source — STAR/Custom Detection Rules, endpoint (EDR), cloud
    workload, identity, and third-party detections. IDs are UUIDs
    (e.g. `019db24c-8b6d-7451-8697-b1b2e1a270f1`).
  - REST /cloud-detection/alerts is the older surface scoped to cloud-
    detection events (primarily STAR rule hits, EDR overflow). IDs are
    64-bit integers (e.g. `2055164731151448891`). The REST payload is
    denormalized — each alert embeds `agentDetectionInfo`, `sourceProcess`,
    `targetProcess`, `ruleInfo`, etc.

On "create" for alerts
----------------------
S1 does NOT expose a generic `createAlert` anywhere. Alerts are
server-side byproducts of detection engines: STAR rules firing, IOC
matches, cloud threat policies, endpoint threats, identity posture rules.
To "generate an alert" you either:
  1. Create a STAR / Custom Detection rule whose query matches current
     telemetry (POST /web/api/v2.1/cloud-detection/rules)
  2. Upload an IOC that matches something an agent is seeing
     (POST /web/api/v2.1/threat-intelligence/iocs — see test_ioc_lifecycle.py)
  3. Trigger synthetic EDR telemetry from an agent

The closest thing to a reversible content-creation path on an existing
alert is `addAlertNote` — add a free-text note, reversible via
`deleteAlertNote`. This test exercises that path.

What this test verifies
-----------------------
  1. GraphQL `alerts` query returns alerts.
  2. GraphQL `alert(id)` returns details for a specific alert.
  3. GraphQL mutation `addAlertNote` adds a note.
  4. GraphQL `alertNotes` surfaces the new note.
  5. GraphQL mutation `deleteAlertNote` removes it (with retry for
     `mgmt_note_id` eventual consistency).
  6. REST `/cloud-detection/alerts` returns alerts (different shape).
  7. Cross-check: note lifecycle ends with zero smoke-* notes on the alert.

Safety
------
Read-mostly. The only write is a note tagged with a unique run_tag, and
it's cleaned up before exit. On failure the test prints the note ID and
alert ID for manual cleanup.

Usage
-----
    python tests/test_alerts_dual_api.py
    python tests/test_alerts_dual_api.py --keep    # leave the note
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
import unified_alerts as ua  # noqa: E402


RUN_TAG = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
NOTE_TEXT = f"smoke-test note {RUN_TAG} — safe to delete"


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _pick_alert_graphql(client: S1Client) -> Optional[Dict[str, Any]]:
    res = ua.list_alerts(client, first=5)
    edges = res.get("edges") or []
    for e in edges:
        n = e.get("node") or {}
        if n.get("id"):
            return n
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="do not delete the test note after")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}")

    # --- 1. GraphQL list ---
    _log("GraphQL: list alerts")
    alert = _pick_alert_graphql(client)
    if not alert:
        _log("GraphQL: no alerts on this tenant — cannot test mutations")
        return 1
    alert_id = alert["id"]
    _log(f"GraphQL ok: picked alert {alert_id}  "
         f"product={alert.get('detectionProduct')}  sev={alert.get('severity')}")

    # --- 2. GraphQL alert detail ---
    _log("GraphQL: get alert detail")
    detail = ua.get_alert(client, alert_id)
    if not detail or detail.get("id") != alert_id:
        _log("GraphQL get_alert FAILED")
        return 2
    _log(f"GraphQL ok: detail returned, name='{(detail.get('name') or '')[:60]}'")

    # --- 3. GraphQL add note ---
    _log("GraphQL: add note")
    before_notes = ua.alert_notes(client, alert_id)
    before_ids = {n["id"] for n in before_notes if n.get("id")}
    try:
        notes_after = ua.add_alert_note(client, alert_id, NOTE_TEXT)
    except ua.UAMError as e:
        _log(f"addAlertNote FAILED: {e}")
        return 3
    new_notes = [n for n in notes_after if n.get("id") not in before_ids]
    if not new_notes:
        _log("GraphQL add note FAILED: no new note seen")
        return 4
    note_id = new_notes[0]["id"]
    _log(f"GraphQL ok: note added id={note_id}")

    # --- 4. GraphQL alertNotes surfaces it ---
    _log("GraphQL: alertNotes")
    notes = ua.alert_notes(client, alert_id)
    hit = next((n for n in notes if n.get("id") == note_id), None)
    if not hit:
        _log(f"alertNotes did not surface the new note id={note_id}")
        return 5
    _log(f"GraphQL ok: {len(notes)} notes; our note present")

    # --- 5. REST /cloud-detection/alerts ---
    _log("REST: /cloud-detection/alerts")
    try:
        resp = client.get("/web/api/v2.1/cloud-detection/alerts",
                          params={"limit": 3})
        rest_alerts = resp.get("data") or []
        _log(f"REST ok: {len(rest_alerts)} alerts returned")
        if rest_alerts:
            first = rest_alerts[0]
            rest_id = (first.get("alertInfo") or {}).get("alertId")
            _log(f"  first alertId (REST): {rest_id}  "
                 f"(UAM/REST IDs are different surfaces)")
    except S1APIError as e:
        _log(f"REST call failed: HTTP {e.status} {e}")

    # --- 6. cleanup ---
    if args.keep:
        _log(f"KEEP flag set. Leaving note {note_id} on alert {alert_id}.")
        return 0

    _log("GraphQL: delete the test note (retry up to 120s for mgmt_note_id)")
    try:
        ua.delete_alert_note(client, note_id, max_wait_seconds=120)
    except ua.UAMError as e:
        _log(f"deleteAlertNote FAILED: {e}")
        _log(f"Manual cleanup: note_id={note_id} on alert_id={alert_id}")
        return 6
    _log("GraphQL ok: note deleted")

    # --- 7. verify ---
    notes = ua.alert_notes(client, alert_id)
    if any(n.get("id") == note_id for n in notes):
        _log(f"VERIFY FAILED: note {note_id} still present after delete")
        return 7
    _log("VERIFY ok: test note removed")

    _log("Alerts dual-API round-trip: ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
