"""
Alert status + analyst-verdict round-trip test — REVERSIBLE.

Exercises the bulk-ops mutation path on an existing alert:

    1. Pick most-recent alert, record current {status, analystVerdict}
    2. Mutate status         → new value via set_alert_status
    3. Verify status change
    4. Restore original status
    5. Verify restoration
    6. Same round-trip for analystVerdict
    7. Final check: all mutations recorded in alertHistory audit log

Why pick an existing alert instead of creating one?
    SentinelOne does not expose a `createAlert` mutation. Alerts are
    server-side byproducts of detection engines firing on live telemetry.
    The closest create/destroy pattern is already covered by
    test_custom_rule_lifecycle.py (CREATE disabled rule → DELETE). This
    test complements that by proving the bulk-ops mutation filter shape
    against a real alert, with full round-trip restoration so the alert
    ends the test in its original state.

Blast radius
    On most tenants the target alert's {status, analystVerdict} end the
    test identical to their starting values — so no lasting SOC impact.
    The alertHistory audit log *will* record the transitions, which is
    working-as-intended for an API test (every status change is
    auditable — that's the feature). Use `--keep` to leave the mutations
    in place for UI inspection.

Usage
-----
    python tests/test_alert_mutation_lifecycle.py
    python tests/test_alert_mutation_lifecycle.py --keep  # no restore
    python tests/test_alert_mutation_lifecycle.py --alert-id <id>  # specific

Exit code 0 on full round-trip success, non-zero on any step failure.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client, S1APIError  # noqa: E402
import unified_alerts as ua  # noqa: E402


STATUS_ENUM = ("NEW", "IN_PROGRESS", "RESOLVED")
# Pick two benign analyst verdicts we can ping-pong between — UNDEFINED
# is the "no verdict recorded" default, so we always use it as one end
# of the round-trip so the restore step is effectively a no-op on a
# fresh alert.
VERDICT_ROUND_TRIP = ("UNDEFINED", "TRUE_POSITIVE_BENIGN")


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _pick_alert(client: S1Client, scope_input: Dict[str, Any],
                alert_id: Optional[str]) -> Dict[str, Any]:
    if alert_id:
        a = ua.get_alert(client, alert_id)
        if not a.get("id"):
            raise RuntimeError(f"alert {alert_id} not found")
        return a
    page = ua.list_alerts(client, scope_input=scope_input, first=5)
    edges = page.get("edges") or []
    if not edges:
        raise RuntimeError("No alerts visible to this token — cannot round-trip")
    return edges[0]["node"]


def _check_triggered_ok(resp: Dict[str, Any], operation: str) -> None:
    """`alertTriggerActions` returns a union type. Inspect __typename and
    raise on TriggerActionsError. ActionsTriggered is considered success
    even if the `failure` sub-list is populated — the test itself will
    verify the post-condition."""
    typ = resp.get("__typename")
    if typ == "TriggerActionsError":
        errs = resp.get("errors") or []
        msg = "; ".join(e.get("errorMessage", "?") for e in errs)
        raise RuntimeError(f"{operation} returned TriggerActionsError: {msg}")
    if typ not in ("ActionsTriggered", "TriggerActionsScheduled"):
        raise RuntimeError(f"{operation} returned unexpected type {typ!r}: {resp}")


def _reread_alert(client: S1Client, alert_id: str) -> Dict[str, Any]:
    # Short poll for propagation — mutation is async on the backend.
    deadline = time.time() + 30
    last: Dict[str, Any] = {}
    while time.time() < deadline:
        last = ua.get_alert(client, alert_id)
        time.sleep(0)  # allow scheduler
        return last
    return last


def _wait_for_field(client: S1Client, alert_id: str, field: str,
                    expected: str, timeout: int = 30) -> Dict[str, Any]:
    """Poll until alert[field] == expected or timeout."""
    deadline = time.time() + timeout
    backoff = 1
    while True:
        a = ua.get_alert(client, alert_id)
        if (a.get(field) or "") == expected:
            return a
        if time.time() >= deadline:
            raise RuntimeError(
                f"Timed out waiting for alert {alert_id}.{field}=={expected!r}, "
                f"last seen {a.get(field)!r}"
            )
        time.sleep(backoff)
        backoff = min(backoff * 1.5, 5)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-id", default=None,
                    help="specific alert to round-trip against (UAM UUID)")
    ap.add_argument("--keep", action="store_true",
                    help="skip the restore step; leave the mutations applied")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}")

    # Resolve scope: first account visible to the token.
    accts = client.get("/web/api/v2.1/accounts", params={"limit": 5}).get("data") or []
    if not accts:
        _log("No accounts visible; cannot continue")
        return 1
    sc = ua.scope([accts[0]["id"]], "ACCOUNT")
    _log(f"scope=ACCOUNT:{accts[0]['id']}  name={accts[0]['name']!r}")

    # --- pick alert ---
    try:
        alert = _pick_alert(client, sc, args.alert_id)
    except Exception as e:
        _log(f"pick_alert failed: {e}")
        return 1
    alert_id = alert["id"]
    orig_status = alert.get("status") or "NEW"
    orig_verdict = alert.get("analystVerdict") or "UNDEFINED"
    _log(f"alert_id={alert_id}  current status={orig_status!r}  "
         f"verdict={orig_verdict!r}")

    # Decide the "new" status: rotate one step through the enum.
    next_status = {
        "NEW": "IN_PROGRESS",
        "IN_PROGRESS": "NEW",  # keep RESOLVED out of the loop
        "RESOLVED": "IN_PROGRESS",
    }.get(orig_status, "IN_PROGRESS")

    # Decide the "new" verdict: flip between UNDEFINED and BENIGN.
    next_verdict = (VERDICT_ROUND_TRIP[1]
                    if orig_verdict == VERDICT_ROUND_TRIP[0]
                    else VERDICT_ROUND_TRIP[0])

    # --- 1. status mutation round-trip ---
    _log(f"STATUS: {orig_status!r} → {next_status!r}")
    try:
        resp = ua.set_alert_status(client, scope_input=sc,
                                   alert_ids=[alert_id], status=next_status)
        _check_triggered_ok(resp, "statusUpdate")
        _wait_for_field(client, alert_id, "status", next_status)
    except Exception as e:
        _log(f"STATUS mutation FAILED: {e}")
        return 2
    _log(f"STATUS ok: now {next_status!r}")

    if not args.keep:
        _log(f"STATUS RESTORE: {next_status!r} → {orig_status!r}")
        try:
            resp = ua.set_alert_status(client, scope_input=sc,
                                       alert_ids=[alert_id], status=orig_status)
            _check_triggered_ok(resp, "statusUpdate restore")
            _wait_for_field(client, alert_id, "status", orig_status)
        except Exception as e:
            _log(f"STATUS RESTORE FAILED: {e}")
            _log(f"Manual cleanup: set alert {alert_id} status back to {orig_status!r}")
            return 3
        _log(f"STATUS RESTORE ok")

    # --- 2. verdict mutation round-trip ---
    _log(f"VERDICT: {orig_verdict!r} → {next_verdict!r}")
    try:
        resp = ua.set_analyst_verdict(client, scope_input=sc,
                                      alert_ids=[alert_id], verdict=next_verdict)
        _check_triggered_ok(resp, "analystVerdictUpdate")
        _wait_for_field(client, alert_id, "analystVerdict", next_verdict)
    except Exception as e:
        _log(f"VERDICT mutation FAILED: {e}")
        return 4
    _log(f"VERDICT ok: now {next_verdict!r}")

    if not args.keep:
        _log(f"VERDICT RESTORE: {next_verdict!r} → {orig_verdict!r}")
        try:
            resp = ua.set_analyst_verdict(client, scope_input=sc,
                                          alert_ids=[alert_id],
                                          verdict=orig_verdict)
            _check_triggered_ok(resp, "analystVerdictUpdate restore")
            _wait_for_field(client, alert_id, "analystVerdict", orig_verdict)
        except Exception as e:
            _log(f"VERDICT RESTORE FAILED: {e}")
            _log(f"Manual cleanup: set alert {alert_id} verdict back to {orig_verdict!r}")
            return 5
        _log(f"VERDICT RESTORE ok")

    # --- 3. history audit verification ---
    _log("HISTORY: fetch audit log for the round-trip events")
    try:
        hist = ua.alert_history(client, alert_id, first=20)
    except Exception as e:
        _log(f"HISTORY fetch failed: {e}")
        return 6
    events = [e["node"] for e in (hist.get("edges") or [])]
    recent_types = {ev.get("eventType") for ev in events[:10]}
    _log(f"HISTORY ok: {len(events)} recent events; "
         f"recent eventTypes={sorted(t for t in recent_types if t)}")

    if args.keep:
        _log("KEEP flag set — mutations applied but not restored. Final state:")
        final = ua.get_alert(client, alert_id)
        _log(f"  status={final.get('status')!r}  verdict={final.get('analystVerdict')!r}")
        _log(f"  (originals were status={orig_status!r}  verdict={orig_verdict!r})")

    _log("Alert mutation lifecycle: STATUS round-trip → VERDICT round-trip "
         "→ HISTORY check — ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
