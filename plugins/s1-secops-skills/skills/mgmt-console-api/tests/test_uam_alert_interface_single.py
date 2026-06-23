"""
UAM Alert Interface -- single indicator + single alert round-trip test -- REVERSIBLE.

Minimum viable happy path. Proves the wire-level contract: one OCSF
FileSystem Activity indicator gets POSTed, one SecurityAlert references
it, UAM stitches them together, and the indicator shows up inside the
alert's rawIndicators. For the comprehensive case (batched ingest,
multiple observables per indicator, multiple indicators per alert), see
test_uam_alert_interface_batch.py.

Steps
-----
    1. POST /v1/indicators  -> 202 Accepted (gzip + Bearer + S1-Scope)
    2. POST /v1/alerts      -> 202 Accepted (finding_info.related_events[0].uid)
    3. Poll UAM GraphQL until the ingested alert surfaces (name filter).
    4. Read alert.rawIndicators, assert indicator.metadata.uid is present.
    5. Cleanup (reversibility): status=RESOLVED, analystVerdict=TRUE_POSITIVE_BENIGN
       via UAM bulk-ops -- ingested alerts are not hard-deletable via public API.

Wire contract quirks (baked in):
  * Auth MUST be `Bearer <JWT>`. `ApiToken <JWT>` -> HTTP 401.
  * Payload MUST be gzip-compressed; Content-Encoding: gzip is mandatory.
  * S1-Scope header is mandatory: `<accountId>` or `<accountId>:<siteId>`.
  * Indicator must carry metadata.profiles = ["s1/security_indicator"].

Usage
-----
    python tests/test_uam_alert_interface_single.py
    python tests/test_uam_alert_interface_single.py --keep
    python tests/test_uam_alert_interface_single.py \\
        --account-id <account-id> --site-id <site-id-alt>

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

from s1_client import S1Client  # noqa: E402
import unified_alerts as ua  # noqa: E402
from uam_alert_interface import (  # noqa: E402
    UAMAlertInterfaceClient,
    UAMAlertInterfaceError,
    build_file_indicator,
    build_alert_referencing,
)


RUN_TAG = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _pick_account_and_site(
    client: S1Client,
    want_account: Optional[str],
    want_site: Optional[str],
) -> tuple[str, str, str]:
    if want_account:
        accts = [a for a in (client.get(
                    "/web/api/v2.1/accounts",
                    params={"ids": want_account}).get("data") or [])]
    else:
        accts = client.get("/web/api/v2.1/accounts",
                           params={"limit": 5}).get("data") or []
    if not accts:
        raise RuntimeError("No accounts visible to this token")
    acct = accts[0]
    sites = (client.get(
                "/web/api/v2.1/sites",
                params={"accountIds": acct["id"], "limit": 5})
             .get("data") or {}).get("sites") or []
    if not sites:
        raise RuntimeError(f"No sites under account {acct['id']}")
    site = next((s for s in sites if s["id"] == want_site), sites[0])
    return acct["id"], acct.get("name", "?"), site["id"]


def _poll_for_alert(client: S1Client, scope_input: Dict[str, Any],
                    run_tag: str, *, timeout_s: int = 90
                    ) -> Optional[Dict[str, Any]]:
    deadline = time.time() + timeout_s
    backoff = 3
    while True:
        page = ua.list_alerts(client, scope_input=scope_input, first=25)
        for edge in (page.get("edges") or []):
            n = edge["node"]
            if run_tag in (n.get("name") or "") or run_tag in (
                    n.get("description") or ""):
                return n
        if time.time() >= deadline:
            return None
        time.sleep(backoff)
        backoff = min(backoff * 1.3, 10)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--account-id", default=None,
                    help="Target account (default: first visible).")
    ap.add_argument("--site-id", default=None,
                    help="Target site (default: first under account).")
    ap.add_argument("--uam-url", "--igw-url", dest="uam_url", default=None,
                    help="Override UAM Alert Interface base URL. Defaults "
                         "to config.uam_alert_interface_url or the built-in "
                         "prod URL ingest.us1.sentinelone.net.")
    ap.add_argument("--keep", action="store_true",
                    help="Skip cleanup; leave the alert in NEW state.")
    ap.add_argument("--timeout", type=int, default=90,
                    help="Seconds to wait for alert to surface in UAM.")
    args = ap.parse_args()

    mgmt = S1Client(timeout=30)
    uam_iface = UAMAlertInterfaceClient(
        bearer_token=mgmt.api_token, base_url=args.uam_url)
    _log(f"mgmt={mgmt.base_url}  uam_iface={uam_iface.base_url}  "
         f"run_tag={RUN_TAG}")

    try:
        account_id, account_name, site_id = _pick_account_and_site(
            mgmt, args.account_id, args.site_id)
    except Exception as e:
        _log(f"scope resolution failed: {e}")
        return 1
    scope_str = f"{account_id}:{site_id}"
    _log(f"account={account_id} ({account_name!r})  site={site_id}  "
         f"S1-Scope={scope_str!r}")

    now_ms = int(time.time() * 1000)
    ind_uid = str(uuid.uuid4())
    alert_uid = str(uuid.uuid4())

    indicator = build_file_indicator(
        indicator_uid=ind_uid,
        file_name=f"{RUN_TAG}.iso",
        device_uid=str(uuid.uuid4()),
        device_hostname=f"{RUN_TAG}-host",
        user_uid=str(uuid.uuid4()),
        now_ms=now_ms,
        message=f"{RUN_TAG} indicator",
    )
    alert = build_alert_referencing(
        alert_uid=alert_uid,
        indicators=[indicator],
        now_ms=now_ms,
        title=f"{RUN_TAG} alert",
        description=f"Smoke-test UAM Alert Interface single-indicator alert. "
                    f"run_tag={RUN_TAG}. Safe to resolve.",
    )

    _log(f"INGEST: POST /v1/indicators  metadata.uid={ind_uid}")
    try:
        r = uam_iface.post_indicators([indicator], scope=scope_str)
    except UAMAlertInterfaceError as e:
        _log(f"INDICATOR INGEST FAILED: HTTP {e.status} :: {e.body}")
        return 2
    _log(f"INDICATOR INGEST ok: {r}")

    _log(f"INGEST: POST /v1/alerts  finding_info.uid={alert_uid} "
         f"related_events[0].uid={ind_uid}")
    try:
        r = uam_iface.post_alerts([alert], scope=scope_str)
    except UAMAlertInterfaceError as e:
        _log(f"ALERT INGEST FAILED: HTTP {e.status} :: {e.body}")
        return 3
    _log(f"ALERT INGEST ok: {r}")

    sc = ua.scope([account_id], "ACCOUNT")
    _log(f"POLL: UAM list_alerts for name~={RUN_TAG!r} (up to {args.timeout}s)")
    node = _poll_for_alert(mgmt, sc, RUN_TAG, timeout_s=args.timeout)
    if not node:
        _log("POLL FAILED: alert did not appear in UAM within timeout")
        _log(f"run_tag={RUN_TAG}  alert_uid(finding_info.uid)={alert_uid}")
        return 4
    uam_alert_id = node["id"]
    _log(f"POLL ok: uam_alert_id={uam_alert_id}  name={node.get('name')!r}  "
         f"detectedAt={node.get('detectedAt')}")

    wri = ua.get_alert_with_raw_indicators(mgmt, uam_alert_id)
    raw_uids = [
        (r.get("metadata.uid") or r.get("uid") or "")
        for r in (wri.get("rawIndicators") or [])
    ]
    if ind_uid in raw_uids:
        _log(f"LINK ok: indicator metadata.uid={ind_uid[:12]}... attached to "
             f"alert {uam_alert_id}")
    else:
        _log(f"LINK WARNING: indicator metadata.uid={ind_uid[:12]}... NOT "
             f"found in alert.rawIndicators. raw_uids={raw_uids}")

    if args.keep:
        _log(f"KEEP flag set -- leaving alert {uam_alert_id} in current state")
        return 0

    _log(f"CLEANUP: status->RESOLVED + analystVerdict->TRUE_POSITIVE_BENIGN "
         f"on {uam_alert_id}")
    try:
        ua.set_alert_status(mgmt, scope_input=sc, alert_ids=[uam_alert_id],
                            status="RESOLVED")
        time.sleep(1)
        ua.set_analyst_verdict(mgmt, scope_input=sc, alert_ids=[uam_alert_id],
                               verdict="TRUE_POSITIVE_BENIGN")
        time.sleep(2)
    except Exception as e:
        _log(f"CLEANUP FAILED: {e}")
        _log(f"Manual cleanup: resolve alert id={uam_alert_id}")
        return 5

    final = ua.get_alert(mgmt, uam_alert_id)
    _log(f"CLEANUP ok: final status={final.get('status')!r} "
         f"verdict={final.get('analystVerdict')!r}")

    _log("UAM Alert Interface single: INGEST -> POLL -> LINK -> CLEANUP -- "
         "ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
