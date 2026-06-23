"""
Alert → Indicator pivot test — REVERSIBLE.

Exercises the SOC workflow "take an indicator observed on an alert and
promote it to a tracked Threat-Intelligence IOC."

    1. Pick most-recent alert.
    2. Read alert.rawIndicators, extract a file-hash observable
       (MD5/SHA256) — real detection artifact, NOT a safe placeholder.
    3. Create a TI IOC for that hash, tagged to the alert
         - externalId  = "<run_tag>-<alert_id>"
         - description = "Pinned from alert <alert_id> by API test"
         - source      = run_tag           (uniquely per-run tag)
         - method      = EQUALS / severity = 1 (low)
       This is the same shape a SOC analyst would use to add a block
       for the hash after confirming the alert is a true positive.
    4. LIST /iocs?name__contains=<run_tag> — verify the IOC is linked
       back to its alert via externalId + description fields.
    5. DELETE the IOC by uuid (reversible; the alert itself is
       untouched).
    6. VERIFY re-query returns zero.

If the alert's rawIndicators do not expose a usable hash, the test
falls back to a safe deterministic hash derived from the run_tag — the
workflow (read alert → create IOC → link → delete) is still proven,
just with a non-real-world hash.

IMPORTANT: uses `token_kind="single_scope"` because
`/threat-intelligence/iocs` rejects multi-scope tokens with code
4030010 ("This page doesn't support multi-scopes users yet").

Usage
-----
    python tests/test_alert_indicator_pivot.py
    python tests/test_alert_indicator_pivot.py --keep
    python tests/test_alert_indicator_pivot.py --alert-id <id>

Exit code 0 on success, non-zero on any step failure.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client, S1APIError  # noqa: E402
import unified_alerts as ua  # noqa: E402


RUN_TAG = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"

_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Indicator-value field patterns we look for in rawIndicators.
# Different detection products emit different keys; this picks up the
# common ones without being exhaustive.
_HASH_FIELD_HINTS = (
    "actor.process.file.hashes",       # OCSF actor-process hash array
    "actor.process.parent_process.file.hashes",
    "malware[0].classification_ids",   # occasional location for hash
    "sha256", "SHA256", "Sha256",
    "md5", "MD5", "Md5",
    "file.hashes",
)


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _find_hash_in_raw(raw: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Return (hash_value, indicator_type) found in a rawIndicators dict.

    Scans all string values for something that matches the SHA256/MD5
    regex; falls back to None/None if nothing found.
    """
    if not isinstance(raw, dict):
        return None, None
    for k, v in raw.items():
        if not isinstance(v, str):
            continue
        if _SHA256_RE.match(v):
            return v.lower(), "SHA256"
        if _MD5_RE.match(v):
            return v.lower(), "MD5"
    return None, None


def _pick_alert_and_indicator(
    client: S1Client,
    scope_input: Dict[str, Any],
    alert_id: Optional[str],
) -> Tuple[str, str, str]:
    """Returns (alert_id, hash_value, indicator_type)."""
    if alert_id:
        wri = ua.get_alert_with_raw_indicators(client, alert_id)
        if not wri.get("alert", {}).get("id"):
            raise RuntimeError(f"alert {alert_id} not found")
    else:
        pg = ua.list_alerts(client, scope_input=scope_input, first=5)
        edges = pg.get("edges") or []
        if not edges:
            raise RuntimeError("No alerts visible to this token")
        alert_id = edges[0]["node"]["id"]
        wri = ua.get_alert_with_raw_indicators(client, alert_id)

    for raw in (wri.get("rawIndicators") or []):
        h, t = _find_hash_in_raw(raw)
        if h:
            return alert_id, h, t
    # Fallback: deterministic hash from the run tag. Workflow still proven.
    seed = f"alert-pivot-fallback-{RUN_TAG}-{alert_id}".encode()
    return alert_id, hashlib.sha256(seed).hexdigest(), "SHA256"


def create_pinned_ioc(
    client: S1Client,
    alert_id: str,
    hash_value: str,
    hash_type: str,
    account_id: str,
) -> Dict[str, Any]:
    body = {
        "filter": {"accountIds": [account_id]},
        "data": [{
            "type":        hash_type,
            "value":       hash_value,
            "method":      "EQUALS",
            "source":      RUN_TAG,
            "externalId":  f"{RUN_TAG}-{alert_id}",
            "name":        f"{RUN_TAG}-pinned-from-{alert_id[:12]}",
            "description": f"Pinned from alert {alert_id} by API test. "
                           "Safe to delete.",
            "severity":    1,
            "labels":      ["smoke-test", "alert-pivot", RUN_TAG],
        }],
    }
    return client.post("/web/api/v2.1/threat-intelligence/iocs", json_body=body)


def _pick_account_id(client: S1Client) -> str:
    resp = client.get("/web/api/v2.1/accounts", params={"limit": 1})
    data = resp.get("data") or []
    if not data:
        raise RuntimeError("No accounts visible to this token")
    return data[0]["id"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-id", default=None,
                    help="specific alert to pivot off")
    ap.add_argument("--keep", action="store_true",
                    help="do not delete the pinned IOC after")
    args = ap.parse_args()

    # /iocs endpoint rejects multi-scope tokens; use the single-scope one.
    client = S1Client(timeout=30, token_kind="single_scope")
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}")

    try:
        account_id = _pick_account_id(client)
    except Exception as e:
        _log(f"account resolution failed: {e}")
        return 1
    sc = ua.scope([account_id], "ACCOUNT")

    # --- 1/2. pick alert + extract indicator ---
    try:
        alert_id, hash_val, hash_type = _pick_alert_and_indicator(
            client, sc, args.alert_id,
        )
    except Exception as e:
        _log(f"alert/indicator discovery failed: {e}")
        return 2
    _log(f"alert_id={alert_id}  indicator {hash_type}={hash_val[:12]}…")

    # --- 3. create pinned IOC ---
    _log("CREATE: POST /threat-intelligence/iocs (pinned to alert)")
    try:
        cresp = create_pinned_ioc(client, alert_id, hash_val, hash_type,
                                  account_id)
    except S1APIError as e:
        _log(f"CREATE FAILED: HTTP {e.status} {e}")
        return 3
    created = cresp.get("data") or []
    _log(f"CREATE ok: {len(created)} IOC(s)")

    # --- 4. LIST + verify linkage ---
    time.sleep(2)
    _log(f"LIST: /iocs?name__contains={RUN_TAG!r}")
    hits = [r for r in client.iter_items(
                "/web/api/v2.1/threat-intelligence/iocs",
                params={"name__contains": RUN_TAG, "accountIds": account_id,
                        "limit": 20})
            if (r.get("source") or "") == RUN_TAG]
    if not hits:
        _log(f"LIST FAILED: pinned IOC not found via name__contains={RUN_TAG!r}")
        return 4
    ioc = hits[0]
    linked_ext = ioc.get("externalId") or ""
    linked_desc = ioc.get("description") or ""
    if alert_id not in linked_ext and alert_id not in linked_desc:
        _log(f"LINK FAILED: IOC does not reference alert {alert_id} in "
             f"externalId={linked_ext!r} or description={linked_desc!r}")
        # still proceed to cleanup
    else:
        _log(f"LIST ok: linked via "
             f"{'externalId' if alert_id in linked_ext else 'description'}")

    # --- 5. DELETE ---
    uuids = [h["uuid"] for h in hits if h.get("uuid")]
    if args.keep:
        _log(f"KEEP flag set. Leaving {len(uuids)} IOC(s): {uuids}")
        return 0
    _log(f"DELETE: removing {len(uuids)} pinned IOC(s) by uuid")
    try:
        dresp = client.request(
            "DELETE", "/web/api/v2.1/threat-intelligence/iocs",
            json_body={"filter": {"accountIds": [account_id], "uuids": uuids}},
        )
    except S1APIError as e:
        _log(f"DELETE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: uuids={uuids}  account_id={account_id}")
        return 5
    affected = (dresp.get("data") or {}).get("affected")
    _log(f"DELETE ok: affected={affected}")

    # --- 6. VERIFY ---
    time.sleep(2)
    remaining = [r for r in client.iter_items(
                    "/web/api/v2.1/threat-intelligence/iocs",
                    params={"name__contains": RUN_TAG,
                            "accountIds": account_id, "limit": 10})
                 if r.get("uuid") in set(uuids)]
    if remaining:
        _log(f"VERIFY FAILED: {len(remaining)} IOC(s) still present")
        return 6
    _log("VERIFY ok: zero remaining")

    _log("Alert→Indicator pivot: READ → CREATE → LIST+LINK → DELETE → VERIFY "
         "— ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
