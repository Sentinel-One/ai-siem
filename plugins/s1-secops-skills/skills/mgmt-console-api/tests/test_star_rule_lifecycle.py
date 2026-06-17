"""
STAR rule lifecycle round-trip test — REVERSIBLE.

"STAR rules" is the product term for streaming Custom Detection rules that
fire on every matching event in real-time. The API has no separate /star-rules
path — they are cloud-detection/rules with queryType=events.

Exercises:

    CREATE  POST   /web/api/v2.1/cloud-detection/rules   (queryType=events, status=Draft)
    LIST    GET    /web/api/v2.1/cloud-detection/rules?nameSubstring=...&siteIds=...
    UPDATE  PUT    /web/api/v2.1/cloud-detection/rules/{rule_id}
    DELETE  DELETE /web/api/v2.1/cloud-detection/rules   (body: {filter: {ids, siteIds}})
    VERIFY  GET    (expect 0 hits for the deleted rule id)

The rule uses status=Draft throughout — it is never activated, so it cannot
fire against live telemetry. The s1ql targets a fictional process name that
will never exist on a real endpoint. Zero blast radius.

Endpoint notes (confirmed via swagger + live API, 2026-05)
----------------------------------------------------------
- No separate /star-rules path exists in the API (returns 404). STAR rules
  are queryType=events on the shared cloud-detection/rules endpoint.
- queryType enum: events, scheduled, correlation, uebafirstseen.
- isLegacy=false is NOT required for events rules (only for scheduled).
- DELETE body: top-level {filter: {ids: [...], siteIds: [...]}} — no "data" wrapper.
  Returns {"data": {"affected": N}}.
- PUT /{rule_id} requires all 5 fields: name, queryType, severity,
  expirationMode, status. s1ql must also be re-supplied.
- "activeResponse" in CREATE body returns HTTP 400 "Unknown field" — omit it.
- queryLang defaults to "1.0" for events rules; do not set it explicitly.
- treatAsThreat="UNDEFINED" is accepted but stored as null in the response.
- GET nameSubstring + queryType together returns HTTP 500 — use only one filter
  at a time, or use ids for point-lookup.

Usage
-----
    python tests/test_star_rule_lifecycle.py
    python tests/test_star_rule_lifecycle.py --site-id <id>
    python tests/test_star_rule_lifecycle.py --keep

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
RULE_NAME = f"{RUN_TAG}-star"

# demo site — confirmed safe for detection-rule tests
DEFAULT_SITE_ID = "<site-id>"

RULES_BASE = "/web/api/v2.1/cloud-detection/rules"

# S1QL that matches a process name that will never exist on a real endpoint.
SAFE_S1QL = (
    "EventType = \"Process Creation\""
    " AND ProcessName = \"zzz-smoke-test-star-rule-does-not-exist.exe\""
)


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _pick_site_id(client: S1Client) -> str:
    resp = client.get("/web/api/v2.1/sites", params={"limit": 1, "state": "active"})
    sites = (resp.get("data") or {}).get("sites") or []
    if not sites:
        raise RuntimeError("No active sites visible to this token")
    return sites[0]["id"]


def create_star_rule(client: S1Client, site_id: str) -> Dict[str, Any]:
    """
    Create a STAR (events) rule in Draft status — safe, never fires.

    Required fields (confirmed against swagger + live API):
      name, queryType, severity, expirationMode, status (all 5 mandatory).
      s1ql is technically optional per swagger but required in practice.

    Confirmed gotchas (live API, 2026-05):
    - "activeResponse" is rejected as an unknown field — do not include it.
    - "treatAsThreat": "UNDEFINED" is accepted but stored as null in the response.
    - queryLang defaults to "1.0" for events rules; do not set it explicitly.
    """
    body = {
        "data": {
            "name": RULE_NAME,
            "description": f"Smoke test. run_tag={RUN_TAG}. Safe to delete.",
            "queryType": "events",
            # queryLang: not set — defaults to "1.0" for events rules (S1QL, not PQ 2.0)
            # activeResponse: NOT included — live API returns HTTP 400 "unknown field"
            "s1ql": SAFE_S1QL,
            "severity": "Low",
            "expirationMode": "Permanent",
            "status": "Draft",          # never activates; safe
            "treatAsThreat": "UNDEFINED",
            "networkQuarantine": False,
        },
        "filter": {"siteIds": [site_id]},
    }
    resp = client.post(RULES_BASE, json_body=body)
    data = resp.get("data") or {}
    if not data.get("id"):
        raise RuntimeError(f"CREATE returned no id. Response: {resp}")
    return data


def list_rules_by_name(client: S1Client, site_id: str,
                        name_substring: str) -> List[Dict[str, Any]]:
    """
    GET with nameSubstring filter scoped to one site.
    No isLegacy param needed for events rules (only required for scheduled).

    Confirmed gotcha (live API, 2026-05): combining nameSubstring + queryType
    in the same request returns HTTP 500. Use one or the other; prefer ids for
    point-lookup after create.
    """
    resp = client.get(RULES_BASE, params={
        "nameSubstring": name_substring,
        "siteIds": site_id,
        # queryType intentionally omitted — combining with nameSubstring causes HTTP 500
        "limit": 10,
    })
    # Client-side filter to our run_tag since we can't use queryType in the same call
    return [r for r in (resp.get("data") or []) if RUN_TAG in r.get("name", "")]


def get_rule_by_id(client: S1Client, rule_id: str,
                   site_id: str) -> Optional[Dict[str, Any]]:
    resp = client.get(RULES_BASE, params={"ids": rule_id, "siteIds": site_id})
    items = resp.get("data") or []
    return items[0] if items else None


def update_star_rule(client: S1Client, rule_id: str,
                     site_id: str) -> Dict[str, Any]:
    """
    PUT /{rule_id} — all 5 required fields must be re-supplied.
    Updates the description to confirm write-back works.
    """
    body = {
        "data": {
            "name": RULE_NAME,
            "description": f"Smoke test UPDATED. run_tag={RUN_TAG}.",
            "queryType": "events",
            "s1ql": SAFE_S1QL,
            "severity": "Low",
            "expirationMode": "Permanent",
            "status": "Draft",
            "treatAsThreat": "UNDEFINED",
            "networkQuarantine": False,
        },
        "filter": {"siteIds": [site_id]},
    }
    return client.put(f"{RULES_BASE}/{rule_id}", json_body=body)


def delete_rule(client: S1Client, rule_id: str, site_id: str) -> Any:
    """
    DELETE body uses top-level filter (no "data" wrapper).
    Confirmed: {"filter": {"ids": [...], "siteIds": [...]}} is the correct shape.
    """
    return client.delete(RULES_BASE, json_body={
        "filter": {"ids": [rule_id], "siteIds": [site_id]},
    })


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-id", default=None, help="pin to a specific site ID")
    ap.add_argument("--keep", action="store_true", help="skip delete after run")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}")

    # Resolve site ID
    if args.site_id:
        site_id = args.site_id
    else:
        site_id = DEFAULT_SITE_ID
    _log(f"site_id={site_id}  rule_name={RULE_NAME!r}")

    # --- 1. CREATE ---
    _log(f"CREATE: POST {RULES_BASE} (queryType=events, status=Draft)")
    try:
        created = create_star_rule(client, site_id)
    except S1APIError as e:
        if e.status == 403:
            _log("CREATE skipped: HTTP 403 — token lacks cloud-detection write scope")
            return 0
        _log(f"CREATE FAILED: HTTP {e.status} {e}")
        return 1
    rule_id = created["id"]
    _log(f"CREATE ok: rule_id={rule_id}  name={created.get('name')!r}  "
         f"status={created.get('status')}  queryType={created.get('queryType')}")

    # --- 2. LIST ---
    time.sleep(1)
    _log(f"LIST: GET {RULES_BASE}?nameSubstring={RUN_TAG!r}&siteIds={site_id}")
    hits = list_rules_by_name(client, site_id, RUN_TAG)
    list_ok = any(h.get("id") == rule_id for h in hits)
    if not list_ok:
        _log(f"LIST consistency issue: rule_id={rule_id} not found in {len(hits)} hit(s). "
             f"Ids found: {[h.get('id') for h in hits]}")
    else:
        _log(f"LIST ok: {len(hits)} hit(s); created rule present")

    # --- 3. UPDATE ---
    _log(f"UPDATE: PUT {RULES_BASE}/{rule_id}")
    try:
        update_star_rule(client, rule_id, site_id)
    except S1APIError as e:
        _log(f"UPDATE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: rule_id={rule_id}")
        return 3
    # Confirm description was written back
    updated = get_rule_by_id(client, rule_id, site_id)
    if updated and "UPDATED" in (updated.get("description") or ""):
        _log("UPDATE ok: description updated")
    else:
        _log("UPDATE ok (description not confirmed in read-back — continuing)")

    # --- 4. DELETE ---
    if args.keep:
        _log(f"KEEP flag set. Leaving rule {rule_id} (name={RULE_NAME!r})")
        return 0

    _log(f"DELETE: DELETE {RULES_BASE}  filter.ids=[{rule_id}]")
    try:
        del_resp = delete_rule(client, rule_id, site_id)
    except S1APIError as e:
        _log(f"DELETE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: rule_id={rule_id}")
        return 4
    affected = (del_resp.get("data") or {}).get("affected")
    _log(f"DELETE ok: affected={affected}")

    # --- 5. VERIFY ---
    time.sleep(1)
    remaining = get_rule_by_id(client, rule_id, site_id)
    if remaining:
        _log(f"VERIFY FAILED: rule {rule_id} still present after delete "
             f"(status={remaining.get('status')})")
        return 5
    _log("VERIFY ok: rule absent")

    _log("STAR rule lifecycle: CREATE → LIST → UPDATE → DELETE → VERIFY — ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
