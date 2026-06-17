"""
Scheduled default-report task lifecycle round-trip — REVERSIBLE.

Exercises /web/api/v2.1/report-tasks CRUD for scheduled reports:

    CREATE  POST  /web/api/v2.1/report-tasks
          body: {data: {name, scheduleType, insightTypes, fromDate, toDate},
                 filter: {siteIds: [...]}}
    LIST   GET   /web/api/v2.1/report-tasks?name=<run_tag>
    UPDATE PUT   /web/api/v2.1/report-tasks/{id}
    DELETE POST  /web/api/v2.1/reports/delete-tasks
          body: {filter: {ids: [...]}}
    VERIFY GET   /web/api/v2.1/report-tasks?name=<run_tag>  (expect 0)

Quirks worth knowing (baked in):
  * CREATE response is `{data: {success: true}}` — no id returned.
    The new task is retrieved by NAME in the LIST step.
  * DELETE uses `POST /reports/delete-tasks` (not a true DELETE verb), and
    the body wrapper is `filter.ids`, not `data.ids`.
  * The schema requires `fromDate`/`toDate` even for "manually" scheduled
    reports (they're the report's content window, not the run window).
  * Scope fields (`siteIds`, etc.) belong in the top-level `filter`, NOT
    inside `data` — the server rejects them as "Unknown field" if placed
    inside data.

The report is created with `scheduleType="manually"`, which means the
task exists as a scheduled job but only runs when triggered manually from
the console UI. No PDF is generated during the test window. Safe to run
anytime.

Usage
-----
    python tests/test_scheduled_report_lifecycle.py
    python tests/test_scheduled_report_lifecycle.py --keep

Exit code 0 on full round-trip success, non-zero on any step failure.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client, S1APIError  # noqa: E402


RUN_TAG = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
TASK_NAME = f"{RUN_TAG}-report"


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _pick_site_id(client: S1Client) -> str:
    resp = client.get("/web/api/v2.1/sites", params={"limit": 1})
    sites = (resp.get("data") or {}).get("sites") or []
    if not sites:
        raise RuntimeError("No sites visible to this token")
    return sites[0]["id"]


def create_task(client: S1Client, name: str, site_id: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    body = {
        "data": {
            "name": name,
            "scheduleType": "manually",
            "insightTypes": [
                {"report_id_name": "executive_insights", "report_args": []},
            ],
            "fromDate": (now - timedelta(days=1)).isoformat(timespec="seconds"),
            "toDate":   now.isoformat(timespec="seconds"),
        },
        "filter": {"siteIds": [site_id]},
    }
    return client.post("/web/api/v2.1/report-tasks", json_body=body)


def list_by_name(client: S1Client, name: str) -> List[Dict[str, Any]]:
    return list(client.iter_items(
        "/web/api/v2.1/report-tasks",
        params={"name": name, "limit": 50},
    ))


def update_task(client: S1Client, task_id: str, new_name: str,
                site_id: str) -> Dict[str, Any]:
    # PUT /report-tasks/{id} uses a different, narrower schema than POST —
    # `insightTypes`, `fromDate`, `toDate`, `scheduleType` are rejected as
    # "Unknown field" in the UPDATE body. Only the mutable metadata fields
    # (name, frequency, day, recipients, attachmentTypes) are accepted. We
    # update `name` as the minimal provable change.
    body = {"data": {"name": new_name}}
    return client.put(f"/web/api/v2.1/report-tasks/{task_id}", json_body=body)


def delete_tasks(client: S1Client, ids: List[str]) -> Dict[str, Any]:
    body = {"filter": {"ids": ids}}
    return client.post("/web/api/v2.1/reports/delete-tasks", json_body=body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="do not delete the test task at the end")
    args = ap.parse_args()

    client = S1Client(timeout=30)
    _log(f"tenant={client.base_url}  run_tag={RUN_TAG}")

    try:
        site_id = _pick_site_id(client)
    except Exception as e:
        _log(f"site resolution failed: {e}")
        return 1
    _log(f"site_id={site_id}  task_name={TASK_NAME!r}")

    # --- 1. CREATE ---
    _log("CREATE: POST /report-tasks")
    try:
        cresp = create_task(client, TASK_NAME, site_id)
    except S1APIError as e:
        _log(f"CREATE FAILED: HTTP {e.status} {e}")
        return 2
    if not (cresp.get("data") or {}).get("success"):
        _log(f"CREATE unexpected response: {cresp}")
        return 2
    _log("CREATE ok (no id in response; retrieving by name)")

    # --- 2. LIST (resolve id from name) ---
    time.sleep(1)
    _log(f"LIST: /report-tasks?name={TASK_NAME!r}")
    hits = list_by_name(client, TASK_NAME)
    if not hits:
        _log(f"LIST FAILED: no task with name={TASK_NAME!r}")
        return 2
    task_id = hits[0]["id"]
    _log(f"LIST ok: {len(hits)} hit(s); task_id={task_id}")

    # --- 3. UPDATE ---
    new_name = f"{TASK_NAME}-updated"
    _log(f"UPDATE: PUT /report-tasks/{task_id}  name → {new_name!r}")
    try:
        update_task(client, task_id, new_name, site_id)
    except S1APIError as e:
        _log(f"UPDATE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: task_id={task_id}")
        return 3
    _log("UPDATE ok")

    # --- 4. DELETE ---
    if args.keep:
        _log(f"KEEP flag set. Leaving task {task_id} (name={new_name!r})")
        return 0

    _log(f"DELETE: POST /reports/delete-tasks  filter.ids=[{task_id}]")
    try:
        dresp = delete_tasks(client, [task_id])
    except S1APIError as e:
        _log(f"DELETE FAILED: HTTP {e.status} {e}")
        _log(f"Manual cleanup: task_id={task_id}")
        return 4
    affected = (dresp.get("data") or {}).get("affected")
    _log(f"DELETE ok: affected={affected}")

    # --- 5. VERIFY ---
    time.sleep(1)
    remaining = [t for t in list_by_name(client, new_name)
                 if t.get("id") == task_id]
    if remaining:
        _log(f"VERIFY FAILED: task {task_id} still present after delete")
        return 5
    _log("VERIFY ok: task removed")

    _log("Scheduled-report lifecycle: CREATE → LIST → UPDATE → DELETE → VERIFY — ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
