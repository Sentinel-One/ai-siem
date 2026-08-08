"""
End-to-end smoke test that exercises every SDL API method against a
real tenant. Prints a compact pass/fail summary at the end.

Run:
    python tests/smoke_test.py
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))

from sdl_client import SDLClient, SDLAPIError  # noqa: E402


RESULTS = []


def _run(name, fn):
    start = time.time()
    try:
        out = fn()
        dur = time.time() - start
        status = out.get("status", "?") if isinstance(out, dict) else "ok"
        summary = _summarize(out)
        RESULTS.append((name, "PASS", dur, status, summary))
        print(f"[PASS] {name:<22} {dur*1000:6.0f}ms status={status} :: {summary}")
        return out
    except SDLAPIError as e:
        dur = time.time() - start
        body_status = ""
        if isinstance(e.body, dict):
            body_status = e.body.get("status", "")
        RESULTS.append((name, "FAIL", dur, f"HTTP {e.status}", str(e)[:200]))
        print(f"[FAIL] {name:<22} {dur*1000:6.0f}ms HTTP={e.status} status={body_status} :: {str(e)[:160]}")
        if isinstance(e.body, dict):
            print("         body:", json.dumps(e.body, default=str)[:300])
        return None
    except Exception as e:
        dur = time.time() - start
        RESULTS.append((name, "FAIL", dur, "exception", str(e)[:200]))
        print(f"[FAIL] {name:<22} {dur*1000:6.0f}ms exception :: {e}")
        return None


def _summarize(out):
    if not isinstance(out, dict):
        return str(out)[:120]
    keys = []
    for k in ("bytesCharged", "matches", "values", "paths", "results", "continuationToken", "matchingEvents", "matchCount", "version"):
        if k in out:
            v = out[k]
            if isinstance(v, list):
                keys.append(f"{k}[{len(v)}]")
            elif isinstance(v, dict):
                keys.append(f"{k}={{...}}")
            elif isinstance(v, str) and len(v) > 40:
                keys.append(f"{k}=<{len(v)}b>")
            else:
                keys.append(f"{k}={v}")
    return ", ".join(keys) or json.dumps(out, default=str)[:120]


def main():
    c = SDLClient()
    print(f"Base URL: {c.base_url}")
    print(f"Keys configured: "
          f"token={'Y' if c.token else 'n'}")
    print("-" * 80)

    test_nonce = f"sdl-skill-smoke-{uuid.uuid4()}"
    test_parser = "sdl_skill_smoke_parser"
    test_logfile = "sdl-skill-smoke"
    test_path = f"/lookups/sdl_skill_smoke_{int(time.time())}"

    # --------------------------- LOG READ ------------------------------------
    _run("query (minimal)", lambda: c.query(filter="", start_time="5m", max_count=5))

    _run("query (with filter)", lambda: c.query(
        filter="tag='sdl-skill-smoke'",
        start_time="10m",
        max_count=5,
        columns="timestamp,message,tag",
    ))

    _run("facetQuery", lambda: c.facet_query(
        field="tag",
        filter="tag=*",
        start_time="1h",
        max_count=5,
    ))

    _run("numericQuery", lambda: c.numeric_query(
        function="count",
        filter="",
        start_time="1h",
        buckets=4,
    ))

    _run("timeseriesQuery", lambda: c.timeseries_query(queries=[
        {"function": "count", "filter": "", "startTime": "1h", "buckets": 6,
         "createSummaries": False, "onlyUseSummaries": False},
    ]))

    _run("powerQuery (stats)", lambda: c.power_query(
        query="| group n = count()",
        start_time="1h",
    ))

    # --------------------------- CONFIG READ (GraphQL) -----------------------
    # configFiles is the canonical listing. The legacy REST listFiles is checked
    # too, but only to assert it is the NARROWER of the two: if REST ever equals
    # or exceeds GraphQL, either the tenant has no dashboards or this test is
    # pointed at the wrong surface, and the udoId guidance needs re-verifying.
    files = _run("configFiles (GraphQL)", lambda: c.config_files())
    rest = _run("listFiles (legacy REST)", lambda: c.list_files())

    if isinstance(files, list) and isinstance(rest, dict):
        gql_n, rest_n = len(files), len(rest.get("paths") or [])
        dashboards = [f for f in files if (f.get("name") or "").startswith("/dashboards/")]
        udo = [f for f in dashboards if f.get("udoId")]
        ok = rest_n <= gql_n
        RESULTS.append((
            "GraphQL listing is a superset of REST", "PASS" if ok else "FAIL", 0,
            f"graphql={gql_n} rest={rest_n} dashboards={len(dashboards)} udoId-addressed={len(udo)}",
            "" if ok else "REST returned at least as many paths as GraphQL; investigate before trusting either.",
        ))
        print(f"[{'PASS' if ok else 'FAIL'}] GraphQL listing is a superset of REST"
              f"       graphql={gql_n} rest={rest_n} udoId-addressed={len(udo)}")

        # Read a udoId-addressed dashboard: the exact class of file REST cannot see.
        if udo:
            sample = udo[0]
            _run(f"configFile by udoId ({str(sample['udoId'])[:16]})",
                 lambda: c.config_file(udo_id=sample["udoId"]))
        else:
            print("[SKIP] configFile by udoId; tenant has no udoId-addressed dashboards")
            RESULTS.append(("configFile by udoId", "SKIP", 0, "none present", ""))

    # --------------------------- CONFIG WRITE (GraphQL) ----------------------
    # Create, read, update (with optimistic locking), delete a harmless file.
    _run("put_config_file create", lambda: c.put_config_file(name=test_path, content='{"keys": {"a": "1"}}'))

    read_back = _run("config_file (created)", lambda: c.config_file(name=test_path))
    v = read_back.get("version") if isinstance(read_back, dict) else None

    _run("put_config_file update (expectedVersion)",
         lambda: c.put_config_file(name=test_path, content='{"keys": {"a": "1", "b": "2"}}',
                                   expected_version=v))

    # expectedVersion must be enforced on name-addressed writes, not merely accepted.
    # Re-using the now-stale v must be rejected; if it succeeds, optimistic
    # locking is silently a no-op and concurrent edits will be lost.
    stale_rejected = False
    try:
        c.put_config_file(name=test_path, content='{"keys": {"stale": true}}', expected_version=v)
    except Exception:
        stale_rejected = True
    RESULTS.append((
        "stale expectedVersion is rejected", "PASS" if stale_rejected else "FAIL", 0,
        "conflict raised" if stale_rejected else "stale write ACCEPTED",
        "" if stale_rejected else "Optimistic locking is not being enforced on name-addressed writes.",
    ))
    print(f"[{'PASS' if stale_rejected else 'FAIL'}] stale expectedVersion is rejected")

    cur = c.config_file(name=test_path)
    _run("delete_config_file", lambda: c.delete_config_file(name=test_path,
                                                            expected_version=cur.get("version")))

    gone = not [f for f in c.config_files() if f.get("name") == test_path]
    RESULTS.append((
        "deleted file is gone from configFiles", "PASS" if gone else "FAIL", 0,
        "absent" if gone else "STILL PRESENT",
        "" if gone else "delete_config_file reported success but the file survived.",
    ))
    print(f"[{'PASS' if gone else 'FAIL'}] deleted file is gone from configFiles")

    # --------------------------- SUMMARY -------------------------------------
    print("-" * 80)
    passed = sum(1 for r in RESULTS if r[1] == "PASS")
    failed = sum(1 for r in RESULTS if r[1] == "FAIL")
    skipped = sum(1 for r in RESULTS if r[1] == "SKIP")
    print(f"Total: {len(RESULTS)}  PASS: {passed}  FAIL: {failed}  SKIP: {skipped}")
    if failed:
        print("\nFailures:")
        for r in RESULTS:
            if r[1] == "FAIL":
                print(f"  - {r[0]:<22} {r[3]} :: {r[4]}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
