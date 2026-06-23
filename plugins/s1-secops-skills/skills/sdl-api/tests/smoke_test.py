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
          f"log_read={'Y' if c.keys['log_read_key'] else 'n'} "
          f"config_read={'Y' if c.keys['config_read_key'] else 'n'} "
          f"config_write={'Y' if c.keys['config_write_key'] else 'n'}")
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

    # --------------------------- CONFIG READ ---------------------------------
    list_res = _run("listFiles", lambda: c.list_files())

    pick_path = None
    if isinstance(list_res, dict):
        paths = list_res.get("paths") or []
        # prefer a /logParsers path for getFile; else the first one
        parsers = [p for p in paths if p.startswith("/logParsers/")]
        pick_path = (parsers or paths or [None])[0]

    if pick_path:
        _run(f"getFile ({pick_path[:30]})", lambda: c.get_file(pick_path, prettyprint=False))
    else:
        print("[SKIP] getFile — no files present to read")
        RESULTS.append(("getFile", "SKIP", 0, "no files", "tenant has no config files yet"))

    # --------------------------- CONFIG WRITE --------------------------------
    # Create, read, update, delete a harmless lookup file.
    create_body = '{"keys": {"a": "1"}}'  # simple JSON lookup

    put_create = _run("putFile create", lambda: c.put_file(test_path, content=create_body))

    # read back to capture version for expectedVersion
    read_back = _run("getFile (created)", lambda: c.get_file(test_path))
    v = None
    if isinstance(read_back, dict):
        v = read_back.get("version")

    update_body = '{"keys": {"a": "1", "b": "2"}}'
    _run("putFile update", lambda: c.put_file(test_path, content=update_body, expected_version=v))

    _run("putFile delete", lambda: c.put_file(test_path, delete=True))

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
