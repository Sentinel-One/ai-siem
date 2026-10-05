"""Tests for the query slicing runner (scripts/lrq_sliced.py) against a local fake LRQ server.

Zero dependencies: `python3 -m unittest discover -s tests`.
"""
import importlib.util
import json
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lrq_sliced", SKILL_DIR / "scripts" / "lrq_sliced.py")
L = importlib.util.module_from_spec(spec)
sys.modules["lrq_sliced"] = L          # dataclasses resolve annotations through sys.modules
spec.loader.exec_module(L)
L.POLL_INTERVAL_S = 0.01


class Fake:
    """Each launch returns one row per source with n = window hours; behaviour knobs below."""
    def __init__(self):
        self.lock = threading.Lock()
        self.launches = 0
        self.deletes = 0
        self.gets = 0
        self.throttle_first = 0        # first N launches return 429
        self.complete_on_launch = True
        self.bad_query = False
        self.slow_over_hours = None    # a window longer than this never completes
        self.queries = {}
        self.bodies = []


def make_handler(f: Fake):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj, headers=None):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _data(self, body):
            a = datetime.strptime(body["startTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            b = datetime.strptime(body["endTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            hrs = (b - a).total_seconds() / 3600
            return hrs, {"columns": [{"name": "src"}, {"name": "n"}, {"name": "first"}],
                         "values": [["a", hrs, a.timestamp()], ["b", 2 * hrs, a.timestamp()]],
                         "matchCount": 3 * hrs}

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            with f.lock:
                f.launches += 1
                n = f.launches
                f.bodies.append(body)
            if n <= f.throttle_first:
                return self._send(429, {"message": "too many"})
            if f.bad_query:
                return self._send(400, {"code": "invalid_argument", "message": "Unknown EDR field"})
            hrs, data = self._data(body)
            qid = f"q{n}"
            slow = f.slow_over_hours is not None and hrs > f.slow_over_hours
            f.queries[qid] = (data, slow)
            done = f.complete_on_launch and not slow
            out = {"id": qid, "stepsCompleted": 2 if done else 0, "stepsTotal": 2, "totalSteps": 2}
            if done:
                out["data"] = data
            self._send(200, out, {"X-Dataset-Query-Forward-Tag": "tag-" + qid})

        def do_GET(self):
            qid = self.path.split("/")[-1].split("?")[0]
            with f.lock:
                f.gets += 1
            if self.headers.get("X-Dataset-Query-Forward-Tag") != "tag-" + qid:
                return self._send(403, {"message": "missing forward tag"})
            data, slow = f.queries[qid]
            if slow:
                return self._send(200, {"id": qid, "stepsCompleted": 1, "stepsTotal": 2})
            self._send(200, {"id": qid, "stepsCompleted": 2, "stepsTotal": 2, "data": data})

        def do_DELETE(self):
            with f.lock:
                f.deletes += 1
            self._send(204, {})
    return H


class SlicingRunner(unittest.TestCase):
    def setUp(self):
        self.f = Fake()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.f))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.end = datetime(2026, 10, 5, tzinfo=timezone.utc)
        self.start = self.end - timedelta(days=30)

    def tearDown(self):
        self.srv.shutdown()

    def client(self, **kw):
        return L.LRQClient(self.url, "tok", rps=1000, **kw)

    def merge(self):
        return L.Merge(keys=["src"], sum=["n"], min=["first"])

    def test_merged_totals_equal_single_window(self):
        r = L.run_sliced(self.client(), "q", self.start, self.end, slices=15, workers=15, merge=self.merge())
        rows = {row[0]: row for row in r["values"]}
        self.assertAlmostEqual(rows["a"][1], 720)          # 30 days in hours, summed over slices
        self.assertAlmostEqual(rows["b"][1], 1440)
        self.assertEqual(rows["a"][2], self.start.timestamp())   # min of mins
        self.assertEqual(r["stats"]["slices"], 15)
        self.assertEqual(r["matchCount"], 2160)

    def test_every_query_is_cancelled(self):
        L.run_sliced(self.client(), "q", self.start, self.end, slices=7, merge=self.merge())
        self.assertEqual(self.f.deletes, 7)

    def test_launch_response_used_when_complete(self):
        L.run_sliced(self.client(), "q", self.start, self.end, slices=5, merge=self.merge())
        self.assertEqual(self.f.gets, 0, "a query complete on launch should not be polled")

    def test_polls_with_forward_tag_when_not_complete(self):
        self.f.complete_on_launch = False
        r = L.run_sliced(self.client(), "q", self.start, self.end, slices=3, merge=self.merge())
        self.assertEqual(r["stats"]["slices"], 3)
        self.assertGreaterEqual(self.f.gets, 3)

    def test_launch_429_is_retried(self):
        self.f.throttle_first = 3
        L.LAUNCH_RETRIES = 8
        orig = L.time.sleep
        L.time.sleep = lambda s: None
        try:
            c = self.client()
            r = L.run_sliced(c, "q", self.start, self.end, slices=2, workers=1, merge=self.merge())
        finally:
            L.time.sleep = orig
        self.assertEqual(r["stats"]["slices"], 2)
        self.assertEqual(c.stats.launch_429, 3)

    def test_400_is_permanent_and_not_retried(self):
        self.f.bad_query = True
        with self.assertRaises(L.LRQError) as cm:
            L.run_sliced(self.client(), "q", self.start, self.end, slices=4, workers=1, merge=self.merge())
        self.assertTrue(cm.exception.permanent)
        # Not retried, and slices not yet started are dropped. One more may already have been
        # handed to the single worker before the failure was seen, never all four.
        self.assertLessEqual(self.f.launches, 2)

    def test_slow_slice_is_split(self):
        self.f.complete_on_launch = False
        self.f.slow_over_hours = 30           # a 2-day slice never finishes; 24 h halves do
        r = L.run_sliced(self.client(), "q", self.start, self.end, slices=15, workers=15,
                         merge=self.merge(), deadline_s=0.2)
        self.assertEqual(r["stats"]["splits"], 15)
        self.assertEqual(r["stats"]["slices"], 30)
        self.assertAlmostEqual({row[0]: row for row in r["values"]}["a"][1], 720)

    def test_edr_scheme_and_account_scope_in_body(self):
        L.run_sliced(self.client(scheme="edr", account_ids=["123"]), "q", self.start, self.end,
                     slices=1, merge=self.merge())
        b = self.f.bodies[0]
        self.assertEqual(b["scheme"], "edr")
        self.assertEqual(b["accountIds"], ["123"])
        self.assertIs(b["tenant"], False)

    def test_unlisted_column_refuses_to_merge(self):
        with self.assertRaises(ValueError):
            L.run_sliced(self.client(), "q", self.start, self.end, slices=2,
                         merge=L.Merge(keys=["src"], sum=["n"]))

    def test_concat_mode(self):
        r = L.run_sliced(self.client(), "q", self.start, self.end, slices=3,
                         merge=L.Merge(mode="concat", limit=4))
        self.assertEqual(len(r["values"]), 4)


class Slices(unittest.TestCase):
    def test_slices_cover_window_exactly(self):
        a = datetime(2026, 1, 1, tzinfo=timezone.utc)
        b = a + timedelta(days=30, minutes=7)
        s = L.make_slices(a, b, 15)
        self.assertEqual(s[0][0], a)
        self.assertEqual(s[-1][1], b)
        for (x1, y1), (x2, y2) in zip(s, s[1:]):
            self.assertEqual(y1, x2)


if __name__ == "__main__":
    unittest.main()
