#!/usr/bin/env python3
"""Time-sliced, parallel PowerQuery over the LRQ API, merged client-side.

Query slicing solution (sdl-solutions). A long window run as one query is
bound by one backend execution; split into slices and run in parallel it is
bound by the slowest slice. Measured on S-26.3.4 (2026-10-05), one token:
a 30-day `| group n=count() by dataSource.name` over 14.1M events took
21 to 40 s as one query and about 5 s as 15 two-day slices in parallel, with
identical merged totals. 30 slices in flight was slower (10 s).

Limits this runner is built around (same measurement):
  * one token sustains about 30 calls/s with no 429s; 429s start near 35/s and
    hit ONLY launches (POST), never polls or cancels
  * so: token bucket at 25 calls/s, 15 slices in flight, launch 429s retried
    with exponential backoff plus jitter, every query cancelled when done
  * a query is dead 30 s after launch or after the last poll; poll every 1 s
  * many short queries are already complete in the launch response; use it

Zero dependencies (stdlib only), so deployers can vendor this file as is.

Library use:
    from lrq_sliced import LRQClient, run_sliced, Merge
    c = LRQClient(console_url, token)               # rps=25 by default
    res = run_sliced(c, "| group n=count() by dataSource.name",
                     start, end, slices=15, workers=15,
                     merge=Merge(keys=["dataSource.name"], sum=["n"]))
    res["columns"], res["values"], res["stats"]

CLI:
    python3 lrq_sliced.py --query "| group n=count() by dataSource.name" \
        --days 30 --slices 15 --keys dataSource.name --sum n

Credentials: S1_CONSOLE_URL + S1_CONSOLE_API_TOKEN from the environment, or
--creds <credentials.json> holding the same keys.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_RPS = 25.0          # calls/s per token (launch + poll + cancel all count)
DEFAULT_WORKERS = 15        # slices in flight
DEFAULT_SLICES = 15
POLL_INTERVAL_S = 1.0       # the query expires 30 s after the last poll
SLICE_DEADLINE_S = 120.0    # per slice; a slice that runs longer is split in two
MIN_SLICE_S = 15 * 60       # never split below 15 minutes
LAUNCH_RETRIES = 8


class LRQError(RuntimeError):
    def __init__(self, msg: str, status: Optional[int] = None, permanent: bool = False):
        super().__init__(msg)
        self.status = status
        self.permanent = permanent


class SliceTimeout(LRQError):
    pass


class TokenBucket:
    """Thread-safe token bucket. One per token, shared by every worker."""

    def __init__(self, rps: float, burst: Optional[float] = None):
        self.rps = float(rps)
        self.cap = float(burst if burst is not None else max(1.0, rps))
        self.tokens = self.cap
        self.t = time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.cap, self.tokens + (now - self.t) * self.rps)
                self.t = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rps
            time.sleep(wait)


@dataclass
class Stats:
    calls: int = 0
    launches: int = 0
    launch_429: int = 0
    splits: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, **kw: int) -> None:
        with self.lock:
            for k, v in kw.items():
                setattr(self, k, getattr(self, k) + v)

    def as_dict(self) -> Dict[str, int]:
        return {"calls": self.calls, "launches": self.launches,
                "launch_429": self.launch_429, "splits": self.splits}


class LRQClient:
    """Minimal LRQ client: launch, poll, cancel, with rate limiting and launch-429 backoff."""

    def __init__(self, console_url: str, token: str, rps: float = DEFAULT_RPS,
                 burst: Optional[float] = None, timeout: float = 60.0,
                 account_ids: Optional[List[str]] = None, scheme: Optional[str] = None):
        self.base = console_url.rstrip("/") + "/sdl/v2/api/queries"
        self.token = token
        self.bucket = TokenBucket(rps, burst)
        self.timeout = timeout
        self.account_ids = [str(a) for a in (account_ids or [])]
        self.scheme = scheme            # "edr": typo'd EDR fields fail with 400 instead of 0 rows
        self.stats = Stats()

    # -- HTTP ---------------------------------------------------------------
    def _call(self, method: str, url: str, body: Optional[dict] = None,
              ftag: Optional[str] = None) -> Tuple[int, dict, dict]:
        self.bucket.take()
        self.stats.add(calls=1)
        h = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        if body is not None:
            h["Content-Type"] = "application/json"
        if ftag:
            h["X-Dataset-Query-Forward-Tag"] = ftag
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {}), {k.lower(): v for k, v in r.getheaders()}
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                j = json.loads(raw) if raw else {}
            except ValueError:
                j = {"raw": raw[:300].decode("utf-8", "replace")}
            return e.code, j, {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}

    # -- one query ------------------------------------------------------------
    def _body(self, query: str, start: str, end: str) -> dict:
        b: Dict[str, Any] = {"queryType": "PQ", "startTime": start, "endTime": end,
                             "queryPriority": "HIGH", "pq": {"query": query, "resultType": "TABLE"}}
        if self.account_ids:
            b["tenant"] = False
            b["accountIds"] = self.account_ids
        else:
            b["tenant"] = True
        if self.scheme:
            b["scheme"] = self.scheme
        return b

    def launch(self, query: str, start: str, end: str) -> Tuple[str, str, dict]:
        body = self._body(query, start, end)
        for attempt in range(LAUNCH_RETRIES):
            self.stats.add(launches=1)
            code, j, h = self._call("POST", self.base, body)
            if code == 429:
                self.stats.add(launch_429=1)
                ra = h.get("retry-after")
                wait = float(ra) if ra and ra.replace(".", "", 1).isdigit() else 0.5 * 2 ** attempt
                time.sleep(min(wait, 16.0) + random.random() * 0.25)
                continue
            if code >= 500:
                time.sleep(min(0.5 * 2 ** attempt, 8.0))
                continue
            if code >= 400:
                # 400 is the query (syntax, unknown EDR field, scope): retrying cannot fix it.
                raise LRQError(f"launch HTTP {code}: {json.dumps(j)[:300]}", code, permanent=True)
            qid, ftag = j.get("id"), h.get("x-dataset-query-forward-tag")
            if not qid or not ftag:
                raise LRQError(f"launch response missing id or forward tag: {json.dumps(j)[:200]}")
            return qid, ftag, j
        raise LRQError(f"launch still throttled after {LAUNCH_RETRIES} attempts", 429)

    @staticmethod
    def _done(j: dict) -> bool:
        total = j.get("stepsTotal", j.get("totalSteps")) or 0
        return total > 0 and (j.get("stepsCompleted") or 0) >= total

    def run(self, query: str, start: str, end: str, deadline_s: float = SLICE_DEADLINE_S) -> dict:
        """Launch, poll to completion, always cancel. Returns the `data` block."""
        qid, ftag, j = self.launch(query, start, end)
        url = f"{self.base}/{qid}"
        t_end = time.monotonic() + deadline_s
        try:
            while not self._done(j):
                if time.monotonic() > t_end:
                    raise SliceTimeout(f"slice {start}..{end} still running after {deadline_s:.0f}s")
                time.sleep(POLL_INTERVAL_S)
                code, j2, _ = self._call("GET", f"{url}?lastStepSeen={j.get('stepsCompleted', 0)}", ftag=ftag)
                if code == 429:
                    continue
                if code >= 400:
                    raise LRQError(f"poll HTTP {code}: {json.dumps(j2)[:200]}", code, permanent=code < 500)
                j = j2
            return j.get("data") or {}
        finally:
            try:
                self._call("DELETE", url, ftag=ftag)
            except Exception:
                pass


# -- slicing and merging ----------------------------------------------------------

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def make_slices(start: datetime, end: datetime, n: int) -> List[Tuple[datetime, datetime]]:
    n = max(1, int(n))
    step = (end - start) / n
    out = [(start + step * i, start + step * (i + 1)) for i in range(n)]
    out[-1] = (out[-1][0], end)
    return out


@dataclass
class Merge:
    """How to re-aggregate per-slice results.

    keys: group-by columns. sum / min / max: aggregate columns.
    mode "aggregate" (default) needs every non-key column listed in sum, min or max;
    count() and sum() add, min() takes the min, max() the max. estimate_distinct,
    avg and percentiles are NOT additive: compute them in a final pass instead.
    mode "concat" appends rows (raw or per-slice rows), optionally capped by limit.
    """
    keys: List[str] = field(default_factory=list)
    sum: List[str] = field(default_factory=list)
    min: List[str] = field(default_factory=list)
    max: List[str] = field(default_factory=list)
    mode: str = "aggregate"
    limit: Optional[int] = None


def _num(v: Any) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def merge_results(parts: List[dict], m: Merge) -> Tuple[List[str], List[list]]:
    cols: List[str] = []
    for p in parts:
        c = [x.get("name") for x in p.get("columns") or []]
        if c:
            cols = c
            break
    if not cols:
        return [], []
    if m.mode == "concat":
        rows = [r for p in parts for r in (p.get("values") or [])]
        return cols, rows[: m.limit] if m.limit else rows
    listed = set(m.keys) | set(m.sum) | set(m.min) | set(m.max)
    unlisted = [c for c in cols if c not in listed]
    if unlisted:
        raise ValueError(f"columns {unlisted} have no merge rule; list them in keys, sum, min or max, "
                         "or use mode=concat")
    idx = {c: i for i, c in enumerate(cols)}
    acc: Dict[Tuple, list] = {}
    for p in parts:
        pc = [x.get("name") for x in p.get("columns") or []]
        if pc and pc != cols:
            raise ValueError(f"slice columns differ: {pc} vs {cols}")
        for row in p.get("values") or []:
            k = tuple(row[idx[c]] for c in m.keys)
            if k not in acc:
                acc[k] = list(row)
                continue
            cur = acc[k]
            for c in m.sum:
                a, b = _num(cur[idx[c]]), _num(row[idx[c]])
                cur[idx[c]] = (a or 0) + (b or 0) if (a is not None or b is not None) else None
            for c in m.min:
                a, b = _num(cur[idx[c]]), _num(row[idx[c]])
                cur[idx[c]] = b if a is None else (a if b is None else min(a, b))
            for c in m.max:
                a, b = _num(cur[idx[c]]), _num(row[idx[c]])
                cur[idx[c]] = b if a is None else (a if b is None else max(a, b))
    rows = list(acc.values())
    if m.sum:
        s0 = idx[m.sum[0]]
        rows.sort(key=lambda r: -(_num(r[s0]) or 0))
    return cols, rows[: m.limit] if m.limit else rows


def run_sliced(client: LRQClient, query: str, start: datetime, end: datetime,
               slices: int = DEFAULT_SLICES, workers: int = DEFAULT_WORKERS,
               merge: Optional[Merge] = None, deadline_s: float = SLICE_DEADLINE_S) -> dict:
    """Run `query` over [start, end) as `slices` parallel slices and merge the results.

    A slice that is still running at `deadline_s` is split in two and re-run (down to 15
    minutes). A permanent error (HTTP 400, for example a query error) fails the whole run.
    """
    merge = merge or Merge(mode="concat")
    t0 = time.monotonic()
    parts: List[dict] = []
    lock = threading.Lock()

    def one(a: datetime, b: datetime) -> List[Tuple[datetime, datetime]]:
        try:
            d = client.run(query, iso(a), iso(b), deadline_s)
        except SliceTimeout:
            if (b - a).total_seconds() / 2 < MIN_SLICE_S:
                raise
            client.stats.add(splits=1)
            mid = a + (b - a) / 2
            return [(a, mid), (mid, b)]
        with lock:
            parts.append(d)
        return []

    pending = make_slices(start, end, slices)
    ex = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futs = {ex.submit(one, a, b) for a, b in pending}
        while futs:
            done = next(as_completed(futs))
            futs.remove(done)
            for a, b in done.result():          # raises on a permanent error
                futs.add(ex.submit(one, a, b))
    except BaseException:
        # A permanent error (a 400 is the query itself) fails every slice the same way:
        # drop the slices not started yet instead of launching them only to fail.
        ex.shutdown(wait=True, cancel_futures=True)
        raise
    ex.shutdown(wait=True)
    cols, rows = merge_results(parts, merge)
    match = sum(int(_num(p.get("matchCount")) or 0) for p in parts)
    return {"columns": cols, "values": rows, "matchCount": match,
            "stats": dict(client.stats.as_dict(), slices=len(parts),
                          wall_s=round(time.monotonic() - t0, 2))}


# -- CLI ---------------------------------------------------------------------------

def _creds(path: Optional[str]) -> Tuple[str, str]:
    url, tok = os.environ.get("S1_CONSOLE_URL"), os.environ.get("S1_CONSOLE_API_TOKEN")
    if path:
        d = json.loads(open(path).read())
        url, tok = d.get("S1_CONSOLE_URL", url), d.get("S1_CONSOLE_API_TOKEN", tok)
    if not url or not tok:
        sys.exit("set S1_CONSOLE_URL and S1_CONSOLE_API_TOKEN, or pass --creds credentials.json")
    return url, tok


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--query", required=True)
    w = ap.add_mutually_exclusive_group()
    w.add_argument("--days", type=float)
    w.add_argument("--hours", type=float)
    ap.add_argument("--start", help="ISO-8601 Z start (with --end)")
    ap.add_argument("--end", help="ISO-8601 Z end")
    ap.add_argument("--slices", type=int, default=DEFAULT_SLICES)
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--rps", type=float, default=DEFAULT_RPS)
    ap.add_argument("--keys", default="", help="comma-separated group-by columns")
    ap.add_argument("--sum", default="", help="comma-separated columns to add across slices")
    ap.add_argument("--min", default="")
    ap.add_argument("--max", default="")
    ap.add_argument("--concat", action="store_true", help="append rows instead of re-aggregating")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--account-ids", default="")
    ap.add_argument("--edr-strict", action="store_true", help='send scheme="edr" (fail loud on field typos)')
    ap.add_argument("--creds")
    a = ap.parse_args()

    end = parse_iso(a.end) if a.end else datetime.now(timezone.utc).replace(microsecond=0)
    if a.start:
        start = parse_iso(a.start)
    else:
        start = end - (timedelta(hours=a.hours) if a.hours else timedelta(days=a.days or 1))
    sp = lambda s: [x.strip() for x in s.split(",") if x.strip()]
    merge = Merge(keys=sp(a.keys), sum=sp(a.sum), min=sp(a.min), max=sp(a.max),
                  mode="concat" if a.concat else "aggregate", limit=a.limit)
    url, tok = _creds(a.creds)
    c = LRQClient(url, tok, rps=a.rps, account_ids=sp(a.account_ids),
                  scheme="edr" if a.edr_strict else None)
    try:
        res = run_sliced(c, a.query, start, end, a.slices, a.workers, merge)
    except LRQError as e:
        sys.exit(f"error: {e}")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
