"""
SentinelOne Long Running Query (LRQ) runner -- the foolproof path for
"query logs via the mgmt console API".

Why this module exists
----------------------
Every time an LRQ is rolled inline with `requests.post(...)`, something
goes wrong: wrong auth prefix, wrong endpoint path, missing
`X-Dataset-Query-Forward-Tag`, missing `tenant: true`, no retry on
transient 5xx, no 0-rows debugging. This module encapsulates the
entire launch-poll-cancel lifecycle so the caller writes one line:

    from s1_client import S1Client
    from pq import run_pq

    c = S1Client()
    res = run_pq(c, "dataSource.name='Example Source' "
                    "| group ct=count() by event.type | sort -ct",
                 hours=24)
    print(res["row_count"], "rows")
    for row in res["rows"]:
        print(row)

The same JWT that S1Client uses for ApiToken REST auth is used here
with the `Bearer` prefix that LRQ requires. The endpoint is
`POST /sdl/v2/api/queries` on the tenant's own console host -- NOT
`/web/api/v2.1/sdl/v2/api/queries`, NOT `xdr.us1.sentinelone.net`.

Key behaviors
-------------
* Auth:          Authorization: Bearer <jwt>   (flipped from ApiToken)
* Endpoint:      <console>/sdl/v2/api/queries   (launch, poll, cancel)
* Forward tag:   X-Dataset-Query-Forward-Tag captured on POST, echoed
                 on every GET and DELETE (mandatory; LRQ rejects
                 otherwise)
* Poll cadence:  every 1.0s (query expires 30s after last poll)
* Retry:         5xx + connection errors retried with exponential
                 backoff (0.5, 1.0, 2.0, 4.0s; max 5 attempts). 429
                 honors Retry-After if present.
* Cancel:        always called, even on success or error path, to
                 release the per-account concurrent query budget.
* Discovery:     list_data_sources(c, hours=24) is the FIRST call you
                 should make when a user names a data source you've
                 never queried on this tenant. It answers "does this
                 exist?" and "what's the exact string?" before you
                 write a filter.

0-rows debugging ladder
-----------------------
If `run_pq` returns 0 rows, do NOT widen the time window first. In
order:

  1. Call `list_data_sources(c, hours=24)` to confirm the data source
     string you're filtering on actually exists on this tenant and is
     spelled the way you think (case-sensitive, spaces/punctuation
     matter).
  2. Check `matchCount` vs `row_count`. `matchCount=0` means the
     initial filter eliminated everything; `matchCount>0` with
     `row_count=0` means your post-filter pipeline (|group, |filter,
     |filter after group) threw everything out.
  3. Only after both of those come back clean, widen the time range.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests


# ---------------------------------------------------------------------- auth

def _bearer_headers(jwt: str, forward_tag: Optional[str] = None
                    ) -> Dict[str, str]:
    h = {"Authorization": f"Bearer {jwt}",
         "Content-Type": "application/json"}
    if forward_tag:
        h["X-Dataset-Query-Forward-Tag"] = forward_tag
    return h


# ---------------------------------------------------------------- time range

def _resolve_window(
    *,
    hours: Optional[float],
    days: Optional[float],
    start_time: Optional[str],
    end_time: Optional[str],
) -> tuple[str, str]:
    """Accept any of (hours=, days=, start_time=+end_time=) and return
    ISO-8601 Z-suffixed strings. `hours`/`days` are relative to now
    (UTC). Mixing forms raises ValueError."""
    if start_time and end_time:
        if hours is not None or days is not None:
            raise ValueError(
                "pass either start_time+end_time OR hours/days, not both")
        return start_time, end_time
    if start_time or end_time:
        raise ValueError(
            "start_time and end_time must be passed together")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    hours_total = (hours or 0) + (days or 0) * 24
    if hours_total <= 0:
        hours_total = 24
    start = now - timedelta(hours=hours_total)
    iso = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
    return iso(start), iso(now)


# ---------------------------------------------------------------- retry core

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_CONNECTION_ERRORS = (requests.ConnectionError, requests.Timeout)


class PQError(RuntimeError):
    """Raised when the LRQ lifecycle fails in a way retries couldn't fix."""

    def __init__(self, message: str, *, status: Optional[int] = None,
                 body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


def _request_with_retry(
    method: str,
    url: str,
    *,
    headers: Dict[str, str],
    json_body: Any = None,
    timeout: float = 30.0,
    max_attempts: int = 5,
) -> requests.Response:
    """HTTP call with exponential backoff on 5xx/429/connection errors.

    The DNS-cache-overflow 503s and transient timeouts observed behind
    some egress proxies are the motivating case. Caller still gets the
    final response (success or non-retryable error) -- this function
    never swallows a real 4xx.
    """
    last_exc: Optional[Exception] = None
    last_resp: Optional[requests.Response] = None
    backoff = 0.5
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.request(
                method, url, headers=headers, json=json_body, timeout=timeout)
        except _CONNECTION_ERRORS as e:
            if isinstance(e, requests.exceptions.ProxyError):
                raise PQError(
                    f"Sandbox proxy blocked {method} {url}. "
                    f"The Cowork sandbox egress proxy returns 403 on HTTPS CONNECT "
                    f"to sentinelone.net. Use s1-secops-mcp MCP tools instead "
                    f"(powerquery_run, powerquery_schema_discover), which run locally "
                    f"and bypass the sandbox proxy. This is not a credential issue."
                ) from e
            last_exc = e
            if attempt == max_attempts:
                raise PQError(
                    f"{method} {url} failed after {max_attempts} attempts: "
                    f"{type(e).__name__}: {e}") from e
            time.sleep(backoff)
            backoff = min(backoff * 2, 8.0)
            continue
        if resp.status_code in _RETRY_STATUSES and attempt < max_attempts:
            last_resp = resp
            # Honor Retry-After on 429 if present; otherwise exp backoff.
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    sleep_s = float(retry_after)
                except ValueError:
                    sleep_s = backoff
            else:
                sleep_s = backoff
            time.sleep(sleep_s)
            backoff = min(backoff * 2, 8.0)
            continue
        return resp
    # Should be unreachable, but be defensive:
    if last_resp is not None:
        return last_resp
    raise PQError(f"{method} {url} exhausted retries without response "
                  f"(last_exc={last_exc!r})")


# ------------------------------------------------------------ core LRQ calls

def _launch(base_url: str, jwt: str, body: Dict[str, Any], timeout: float
            ) -> tuple[str, str]:
    """POST /sdl/v2/api/queries. Returns (queryId, forward_tag)."""
    url = f"{base_url.rstrip('/')}/sdl/v2/api/queries"
    r = _request_with_retry(
        "POST", url, headers=_bearer_headers(jwt), json_body=body,
        timeout=timeout)
    if r.status_code >= 400:
        raise PQError(f"LRQ launch failed: HTTP {r.status_code} "
                      f"{r.text[:400]}", status=r.status_code, body=r.text)
    try:
        data = r.json()
    except ValueError:
        raise PQError(f"LRQ launch returned non-JSON: {r.text[:400]}")
    qid = data.get("id")
    ftag = r.headers.get("X-Dataset-Query-Forward-Tag")
    if not qid:
        raise PQError(f"LRQ launch missing id: {data}")
    if not ftag:
        raise PQError("LRQ launch response missing "
                      "X-Dataset-Query-Forward-Tag header (required for "
                      "subsequent GET/DELETE routing)")
    return qid, ftag


def _poll_once(base_url: str, jwt: str, qid: str, ftag: str,
               last_seen: int, timeout: float) -> Dict[str, Any]:
    url = (f"{base_url.rstrip('/')}/sdl/v2/api/queries/{qid}"
           f"?lastStepSeen={last_seen}")
    r = _request_with_retry(
        "GET", url, headers=_bearer_headers(jwt, ftag), timeout=timeout)
    if r.status_code >= 400:
        raise PQError(f"LRQ poll failed: HTTP {r.status_code} "
                      f"{r.text[:400]}", status=r.status_code, body=r.text)
    try:
        return r.json()
    except ValueError:
        raise PQError(f"LRQ poll returned non-JSON: {r.text[:400]}")


def _cancel(base_url: str, jwt: str, qid: str, ftag: str, timeout: float
            ) -> None:
    """Best-effort cancel. Never raises -- we don't want cleanup to
    mask a real result."""
    try:
        url = f"{base_url.rstrip('/')}/sdl/v2/api/queries/{qid}"
        _request_with_retry(
            "DELETE", url, headers=_bearer_headers(jwt, ftag),
            timeout=timeout, max_attempts=2)
    except Exception:
        pass


# ------------------------------------------------------------ public surface

def run_pq(
    client: Any,
    query: str,
    *,
    hours: Optional[float] = None,
    days: Optional[float] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    tenant: bool = True,
    account_ids: Optional[List[str]] = None,
    priority: str = "HIGH",
    result_type: str = "TABLE",
    poll_interval_s: float = 1.0,
    poll_deadline_s: float = 180.0,
    request_timeout_s: float = 30.0,
) -> Dict[str, Any]:
    """Run one PowerQuery via the LRQ API and return the result.

    The ONE call that replaces hand-rolled launch/poll/cancel. Pass
    the same S1Client you use for REST; the JWT is reused with a
    Bearer prefix. The tenant console base_url is reused as-is.

    Parameters
    ----------
    client : S1Client
        Any object exposing `api_token` (the raw JWT) and `base_url`.
    query : str
        The PowerQuery string. Do NOT wrap in an outer object; pass
        the query text as you'd write it in Event Search.
    hours / days : number, optional
        Relative time window anchored at now (UTC). Pass exactly one
        of (hours=, days=, start_time+end_time). If none given,
        defaults to 24 hours.
    start_time / end_time : ISO-8601 string, optional
        Absolute window. Must be passed together. Z-suffixed UTC.
    tenant : bool, default True
        Query the full tenant scope. Set False and pass `account_ids`
        to scope to specific accounts. LRQ rejects `tenant=true` with
        `accountIds` populated, so this helper clears `tenant` when
        `account_ids` is provided.
    account_ids : list[str], optional
        Account IDs to scope to. Implies tenant=false.
    priority : "HIGH" | "LOW", default "HIGH"
    result_type : "TABLE" (default) | other LRQ result types
    poll_interval_s : float, default 1.0
        How often to GET. LRQ expires the query 30s after the last
        poll, so this MUST stay <= ~5s.
    poll_deadline_s : float, default 180.0
        Wall-clock cap on how long to wait for completion.
    request_timeout_s : float, default 30.0
        Per-HTTP-call socket timeout.

    Returns
    -------
    dict with keys:
        id           : queryId (useful for log correlation)
        elapsed_s    : wall clock, launch to done
        matchCount   : events matched by the initial filter
                       (before | group, | filter, etc.)
        row_count    : rows in the final output
        columns      : list of column names
        values       : list of lists, raw LRQ 2D table
        rows         : list of dicts, zipped {column: value} (convenience)
        data         : the full `data` block from the final poll
                       (for advanced callers who want stats / paging)

    Raises
    ------
    PQError
        On launch failure, poll failure, or deadline exceeded.
    """
    base_url = client.base_url
    jwt = client.api_token
    if not jwt or not base_url:
        raise PQError("client is missing api_token or base_url")

    start_iso, end_iso = _resolve_window(
        hours=hours, days=days,
        start_time=start_time, end_time=end_time)

    body: Dict[str, Any] = {
        "queryType": "PQ",
        "startTime": start_iso,
        "endTime": end_iso,
        "queryPriority": priority,
        "pq": {"query": query, "resultType": result_type},
    }
    if account_ids:
        body["accountIds"] = list(account_ids)
        body["tenant"] = False
    else:
        body["tenant"] = bool(tenant)

    t0 = time.time()
    qid, ftag = _launch(base_url, jwt, body, timeout=request_timeout_s)

    last_seen = 0
    last_data: Dict[str, Any] = {}
    deadline = t0 + poll_deadline_s
    try:
        while True:
            now = time.time()
            if now > deadline:
                raise PQError(
                    f"LRQ poll deadline ({poll_deadline_s}s) exceeded "
                    f"for query {qid}. Consider narrowing the initial "
                    f"filter or raising poll_deadline_s.")
            last_data = _poll_once(
                base_url, jwt, qid, ftag, last_seen,
                timeout=request_timeout_s)
            steps_done = int(last_data.get("stepsCompleted") or 0)
            steps_total = int(last_data.get("stepsTotal") or 0)
            last_seen = steps_done
            if steps_total > 0 and steps_done >= steps_total:
                break
            time.sleep(poll_interval_s)
    finally:
        _cancel(base_url, jwt, qid, ftag, timeout=request_timeout_s)

    data_block = last_data.get("data") or {}
    raw_columns = data_block.get("columns") or []
    values = data_block.get("values") or []
    # LRQ returns `columns` as a list of dicts like
    # {"name": "dataSource.name", "cellType": "STRING", "decimalPlaces": 0}.
    # Callers want a flat list of names for zipping, so flatten defensively
    # -- tolerate either dict-shaped or already-string column entries in
    # case a future response format change makes them strings.
    column_names: List[str] = []
    for col in raw_columns:
        if isinstance(col, dict):
            column_names.append(str(col.get("name") or ""))
        else:
            column_names.append(str(col))
    rows = [dict(zip(column_names, v)) for v in values]
    # `matchCount` lives inside the `data` block in the LRQ response
    # (count of events matched by the initial filter, BEFORE
    # |group/|filter stages). Tolerate either location in case a
    # future response format promotes it to the top.
    match_count = data_block.get("matchCount")
    if match_count is None:
        match_count = last_data.get("matchCount")
    return {
        "id": qid,
        "elapsed_s": round(time.time() - t0, 2),
        "matchCount": match_count,
        "row_count": len(values),
        "columns": column_names,
        "column_meta": raw_columns,
        "values": values,
        "rows": rows,
        "data": data_block,
    }


def list_data_sources(
    client: Any,
    *,
    hours: float = 24,
    limit: int = 200,
    include_category: bool = True,
) -> List[Dict[str, Any]]:
    """Enumerate the `dataSource.name` values visible on this tenant.

    Use this BEFORE filtering by a vendor-named data source ("Prompt
    Security", "Zscaler Internet Access", "FortiGate UTM", etc.). The
    enumeration answers two questions at once:

      1. Does this data source actually land on this tenant?
      2. What's the EXACT string -- the filter is case-sensitive and
         punctuation-sensitive, and vendors don't always use the name
         you'd guess.

    Example
    -------
        >>> sources = list_data_sources(c, hours=24)
        >>> [s["dataSource.name"] for s in sources[:5]]
        ['SentinelOne', 'Example Source', 'Azure', 'Okta', ...]

    Returns a list of dicts sorted by descending event count.
    """
    if include_category:
        query = ("dataSource.name = * "
                 "| group ct = count() "
                 "  by dataSource.name, dataSource.category "
                 "| sort -ct "
                 f"| limit {limit}")
    else:
        query = ("dataSource.name = * "
                 "| group ct = count() by dataSource.name "
                 "| sort -ct "
                 f"| limit {limit}")
    res = run_pq(client, query, hours=hours)
    rows = res["rows"]
    # The LRQ engine can return null for count() on some category-bucketed rows.
    # Normalise here so callers never receive ct=None.
    for row in rows:
        if row.get("ct") is None:
            row["ct"] = 0
    return rows
