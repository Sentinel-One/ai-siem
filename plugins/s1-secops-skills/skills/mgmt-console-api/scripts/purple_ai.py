"""Purple AI natural-language query wrapper.

SentinelOne exposes an undocumented GraphQL endpoint at
`POST /web/api/v2.1/graphql` that powers the console's Purple AI chat.
This module wraps the `purpleLaunchQuery` operation so the skill can
ask Purple AI in natural language and get a structured response back
(summary text + generated PowerQuery).

Auth is identical to the REST API — `Authorization: ApiToken <token>` —
so this reuses S1Client for transport and doesn't add any new credential
requirements.

Purple AI's domain boundary (important):
    It answers questions about SDL telemetry — process/network/file
    events, indicators, ingested third-party logs. It does NOT answer
    questions about console entities like alerts, threats, agents,
    sites, or policies. Those are REST resources; route them to the
    matching REST endpoint instead (e.g. GET /web/api/v2.1/threats).
    Out-of-domain questions return HTTP 200 with status.state=COMPLETED
    and a scope-refusal message in result.message.

Typical failure modes (all return HTTP 200):
  * Tenant lacks Purple AI entitlement — status.error.errorType is set.
  * Token's role lacks Purple AI permission — same surface as above.
  * Malformed GraphQL body — top-level `errors` array is populated.
The wrapper raises PurpleAIError on any of the above so callers don't
silently receive empty results.

Usage:
    from s1_client import S1Client
    from purple_ai import purple_query, PurpleAIError

    c = S1Client()
    r = purple_query(c, "Show powershell.exe outbound connections, top 10")
    print(r["message"])
    print(r["power_query"])  # may be None if Purple answered in docs mode
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

# S1Client is the only transport dependency. It already handles auth,
# retries, TLS config, and base_url resolution.
from s1_client import S1Client, S1APIError  # noqa: F401  (S1APIError re-exported)


# Purple AI viewSelector values observed on live tenants. The console UI
# uses these to scope NL->PQ translation to a particular data domain.
VIEW_SELECTORS = ("EDR", "IDENTITY", "CLOUD", "NGFW", "DATA_LAKE")


class PurpleAIError(RuntimeError):
    """Raised when Purple AI returns a non-recoverable error inside a 200 response.

    Common causes:
      * Tenant is not entitled to Purple AI.
      * API token's role lacks Purple AI permission.
      * The GraphQL query itself was malformed (top-level `errors`).

    The `error_type`, `error_detail`, and `raw` attributes let callers
    distinguish these cases programmatically.
    """

    def __init__(
        self,
        message: str,
        *,
        error_type: Optional[str] = None,
        error_detail: Optional[str] = None,
        raw: Any = None,
    ):
        super().__init__(message)
        self.error_type = error_type
        self.error_detail = error_detail
        self.raw = raw


def _build_query(
    base_url: str,
    *,
    view_selector: str,
    start_ms: int,
    end_ms: int,
    is_async: bool,
    conversation_id: str,
) -> str:
    """Return the GraphQL query string with scalar fields interpolated.

    Purple AI's `purpleLaunchQuery` takes most of its inputs as literal
    fields on the `request` object rather than GraphQL variables, so we
    substitute them into the query text. Only `$input` is a true
    variable (safer, because it's the one field that comes from the
    caller's untrusted natural-language input).
    """
    async_literal = "true" if is_async else "false"
    return f"""query PurpleLaunch($input: String!) {{
  purpleLaunchQuery(request: {{
    isAsync: {async_literal}
    contentType: NATURAL_LANGUAGE
    consoleDetails: {{ baseUrl: "{base_url}" version: "S" }}
    conversation: {{ id: "{conversation_id}", messages: [], entitlements: null }}
    inputContent: {{
      userInput: $input
      displayedTimeRange: {{ start: {start_ms}, end: {end_ms} }}
      viewSelector: {view_selector}
      contentType: NATURAL_LANGUAGE
      userDetails: {{
        accountId: ""
        teamToken: ""
        sessionId: "skill-session"
        emailAddress: null
        userAgent: "s1-mgmt-skill"
        buildDate: null
        buildHash: null
      }}
    }}
  }}) {{
    result {{
      message
      summary
      powerQuery {{ query timeRange {{ start end }} viewSelector }}
      suggestedQuestions {{ question }}
    }}
    resultType
    status {{ state error {{ errorDetail errorType origin }} }}
    stepsCompleted
    token
  }}
}}"""


def purple_query(
    client: S1Client,
    user_input: str,
    *,
    view_selector: str = "EDR",
    hours: int = 24,
    start_ms: Optional[int] = None,
    end_ms: Optional[int] = None,
    is_async: bool = False,
    conversation_id: str = "SKILL-SESSION",
) -> Dict[str, Any]:
    """Ask Purple AI a natural-language question.

    Args:
        client: An S1Client (transport + auth).
        user_input: The natural-language question.
        view_selector: Data domain hint — one of VIEW_SELECTORS. Default EDR.
        hours: Look-back window from now. Ignored if start_ms/end_ms given.
        start_ms, end_ms: Explicit time window in epoch milliseconds.
        is_async: If True, Purple AI may return before generation completes
            and hand back a continuation token. Default False (blocking).
        conversation_id: Identifier the Purple backend uses to tag this
            traffic (useful for distinguishing SOAR from UI).

    Returns:
        Normalized dict:
            {
              "state": "COMPLETED" | "ERROR" | ...,
              "result_type": "MESSAGE" | "POWER_QUERY" | ...,
              "message": str,                # may be empty if result_type=POWER_QUERY
              "power_query": str | None,     # generated PQ, if any
              "view_selector": str | None,   # selector Purple actually used
              "time_range": {"start": int, "end": int} | None,
              "suggested_questions": [str, ...],
              "steps_completed": int | None,
              "token": str | None,           # continuation token (async mode)
              "raw": <full GraphQL response>,
            }

    Raises:
        PurpleAIError: on entitlement/permission errors, or malformed GraphQL.
        S1APIError: on transport errors (non-2xx). Pass-through from S1Client.
    """
    if view_selector not in VIEW_SELECTORS:
        # Not enforced server-side on all versions, but catching it client-side
        # prevents silent misrouting of queries to the wrong data domain.
        raise ValueError(
            f"view_selector must be one of {VIEW_SELECTORS}, got {view_selector!r}"
        )

    if start_ms is None or end_ms is None:
        now_ms = int(time.time() * 1000)
        end_ms = now_ms if end_ms is None else end_ms
        start_ms = (now_ms - hours * 60 * 60 * 1000) if start_ms is None else start_ms

    query = _build_query(
        client.base_url,
        view_selector=view_selector,
        start_ms=start_ms,
        end_ms=end_ms,
        is_async=is_async,
        conversation_id=conversation_id,
    )
    body = {"query": query, "variables": {"input": user_input}}

    resp = client.post("/web/api/v2.1/graphql", json_body=body)

    # Top-level GraphQL errors — malformed query, auth issues that bubbled up
    # as a GraphQL error rather than HTTP 401.
    if resp.get("errors"):
        first = resp["errors"][0] if resp["errors"] else {}
        raise PurpleAIError(
            f"Purple AI GraphQL error: {first.get('message', 'unknown')}",
            error_type="GRAPHQL_ERROR",
            error_detail=str(resp["errors"]),
            raw=resp,
        )

    plq = (resp.get("data") or {}).get("purpleLaunchQuery") or {}
    status = plq.get("status") or {}
    state = status.get("state")
    err = status.get("error")

    # Status-level error — typically entitlement or permission.
    if err:
        raise PurpleAIError(
            f"Purple AI returned an error ({err.get('errorType')}): "
            f"{err.get('errorDetail')}",
            error_type=err.get("errorType"),
            error_detail=err.get("errorDetail"),
            raw=resp,
        )

    result = plq.get("result") or {}
    pq = result.get("powerQuery") or {}
    tr = pq.get("timeRange") or {}
    suggestions: List[str] = [
        q.get("question")
        for q in (result.get("suggestedQuestions") or [])
        if q.get("question")
    ]

    return {
        "state": state,
        "result_type": plq.get("resultType"),
        "message": result.get("message") or "",
        "summary": result.get("summary"),
        "power_query": pq.get("query"),
        "view_selector": pq.get("viewSelector"),
        "time_range": {"start": tr.get("start"), "end": tr.get("end")} if tr else None,
        "suggested_questions": suggestions,
        "steps_completed": plq.get("stepsCompleted"),
        "token": plq.get("token"),
        "raw": resp,
    }
