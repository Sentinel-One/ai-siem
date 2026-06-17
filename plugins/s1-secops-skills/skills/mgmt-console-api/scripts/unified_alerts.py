"""Unified Alert Management (UAM) GraphQL wrapper.

SentinelOne exposes a documented GraphQL endpoint at
`POST /web/api/v2.1/unifiedalerts/graphql` for alert CRUD, enrichment,
and action triggering. This module is a thin layer on top that exposes
the common read and write operations as plain Python functions, so the
skill can list/filter/mutate alerts without each caller having to
memorise GraphQL and the UAM schema's sharp edges.

Auth is identical to the REST API — `Authorization: ApiToken <token>` —
so this reuses S1Client for transport, same as `purple_ai.py`.

Schema quirks this wrapper hides (learned from discovery):
  * OrFilterSelectionInput requires `or: [{ and: [filter,...] }]` nesting.
    Plain `{fieldId, stringEqual}` at the top works ONLY for the `alerts`
    query's `filters:` argument (which takes `[FilterInput!]` directly),
    not for mutations or `alertAvailableActions` which use OrFilter.
  * `alertNotes`, `alertMitigationActionResults`, `alertGroupByCount`,
    `alertFiltersCount`, `alertAvailableActions` wrap results in `data`.
  * `alertHistory`, `alertTimeline`, `alertGroups`, `alerts` use a
    connection pattern with `edges { node { ... } }`, `totalCount`,
    `pageInfo { hasNextPage endCursor }`.
  * `AlertHistoryItem` and `AlertTimelineItem` have no `id` — use
    `createdAt`, `eventType`, `eventText` instead.
  * `AlertGroup` fields are `value`, `label`, `count` (not `groupValue`).
  * `AutocompleteOption` has `{value, count}` only — no `label`.
    Autocomplete also rejects fields that don't support it (e.g.
    `externalId`) and requires `searchText` length ≥ 3.
  * `alertsViewDataAvailability` needs nested subselection:
    `{ viewDataAvailability { viewType dataAvailable } }`.
  * `CsvResponse` needs `{ data }` subselection.
  * `aiInvestigations` returns `[AiInvestigation!]` directly — no wrapper.
  * `alertAvailableActions.errors` is `[ActionsError!]` and needs
    `{ errorMessage }` subselection if you ask for it.

Mutation eventual consistency (important):
  `updateAlertNote` and `deleteAlertNote` fail for roughly 30–90 seconds
  after a note is freshly created with
    "Alert Note with ID ... does not have mgmt_note_id set, unable to
     [edit|delete], try again later!"
  This is a backend propagation window — the UAM-facing ID is minted
  before the management-console-side mgmt_note_id. Callers that chain
  create→edit or create→delete should retry with backoff. The wrapper's
  `update_alert_note` and `delete_alert_note` expose a `wait_for_ready`
  retry helper for this.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional

from s1_client import S1Client, S1APIError  # noqa: F401

UAM_PATH = "/web/api/v2.1/unifiedalerts/graphql"
SCHEMA_PATH = "/web/api/v2.1/unifiedalerts/graphql/schema"

# Scope types accepted by ScopeSelectorInput.
SCOPE_TYPES = ("ACCOUNT", "SITE", "GROUP", "GLOBAL")

# ViewType enum values used by alerts(), alertsCsvExport(),
# alertsViewDataAvailability(), alertTriggerActions().
VIEW_TYPES = ("ALL", "ENDPOINT", "IDENTITY", "STAR", "CUSTOM_ALERTS", "CLOUD", "THIRD_PARTY")


# --------------------------------------------------------------------------- errors

class UAMError(RuntimeError):
    """Raised when the UAM endpoint returns GraphQL errors in a 200 response."""

    def __init__(self, message: str, errors: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.errors = errors or []


# --------------------------------------------------------------------------- core

def _gql(
    client: S1Client,
    query: str,
    variables: Optional[Dict[str, Any]] = None,
    *,
    raise_on_error: bool = True,
) -> Dict[str, Any]:
    """POST a GraphQL query and return the parsed response.

    If `raise_on_error` is True (default), non-empty `errors` turn into
    UAMError. Set to False if the caller wants to inspect errors itself
    (e.g. to tolerate the mgmt_note_id eventual-consistency window).
    """
    body: Dict[str, Any] = {"query": query}
    if variables:
        body["variables"] = variables
    resp = client.post(UAM_PATH, json_body=body)
    if raise_on_error and resp.get("errors"):
        first = resp["errors"][0].get("message", "UAM GraphQL error")
        raise UAMError(first, resp["errors"])
    return resp


def fetch_schema(client: S1Client) -> Dict[str, Any]:
    """Fetch the full UAM SDL schema. The response includes a `_raw` key
    with the complete SDL text, plus parsed type info in the other keys."""
    return client.post(SCHEMA_PATH, json_body={})


# --------------------------------------------------------------------------- filter helpers

def build_filter(**kwargs: Any) -> Dict[str, Any]:
    """Convenience for building a single `FilterInput`.

    Example:
        build_filter(fieldId="detectionProduct", stringEqual={"value": "EDR"})
        build_filter(fieldId="status", stringIn={"values": ["NEW", "IN_PROGRESS"]})
    """
    if "fieldId" not in kwargs:
        raise ValueError("fieldId is required")
    return dict(kwargs)


def or_filter(*groups: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Build an `OrFilterSelectionInput` from one or more AND groups.

    Each arg is a list of FilterInput dicts representing an AND group;
    the groups are OR'd together. Mutations + alertAvailableActions need
    this shape.

    Example:
        or_filter(
            [build_filter(fieldId="status", stringEqual={"value": "NEW"})],
            [build_filter(fieldId="severity", stringEqual={"value": "HIGH"})],
        )
    """
    ands = [{"and": list(g)} for g in groups]
    return {"or": ands}


def scope(account_ids: List[str], scope_type: str = "ACCOUNT") -> Dict[str, Any]:
    """Build a `ScopeSelectorInput`."""
    if scope_type not in SCOPE_TYPES:
        raise ValueError(f"scope_type must be one of {SCOPE_TYPES}")
    return {"scopeIds": list(account_ids), "scopeType": scope_type}


# --------------------------------------------------------------------------- queries

_ALERT_CORE_FIELDS = (
    "id detectedAt createdAt updatedAt name status severity analystVerdict "
    "externalId storylineId attackSurfaces confidenceLevel classification "
    "detectionSource { product vendor } assignee { fullName email }"
)

# Expanded selection for single-alert lookups (`get_alert`). Includes the
# `assets` block so callers can see whether an alert is bound to a real
# S1 agent (agentUuid populated) or to a synthesized/ingested asset
# (agentUuid null, category driven by metadata.product on ingest). Not
# used as the list-alerts default because pulling assets for every edge
# in a large paginated page is wasteful. See references/ASSET_LINKAGE.md
# for the empirics on what ingest payloads populate which asset fields.
_ALERT_DETAIL_FIELDS = _ALERT_CORE_FIELDS + (
    " assets { id name agentUuid category subcategory osType osVersion "
    "primary accessible decommissioned deleted status agentVersion "
    "lastLoggedInUser } "
    "dataSources { id name }"
)


def list_alerts(
    client: S1Client,
    *,
    filters: Optional[List[Dict[str, Any]]] = None,
    sort_by: str = "detectedAt",
    sort_order: str = "DESC",
    first: Optional[int] = None,
    after: Optional[str] = None,
    fields: str = _ALERT_CORE_FIELDS,
    view_type: Optional[str] = None,
    scope_input: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run the `alerts` query. Returns `{totalCount, edges, pageInfo}`.

    `filters` is a list of FilterInput dicts (use build_filter); they are
    AND'd together. For OR semantics use `or_filter` with the mutation
    family instead (alerts query takes flat list only).
    """
    args = ["filters: $filters", "sort: {by: $sortBy, order: $sortOrder}"]
    var_defs = [
        "$filters: [FilterInput!]",
        "$sortBy: String!",
        "$sortOrder: SortOrderType!",
    ]
    variables: Dict[str, Any] = {
        "filters": filters or [],
        "sortBy": sort_by,
        "sortOrder": sort_order,
    }
    if first is not None:
        args.append("first: $first")
        var_defs.append("$first: Int")
        variables["first"] = first
    if after is not None:
        args.append("after: $after")
        var_defs.append("$after: String")
        variables["after"] = after
    if view_type is not None:
        args.append("viewType: $viewType")
        var_defs.append("$viewType: ViewType")
        variables["viewType"] = view_type
    if scope_input is not None:
        args.append("scope: $scope")
        var_defs.append("$scope: ScopeSelectorInput")
        variables["scope"] = scope_input

    query = f"""
    query listAlerts({', '.join(var_defs)}) {{
      alerts({', '.join(args)}) {{
        edges {{ node {{ {fields} }} cursor }}
        pageInfo {{ hasNextPage endCursor }}
        totalCount
      }}
    }}
    """
    r = _gql(client, query, variables)
    return (r.get("data") or {}).get("alerts") or {}


def paginate_alerts(
    client: S1Client,
    *,
    filters: Optional[List[Dict[str, Any]]] = None,
    sort_by: str = "detectedAt",
    sort_order: str = "DESC",
    page_size: int = 100,
    max_alerts: Optional[int] = None,
    fields: str = _ALERT_CORE_FIELDS,
    view_type: Optional[str] = None,
) -> Iterable[Dict[str, Any]]:
    """Yield alert nodes one at a time using cursor pagination."""
    after: Optional[str] = None
    yielded = 0
    while True:
        page = list_alerts(
            client,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
            first=page_size,
            after=after,
            fields=fields,
            view_type=view_type,
        )
        for e in page.get("edges") or []:
            node = e.get("node") or {}
            yield node
            yielded += 1
            if max_alerts and yielded >= max_alerts:
                return
        pi = page.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            return
        after = pi.get("endCursor")


def get_alert(
    client: S1Client,
    alert_id: str,
    *,
    fields: str = _ALERT_DETAIL_FIELDS,
) -> Dict[str, Any]:
    """Fetch a single alert by id.

    Default selection (`_ALERT_DETAIL_FIELDS`) includes the `assets`
    block so callers can immediately tell whether an alert is bound to
    real S1 agent inventory (`agentUuid` populated) or to an ingested
    synthetic asset (`agentUuid` null, category driven by the ingest
    payload's `metadata.product/vendor_name`). Pass `fields=_ALERT_CORE_FIELDS`
    to skip the asset join on latency-sensitive calls.
    """
    query = f"""
    query alertOne($id: ID!) {{
      alert(id: $id) {{ {fields} }}
    }}
    """
    r = _gql(client, query, {"id": alert_id})
    return (r.get("data") or {}).get("alert") or {}


def get_alert_with_raw_indicators(client: S1Client, alert_id: str) -> Dict[str, Any]:
    """`alertWithRawIndicators` — alert plus its raw indicator payload."""
    query = """
    query ri($id: ID!) {
      alertWithRawIndicators(id: $id) {
        alert { id name detectedAt status severity }
        rawIndicators
      }
    }
    """
    r = _gql(client, query, {"id": alert_id})
    return (r.get("data") or {}).get("alertWithRawIndicators") or {}


def column_metadata(client: S1Client) -> List[Dict[str, Any]]:
    """`alertColumnMetadata` — the list of queryable fields, their
    filterTypes, sortable/groupable flags, and allowed enum values."""
    query = """
    query { alertColumnMetadata { fieldId filterTypes sortable groupable enumValues } }
    """
    r = _gql(client, query)
    return (r.get("data") or {}).get("alertColumnMetadata") or []


def available_actions(
    client: S1Client,
    *,
    scope_input: Dict[str, Any],
    filter_input: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """`alertAvailableActions` — list actions a caller can trigger.

    `scope_input` is required (use `scope(...)`). `filter_input` is an
    OrFilterSelectionInput (use `or_filter(...)`); pass None for "all
    alerts in scope". Returns `{data: [...], errors: [...]}`.
    """
    query = """
    query actions($filter: OrFilterSelectionInput, $scope: ScopeSelectorInput!) {
      alertAvailableActions(filter: $filter, scope: $scope) {
        data { id title type isDisabled disabledReason }
        errors { errorMessage }
      }
    }
    """
    variables = {"scope": scope_input, "filter": filter_input or {"or": []}}
    r = _gql(client, query, variables)
    return (r.get("data") or {}).get("alertAvailableActions") or {}


def alert_notes(client: S1Client, alert_id: str) -> List[Dict[str, Any]]:
    """`alertNotes` — list notes on an alert. Returns list of note dicts."""
    query = """
    query n($id: ID!) {
      alertNotes(alertId: $id) {
        data { id alertId text createdAt type author { fullName email } }
      }
    }
    """
    r = _gql(client, query, {"id": alert_id})
    return ((r.get("data") or {}).get("alertNotes") or {}).get("data") or []


def alert_history(
    client: S1Client, alert_id: str, *, first: int = 50, after: Optional[str] = None
) -> Dict[str, Any]:
    """`alertHistory` — audit log. Connection shape."""
    query = """
    query h($id: ID!, $first: Int, $after: String) {
      alertHistory(alertId: $id, first: $first, after: $after) {
        edges { node { createdAt eventType eventText } cursor }
        pageInfo { hasNextPage endCursor }
        totalCount
      }
    }
    """
    r = _gql(client, query, {"id": alert_id, "first": first, "after": after})
    return (r.get("data") or {}).get("alertHistory") or {}


def alert_timeline(
    client: S1Client, alert_id: str, *, first: int = 50, after: Optional[str] = None
) -> Dict[str, Any]:
    """`alertTimeline` — timeline view. Connection shape."""
    query = """
    query t($id: ID!, $first: Int, $after: String) {
      alertTimeline(alertId: $id, first: $first, after: $after) {
        edges { node { createdAt eventType eventText } cursor }
        pageInfo { hasNextPage endCursor }
        totalCount
      }
    }
    """
    r = _gql(client, query, {"id": alert_id, "first": first, "after": after})
    return (r.get("data") or {}).get("alertTimeline") or {}


def alert_mitigation_action_results(client: S1Client, alert_id: str) -> List[Dict[str, Any]]:
    """`alertMitigationActionResults` — per-alert action outcomes."""
    query = """
    query m($id: ID!) {
      alertMitigationActionResults(alertId: $id) {
        data { id status mitigationActionType createdAt }
      }
    }
    """
    r = _gql(client, query, {"id": alert_id})
    return ((r.get("data") or {}).get("alertMitigationActionResults") or {}).get("data") or []


def group_by_count(
    client: S1Client,
    field_ids: List[str],
    *,
    filters: Optional[List[Dict[str, Any]]] = None,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """`alertGroupByCount` — faceted counts by one or more fields.

    Note: the backend marks this as deprecated in favour of `alertGroups`,
    but both are still live. Use `alert_groups()` for paginated output.
    """
    query = """
    query g($fieldIds: [String!]!, $filters: [FilterInput!], $limit: Int) {
      alertGroupByCount(fieldIds: $fieldIds, filters: $filters, limit: $limit) {
        data { fieldId hasNextPage values { value label count } }
      }
    }
    """
    variables = {"fieldIds": field_ids, "filters": filters or [], "limit": limit}
    r = _gql(client, query, variables)
    return ((r.get("data") or {}).get("alertGroupByCount") or {}).get("data") or []


def filters_count(
    client: S1Client,
    field_ids: List[str],
    *,
    filters: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """`alertFiltersCount` — facet value counts (used by UI sidebars)."""
    query = """
    query f($fieldIds: [String!]!, $filters: [FilterInput!]) {
      alertFiltersCount(fieldIds: $fieldIds, filters: $filters) {
        data { fieldId values { value label count } }
      }
    }
    """
    variables = {"fieldIds": field_ids, "filters": filters or []}
    r = _gql(client, query, variables)
    return ((r.get("data") or {}).get("alertFiltersCount") or {}).get("data") or []


def alert_groups(
    client: S1Client,
    group_by_field_id: str,
    *,
    filters: Optional[List[Dict[str, Any]]] = None,
    first: int = 20,
    after: Optional[str] = None,
) -> Dict[str, Any]:
    """`alertGroups` — group-by listing, connection shape."""
    query = """
    query ag($fid: String!, $filters: [FilterInput!], $first: Int, $after: String) {
      alertGroups(groupByFieldId: $fid, filters: $filters, first: $first, after: $after) {
        edges { node { value label count } cursor }
        pageInfo { hasNextPage endCursor }
        totalCount
      }
    }
    """
    variables = {
        "fid": group_by_field_id,
        "filters": filters or [],
        "first": first,
        "after": after,
    }
    r = _gql(client, query, variables)
    return (r.get("data") or {}).get("alertGroups") or {}


def autocomplete(
    client: S1Client, field_id: str, search_text: str, *, scope_input: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """`autocompleteOptions` — value suggestions for a field.

    Not every field supports autocomplete (the backend will refuse with
    "Field doesn't support auto-complete"); `search_text` must be ≥ 3 chars.
    """
    query = """
    query ac($fid: String!, $q: String!, $scope: ScopeSelectorInput) {
      autocompleteOptions(fieldId: $fid, searchText: $q, scope: $scope) {
        fieldId values { value count }
      }
    }
    """
    variables = {"fid": field_id, "q": search_text, "scope": scope_input}
    r = _gql(client, query, variables)
    return (r.get("data") or {}).get("autocompleteOptions") or {}


def view_data_availability(client: S1Client) -> List[Dict[str, Any]]:
    """`alertsViewDataAvailability` — which views have data."""
    query = """
    query { alertsViewDataAvailability { viewDataAvailability { viewType dataAvailable } } }
    """
    r = _gql(client, query)
    return ((r.get("data") or {}).get("alertsViewDataAvailability") or {}).get(
        "viewDataAvailability"
    ) or []


def ai_investigations(client: S1Client, alert_ids: List[str]) -> List[Dict[str, Any]]:
    """`aiInvestigations` — AI investigation status for the given alerts."""
    query = """
    query ai($ids: [ID!]!) {
      aiInvestigations(alertIds: $ids) {
        alertId status verdict timestamp purpleAiStatus
      }
    }
    """
    r = _gql(client, query, {"ids": alert_ids})
    return (r.get("data") or {}).get("aiInvestigations") or []


def export_alerts_csv(
    client: S1Client,
    *,
    filters: Optional[List[Dict[str, Any]]] = None,
    view_type: str = "ALL",
) -> str:
    """`alertsCsvExport` — returns a CSV string."""
    query = """
    query ($filters: [FilterInput!], $viewType: ViewType!) {
      alertsCsvExport(filters: $filters, viewType: $viewType) { data }
    }
    """
    variables = {"filters": filters or [], "viewType": view_type}
    r = _gql(client, query, variables)
    return ((r.get("data") or {}).get("alertsCsvExport") or {}).get("data") or ""


def export_alert_history_csv(client: S1Client, alert_id: str) -> str:
    """`alertHistoryCsvExport` — CSV of audit events for one alert."""
    query = "query ($id: ID!) { alertHistoryCsvExport(alertId: $id) { data } }"
    r = _gql(client, query, {"id": alert_id})
    return ((r.get("data") or {}).get("alertHistoryCsvExport") or {}).get("data") or ""


# --------------------------------------------------------------------------- mutations

def add_alert_note(
    client: S1Client,
    alert_id: str,
    text: str,
    *,
    plain_text: Optional[str] = None,
    content_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Create a note on an alert.

    Returns the full list of notes on the alert after the add (that's how
    AlertNotesListResponse works). Find your new note by matching the
    text, or by capturing the ids of notes before/after.
    """
    query = """
    mutation add($id: ID!, $text: String!, $plain: String, $type: ContentType) {
      addAlertNote(alertId: $id, text: $text, plainText: $plain, type: $type) {
        data { id alertId text createdAt type author { fullName } }
      }
    }
    """
    variables = {"id": alert_id, "text": text, "plain": plain_text, "type": content_type}
    r = _gql(client, query, variables)
    return ((r.get("data") or {}).get("addAlertNote") or {}).get("data") or []


def update_alert_note(
    client: S1Client,
    note_id: str,
    text: str,
    *,
    plain_text: Optional[str] = None,
    content_type: Optional[str] = None,
    wait_for_ready: bool = True,
    max_wait_seconds: int = 120,
) -> List[Dict[str, Any]]:
    """Edit an existing alert note.

    If `wait_for_ready` is True (default), retry on the
    "mgmt_note_id not set" error for up to `max_wait_seconds`, since
    freshly-created notes take ~30-90s before they can be edited.
    """
    query = """
    mutation upd($nid: ID!, $text: String!, $plain: String, $type: ContentType) {
      updateAlertNote(alertNoteId: $nid, text: $text, plainText: $plain, type: $type) {
        data { id alertId text createdAt }
      }
    }
    """
    variables = {"nid": note_id, "text": text, "plain": plain_text, "type": content_type}
    return _mutate_note_with_retry(
        client, query, variables, "updateAlertNote",
        wait_for_ready=wait_for_ready, max_wait_seconds=max_wait_seconds,
    )


def delete_alert_note(
    client: S1Client,
    note_id: str,
    *,
    wait_for_ready: bool = True,
    max_wait_seconds: int = 120,
) -> List[Dict[str, Any]]:
    """Delete an alert note (with the same eventual-consistency retry
    behaviour as `update_alert_note`)."""
    query = """
    mutation del($nid: ID!) {
      deleteAlertNote(alertNoteId: $nid) { data { id } }
    }
    """
    return _mutate_note_with_retry(
        client, query, {"nid": note_id}, "deleteAlertNote",
        wait_for_ready=wait_for_ready, max_wait_seconds=max_wait_seconds,
    )


def _mutate_note_with_retry(
    client: S1Client,
    query: str,
    variables: Dict[str, Any],
    root: str,
    *,
    wait_for_ready: bool,
    max_wait_seconds: int,
) -> List[Dict[str, Any]]:
    deadline = time.time() + max_wait_seconds
    backoff = 5
    while True:
        r = _gql(client, query, variables, raise_on_error=False)
        errors = r.get("errors") or []
        if not errors:
            return ((r.get("data") or {}).get(root) or {}).get("data") or []
        msg = errors[0].get("message") or ""
        if wait_for_ready and "mgmt_note_id" in msg and time.time() < deadline:
            time.sleep(backoff)
            backoff = min(backoff * 1.5, 30)
            continue
        raise UAMError(msg, errors)


def trigger_actions(
    client: S1Client,
    *,
    scope_input: Dict[str, Any],
    actions: List[Dict[str, Any]],
    filter_input: Optional[Dict[str, Any]] = None,
    view_type: str = "ALL",
) -> Dict[str, Any]:
    """`alertTriggerActions` — run one or more actions against a filter.

    `actions` is a list of `TriggerActionInput` dicts. Example:
        [
          {"id": "S1/alert/statusUpdate",
           "payload": {"status": {"value": "RESOLVED"}}},
          {"id": "S1/alert/addNote",
           "payload": {"note": {"value": "Closed by automation"}}},
        ]

    `filter_input` is an OrFilterSelectionInput (use `or_filter(...)`).
    Passing `None` means "all alerts in scope" — USE WITH CAUTION.

    Returns the raw union payload — inspect `__typename`:
      * ActionsTriggered — `actions[]` with success/skip/failure lists.
      * TriggerActionsScheduled — `bulkActionTriggerId` for long jobs.
      * TriggerActionsError — `errors[]` with `errorMessage`.
    """
    query = """
    mutation trigger(
      $scope: ScopeSelectorInput!,
      $filter: OrFilterSelectionInput,
      $actions: [TriggerActionInput!]!,
      $viewType: ViewType!
    ) {
      alertTriggerActions(
        scope: $scope, filter: $filter, actions: $actions, viewType: $viewType
      ) {
        __typename
        ... on ActionsTriggered {
          actions {
            actionId
            success { id __typename }
            skip    { id __typename }
            failure { id __typename }
          }
        }
        ... on TriggerActionsError { errors { errorMessage } }
        ... on TriggerActionsScheduled { bulkActionTriggerId }
      }
    }
    """
    variables = {
        "scope": scope_input,
        "filter": filter_input,
        "actions": actions,
        "viewType": view_type,
    }
    r = _gql(client, query, variables)
    return (r.get("data") or {}).get("alertTriggerActions") or {}


# --------------------------------------------------------------------------- convenience wrappers

def set_alert_status(
    client: S1Client,
    *,
    scope_input: Dict[str, Any],
    alert_ids: List[str],
    status: str,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience wrapper: status update (+ optional note) on a specific
    set of alerts. Builds the or/and filter for the caller.

    `status` must be a valid enum value for the alert status field — see
    `column_metadata()` for the enum list. Common: NEW, IN_PROGRESS,
    RESOLVED.
    """
    filt = or_filter([build_filter(fieldId="id", stringIn={"values": alert_ids})])
    actions: List[Dict[str, Any]] = [
        {"id": "S1/alert/statusUpdate", "payload": {"status": {"value": status}}}
    ]
    if note:
        actions.append({"id": "S1/alert/addNote", "payload": {"note": {"value": note}}})
    return trigger_actions(
        client, scope_input=scope_input, actions=actions, filter_input=filt
    )


def set_analyst_verdict(
    client: S1Client,
    *,
    scope_input: Dict[str, Any],
    alert_ids: List[str],
    verdict: str,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience wrapper: analyst-verdict update on specific alerts.

    `verdict` enum: TRUE_POSITIVE, SUSPICIOUS, FALSE_POSITIVE_USER_ERROR,
    etc. (see column_metadata for the full enum)."""
    filt = or_filter([build_filter(fieldId="id", stringIn={"values": alert_ids})])
    actions: List[Dict[str, Any]] = [
        {"id": "S1/alert/analystVerdictUpdate", "payload": {"analystVerdict": {"value": verdict}}}
    ]
    if note:
        actions.append({"id": "S1/alert/addNote", "payload": {"note": {"value": note}}})
    return trigger_actions(
        client, scope_input=scope_input, actions=actions, filter_input=filt
    )


def assign_alerts(
    client: S1Client,
    *,
    scope_input: Dict[str, Any],
    alert_ids: List[str],
    user_email: str,
) -> Dict[str, Any]:
    """Convenience wrapper: assign a set of alerts to a user."""
    filt = or_filter([build_filter(fieldId="id", stringIn={"values": alert_ids})])
    actions = [
        {"id": "S1/alert/assignUser", "payload": {"assignUser": {"userEmail": user_email}}}
    ]
    return trigger_actions(
        client, scope_input=scope_input, actions=actions, filter_input=filt
    )
