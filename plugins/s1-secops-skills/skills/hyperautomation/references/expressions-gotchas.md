# Expression gotchas

Failures that each cost a live debugging cycle. All observed on a real tenant while building a
scheduled data-pipeline workflow.

---

## 1. `Function.JQ(..., true)` returns a STRING

The third argument means raw output, so the result is handed on as **text**, not an object. Any
downstream `Function.JQ` that indexes it fails:

```text
Couldn't apply jq filter ... Error: Cannot index string with string "rows"
```

This bites whenever one JQ step feeds another, merge then roll up, parse then filter. Defensive
prelude for any jq program that consumes another jq step's output:

```jq
def asobj: if type == "string" then (fromjson? // {}) else (. // {}) end;
(asobj.rows // []) | ...
```

Accept both shapes rather than assuming; the same program then works whether HA hands over text or
a materialised object.

## 2. `Function.PARSE_JSON` rejects an already-materialised object

A JSON literal built by template interpolation is **already an object**. Passing it to `PARSE_JSON`:

```text
Object of type 'dict' cannot be converted to JSON, only JSON string is allowed
```

Worse, the failure cascades: the *next* action reports
`Object of type UnresolvedLanguageReference is not JSON serializable`, which points at the wrong
place entirely. Pass interpolated JSON straight to `Function.JQ`.

## 3. A `local_var` cannot be read by the action that defines it

```text
Local Variable jq_pick couldn't be found. Please make sure the referenced
variable is defined and executed before this action.
```

Variables in one `variable` action are not visible to later variables **in that same action**. Split
into two actions. (Also stated in `validation-rules.md`; repeated here because it is hit at runtime,
not at validation.)

## 4. Quote-bearing expressions inlined in a payload fail at ACTIVATION

Import succeeds. Activation returns:

```text
400 {"errors":[{"type":"invalid_references","actions_ids":["<id>"]}]}
```

Cause: an expression containing quotes inlined into an `http_request` JSON payload, where the
serialiser escapes them. The expression evaluates perfectly standalone, which makes this very hard
to attribute.

**General rule, not a JQ-specific tip:** hold any quote-bearing expression in a `variable` action
and reference `local_var.*` from the payload.

## 5. Absolute calendar-day windows

`timebucket('1d')` is aligned to absolute UTC midnight, but `DELTA_NOW` is a **rolling** window. A
rolling window only contains a complete day bucket if it reaches back `run_hour + 24h`, so the width
needed tracks the schedule, 26 h at 01:00, 39 h at 14:00. **Moving a flow's schedule silently
changes how much it scans**, and can leave it scanning no complete bucket at all.

Verified working, hour-independent, exactly 24 h:

```text
startTime  {{Function.FORMATTED_DATE(Function.DELTA_NOW(24), "%Y-%m-%dT00:00:00Z")}}
endTime    {{Function.FORMATTED_DATE(Function.DATETIME_NOW(), "%Y-%m-%dT00:00:00Z")}}
```

Store these in a `variable` action per gotcha 4, not inline in the payload.

## 6. Test expressions before deploying

`POST /hyper-automate/api/public/workflow-action-expressions/{base_action_id}/evaluate-expression`
evaluates an expression against a real action context. Use it as a test loop for anything
non-trivial rather than deploying and hoping.

Two gotchas:

- `base_action_id` must be a runtime action **UUID**. The export's `export_id` is a small integer and
  returns `422 uuid_parsing`.
- Evaluating against an action whose upstream has not run returns
  `The following actions need to be tested before: <slug>`. Pick a trigger or a first action instead.

## 7. Validate every `Function.*` against the documented list

It is easy to write a plausible-sounding function that does not exist. `Function.OBJECT` and
`Function.EPOCH_NANOS_DAYS_AGO` both shipped into a draft in this way; neither is real. There is no
`Function.OBJECT`, compose a JSON literal by template interpolation instead, and there is no
epoch-nanos helper, derive the value inside jq.

Cheap guard: fail the build on any `Function.<NAME>` not present in `functions-reference.md`.

## 8. The fake-attribute "throw" idiom

A `variable` action referencing a deliberately non-existent attribute is an intentional way to
**fail a run**, with the attribute name doubling as the error string:

```text
{{poll-action.body.LRQ_TERMINATED_see_lrq_http_status_and_lrq_error_body}}
```

This reads as a bug on first encounter and is easily misdiagnosed as one. It is not, but it is
improvable. Set the real diagnostics in **preceding** variables in the same action so the execution
record carries the actual status code and message, then throw last:

```text
lrq_http_status  {{poll-action.status_code}}
lrq_error_body   {{Function.JQ(poll-action.body, "(.message // .code // .detail // tostring)", true)}}
abort            {{poll-action.body.LRQ_TERMINATED_see_lrq_http_status_and_lrq_error_body}}
```

The first two resolve and are recorded; only the third throws.

## 9. Retrying a poll cannot revive a dead query

An LRQ killed backend-side surfaces as a poll returning
`500 "timeout prevented savelookup from completing"` or `408`. The query is already gone, so
`retry_on_status_codes` on the poll action burns the whole budget for nothing. **Retry means
relaunch.** Either widen the poll budget for slow-but-alive queries, or restructure so a
termination relaunches the query.

## 10. Export and activation surface details

- Export is `GET .../workflow-import-export/export/{workflow_id}/{version_id}`. Omitting
  `version_id` returns `404`, which reads like "not found" rather than "wrong shape".
- A token without `Hyper Automate.workflowsExport` gets a flat `403 Insufficient permissions` on
  both single and batch export while list and execution reads keep working, the gap is invisible
  until you try.
- The platform **reassigns `export_id`** on export. Diffing two exports by `export_id` compares
  unrelated actions and produces nonsense. Normalise to a name-keyed graph first.
- Loop children carry `parent_action` set to the loop's `export_id`, and the loop connects to its
  first child with `custom_handle: "inner"`.
