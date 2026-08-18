# Interaction Forms (form-based interactions)

Single source of truth for form-based human-in-the-loop steps. **Part 1** mirrors the official
product documentation. **Part 2** is the JSON and API layer, tenant-validated. **Part 3** maps one
to the other so drift between them stays visible.

Supported from platform **S-26.2.6**.

> Part 1 restates the product documentation for Interaction Forms; re-verify it against the
> current official docs when the platform version changes. Part 2 was validated live on a tenant
> running S-26.2.6 on 2026-08-18.

---

# Part 1: product behaviour

## Overview

Interaction forms let a workflow collect complex, structured input from a person in the middle of a
run. The workflow creates a form, shares a link to it (by email, chat message, ticket comment),
pauses until the recipient submits, then continues with the submitted values available to
downstream actions.

Use forms when the existing simple-choice interaction (buttons and option links) is not enough:
when you need free text, numbers, dates, JSON payloads, or several answers at once.

## Common use cases

- **Approval with context**: ask an approver not just to approve or deny but to supply a reason,
  a ticket number, or a scope for the approved action.
- **Analyst enrichment**: pause a triage workflow and ask an analyst to classify an alert, paste
  IOCs, or provide investigation notes that feed the next steps.
- **External data collection**: request structured details from an employee or stakeholder
  impacted by an incident (confirm ownership of an asset, describe suspicious activity).
- **Change requests**: gather parameters for a remediation (maintenance window, target scope)
  before executing it.

## How it works

Two actions, with a delivery action between them:

1. **Create Interaction** (type: Form) defines the form and generates a shareable link.
2. Any delivery action (Send Email, chat message, ticket comment) puts the `interaction_url` in
   front of the intended respondent.
3. **Wait for Interaction** pauses the workflow until the form is submitted or the timeout expires,
   and exposes the submitted values as its output.

## Creating a form

Add Create Interaction, select the **Form** interaction type, then add fields. Each field defines:

- **Field name**: the key the answer appears under in the response output.
- **Field type**: text, number, JSON, email, date, time, or checkbox.
- **Required / optional**: required fields are validated on submission.
- **Description** (optional): helper text shown to the respondent.

**Preview form** renders the form as the respondent will see it.

## Create Interaction outputs

- `interaction_id`: used by Wait for Interaction to identify which interaction to wait on.
- `interaction_url`: the shareable form link. Live from the moment the action runs.
- `interaction_type`: `"Form"`.

## Pausing the workflow

Add Wait for Interaction after the link has been delivered. Set its identifier to the
`interaction_id` output of the Create Interaction action, and configure the timeout in minutes,
hours or days. If the timeout expires before submission, the workflow continues with
`timeout: true` so you can branch accordingly. While waiting, the execution shows a **Waiting**
status.

## Respondent experience

The respondent opens the link and sees the form page, headed "Your input is needed" with the
subtitle "A workflow requires your response before continuing", showing the fields and helper
texts. Required fields are validated on submission. After submitting they see a confirmation
("Response submitted").

Three page states:

| State | Message |
|---|---|
| Active | "Your input is needed" |
| Invalid or no longer active | "This interaction can't be displayed." |
| Already submitted | "This interaction has already been completed." |

## Using the response

The Wait for Interaction output contains the submitted values keyed by field name:

```json
{
  "response": {
    "response_type": "single",
    "result": { "name": "Fran", "age": 33, "date": "2026-07-02", "agree": true }
  },
  "timeout": false
}
```

Reference these in any downstream action exactly like any other action output.

## Limitations

- **Respondent permissions**: in the initial release the person filling out the form must have
  view permissions for the origin workflow. Fully public, no-login forms are not available in this
  release. Treat this as an internal-responder feature, not a way to collect input from arbitrary
  external recipients.
- **Field types**: text, number, JSON, email, date, time, checkbox. **No file upload.**
- **Create must be paired with Wait**: a Create Interaction with no matching Wait for Interaction
  has no effect on the flow, and the workflow will not activate.
- **Timeout maximum**: 7 days.
- **One submission per interaction**: once completed the link shows "already completed"; use
  expected respondents for multi-respondent scenarios.
- **GovCloud**: Create Interaction and Wait for Interaction are not supported in FedRAMP GovCloud
  consoles.

## FAQ

**How is this different from the existing interactions?** Existing interactions collect a simple
choice (buttons and option links). Forms collect structured, multi-field input in one submission.

**Who can fill out the form?** Anyone who receives the link and has view permissions for the origin
workflow. Public forms without console login are not available in this release.

**What happens if nobody responds?** Wait for Interaction times out after the configured period and
the workflow continues with `timeout: true`, letting you branch (escalate, send a reminder).

**Can I attach files to a form?** Not currently.

---

# Part 2: JSON and API layer

Everything below was validated against a live tenant on S-26.2.6 (2026-08-18): import, activation,
run, form render, submission, and downstream resolution.

## Create Interaction: form

`form_schema` mirrors the manual trigger's `dynamic_properties` shape exactly, including the same
seven input types.

```json
{
  "type": "create_interaction",
  "tag": "core_action",
  "connection_id": null,
  "connection_name": null,
  "use_connection_name": false,
  "integration_id": null,
  "data": {
    "name": "Remediation Approval Form",
    "action_type": "create_interaction",
    "interaction_type": "form",
    "options": ["Approve", "Dismiss"],
    "form_schema": {
      "ticket_number": {
        "title": "Ticket reference",
        "description": "Helper text shown under the field",
        "index": 0,
        "type": "text",
        "validation": { "required": true, "min_length": null, "max_length": null },
        "options": null
      },
      "approve": {
        "title": "Approve this remediation",
        "description": "Tick to approve. Unticked or timed out blocks the action.",
        "index": 1,
        "type": "checkbox",
        "validation": { "required": true, "min_length": null, "max_length": null },
        "options": null
      }
    }
  }
}
```

- `interaction_type` is lowercase `"form"` in JSON. The product doc's `"Form"` is the display value
  the action *outputs*, not the config value.
- The `form_schema` KEY is the response key. `title` is the visible label, `description` is helper
  text. Do not conflate them.
- Field `type`: `text`, `number`, `json`, `email`, `date`, `time`, `checkbox`.
- The server normalises each field by adding `"options": null`. Emit it to match canonical shape.

### `options` is a UI gate, not a runtime one

A saved form-type action exports with `"options": []` and executes correctly, but the console will
not enable **Test Action** until at least one option exists. Populate two (for example
`["Approve", "Dismiss"]`) so the action is testable in the UI.

### Outputs and the interaction URL

`interaction_id`, `interaction_type`, and `interaction_url`, where the URL is
`{console}/hyperautomation/interactions/{interaction_id}`. The id is a long compressed token that
encodes the Create action id.

- **Choice** interaction: one URL per option, `{{create-slug.interaction_url.<option>}}`.
- **Form** interaction: a single `{{create-slug.interaction_url}}`.

## Wait for Interaction

```json
{
  "type": "wait_for_interaction",
  "tag": "core_action",
  "data": {
    "name": "Wait For Approval",
    "action_type": "wait_for_interaction",
    "identifier": "{{remediation-approval-form.interaction_id}}",
    "time_unit": "hours",
    "time_value": 4,
    "expected_respondents": 1,
    "response_targets": null,
    "authentication_type": null
  }
}
```

**Field name trap**: `identifier` (not `interaction_id`) and `time_value` (not `value`).

References on resume:

| Reference | Yields |
|---|---|
| `{{wait-slug.response.result.<field_name>}}` | a submitted value |
| `{{wait-slug.timeout}}` | `true` if nobody responded in time |
| `{{wait-slug.response.response_type}}` | `"single"` |
| `{{wait-slug.response.responder.id}}` | the submitting user's id |

`responder.id` is not in the product doc but is present in the payload. It gives respondent
attribution for the audit trail at no extra cost.

## HARD RULE: guard every OPTIONAL field with `Function.DEFAULT`

An optional field the respondent leaves blank is **absent from `response.result` entirely**, not
present-and-null. A bare reference to an absent attribute **errors the whole run**
("Attribute not found in Action"); it does not resolve to empty.

This is the single most dangerous trap in the feature: a flow works during testing when every field
is filled, then dies in production the first time a respondent skips an optional field.

```json
// WRONG, kills the run the first time the field is skipped
{ "name": "window_time",
  "value": "{{wait-for-approval.response.result.window_start_time}}" }

// RIGHT
{ "name": "window_time",
  "value": "{{Function.DEFAULT(wait-for-approval.response.result.window_start_time, \"not provided\")}}" }
```

Required fields are guaranteed present by form validation and can be referenced directly.

Tenant-validated: a build with a bare reference errored on a blank optional time field; the same
build with the DEFAULT guard completed and returned `"not provided"`.

## Approval gates fail closed

Test for the explicit approval value AND a non-timeout, never `not_equals`:

```json
{
  "condition_type": "multi",
  "condition": null,
  "conditions": [
    { "input_value": "{{wait-for-approval.timeout}}",
      "compared_value": "false", "comparison_operator": "equals" },
    { "input_value": "{{wait-for-approval.response.result.approve}}",
      "compared_value": "true", "comparison_operator": "equals" }
  ],
  "conditions_relationship": "and"
}
```

Route the destructive action off the `"true"` branch only. On timeout the value resolves empty,
which satisfies any `not_equals` test, so a fail-open gate auto-approves on silence.

## Activation enforces the pairing

A Create Interaction whose `interaction_id` is not referenced by some Wait for Interaction's
`identifier` will not activate. Import succeeds; activation is where it is caught.

## Canonical placement in a SOC flow

The form gates the **remediation**, after the AI has done its work. It does not feed the
investigation. See `autonomous-soc-template.md` for the full shape.

---

# Part 3: doc-to-JSON parity

| Product doc statement | JSON / API representation | Verified |
|---|---|---|
| Form interaction type | `"interaction_type": "form"` (lowercase) | yes |
| Field name | the `form_schema` object key | yes |
| Field type: text, number, JSON, email, date, time, checkbox | `"type"` on each field | yes |
| Required / optional | `"validation": {"required": bool, ...}` | yes |
| Description (helper text) | `"description"`; `"title"` is the visible label | yes |
| `interaction_id` output | `{{create-slug.interaction_id}}` | yes |
| `interaction_url` output | `{{create-slug.interaction_url}}` | yes |
| `interaction_type` output `"Form"` | display value; config value is `"form"` | yes |
| Waiting status while paused | execution `state: "Waiting"` | yes |
| `timeout: true` on expiry | `{{wait-slug.timeout}}` | yes |
| Response keyed by field name | `{{wait-slug.response.result.<key>}}` | yes |
| Create must be paired with Wait | activation rejects an unpaired Create | yes |
| Respondent needs view permission on origin workflow | not applicable to JSON | not tested |
| Timeout maximum 7 days | `time_unit` + `time_value` | not tested at the boundary |
| One submission per interaction | not applicable to JSON | not tested |
| Not supported in FedRAMP GovCloud | not applicable to JSON | **not tested** |
| `expected_respondents` for multi-respondent | `"expected_respondents": N` | not tested above 1 |
| (not in doc) responder attribution | `{{wait-slug.response.responder.id}}` | yes |
| (not in doc) `options` required to enable Test Action | `"options": [...]` | yes |
| (not in doc) blank optional field is ABSENT, bare ref errors | wrap in `Function.DEFAULT` | yes |
