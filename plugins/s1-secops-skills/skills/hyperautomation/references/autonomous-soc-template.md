# Autonomous SOC workflow template

An autonomous SOC workflow takes an alert from detection to a decided, executed response with no
analyst in the loop.

## Example prompts that should trigger this template

Use this template when a user asks for end-to-end alert handling, auto-response, or a "SOC in a
box" — even when phrased casually. Representative prompts:

- "Build an autonomous SOC workflow that investigates and responds to alerts on its own."
- "When a critical alert fires, run Purple AI, decide the response, and act, no analyst needed."
- "Auto-triage every high/critical alert, add a verdict note, open a ticket, and remediate."
- "Set up automatic containment: on a ransomware alert, isolate the device and notify the SOC."
- "Create a flow that lets an LLM pick isolate vs quarantine vs close-as-false-positive per alert."
- "Wait for the agentic investigation to finish, summarise it, then take the right action."
- "Auto-close false positives and only escalate real threats to a human."
- "When an identity alert comes in, revoke the user's SaaS sessions and lock their machine."
- "Notify the SOC by email with the verdict and recommended actions whenever we auto-respond."
- "Stop copy-pasting the isolate/quarantine logic into every flow, make them reusable."

The last two map to the reusable-snippet best practice below (a notify-SOC snippet, and factoring
each response into its own snippet). Anything of the form "investigate → decide → respond
automatically" is this template.

## Best practice: factor reusable logic into snippets

**Any part of a flow that other flows also need should be a snippet, not inline actions.** Build the
logic once as a snippet (`references/snippets.md`), publish it, and have every workflow call it.
This removes duplicated logic across flows: when the logic changes you edit one snippet instead of
editing every workflow that copied it, and callers on `use_latest_snippet_version: true` pick the
change up automatically. Reusable pieces in a SOC context are almost always: the response actions
(isolate, quarantine, rollback, revoke, close-as-FP), the collaboration steps (open a channel,
create a ticket, escalate), and shared utilities (poll until an investigation completes). Reach for
a snippet whenever you notice the same action graph appearing in more than one workflow.

## Canonical shape (alert-triggered)

1. **Singularity Response Trigger** — fire on the target alert (filter by name / severity).
2. **Trigger Agentic Investigation** — `http_request` to Unified Alerts GraphQL, mutation
   `alertTriggerActions` with action `S1/aiInvestigation/run`
   (`payload.aiInvestigation{tenantId, consoleVersion:"HyperAutomation", userAgent:"SentinelOne-HyperAutomation"}`).
3. **Pause for Investigation Completion** — a **static** snippet call that polls until the
   investigation finishes (poll-until-complete loop below). Shared by every alert workflow.
4. **Get Investigation Summary** — `http_request` GraphQL `aiInvestigations { status verdict result … }`
   once complete.
5. *(optional)* **IOC enrichment** — extract hashes into a variable, branch SHA1 / SHA256 / MD5
   checks, enrich with an LLM or a threat-intel action.
6. **Triage & Summary** — an `llm` action turns the investigation + alert into a verdict/summary.
7. **Summary markdown** — an `llm` action formats a human-readable summary.
8. **Add Note / Set Status** — `http_request` GraphQL `addAlertNote` + `analystVerdictUpdate` /
   `statusUpdate` (wrap note text in `Function.HTML_ENCODE`).
9. *(optional)* **Ticket + collaboration** — create a ticket, open a Slack channel (snippet), invite,
   notify.
10. **Response Decision** — an `llm` action returns ONE response action, expressed as the **name of a
    response snippet**.
11. **Response** — a **dynamic** `snippet_20` (`is_dynamic: true`,
    `dynamic_snippet_name: "{{response-decision.data}}"`) that dispatches to the chosen response
    snippet, passing the shared input contract.
12. **Wrap-up** — `llm` action summary → update alert notes → update the collaboration channel.

## The reusable snippet library

Each response and each shared step is its own snippet, so any workflow can call it:

- **Utility:** Pause for Investigation Completion (poll loop), Create Slack Channel, Create incident.
- **Containment:** Isolate Device / Isolate from Network, Quarantine Alert, Lock User's Machine.
- **Identity:** Revoke SaaS Session.
- **Recovery:** Rollback.
- **Triage:** Close as False Positive.
- **Escalation:** Escalate to Human.

### Shared input contract (this is what enables dynamic dispatch)

Give every response snippet the SAME `snippet_trigger` inputs so ONE dynamic `snippet_20` can route
to any of them with one `inputs` map. A workable contract:

`Singularity-ID`, `Response-Input`, `Device-UUID`, `Group-ID`, `Channel-ID`, `Alert-Input`.

The Response Decision LLM returns the name of one snippet in the library; the dynamic node runs it
with these inputs. Adding a new response is then just: author a new snippet against the same
contract and teach the LLM its name — no change to the parent workflow.

## Poll-until-complete loop (used by the Pause snippet)

A while-loop that polls a status and breaks when done:

- **loop node:** `data { action_type:"loop", loop_type:"while", number_of_iterations:"1",
  object_to_iterate:null, is_parallel:false }`. For a while-loop `number_of_iterations` is ignored;
  it loops until a `break_loop` fires.
- The loop node's `connected_to` carries BOTH `{target:<first inner node>, custom_handle:"inner"}`
  AND `{target:<node after the loop>, custom_handle:null}` (the post-loop continuation). Omit the
  default edge and nothing runs after the loop.
- **Inner chain** (each node `parent_action` = the loop's `export_id`):
  `[delay] → Get Status (http) → condition(status == "COMPLETED") ─true→ break_loop`. The
  condition's false path has no edge, so the loop iterates again.
- Read the full result AFTER the loop (a fresh Get) — a node placed after the loop can read the
  loop's own outputs but not a loop-internal node's output.

## Build order

1. Create + publish + activate each reusable snippet (import each with `snippet_trigger` +
   the shared-contract inputs + `snippet_output`).
2. Build the parent workflow: **static**-call the utility snippets (Pause, Create Channel) and
   **dynamic**-call the response library through one `snippet_20` driven by the Response Decision LLM.
3. Publish/activate the parent and confirm bindings resolve
   (`GET /workflow-actions/snippets-versions/{id}/{versionId}?query={}`).

## Example: SOC notification snippet (branded HTML email)

A reusable "notify the SOC" snippet: `snippet_trigger` (inputs `Verdict`, `Severity`,
`Recommendation`, `Alert-ID`) → `send_email` → `snippet_output`. The email body is a self-contained,
inline-styled HTML table (email clients need inline styles; no `<style>` blocks, no external CSS)
that reads its values from the snippet inputs. `send_email` is a `core_action` (no connection
needed). Keep the output non-empty (a literal such as `"notified"`).

```html
<div style="margin:0;padding:20px 12px;background:#eef0f4;font-family:Segoe UI,Roboto,Arial,sans-serif;">
<table role="presentation" width="640" align="center" cellpadding="0" cellspacing="0" style="margin:0 auto;max-width:640px;background:#ffffff;border-radius:12px;overflow:hidden;">
<tr><td style="background:#2c1a5e;padding:20px 28px;color:#ffffff;font-size:17px;font-weight:700;">SentinelOne <span style="color:#b79cff;">Purple AI</span>
  <span style="float:right;color:#c9bdf0;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;">Automated SOC Response</span></td></tr>
<tr><td style="padding:26px 28px 6px;">
  <span style="display:inline-block;background:#fde8e6;color:#b31d13;font-size:11px;font-weight:700;padding:6px 13px;border-radius:20px;text-transform:uppercase;">Verdict: {{Function.HTML_ENCODE(snippet-input.Verdict)}}</span>
  <h1 style="margin:14px 0 4px;font-size:21px;color:#181430;">Alert triaged</h1></td></tr>
<tr><td style="padding:14px 28px 26px;">
  <table role="presentation" width="100%" style="border-collapse:collapse;font-size:13px;">
    <tr><td style="padding:10px 0;color:#8a8a96;width:150px;border-bottom:1px solid #eeeef3;">Severity</td><td style="padding:10px 0;color:#1c1830;font-weight:600;border-bottom:1px solid #eeeef3;">{{Function.HTML_ENCODE(snippet-input.Severity)}}</td></tr>
    <tr><td style="padding:10px 0;color:#8a8a96;">Alert ID</td><td style="padding:10px 0;color:#4a4a58;font-family:monospace;font-size:11px;">{{snippet-input.Alert-ID}}</td></tr>
  </table>
  <div style="margin-top:14px;background:#f5f2fd;border-left:4px solid #6b3fd4;padding:16px 18px;">
    <div style="font-size:11px;font-weight:700;color:#4a1fb8;text-transform:uppercase;letter-spacing:0.7px;margin-bottom:8px;">Recommended actions</div>
    <div style="font-size:13px;color:#2a2636;line-height:1.65;">{{snippet-input.Recommendation}}</div>
  </div></td></tr>
</table></div>
```

Notes: wrap free-text inputs shown as text (verdict, severity) in `Function.HTML_ENCODE`; leave a
pre-formatted recommendation raw so its line breaks render. Per the global style, avoid em-dashes in
copy. This snippet is then called from any workflow with a `snippet_20` node (static or dynamic).
