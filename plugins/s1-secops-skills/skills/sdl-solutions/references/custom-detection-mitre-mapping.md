# Playbook: Custom Detections with MITRE Mapping

Solution for custom detections to carry MITRE mapping. Give a custom detection a MITRE ATT&CK tactic and
technique that shows up on the alert in Unified Alert Management (UAM), in `| datasource alerts`
(`mitreTactics`, `mitreTechniques`) and in every downstream consumer that reads them (dashboards,
RBA multi-tactic scoring, reports). Triggers: "map my custom detection to MITRE", "custom detection
MITRE tactic", "STAR rule MITRE", "my custom alerts have no MITRE", "add ATT&CK to a custom detection".
Orchestration only; drives powerquery, hyperautomation, mgmt-console-api and sdl-api.

## Why this is needed (measured, S-26.3.4)

- **A Custom Detection (STAR) rule cannot carry MITRE.** `POST /web/api/v2.1/cloud-detection/rules`
  rejects a `mitre` field and a `mitreTechniques` field with HTTP 400 `data: ... Unknown field`.
  Only library (platform) rules carry `mitre[]` (`GET /detection-library/platform-rules`).
- **STAR alerts reach UAM with no MITRE.** On the validation tenant every STAR alert (3,602) and
  every Hyperautomation alert (1,088) had `mitreTactics` empty. Writing "MITRE: T1059.001" in the
  rule description does not populate anything.
- **UAM does read MITRE from an ingested alert, from one place only.** An alert posted to the ingest
  host `/v1/alerts` with `attacks[]` on each `finding_info.related_events[]` entry populates the
  indicator's `attacks` and the alert's `mitreTactics` / `mitreTechniques`. The same array on
  `finding_info.attacks` is **ignored** (tested side by side: v1 with `finding_info.attacks` only had
  no MITRE, v2 with the per-indicator copy showed `["Execution","Stealth"]` and
  `["T1059.001 PowerShell","T1027 Obfuscated Files or Information"]`).

So the solution runs the custom detection's query from a Hyperautomation watchdog and has the
watchdog raise the alert itself, with the MITRE mapping attached where UAM reads it.

## What gets deployed

One Hyperautomation flow per mapped detection, rendered from
`assets/mitre_watchdog.workflow.template.json` by `scripts/render_mitre_watchdog.py`:

1. Scheduled trigger every `interval_minutes`.
2. Launch the detection PowerQuery through the LRQ API (`/sdl/v2/api/queries`, SDL connection) over
   the last `lookback` hours, then poll until `stepsCompleted` equals the step total.
3. If the query returns rows: build a summary (row count, first row, top 10 rows), then POST one
   OCSF S1 Security Alert (`class_uid 99602001`) to `{{HEC_URL}}/v1/alerts`, gzip, with the MITRE
   `attacks[]` on the inline indicator.
4. If the query returns no rows: end quietly.

The rule spec is the single source of truth for the detection: name, description, severity, query,
lookback, interval and the MITRE list. Keep specs in Git (they are small JSON files) so the mapping
is reviewable.

## Parameters (collect in one prompt, defaults in brackets)

| Parameter | Meaning |
|---|---|
| Rule spec | A JSON file (format below), or an existing scheduled STAR rule to convert (`--from-rule`) |
| MITRE list | One or more `{tactic, technique, technique_name?}` pairs, tactic as `TA00xx`, technique as `T1234` or `T1234.001` |
| Prefix | Customer or solution code for the flow name [`MITRE`] |
| Account id / site id | Where the flow and the alerts live |
| Ingest host | `https://ingest.<region>.sentinelone.net` [from `S1_HEC_INGEST_URL`] |
| SDL integration id | The built-in "SentinelOne SDL" integration id the http_request actions bind to (discover from an existing watchdog: `ha_get_workflow` lists `integration_id` per action) |
| Retire the original rule? | If converting a STAR rule, disable it after the watchdog is validated so the detection does not alert twice [ask] |

## Rule spec format

```json
{
  "name": "Encoded PowerShell execution",
  "description": "PowerShell launched with an encoded command line on a Windows endpoint.",
  "severity": "High",
  "lookback_minutes": 60,
  "interval_minutes": 60,
  "query": "dataSource.name='SentinelOne' event.type='Process Creation' tgt.process.name in:anycase ('powershell.exe','pwsh.exe') tgt.process.cmdline contains:anycase ('-enc', '-encodedcommand') | group hits=count() by endpoint.name, tgt.process.cmdline | sort -hits | limit 50",
  "mitre": [
    {"tactic": "TA0002", "technique": "T1059.001", "technique_name": "PowerShell"},
    {"tactic": "TA0005", "technique": "T1027", "technique_name": "Obfuscated Files or Information"}
  ]
}
```

- `severity`: Info, Low, Medium, High or Critical (OCSF `severity_id` 1 to 5).
- `query`: any PowerQuery the LRQ API accepts, so the scheduled-rule evaluator limits do not apply
  (`datasource`, `savelookup`, joins, more than 1,000 intermediate rows). **Put the entity first.**
  Column 1 of the first row becomes the alert's resource name and its hostname / user observable,
  column 2 is shown next to it, and the first 10 rows go into the description. End the query with a
  `| limit` so the description stays readable.
- `lookback_minutes` is rounded up to whole hours (the LRQ window is expressed in hours).
- `name` and `description` must not contain double quotes, backslashes or newlines; the renderer
  rejects them because they are substituted inside an escaped JSON string.
- Tactic names come from the renderer's table (as UAM renders them on S-26.3.x, ATT&CK v18). TA0005
  is **"Stealth"**, not "Defense Evasion". Anything that groups or filters on MITRE should match the
  tactic id, never the name.

Ready-made specs live in `assets/mitre_rule_specs/`: `encoded_powershell.json` (EDR),
`windows_bruteforce.json` (Windows Event Logs) and `e2e_probe.json` (the synthetic end-to-end test).

## Render

```bash
python3 sdl-solutions/scripts/render_mitre_watchdog.py \
  --spec sdl-solutions/assets/mitre_rule_specs/encoded_powershell.json \
  --prefix ACME --account-id <accountId> --site-id <siteId> \
  --hec-url https://ingest.us1.sentinelone.net \
  --sdl-integration-id <sdlIntegrationId> \
  --out acme_encoded_powershell.workflow.json
```

Convert an existing scheduled STAR rule instead of writing a spec: save the rule object
(`GET /web/api/v2.1/cloud-detection/rules?ids=<id>&isLegacy=false`, `data[0]`) to a file and run

```bash
python3 sdl-solutions/scripts/render_mitre_watchdog.py --from-rule rule.json \
  --mitre '[{"tactic":"TA0006","technique":"T1110","technique_name":"Brute Force"}]' \
  --prefix ACME --account-id <accountId> --site-id <siteId> \
  --hec-url https://ingest.us1.sentinelone.net --sdl-integration-id <sdlIntegrationId> \
  --out acme_bruteforce.workflow.json
```

`--from-rule` takes the query, lookback, interval, severity, name and description from the rule.
It accepts scheduled (PowerQuery) rules only; a single-event or correlation rule's boolean S1QL has
to be rewritten as a PowerQuery first (add the grouping that names the entity).

The renderer fails (exit 2) on an unknown tactic, a malformed technique id, a bad severity, a
missing field or any token left unrendered, and it checks that the alert body still parses with the
MITRE list in place.

## Preview, then deploy (in this order)

1. **Preview.** Show the user the rendered query, schedule, severity and the MITRE list, and run the
   query once with the `powerquery` skill over the same lookback so they see what would alert.
2. **Import** with `ha_import_workflow` (`accountIds` or `siteIds`).
3. **Publish to a Shared Draft in the same step:**
   `POST /web/api/v2.1/hyper-automate/api/v1/workflows/{id}/publish?accountIds=<acct>` (body `{}`).
   An unpublished import is a private draft owned by the API user and invisible in the console.
4. **Activate:** `POST /web/api/v2.1/hyper-automate/api/public/workflows/{id}/{versionId}/activation?accountIds=<acct>`
   with `{"data":{"timeout":86400}}`. Activation fails with 400 "requires configuration" if the SDL
   integration has no connection in that scope; then prompt the user to create the "SentinelOne SDL"
   connection (Bearer console token) and retry.
5. **Run now and verify** (below).
6. If this replaced a STAR rule, disable the original only after verification.

## Validate

1. Run the flow immediately:
   `POST /web/api/v2.1/hyper-automate/api/public/workflow-execution/manual/{id}/{versionId}?accountIds=<acct>`,
   then poll `GET .../workflow-execution/{execId}` until `state` is `Completed` with
   `error_actions: []`.
2. Confirm the alert carries the mapping:

   ```text
   | datasource alerts | filter detectionProduct = '<PREFIX> Custom Detection (MITRE)' | columns externalId, mitreTactics, mitreTechniques
   ```

   or, per alert, UAM GraphQL `alert(id){ indicators { attacks { tactic { uid name } technique { uid name } } } }`.
3. For a synthetic end-to-end test, ingest a few events for the `e2e_probe.json` source with
   `hec_ingest` (`dataSource.name = ZZ_MITRE_PROBE`, fields `probe_host`, `probe_tag`), render and
   deploy that spec, run it, check the alert, then delete the flow and resolve the test alert.

**Validated end to end, 2026-10-05, S-26.3.4.** `e2e_probe.json` rendered, imported, published,
activated and run: `Completed` in 8.6 s, 14 actions, `error_actions: []`. The UAM alert it raised
had the rendered title and description (row count and the top rows) and
`mitreTactics ["Execution","Stealth"]`, `mitreTechniques ["T1059.001 PowerShell","T1027 Obfuscated Files or Information"]`.

## Gotchas

- **`finding_info.attacks` is ignored.** Only `finding_info.related_events[].attacks[]` reaches UAM.
  The template writes it on the indicator; do not "tidy" it up to the finding.
- **HEC returns 202 even when the stitcher drops an alert.** Verify in UAM, never from the HTTP code.
  One alert per POST (a multi-alert body keeps only one).
- **One alert per run, not per row.** The flow raises a single alert summarising every matching row.
  For an alert per entity, group the query so each run returns one row, or deploy one flow per
  entity class.
- **No built-in suppression.** If the condition stays true the flow alerts every interval. Make the
  lookback equal to the interval for a "new in the last window" detection, or add a lookup-backed
  "already alerted" anti-join to the query.
- **`confidence_id` on an ingested alert maps to UAM `confidenceLevel` as 1 = SUSPICIOUS,
  3 = MALICIOUS, 99 = INFORMATIONAL, 0 = none.** 2 and 4 were silently dropped (202, no alert). The
  template sends none. INFORMATIONAL alerts are hidden from unfiltered UAM listings and from
  `| datasource alerts` unless you filter on `confidenceLevel` explicitly.
- **Template action names are load-bearing.** HA resolves `{{launch-lrq.body.id}}` and
  `{{poll-lrq...}}` from the action names "Launch LRQ" and "Poll LRQ". Renaming an action breaks
  every reference to it.
- **Asset binding.** The alert's resource is named from column 1 but carries a generated `uid`, so it
  will not bind to an Asset Inventory record. If binding matters, project the agent UUID in column 1
  and adapt the template's resource `uid`.
