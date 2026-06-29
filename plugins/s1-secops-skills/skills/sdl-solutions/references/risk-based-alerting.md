# Playbook: Risk-Based Alerting (RBA)

Implement the Risk-Based Alerting (RBA) paradigm in SentinelOne SDL. Instead of alerting on every noisy-but-interesting observation, each observation is published as a low-noise **risk event** into a dedicated risk index. Risk accumulates per **risk object** (user or host), amplified by **risk factors** (asset criticality, privileged, watchlist). A single high-fidelity alert fires only when a risk object crosses a cumulative-score or distinct-MITRE-tactic threshold. The analyst gets a contextualised story (a timeline of contributing events across tactics), not a flood of disconnected alerts.

Every mechanic in this playbook is tenant-validated end to end (2026-06-24/25): risk index, contributors, factor multipliers, collector flow, incident rules, dashboard, and a real fired alert.

## Concept mapping: RBA concepts to SentinelOne

| RBA concept | SentinelOne |
|---|---|
| Risk index | Custom SDL data source `dataSource.name='risk'`, populated via SDL HTTP ingest (`POST /services/collector/event?isParsed=true`) |
| Risk Analysis adaptive response (write a risk event, do not alert) | Risk collector: a scheduled Hyperautomation flow that runs contributor PowerQueries and publishes the resulting risk events |
| Risk object (user / system) | `risk_object` + `risk_object_type` ('user' or 'host'); source fields `src.process.user` / `actor.user.name` (user), `endpoint.name` / `agent.uuid` (host) |
| Threat object (cmdline, hash, account) | `threat_object` + `threat_object_type` on the risk event |
| MITRE annotation | `mitre_tactic` + `mitre_technique` on the risk event |
| Base risk score | `base_score` per contributor |
| Risk factors (multipliers) | A factor lookup keyed by object, sourced from the Asset Inventory (criticality / privileged / riskFactors); `risk_score = base_score * multiplier` |
| Risk incident rule | A STAR scheduled PowerQuery rule over `dataSource.name='risk'`: sum score and count distinct tactics per `risk_object`, fire over threshold |
| Notable with timeline | The incident alert (entity-bound to the risk object) plus the dashboard's per-object timeline of contributing risk events |
| Risk Factor Editor | The `{{PREFIX}}RiskFactors.csv` factor table the analyst edits |

## Architecture / data flow

1. **Risk model config (contributors).** A set of contributor definitions (`assets/rba_contributors.json`): each is `{ name, powerquery, base_score, mitre_tactic, mitre_technique, risk_object field, risk_object_type, threat_object field }`. Each contributor PQ ends in a `| columns` projection emitting the risk-event schema.
2. **Risk collector (scheduled HA flow).** Runs each contributor via the synchronous SDL PowerQuery endpoint, maps result rows to named objects (`MAP_TABLE`), applies the risk-factor multiplier (a `| lookup` against the factor table inside the contributor PQ), shapes them to NDJSON risk events (JQ `tojson`), and publishes them into `dataSource.name='risk'`. Runs hourly.
3. **Risk factors.** A CSV factor table (`{{PREFIX}}RiskFactors.csv`) keyed by object value, holding `risk_multiplier` + `reason`. Built/refreshed from the Asset Inventory (`| datasource assets from 'surface/endpoint'` / `'surface/identity'`); analysts can hand-edit it (the "Risk Factor Editor").
4. **Risk incident rules (STAR scheduled, over `risk`).** Four rules: per user and per host, each with a 24h cumulative-score rule and a 7d distinct-MITRE-tactic rule (catches fast and "low and slow"). Each emits one row per risk object with `entityMappings` binding the object, and carries score / tactic / technique / contributor counts + first/last seen + top message.
5. **Dashboard.** Risk leaderboard, risk-events count, score over time by object type, MITRE tactic and contributor breakdowns, top threat objects, and the contributing-events timeline.
6. **Response (optional).** A Hyperautomation flow off the incident alert (reuse the onboarding `threat_response_workflow.template.json` pattern, VirusTotal-gated containment).

## Step 0: intake (ask only what the prompt leaves out)

1. **Risk objects** (default both): user, host, or both. Both deploys two parallel incident-rule tracks.
2. **Contributors** (default: ship the starter set in `rba_contributors.json`). Each is a noisy-but-interesting behaviour with a base score and MITRE tag. The analyst can add/remove.
3. **Risk factors** (default: reuse asset enrichment): pull criticality / privileged / watchlist from the Asset Inventory, plus an optional static-override CSV.
4. **Thresholds** (defaults): user 24h cumulative score >= 50, host >= 40; user 7d distinct tactics >= 4, host >= 3. Base scores 10 to 25 per contributor; factor multipliers 1 to 3.
5. **Scope** (default account): `accountIds` or a resolved `siteIds`.
6. **Collector cadence** (default hourly): `runIntervalMinutes` 60 and the contributor PQ `startTime` matched to it (last 1h).

## Step 1: risk index

HEC (HTTP Event Collector) is SentinelOne's HTTP event-ingest endpoint; the risk index is a custom SDL data source written through it.

The risk index is created implicitly on first publish: ingest one sample risk event to materialise it, then confirm it queries back:

```
POST {{HEC_INGEST_URL}}/services/collector/event?isParsed=true
Authorization: Bearer <console JWT>
S1-Scope: {{ACCOUNT_ID}}

{"dataSource.name":"risk","dataSource.vendor":"S1-RBA","dataSource.category":"security","risk_object":"<obj>","risk_object_type":"user","base_score":10,"risk_score":10,"mitre_tactic":"Execution","mitre_technique":"T1059.001","threat_object":"<cmdline>","threat_object_type":"command_line","contributor":"<name>","risk_message":"<desc>"}
```

`isParsed=true` indexes the JSON keys directly (no parser). The dotted `dataSource.name` key makes it land as the `risk` source. Confirm:

```
dataSource.name='risk' risk_object=* | group events=count(), score=sum(number(risk_score)), tactics=estimate_distinct(mitre_tactic) by risk_object, risk_object_type | sort -score | limit 25
```

`number(risk_score)` is mandatory (SDL columns can be string-typed; see the numeric-cast rule).

## Step 2: factor table

Write `{{PREFIX}}RiskFactors.csv` to `/datatables/`. Header `factor_key,factor_type,risk_multiplier,reason`. Build it from the Asset Inventory (criticality / privileged / riskFactors) plus optional hand-edited overrides. The contributor PQ joins it:

```
| lookup mult=risk_multiplier from {{PREFIX}}RiskFactors.csv by factor_key =:anycase risk_object
| let risk_score = base_score * (mult ? number(mult) : 1)
```

`mult ? number(mult) : 1` is the bare-field coalesce (no `coalesce()` in PQ); unmatched objects keep multiplier 1. `=:anycase` matches case-insensitively. Validated: a privileged user (x2) amplified base 15 to risk_score 30.

### Risk factors from AD objects (ISPM)

This is the SentinelOne equivalent of Splunk RBA "importing customer assets via AD objects." If the customer has **ISPM (Identity Security Posture Management / Ranger AD)**, Active Directory objects sync into the Asset Inventory **identity surface**, so the factor table is built directly from AD, no manual CSV. Confirmed live (2026-06-25): identity assets carry `activeCoverage: ["ISPM"]`, `assetEnvironment: "Active Directory"`, and per-object AD attributes `privileged` (bool), `adminCount` (number), `serviceAccount` (bool), `memberOf` (group DNs), `distinguishedName` (OU), `objectSid`, `principalName` / `samAccountName`, and `riskFactors` (e.g. `["Unresolved Alerts"]`). Real examples seen: `IMPERIUM\adm.webb` (`privileged=true`, `adminCount=1`), `MOHIT\admin.one` (`riskFactors=["Unresolved Alerts"]`).

Build the factor table from AD with a `savelookup`:

```
| datasource assets from 'surface/identity'
| filter resourceType='AD User' principalName=*
| let mult = privileged=true ? 2.0 : (number(adminCount) > 0 ? 1.5 : (serviceAccount=true ? 0.5 : 1.0))
| let reason = privileged=true ? 'Privileged (ISPM)' : (number(adminCount) > 0 ? 'adminCount>0 (ISPM)' : (serviceAccount=true ? 'Service account' : 'Standard AD user'))
| columns factor_key = principalName, factor_type = 'user', risk_multiplier = mult, reason
| limit 100000
| savelookup '{{PREFIX}}RiskFactors'
```

`principalName` (e.g. `IMPERIUM\adm.webb`) is the join key against the `risk_object` a user contributor emits. Layer extra weight from `riskFactors` (an account flagged `"Unresolved Alerts"`), Tier-0 OU membership (`distinguishedName` contains the privileged OU), or `memberOf` (Domain Admins) as the environment warrants. Refresh nightly (the collector or a refresh flow) so multipliers track AD changes. `privileged`/`serviceAccount` are booleans, compare with `=true` (not `'true'`). For hosts, the same pattern on `'surface/endpoint'` gives criticality/tags.

**No ISPM?** Fall back to the endpoint surface (`'surface/endpoint'`) for host context plus a hand-maintained static CSV (`assets/rba_risk_factors.csv.template`) for the rest.

## Step 3: contributors

Render the contributor PowerQueries from `rba_contributors.json`. Each ends in:

```
| columns risk_object, risk_object_type, risk_score, base_score, mitre_tactic, mitre_technique, contributor, threat_object, threat_object_type, endpoint, risk_message | limit 1000
```

The collector unions/sequences these per run. Use `contains:anycase ('-enc', ...)` style predicates in collector queries rather than regex with `\s` escapes, to avoid multi-level escaping inside the workflow JSON.

## Step 4: collector (deploy as Shared Draft, then prompt, then activate)

> Import is not complete until published: treat `ha_import_workflow` and publish as ONE atomic step (publish in the SAME step as the import, never a follow-up). The collector must be a Shared Draft before you prompt the user to bind and activate.

Render `assets/rba_collector.workflow.template.json` (scheduled trigger, sync PowerQuery, MAP_TABLE, JQ-to-NDJSON, publish). Deploy in this order, this is mandatory because the SDL connection cannot be bound via API:

1. **Import** via `POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import?accountIds={{ACCOUNT_ID}}` with body `{"data": <workflow>}`. New workflows land as a Private Draft.
2. **Publish to Shared Draft** so the requester can see it: `POST /web/api/v2.1/hyper-automate/api/v1/workflows/{id}/publish?accountIds={{ACCOUNT_ID}}` (bodyless, 204).
3. **Prompt the user** to open the flow and bind the **"SentinelOne SDL" (Bearer)** connection on both HTTP actions (Run Contributors + Publish Risk Events). This is a console step; the API cannot create or bind connections.
4. **Activate** after the user confirms the connection is bound: `POST /web/api/v2.1/hyper-automate/api/v1/workflows/{id}/{version_id}/activation?accountIds={{ACCOUNT_ID}}` (204). If a single "SentinelOne SDL" connection exists the platform may auto-resolve it, but do NOT rely on that, always publish + prompt first.
5. **Run-now to test** (works on a scheduled-trigger workflow): `POST /web/api/v2.1/hyper-automate/api/public/workflow-execution/manual/{id}/{version_id}?accountIds={{ACCOUNT_ID}}`, then poll `GET /web/api/v2.1/hyper-automate/api/v1/workflow-execution/{execution_id}?accountIds={{ACCOUNT_ID}}` until `state=Completed`; confirm `executed_actions` equals the action count and there are no `error_actions`. Validated: a 6-action collector ran in ~2.9s, 6/6 actions, clean.

Collector workflow shape (6 actions): scheduled_trigger to Run Contributors (`POST {{Connection.url}}/sdl/api/powerQuery`, sync, returns `body.columns` + `body.values`) to Prep (variable: `cols` = `JQ(.columns, ".[].name")`, `jqFilter`) to Map Rows (variable: `MAP_TABLE(cols, values)`) to Build NDJSON (variable: `JQ(mapped, jqFilter, true)`) to Publish Risk Events (`POST {{HEC_INGEST_URL}}/services/collector/event?isParsed=true`, `use_authentication_data:true`, `S1-Scope` header). The collector builds JSON server-side, so object names with backslashes (`DOMAIN\user`) are clean single-backslash values (no manual-escaping artifact).

## Step 5: incident rules

Deploy the four STAR scheduled rules (`assets/rba_incident_cumulative_score.template.json` and `assets/rba_incident_multitactic.template.json`, rendered per object type) via `POST /web/api/v2.1/cloud-detection/rules`, then enable with `PUT /web/api/v2.1/cloud-detection/rules/enable` body `{"filter": {"ids": [...]}}`. They report `Activating` and go Active within ~1 hour, then evaluate on cadence. All four: `queryType: scheduled`, `queryLang: 2.0`, `treatAsThreat: UNDEFINED`, `networkQuarantine: false`, `entityMappings: [{"columnName": "risk_object"}]`.

Cumulative-score body (per object type):

```
dataSource.name='risk' risk_object_type='{{RISK_OBJECT_TYPE}}' risk_object=*
| group risk_score_total=sum(number(risk_score)), tactics=estimate_distinct(mitre_tactic), techniques=estimate_distinct(mitre_technique), contributors=estimate_distinct(contributor), events=count(), first_seen=oldest(timestamp), last_seen=newest(timestamp), top_message=max_by(risk_message, number(risk_score)) by risk_object
| filter risk_score_total >= {{THRESHOLD}}
| columns risk_object, risk_score_total, tactics, techniques, contributors, events, first_seen, last_seen, top_message
| sort -risk_score_total | limit 100
```

Multi-tactic body swaps the filter to `| filter tactics >= {{TACTIC_THRESHOLD}}` and sorts `-tactics`, with `runIntervalMinutes:1440`, `lookbackWindowMinutes:10080` (7d). Use `max_by`/`oldest`/`newest` (not `first`/`last`), and `number()` on `risk_score`.

## Step 6: dashboard

Render `assets/rba_dashboard.template.json` and `sdl_put_file` to `/dashboards/{{PREFIX}}-RBA`. Panels: risk-events / risk-objects / contributors number tiles, risk leaderboard (cumulative score per object, `showBarsColumn`), risk by MITRE tactic (donut), risk by contributor (donut), risk score over time by object type (stacked_bar, `transpose risk_object_type on timestamp`, safe single-token values), top threat objects (table), and the contributing-events timeline (table). Format timestamps with `simpledateformat(timestamp,'yyyy-MM-dd HH:mm:ss','UTC')` and put `sort` before `columns`.

## Scoring example (worked)

A privileged AD user, `IMPERIUM\adm.webb` (ISPM: `privileged=true`, `adminCount=1`), so the factor table gives a x2.0 multiplier. Over a 24h window the collector publishes these risk events:

| Time (UTC) | Contributor | MITRE tactic / technique | base_score | x factor | risk_score |
|---|---|---|---|---|---|
| 09:02 | suspicious_powershell_flags | Execution / T1059.001 | 15 | 2.0 | 30 |
| 09:14 | ad_recon_burst | Discovery / T1087 | 15 | 2.0 | 30 |
| 09:31 | lolbin_download | Command and Control / T1105 | 20 | 2.0 | 40 |
| 10:05 | eventlog_clear | Defense Evasion / T1070.001 | 25 | 2.0 | 50 |

Cumulative 24h `risk_score_total` = **150** across **4 distinct MITRE tactics**.

- The **user 24h cumulative-score** rule (threshold >= 50) fires: 150 >= 50. One HIGH alert, entity-bound to `IMPERIUM\adm.webb`, carrying the four contributing events as its timeline.
- The **user 7d multi-tactic** rule (threshold >= 4 tactics) also fires if the same four spread over days rather than one burst.

The amplification is the point. The same four observations on a standard, non-privileged user (`IMPERIUM\adm.kowalski`, x1.0) total **75**, over threshold but ranked far below the privileged user. On a service account factored down to x0.5 they total **37.5**, *below* the 50 threshold, so it stays quiet, which is the intended noise suppression. Identical behaviour, different outcome, driven entirely by the AD-derived risk factor.

## Validation

1. ingest sample risk events; confirm they query back and aggregate per object.
2. Run one contributor over live EDR; confirm it emits well-formed risk-event rows.
3. Join the factor table; confirm `risk_score = base_score * multiplier` amplifies.
4. Run-now the collector; confirm `Completed`, all actions, clean, and fresh risk events appear in the index.
5. Confirm an incident rule produces one row per over-threshold object (run the body via LRQ); enable and confirm a UAM alert fires.
6. Open the dashboard; confirm panels render (send screenshots, render is a separate path from query validation).

## Gotchas

- **Collector connection is a console step.** Deploy as Shared Draft and prompt the user to bind the "SentinelOne SDL" (Bearer) connection before activating. The API cannot bind connections; do not auto-activate.
- **Ingest manual-authoring backslash trap.** When hand-crafting ingest JSON, `DOMAIN\user` needs careful escaping and is easy to double. The collector's server-side JQ avoids this; prefer the collector over manual ingest for real data.
- **Numeric cast.** Always `number(risk_score)` before `sum`/arithmetic; SDL columns can be string-typed.
- **Cadence vs lookback.** Match the collector `startTime` and the cumulative-rule `lookbackWindowMinutes` to avoid double-publishing / overlap. Hourly collector with a 1h contributor window; 24h cumulative rule run hourly with dedup on (`disableStreaksLogic:false`) + a cool-off.
- **SYSTEM and service accounts dominate volume.** `NT AUTHORITY\SYSTEM` and update tooling generate the most observations. Factor them down (multiplier < 1) or exclude them from contributors, or they top the leaderboard with benign noise. This is the standard RBA tuning lesson ("cultivate the ecology").
- **Activation lag.** Enabled incident rules become Active within ~1 hour, then evaluate on cadence; the first alert is not instant.
- **Rule type.** Incident rules are `scheduled` PowerQuery rules; no inline mitigation (drive response from an HA flow off the alert).

## Deployed artifacts

| Artifact | Template | Deployed to | Purpose |
|---|---|---|---|
| Risk index | (implicit) | `dataSource.name='risk'` | Append-only store of risk events |
| Contributors config | `assets/rba_contributors.json` | rendered into the collector | The risk model: noisy observations to score |
| Risk-factor table | `assets/rba_risk_factors.csv.template` | `/datatables/{{PREFIX}}RiskFactors.csv` | Per-object score multipliers (Risk Factor Editor) |
| Risk collector | `assets/rba_collector.workflow.template.json` | Hyperautomation (scheduled, account/site) | Runs contributors and publishes risk events |
| Incident rule, cumulative score (user + host) | `assets/rba_incident_cumulative_score.template.json` | STAR scheduled rule via `/cloud-detection/rules` | Fire when 24h cumulative score per object >= threshold |
| Incident rule, multi-tactic (user + host) | `assets/rba_incident_multitactic.template.json` | STAR scheduled rule via `/cloud-detection/rules` | Fire when 7d distinct MITRE tactics per object >= threshold |
| RBA dashboard | `assets/rba_dashboard.template.json` | `sdl_put_file /dashboards/{{PREFIX}}-RBA` | Leaderboard, score over time, MITRE / contributor / threat-object breakdowns, timeline |
| Response flow (optional) | reuse `assets/threat_response_workflow.template.json` | Hyperautomation (alert-triggered) | VT-gated containment off an RBA incident alert |

Common tokens: `{{PREFIX}}`, `{{ACCOUNT_ID}}`, `{{SCOPE_KEY}}`, `{{SCOPE_ID}}`, `{{HEC_INGEST_URL}}`, `{{FACTOR_TABLE}}`, `{{RISK_OBJECT_TYPE}}`, `{{THRESHOLD}}`, `{{TACTIC_THRESHOLD}}`, `{{RUN_INTERVAL_MINUTES}}`, `{{LOOKBACK_MINUTES}}`, `{{SEVERITY}}`.
