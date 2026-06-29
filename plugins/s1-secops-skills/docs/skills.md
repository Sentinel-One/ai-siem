# Skills Reference

Each skill is a folder containing a `SKILL.md` that Claude reads when a relevant request triggers it. The SKILL.md encodes confirmed API schemas, field requirements, and procedural knowledge. All seven skills are bundled in the `skills` plugin.

---

## mgmt-console-api

**Triggers on:** S1 console operations: agents, threats, alerts, sites, groups, policies, IOCs, detection rules, exclusions, RemoteOps, Deep Visibility, Hyperautomation, UAM, Purple AI.

**What it provides:**

- Generic REST wrapper (`s1_api_get/post/put/patch/delete`) over 781 Management Console operations across 113 API tags
- Unified Alert Management (UAM): GraphQL-based multi-source alert inbox with filter, triage, note, status, and verdict mutations
- Purple AI: natural-language query interface over SDL telemetry (NLQ → PowerQuery → results)
- Hyperautomation: workflow list/get/import/export/delete
- UAM Alert Interface: OCSF-format alert and indicator ingest via HEC
- Behavioural baselining + anomaly detection pipeline (`baseline_anomaly.py`): source-agnostic, auto-discovers principal/action fields, day-of-week stratification, three anomaly classes (spike, drop, silent pair, new behaviour)

**Key scripts:**

| Script | Purpose |
|---|---|
| `scripts/s1_client.py` | REST client: auth, pooled HTTP, retries, cursor pagination, parallel `get_many()` |
| `scripts/smoke_test_queries.py` | Non-destructive sweep of all GETs; outputs `tenant_capabilities.md` |
| `scripts/search_endpoints.py` | Ranked keyword search over endpoint index (`--only-works` filter) |
| `scripts/unified_alerts.py` | UAM GraphQL wrapper (queries, mutations, triage helpers) |
| `scripts/purple_ai.py` | Purple AI GraphQL wrapper |
| `scripts/baseline_anomaly.py` | Behavioural baselining + anomaly detection |

**Test coverage:** 15 lifecycle test scripts covering IOCs, UAM alerts, exclusions, detection rules (scheduled + events / STAR), Hyperautomation import, XDR graph queries, and more. See [testing.md](./testing.md).

**API field requirements validated through live testing (examples):**
- `queryType=scheduled` detection rules require `isLegacy=false` on GET
- Unified Exclusions POST requires 7 fields including `modeType`, `type`, `engines`, `scopeLevel`, `scopeLevelId`, `value`, and `recommendation`; returns `data` as a list
- Hyperautomation: list response uses nested `workflow.id`, `nextCursor` returns string `"null"` (truthy in Python)
- UAM `addAlertNote` returns `mgmt_note_id` required for `deleteAlertNote`

Full field reference: `mgmt-console-api/SKILL.md`

---

## powerquery

**Triggers on:** PowerQuery authoring, debugging, optimization, STAR/Custom Detection rule bodies, SDL dashboard panels, behavioural baseline building, threat hunting queries.

**What it provides:**

- PowerQuery syntax reference and best practices for SDL/Deep Visibility queries
- STAR rule body authoring (streaming detection, `queryType=events`)
- PowerQuery Alert rule bodies (scheduled detection, `queryType=scheduled`)
- SDL dashboard panel query authoring
- Behavioural baseline building blocks using `| savelookup` + `| lookup` pattern
- Schema-safe patterns: `number()` cast for type-locked columns, `array_agg_distinct` for enumeration

**Key examples:** `powerquery/examples/behavioral-baselines.md`: full PQ building blocks for the baseline + anomaly detection rule body pattern.

---

## sdl-api

**Triggers on:** SDL API operations: log ingest, configuration file management (parsers, dashboards, lookups, datatables), SDL query via API.

**What it provides:**

- SDL log ingest via HEC (`hec_ingest`), uses the console JWT (`S1_CONSOLE_API_TOKEN`) posted to `S1_HEC_INGEST_URL`
- SDL config file CRUD (`sdl_list_files`, `sdl_get_file`, `sdl_put_file`, `sdl_delete_file`)
- SDL V1 query (full-event JSON, used for schema discovery)

**Auth note:** `SDL_CONFIG_WRITE_KEY` does not grant log read access. Force-clear scoped keys to fall through to the console JWT for V1 queries:

```python
c.keys["log_read_key"] = ""
c.keys["config_read_key"] = ""
```

---

## sdl-dashboard

**Triggers on:** SDL dashboard creation, editing, deployment, debugging.

**What it provides:**

- Complete SDL dashboard JSON schema: tabs, panels, parameters, time range controls
- Panel type reference: timeseries, count, table, honeycomb, pie, bar, single value
- PowerQuery integration: panel query validation against tenant sources before deployment
- Dashboard deployment via `sdl_put_file` to `/dashboards/<name>`

**Workflow:** Author dashboard JSON → validate queries against live tenant sources → deploy via SDL API → confirm via `sdl_list_files`.

---

## sdl-log-parser

**Triggers on:** SDL log parser authoring, editing, validation, testing.

**What it provides:**

- SDL parser JSON schema (`formats`, `patterns`, `lineGroupers`, `rewrites`, `discardAttributes`)
- OCSF field mapping guidance by log format (CEF, syslog, JSON key=value, multi-line, CSV)
- Timestamp normalization patterns
- End-to-end validation: `sdl_put_file` → `hec_ingest` (ingest test event) → `powerquery_run` (confirm fields appear)

**Workflow:** Parse raw log sample → generate parser JSON → deploy to SDL → ingest test event → confirm field extraction in query results.

---

## hyperautomation

**Triggers on:** Hyperautomation workflow creation, design, generation, import, export.

**What it provides:**

- Hyperautomation workflow JSON schema: triggers, actions, connections, conditions, loops
- Trigger types: manual, scheduled, HTTP/webhook, email, S1 alert, Singularity response
- Action types: HTTP request, S1 isolate/remediate, send email, Slack/Teams, condition branch, loop, wait
- Workflow import via `ha_import_workflow` (requires `Hyper Automate.write` permission)

**Token note:** Workflows imported with a service user token are invisible to human users in the console UI. Use a personal console user token if the workflow needs to be visible and editable in the UI.

---

## sdl-solutions

**Triggers on:** deploying a packaged, repeatable SDL solution into a specific customer environment from one short prompt, rather than authoring a single query, parser, or workflow. Onboarding: "onboard cisco_meraki logs", "bring our FortiGate source into AI SIEM and build detections", "set up detections and a dashboard for <source>". Asset enrichment: "deploy the asset enrichment solution", "enrich logs with device/user info for <customer>", "set up SDL asset enrichment on <site>". UEBA: "run a behavioural baseline on <source>", "deploy UEBA anomaly detection for <source>", "flag users whose activity is off their 30-day normal". Ingest health: "deploy ingest health monitoring", "monitor ingest per device/firewall/endpoint", "alert me when a source or device stops sending logs", "detect ingest spikes/drops/lag", "find parser drift". Detection exclusions: "add a detection exclusion for <source> logs", "exclude these assets/domains from a detection", "stop my detection alerting on our scanner subnets/corporate domains, here's the list", "allowlist these hosts".

**What it provides:**

- An orchestration layer that deploys whole solutions, rather than authoring a single query, parser, or workflow. It collects environment parameters, renders templates, previews, deploys through the primitive skills, and validates.
- **Solution catalog:**
  - **Data source onboarding**: take a raw log stream already reaching the tenant and operationalise it end to end: locate the source by its `parser` attribute, normalise it to OCSF, enrich with device/user asset context, then build a dashboard, MITRE-mapped STAR detections (with entity/asset mapping and severity-tuned cool-offs), and a SOC threat-response Hyperautomation playbook (alert to VirusTotal-gated containment).
  - **Asset enrichment of raw logs**: enrich ingested events with device and user context (OS, IP, agent UUID, AD groups, SID, criticality, risk factors) from the Asset Inventory via `savelookup` tables, in parser (ingest-time), query-time, and automatic-lookup modes, plus a Hyperautomation refresh flow.
  - **UEBA behavioural anomaly detection**: baseline ANY signal (security or not) per (action, principal), score the live 24h window with a z-score, and surface SPIKE/DROP/SILENT/NEW deviations; deploy as a persisted baseline lookup, a scheduled PowerQuery detection rule, a nightly refresh, and a dashboard.
  - **Ingest health monitoring (per device)**: per-firewall/endpoint/server anomaly detection on a 7-day hour-of-day seasonal baseline rebuilt daily: volume spike/drop (z-score), ingest lag (p95 over SLA), ingest loss (a device went silent), and parser drift; deploys per-device baseline lookups, scheduled PowerQuery detections, an ingest-loss watchdog flow, a dashboard, and an email-notification flow for every failure.
  - **Scheduled detection exclusions**: suppress known-good noise in a scheduled detection over a third-party source by keying it against a CSV exclusion list (assets by IP/CIDR/host, or custom domains/users/values) loaded as an SDL lookup and applied with a lookup anti-join (`| lookup ... | filter excl = null`); deploys the lookup table, a scheduled STAR rule, an exclusion-effectiveness dashboard, and (for `=:cidr`/`=:wildcard`, which the STAR validator rejects) a Hyperautomation detection flow that posts a UAM alert, plus an optional source-of-truth refresh.
- Parameterized templates under `assets/` (savelookup queries, enrichment parser, dashboard skeleton, STAR detection envelope, threat-response and refresh workflows) driven by tokens such as `{{PREFIX}}`, `{{DATASOURCE_NAME}}`, `{{PARSER_NAME}}`, `{{SITE_ID}}`, `{{ACCOUNT_ID}}`.

**Depends on:** `sdl-log-parser` (parser/OCSF), `powerquery` (datasource + savelookup), `sdl-dashboard` (dashboard), `mgmt-console-api` (STAR rules, site/scope), `sdl-api` (deploy config, ingest), `hyperautomation` (response/refresh flows).

**Playbooks:** `references/data-source-onboarding.md`, `references/asset-enrichment.md`, `references/ueba-anomaly-detection.md`, `references/ingest-health-monitoring.md`, `references/scheduled-detection-exclusions.md`. Add new solutions as `references/<solution>.md` plus templates, and name them in the skill description so they trigger.

Full reference: `sdl-solutions/SKILL.md`

---

## CLAUDE.md: SOC Analyst persona

`CLAUDE.md` is not a skill in the plugin sense; it is the operating persona loaded at session start.

It defines:

- **Mandatory session init:** enumerate SDL sources, triage open alerts in parallel, discover schemas per-source before writing any query
- **Evidence rules:** no fabrication, cite every fact to its tool call, mark every assumption explicitly
- **Anomaly checklist:** frequency, timing, geolocation, baseline deviation, new entity, privilege, chain
- **Classification gate:** no CRITICAL or TRUE POSITIVE verdict without independent threat intelligence confirmation
- **Confidence language:** "confirmed" / "consistent with" / "suggests" / "possible", calibrated to evidence weight
- **Investigation workflow:** triage → enrichment → infrastructure pivot → cross-source correlation → MITRE mapping → composite risk score → report

`s1-secops-mcp` exposes it as an MCP resource (`sentinelone://soc-context`) and prompt (`soc_analyst`). Edit `claude-skills/CLAUDE.md` and restart the MCP server to change Claude's operating behaviour.
