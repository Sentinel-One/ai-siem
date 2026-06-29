# Playbook: detection exclusions (single-event or scheduled)

This solution suppresses known-good noise in a SentinelOne Custom Detection (STAR) rule. It builds
the exclusion as either a **STAR single-event rule** (inline hardcoded negative list in a boolean
S1QL body) or a **scheduled PowerQuery detection** (CSV lookup table + anti-join + effectiveness
dashboard). **Always ask the user which rule type first** (see Step 0). The scheduled path is
described in full below; the single-event path is in "Single-event rule path".

Scheduled path overview: suppress known-good noise in a scheduled PowerQuery detection rule by keying the rule
against a CSV exclusion list. The analyst supplies a CSV of assets (hosts, IPs, CIDRs) or a
custom list of values (domains, users, URLs, rule IDs), the solution loads it as an SDL lookup
table, and the detection rule omits any row that matches the list. The exclusion is applied at
the detection itself, not after the alert fires, so excluded activity never creates an alert.

This is the third-party-log counterpart to Unified Exclusions Management. UEM excludes EDR and
Identity engine alerts in the console. It does not cover detections you write yourself over
third-party SDL sources (firewall, DNS, proxy, cloud audit, SaaS). For those, the exclusion lives
in the detection query, and this solution standardises that pattern: one CSV, one lookup, one
anti-join filter, plus a dashboard that shows exactly what the list is suppressing.

## Invocation prompt (natural language)

The analyst just says, in plain language, what they want to stop alerting on. Any of these is
enough to start:

> "Stop my Akamai DNS failed-lookup detection from alerting on our vulnerability-scanner subnets and
> our own corporate domains, here's the list."

> "Exclude these allowlisted hosts/domains from the `<source>` detection." *(attach or paste the CSV)*

> "Build a `<source>` detection that ignores anything from assets tagged `scanner`."

Whatever the prompt leaves out, confirm it with the questions below before deploying, do not assume.

## Step 0: choose the rule type (ask the user first)

This solution can build the exclusion as either of two STAR Custom Detection rule types. **Always ask which one before configuring anything else**, because the parameters and the exclusion mechanic differ by type:

| | STAR single-event (`queryType: "events"`) | Scheduled detection (`queryType: "scheduled"`) |
|---|---|---|
| Detection body | one boolean S1QL filter, NO pipes, in `data.s1ql` | PowerQuery (pipes) in `data.scheduledParams.query` |
| Exclusion mechanic | **inline hardcoded** negative list in the filter: `... AND NOT (<field> in:anycase ('a','b',...))` | **CSV lookup anti-join**: `\| lookup excl = reason from <table> by <key> <op> <field> \| filter excl = null` |
| Exclusion list lives | hardcoded in the rule body | an SDL datatable CSV (edit without touching the rule) |
| Fires | per matching event, streaming at ingest | on a schedule over a lookback window |
| Aggregation / thresholds | no (single event) | yes (`group`, counts, `estimate_distinct`) |
| Effectiveness dashboard | not applicable (no anti-join inverse to count) | yes (excluded vs kept, by list / reason / value) |
| Mitigation | inline Active Response on the rule (`treatAsThreat`, `networkQuarantine`) or an HA flow off the alert | no inline Active Response (`treatAsThreat` must be `UNDEFINED`); mitigate via an HA flow off the alert |
| Best when | the base detection is a deterministic single-event signature and the exclusion list is small and stable | the detection aggregates, or the list is large / dynamic / shared and needs an audit trail |

Prompt to ask:

> "Should this exclusion be a **STAR single-event rule** (inline hardcoded exclusion list, fires per event, supports mitigation) or a **scheduled detection** (CSV exclusion list + anti-join + effectiveness dashboard)?"

If single-event, follow "Single-event rule path" directly below and stop there. If scheduled, skip that section and follow "How the exclusion works" plus Steps 1 to 6 (the lookup / anti-join playbook).

## Single-event rule path

A single-event rule body is one boolean S1QL expression with NO pipes, so there is no `lookup` and no CSV table; the exclusion is a hardcoded negative list inside the filter. This is the right shape when the base detection is itself a single-event signature (a specific process + cmdline, a registry write, one log line) and the allowlist is small and stable.

Body shape (goes in `data.s1ql`):

```
<base single-event filter> AND NOT (<EXCL_FIELD> in:anycase ('<val1>','<val2>',...))
```

Worked example (encoded PowerShell, excluding engineering accounts), tenant-validated 2026-06-24:

```
dataSource.name = 'SentinelOne' AND event.type = 'Process Creation'
AND src.process.name in ('powershell.exe','pwsh.exe')
AND src.process.cmdline matches '(?i)\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b'
AND NOT (src.process.user in:anycase ('corp\jdoe','corp\asmith'))
```

Deploy envelope (render `assets/exclusion_detection_single_event.template.json`):

```json
{
  "data": {
    "name": "{{DETECTION_NAME}}",
    "description": "{{DETECTION_DESCRIPTION}} (MITRE {{MITRE_TECHNIQUE}}).",
    "queryType": "events",
    "queryLang": "2.0",
    "severity": "{{SEVERITY}}",
    "status": "Active",
    "expirationMode": "Permanent",
    "treatAsThreat": "UNDEFINED",
    "networkQuarantine": false,
    "s1ql": "{{BASE_FILTER}} AND NOT ({{EXCL_FIELD}} in:anycase ({{EXCL_LIST}}))"
  },
  "filter": {"{{SCOPE_KEY}}": ["{{SCOPE_ID}}"]}
}
```

Single-event rule rules:

- **Backslash escaping (validated).** The engine matches a SINGLE backslash. Write one backslash in the console UI (`('corp\jdoe')`, `matches '(?i)\s...'`); double each backslash in the JSON POST body (`corp\\jdoe`, `\\s`) so JSON decoding restores one. The double-backslash form typed into the UI does NOT match.
- **`in:anycase`** makes the exclusion case-insensitive. Match the exact value format the field carries (for example `src.process.user` is `DOMAIN\username` on EDR).
- **No lookup, no dashboard.** The list is hardcoded; to change it, edit the rule body (`PUT /web/api/v2.1/cloud-detection/rules/{id}`). For a large or frequently-changing list, use the scheduled path instead.
- **Auto-binds the Target Asset** from the matched event; no `entityMappings` needed.
- **Inline mitigation is available** on single-event rules: set `treatAsThreat` to `Suspicious`/`Malicious` and `networkQuarantine` deliberately for active response. (Scheduled rules cannot act inline, but any alert, including a scheduled-rule alert, can trigger a Hyperautomation flow that mitigates.)
- Deploy with `POST /web/api/v2.1/cloud-detection/rules`, enable with `PUT /web/api/v2.1/cloud-detection/rules/enable`, list with `isLegacy=false`.

If the analyst chose single-event, you are done after deploying and validating the body. Everything below (lookup table, anti-join, refresh flow, effectiveness dashboard) is the **scheduled** path.

## How the exclusion works

A lookup join tags each candidate event with the matching exclusion-list value (or null if the
event is not on the list). The rule then keeps only the null rows:

```
<base detection filters>
| lookup excl = reason from <TABLE>.csv by <KEY_COL> <OP> <EVENT_FIELD>
| filter excl = null          // kept rows had NO exclusion-list entry
| <group / aggregate / project as normal>
```

`excl = null` keeps non-matched rows. To COUNT what was suppressed (the dashboard), run the exact
inverse, `| filter excl = *`, over the same window. By construction, excluded + kept = total, so
the inverse is the reliable way to measure exclusion impact, no separate bookkeeping needed.

Match operator by exclusion kind (left of the operator is the lookup-table column, right is the
event field or expression):

| Exclusion kind | CSV key column holds | Operator | Example `by` clause |
|---|---|---|---|
| Asset by IP or subnet | `10.0.0.0/8`, `1.2.3.4/32` | `=:cidr` | `by cidr =:cidr src_endpoint.ip` |
| Asset by hostname | `host-01`, `scanner.corp` | `=:anycase` | `by host =:anycase device.name` |
| Custom value (domain/user/URL) | `www.example.com` | `=:anycase` | `by value =:anycase domain` |
| Custom value, prefix/suffix | `crl.%`, `%.trusted.com` | `=:wildcard` | `by pattern =:wildcard domain` |
| Exact case-sensitive token | `RULE-1234` | `=` | `by id = rule_id` |

Chain more than one list by adding a second `lookup` + `filter` pair (for example an asset
allowlist AND a domain allowlist in the same rule). Use distinct join-variable names
(`excl_asset`, `excl_domain`) so the two stages do not collide.

All five operators are tenant-validated on Akamai DNS (2026-06-22):
`=:cidr` (51 internal RFC1918 + 1 scanner /32), `=:anycase` on a custom value (domain), `=:anycase`
on a host-style field (`edge`: list entry `EDGE-NYC` matched `edge-nyc`, proving case-insensitivity,
3,375 rows), `=:wildcard` (`api.%` matched `api.example.com` 3,074; `%.example.net` matched
`app.example.net` 2,933), and exact `=` (`www.example.com`, 3,007).

**STAR scheduled-rule operator support (tenant-confirmed).** The rule trigger validator accepts
`=`, `=:anycase`, and `left join`, but REJECTS `=:cidr` ("lookupType 'CIDR' is not supported") and
`=:wildcard` ("lookupType 'WILDCARD' is not supported"). So a `=:cidr` or `=:wildcard` exclusion
cannot live in a STAR scheduled rule. Options for those two: (a) run the detection from a
Hyperautomation flow that POSTs the PowerQuery to the SDL query endpoint (CIDR and wildcard both run
fine there, see `assets/exclusion_detection_ha_workflow.template.json`); (b) for assets, use exact-IP
or hostname `=:anycase` in the rule; (c) pre-expand the subnet/pattern to literal member values when
building the list. `=:cidr` and `=:wildcard` work normally in ad-hoc PowerQuery and in dashboards.

## Questions to configure the solution (ask only what the prompt left out)

Confirm these before deploying. Everything has a sensible default, so the analyst can accept most
with one word; only the source and the list are truly required.

1. **Source** (required). The `dataSource.name` the detection runs over. If not given, enumerate the
   live sources and ask.
2. **What the detection should catch** (the base detection). Default per source, for a DNS source
   it is clients with failed resolutions (`rcode != 'NOERROR'`). If a detection already exists, take
   its query body and just wrap it with the anti-join.
3. **What to exclude, and how it is supplied** (required): either a CSV the analyst attaches or
   pastes (one value per row), or "build it from a source of truth" (for example every asset tagged
   `scanner` in the Asset Inventory, deployed with the optional refresh workflow).
4. **What each list entry matches** (this sets the key field + operator). Ask which event field, and
   whether to match more than one list (you can chain an asset list AND a value list):
   - IP or subnet, field `src_endpoint.ip` (or similar), operator `=:cidr`
   - hostname / device name, field `device.name`, `=:anycase`
   - domain / user / URL / other value, field `domain` / `actor.user.name` / ..., `=:anycase`
   - prefix or suffix pattern, `=:wildcard`
   - exact case-sensitive token, `=`
5. **Where it runs** (the CIDR/wildcard caveat). A STAR scheduled rule supports `=` and `=:anycase`.
   If the match is `=:cidr` or `=:wildcard`, the detection must run as a Hyperautomation flow instead
   (the rule validator rejects those operators). Confirm that is acceptable, or supply exact values.
6. **Scope** (default account). Account-wide for SDL sources, or resolve a site name to a siteId.
7. **Severity, cadence, prefix** (defaults: Medium severity; run every 60 min over a 24h lookback;
   re-notify per entity every 240 min; a short `{{PREFIX}}` code; alert when the query returns
   > 0 rows).

Auto-derived, do NOT prompt (state in the preview): the lookup table path
`/datatables/{{PREFIX}}Exclusions.csv`, the anti-join clause, the inverse (excluded) clause used
by the dashboard, and the null-entity guard (`{{KEY_FIELD}} = *`) so the rule never alerts on a
null asset.

## Parameters and tokens

Single-event-path tokens (used only when the rule type is `events`): `{{DETECTION_NAME}}`,
`{{DETECTION_DESCRIPTION}}`, `{{MITRE_TECHNIQUE}}`, `{{BASE_FILTER}}` (the boolean single-event
filter, no pipes), `{{EXCL_FIELD}}` (the field the inline list matches, e.g. `src.process.user`),
and `{{EXCL_LIST}}` (the quoted, comma-separated hardcoded values, e.g. `'corp\jdoe'`).

| Token | Meaning | Default |
|---|---|---|
| `{{PREFIX}}` | solution / customer code prefix | `dnsExcl` |
| `{{SOURCE}}` | `dataSource.name` the rule runs over | (required) |
| `{{BASE_FILTER}}` | base detection predicate before exclusions | `rcode != 'NOERROR'` (DNS) |
| `{{EXCL_TABLE}}` | lookup table filename (with `.csv`) | `{{PREFIX}}Exclusions.csv` |
| `{{KEY_COL}}` | lookup-table key column | `value` (custom) / `cidr` (asset) |
| `{{OP}}` | match operator | `=:anycase` / `=:cidr` |
| `{{EVENT_FIELD}}` | event field the list matches | `domain` / `src_endpoint.ip` |
| `{{GROUP_KEY}}` | entity the rule groups by | `src_endpoint.ip` |
| `{{ENTITY_COL_1..3}}` | columns mapped to security entities (cap 3) | `src_endpoint.ip`, ... |
| `{{SEVERITY}}` | rule severity | Medium |
| `{{RUN_INTERVAL_MINUTES}}` / `{{LOOKBACK_MINUTES}}` | cadence + window | 60 / 60 |
| `{{THRESHOLD_VALUE}}` / `{{THRESHOLD_OP}}` | fire condition on row count | 0 / Greater |
| `{{RENOTIFY_MINUTES}}` | per-entity re-alert suppression | 240 |
| `{{SCOPE_KEY}}` / `{{SCOPE_ID}}` | `accountIds` / `siteIds` + id | account |
| `{{MITRE_TACTIC}}` / `{{MITRE_TECHNIQUE}}` | optional ATT&CK tag | source-dependent |

## Step 1: get the exclusion list into a lookup table

Two ways, pick per the prompt:

1. **Analyst-supplied CSV (default).** Write the CSV straight to `/datatables/{{EXCL_TABLE}}` via
   `sdl_put_file`. The header row names the columns; the key column is referenced by name in the
   `lookup`. A useful shape carries the match key plus context:

   ```
   value,reason,owner,added           # custom-value list
   www.example.com,Sanctioned corporate domain,SecOps,2026-06-22
   ```
   ```
   cidr,reason,owner,added            # asset list (IP / subnet)
   10.0.0.0/8,Internal RFC1918 client range,NetOps,2026-06-22
   1.2.3.4/32,Known vulnerability scanner,SecOps,2026-06-22
   ```

   To update the list, re-`put` the file (read the current version first, pass it as
   `expectedVersion`). The rule picks up the new list on its next run, no rule edit needed.

2. **Built from a source of truth (savelookup).** When the list should track live state (for
   example every asset tagged `scanner` in the Asset Inventory), build it with a `datasource` +
   `savelookup` query and refresh it on a schedule (Step 4). Example asset-tag list builder:

   ```
   | datasource assets from 'surface/endpoint'
   | filter array_contains(tags, 'allowlist')
   | columns cidr = agentLastReportedIp, reason = 'Asset Inventory allowlist tag', owner = s1SiteName
   | limit 100000
   | savelookup '{{PREFIX}}Exclusions'
   ```

Confirm the load with a readback before wiring the rule:
`<source filter> | lookup excl = reason from {{EXCL_TABLE}} by {{KEY_COL}} {{OP}} {{EVENT_FIELD}} | filter excl = * | group hits = count() by excl | sort -hits | limit 25`

Limits: a CSV lookup table is up to 400 KB; a `savelookup` target up to 100,000 rows / 1.5 MB.
Keep the list an opt-in allowlist (bounded), not an open-ended denylist.

## Step 2: render and preview the detection

Render `assets/exclusion_detection.template.json`. The body is the base detection wrapped with the
anti-join. The validated demo body (Akamai DNS, asset list AND domain list chained):

```
dataSource.name='{{SOURCE}}' {{BASE_FILTER}} {{KEY_FIELD}} = *
| lookup excl_asset = reason from {{ASSET_TABLE}} by cidr =:cidr src_endpoint.ip
| filter excl_asset = null
| lookup excl_domain = reason from {{DOMAIN_TABLE}} by value =:anycase domain
| filter excl_domain = null
| group failed = count(), distinct_domains = estimate_distinct(domain),
        edges = estimate_distinct(edge), last_seen = max(timestamp) by src_endpoint.ip
| filter failed >= {{PER_ENTITY_THRESHOLD}}
| sort -failed
| columns src_endpoint.ip, failed, distinct_domains, edges, last_seen
| limit 500
```

Preview to the user BEFORE deploying: the rendered body, the projected columns, and the
before/after counts (run the body once, then run it again with the `filter excl_* = null` lines
removed, and show total vs kept). The difference is what the list will suppress.

STAR scheduled-rule hard rules (do not skip): `queryType` = `scheduled`, `queryLang` = `2.0`,
`treatAsThreat` = `UNDEFINED`, `networkQuarantine` = false (inline Active Response is not allowed on scheduled
rules), aggregation stays inside `group`, the body ends in an explicit `| columns` projection, and
`entityMappings` is capped at 3 columns. Add the null-entity guard `{{KEY_FIELD}} = *` so a null
asset never becomes an alert.

## Step 3: deploy the rule

`POST /web/api/v2.1/cloud-detection/rules` with the rendered envelope, scoped via
`filter.{{SCOPE_KEY}}`. New rules land Disabled. Validate by running the body once through the LRQ
runner, confirm it parses and returns the expected rows, then enable with
`PUT /web/api/v2.1/cloud-detection/rules/enable`. The rule shows `Activating` then `Active` within
about an hour. List rules with `isLegacy=false` or scheduled PowerQuery rules are silently omitted.

## Step 4 (optional): refresh the list on a schedule

Only needed for the savelookup / source-of-truth path. Render
`assets/exclusion_refresh_workflow.template.json` and import with the hyperautomation primitive,
scoped `?siteIds={{SITE_ID}}`. It re-runs the `savelookup` builder nightly so the exclusion table
tracks live state. Bind the "SentinelOne SDL" connection (Bearer), not the "SentinelOne" mgmt
connection. Imported flows land as a PRIVATE DRAFT owned by the API user (invisible in the console), so
publish it in the SAME step as the import, an import is not complete until it is a Shared Draft:
`POST /web/api/v2.1/hyper-automate/api/v1/workflows/{id}/publish?siteIds={{SITE_ID}}` (bodyless `{}`,
returns 204; stays inactive until bound + activated). An analyst-supplied static CSV needs no refresh;
re-`put` it when it changes.

## Step 5: deploy the exclusion-effectiveness dashboard

Render `assets/exclusion_dashboard.template.json` and `sdl_put_file` to
`/dashboards/{{PREFIX}} Exclusions`. Two tabs:

- **Exclusion Effectiveness:** total candidate detections, excluded count, net (kept), exclusion
  rate %, excluded over time, excluded by list, excluded by reason/owner, and the top excluded
  values. Every "excluded" panel uses the inverse anti-join (`filter excl_* = *`). Because total =
  excluded + kept within one window, these reconcile on any dashboard duration.
- **DNS Security Context:** the post-exclusion threat view (rcode mix, NXDOMAIN over time, top
  failed domains and clients after exclusions, record types, edges) so the analyst sees what
  survived the list, the part that actually matters.

The dashboard doubles as the tuning tool: a single value dominating "top excluded" or a steadily
climbing "excluded over time" is the signal to review whether the list is too broad and is hiding
something real.

**Dashboard readability rules (do not regress).** (1) No markdown banner panels, on this tenant
`graphStyle: "markdown"` renders as an empty "Untitled" box; put context in the dashboard-level
`description`, which renders under the title. (2) Never give a number panel a `suffix` that repeats
its title (title "Excluded (suppressed)" + value "17,478 suppressed" is redundant). Use
`options.format: "commas"` for counts and reserve `suffix` for a real unit the title lacks, such as
`%` on the rate panel. (3) Every panel is a live tenant query, never hardcode counts. (4) Inside a
`let` ternary use `!= null`, not `= *`. (5) Space out arithmetic: `total - excluded`, never
`total-excluded`.

## Step 6: validate and summarise

Run the rule body over the live window and confirm the kept rows match the dashboard's "net"
panel. Read back the lookup table. Confirm the rule exists (GET with `isLegacy=false`) and the
dashboard is present. Summarise the deployed artifacts (table path, rule id, dashboard path,
scope), the total / excluded / kept counts, and the top suppressed values.

## Gotchas

- **`from <table>` takes the literal filename.** If the file is `dnsExclDomains.csv`, write
  `from dnsExclDomains.csv` (keep the `.csv`). A bare name can miss the file, and
  `/datatables/foo` and `/datatables/foo.csv` can coexist.
- **`by` direction is `lookupColumn <op> eventField`.** Left of the operator is the table key
  column, right is the event field or expression. Name the join variable (`excl`) differently from
  any table or event field to avoid parser ambiguity.
- **Measure excluded with the inverse, in one pass.** Counting `excl = *` and `excl = null` in two
  separate calls drifts while a source is actively ingesting (each call recomputes its own
  now-window). Compute total, excluded, and kept in a single query
  (`| let is_excl = (excl = null ? 0 : 1) | group total=count(), excluded=sum(is_excl)`) when you
  need them to reconcile exactly.
- **Guard the null entity.** Group keys can be null (catch-all / leading-stamp rows). Without
  `{{KEY_FIELD}} = *` in the base filter, the rule emits a null-asset alert row.
- **`dataset 'config://datatables/<name>'` can return 0 rows** for a freshly written CSV. Read and
  enrich tables with `| lookup`, not `dataset`.
- **Opt-in, not opt-out.** An allowlist is bounded and safe; an open denylist grows without limit
  and risks suppressing real detections. Keep `reason` and `owner` columns so every entry is
  attributable and reviewable.
- **HA-flow alert creation: ONE self-contained call, `class_uid 99602001`.** When the CIDR/wildcard
  exclusion runs via the Hyperautomation flow (`assets/exclusion_detection_ha_workflow.template.json`)
  and posts a UAM alert, use a SINGLE `/v1/alerts` POST with the indicator embedded inline in
  `finding_info.related_events[]`, no separate `/v1/indicators` call. The alert MUST use
  `class_uid 99602001` (S1 Security Alert), top-level `resources[]`, `metadata.version "1.6.0-dev"`,
  observables carrying `typeName`, and `state_id`/`s1_classification_id`. Generic OCSF `class_uid 2002`
  returns HTTP 202 but is silently dropped (this was the real bug). Also remember the async LRQ
  launch+poll pattern (capture `id` + `X-Dataset-Query-Forward-Tag`, then GET for `data.values`). Full
  field list is in the `hyperautomation` skill (tenant-validated 2026-06-22).

## Deployed artifacts

A full deployment produces the artifacts below. Each renders from a template in `assets/` and is
deployed through the matching primitive skill. The `<prefix>` is the solution/customer code.

| Artifact | Template | Deployed to | Purpose |
|---|---|---|---|
| Asset exclusion list | `assets/exclusion_list_assets.csv.template` | SDL datatable `/datatables/<prefix>ExclAssets.csv` | CSV of IP / CIDR / host values to suppress; keyed `cidr =:cidr <ip field>` (subnets) or `=:anycase <host field>` |
| Custom exclusion list | `assets/exclusion_list_custom.csv.template` | SDL datatable `/datatables/<prefix>ExclValues.csv` | CSV of arbitrary values (domain / user / URL / id); keyed `value =:anycase`, `=`, or `=:wildcard <field>` |
| Single-event detection rule | `assets/exclusion_detection_single_event.template.json` | STAR rule via `POST /web/api/v2.1/cloud-detection/rules` (`queryType: events`) | Single-event base signature with the exclusion as an inline hardcoded `AND NOT (<field> in:anycase (...))` negative list in `data.s1ql`. No lookup table, no dashboard. Supports mitigation |
| Scheduled detection rule | `assets/exclusion_detection.template.json` | STAR rule via `POST /web/api/v2.1/cloud-detection/rules` | Base detection wrapped with the lookup anti-join (`\| lookup ... \| filter excl = null`). Supports `=` and `=:anycase` only |
| CIDR/wildcard detection + UAM alert | `assets/exclusion_detection_ha_workflow.template.json` | Hyperautomation workflow (account/site scope) | Runs the `=:cidr` / `=:wildcard` exclusion the STAR validator rejects, via the SDL LRQ (launch + poll), then posts a self-contained OCSF S1 SecurityAlert (`class_uid 99602001`) to UAM with the offender mapped as indicator + asset |
| Exclusion-effectiveness dashboard | `assets/exclusion_dashboard.template.json` | `sdl_put_file /dashboards/<prefix> Exclusions` | Total vs excluded vs net, exclusion rate, excluded over time, by list / reason / value, plus the post-exclusion threat view |
| List-refresh workflow (optional) | `assets/exclusion_refresh_workflow.template.json` | Hyperautomation workflow (account/site scope) | Nightly rebuild of a source-of-truth (savelookup) exclusion list; not needed for static analyst-supplied CSVs |

Common tokens across templates: `{{PREFIX}}`, `{{SOURCE}}`, `{{BASE_FILTER}}`, `{{KEY_FIELD}}`,
`{{ASSET_TABLE}}`, `{{DOMAIN_TABLE}}`, `{{IP_FIELD}}`, `{{VALUE_FIELD}}`, `{{SCOPE_KEY}}`,
`{{SCOPE_ID}}`, `{{SEVERITY}}`, `{{HEC_INGEST_URL}}`, `{{ACCOUNT_ID}}`.
