# STAR / Custom Detection rule types

SentinelOne Custom Detection (STAR) rules come in three types. All three are created at the same
endpoint, `POST /web/api/v2.1/cloud-detection/rules`, with `queryLang: "2.0"`, and are listed with
`isLegacy=false` (omit that param and scheduled and correlation rules are silently dropped from the
list). The three differ in where the detection logic lives and what language it uses.

Everything here is tenant-validated (2026-06-24). The
authoring reference with full request bodies and gotchas is in the PowerQuery skill:
[`powerquery/references/detection-rules.md`](../skills/powerquery/references/detection-rules.md).
For making the alert bind a real Target Asset, see
[detection-asset-binding.md](./detection-asset-binding.md).

## Asset auto-mapping requires the asset in the raw log

A STAR alert can only show a real Target Asset if the **event the rule matched already carries the
asset's identity**. SentinelOne EDR (native) events carry the agent identity, so single-event and
correlation rules over `dataSource.name='SentinelOne'` bind automatically. **Third-party and custom
SDL sources (firewall, DNS, proxy, cloud, SaaS) do NOT carry the console asset id in their raw logs**,
so a rule over those sources alerts with Target Asset "Unknown Device" unless the asset identity was
enriched into the event first.

This is why the **asset enrichment solution is a prerequisite for asset-mapped STAR alerts on
third-party sources**. Enrichment stamps the device/identity context into the parsed event, supplying
the fields the binding reconciler needs:

- For **single-event** and **correlation** rules: the parser must write `device.uid` (the numeric console agent id, or the unified asset id) plus an endpoint `class_uid` into the event, so the reconciler resolves the asset automatically.
- For **scheduled** rules: project the enriched identity columns (`device_host`, `device_agentid`, `device_agentuuid`, `src_ip`) and map them with `entityMappings`.

Deploy asset enrichment first, then the detection. See the asset enrichment solution
([`docs/solutions/asset-enrichment.md`](./solutions/asset-enrichment.md)) and the full tested binding
matrix in [detection-asset-binding.md](./detection-asset-binding.md).

## At a glance

| Type | `queryType` | Body lives in | Body language | Fires | Asset binding | Mitigation | Best for |
|---|---|---|---|---|---|---|---|
| STAR single-event | `events` | `data.s1ql` | boolean S1QL, no pipes | per matching event, streaming at ingest | automatic from the matched event | inline Active Response (`treatAsThreat`/`networkQuarantine`) or HA flow | deterministic single-event signatures |
| STAR multi-event (correlation) | `correlation` | `data.correlationParams` | boolean S1QL per sub-query, no pipes | when sub-query thresholds are met in a time window, grouped by an entity | automatic; `entityMappings` optional | inline Active Response (`treatAsThreat`) or HA flow | thresholds (N of X) and A-then-B sequences |
| Scheduled (PowerQuery) | `scheduled` | `data.scheduledParams.query` | PowerQuery, pipes allowed | on a schedule over a lookback window | set `entityMappings` on projected columns | via HA flow off the alert (`treatAsThreat` = `UNDEFINED`, no inline Active Response) | aggregation, baselines, lookup/anti-join exclusions |

**Mitigation is possible for all three types.** Single-event and correlation rules support inline Active Response on the rule itself (`treatAsThreat` = `Suspicious`/`Malicious`, `networkQuarantine`). Scheduled rules require `treatAsThreat` = `UNDEFINED`, so they have no inline Active Response, but their alerts, like any alert from any rule type, can trigger a Hyperautomation flow that performs the mitigation (isolate endpoint, block IOC, disable account, and so on). `treatAsThreat` = `UNDEFINED` does not mean mitigation is impossible, only that the rule does not act inline.

Decision guide:

- One event you can describe with a boolean filter, use **single-event**.
- "N occurrences" or "A then B" across several events correlated by a user/host/IP, use **correlation**.
- Anything needing `group`, `estimate_distinct`, `sum`, a `lookup`/anti-join, or any pipe, use **scheduled**.

## 1. STAR single-event (`queryType: "events"`)

The body is one boolean S1QL expression with NO pipes, placed in `data.s1ql`. Operators match a
PowerQuery initial filter (`=`, `in`, `in:anycase`, `contains`, `matches`, `AND`/`OR`/`NOT`). The
rule fires on each matching event as it is ingested, and the Target Asset binds automatically from
that event. Mitigation (Active Response) is available.

```json
{
  "data": {
    "name": "Encoded PowerShell by User",
    "description": "powershell with -EncodedCommand. MITRE T1059.001 / T1027.",
    "queryType": "events",
    "queryLang": "2.0",
    "severity": "High",
    "status": "Active",
    "expirationMode": "Permanent",
    "treatAsThreat": "UNDEFINED",
    "networkQuarantine": false,
    "s1ql": "dataSource.name = 'SentinelOne' AND event.type = 'Process Creation' AND src.process.name in ('powershell.exe','pwsh.exe') AND src.process.cmdline matches '(?i)\\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\\b'"
  },
  "filter": {"accountIds": ["<accountId>"]}
}
```

There is no `lookup` in a single-event body (no pipes). To exclude known-good accounts or hosts,
hardcode an inline negative list: `AND NOT (src.process.user in:anycase ('domain\\user1','domain\\user2'))`.

## 2. STAR multi-event / correlation (`queryType: "correlation"`)

`s1ql` stays empty; the logic lives in `data.correlationParams`:

- `entity`: the field events are correlated/grouped by (`user` is tenant-confirmed; device/endpoint/IP-style entities also exist).
- `matchInOrder`: `false` = sub-queries can match in any order; `true` = ordered sequence (sub-query 1, then 2, and so on).
- `timeWindow.windowMinutes`: the correlation window.
- `subQueries[]`: each `{ "matchesRequired": N, "subQuery": "<boolean S1QL, no pipes>" }`. One sub-query with `matchesRequired: N` is a threshold detection (N of the same event by entity within the window). Multiple sub-queries form a multi-stage or sequence detection.

```json
{
  "data": {
    "name": "Encoded PowerShell burst by user",
    "description": ">=2 encoded PowerShell executions by one user in 60 min. MITRE T1059.001.",
    "queryType": "correlation",
    "queryLang": "2.0",
    "severity": "High",
    "status": "Active",
    "expirationMode": "Permanent",
    "s1ql": "",
    "correlationParams": {
      "entity": "user",
      "matchInOrder": false,
      "timeWindow": {"windowMinutes": 60},
      "subQueries": [
        {"matchesRequired": 2, "subQuery": "event.type = 'Process Creation' and src.process.name in ('powershell.exe','pwsh.exe') and src.process.cmdline matches '(?i)\\s-enc'"}
      ]
    }
  },
  "filter": {"accountIds": ["<accountId>"]}
}
```

Validated 2026-06-24: a single-subQuery correlation (`entity:"user"`, `matchInOrder:false`,
`windowMinutes:60`, `matchesRequired:2`) was accepted (created as Draft, then deleted). The existing
"Abnormal Spike in SSH Login Failures" rule on the tenant uses two sub-queries with
`matchesRequired:500` each over a 60-minute window.

## 3. Scheduled (`queryType: "scheduled"`)

A PowerQuery body (pipes allowed) in `data.scheduledParams.query`, evaluated on a schedule. It is the
only type bound by the PowerQuery alert limits (1,000 rows / 1 MB intermediate, no `nolimit`). It does
NOT auto-bind the asset, set `entityMappings` on the projected columns. It has no inline Active Response (`treatAsThreat` must be `UNDEFINED`), but its alerts can drive mitigation via a Hyperautomation flow.

```json
{
  "data": {
    "name": "Akamai DNS - DGA / NXDOMAIN fan-out",
    "description": "High NXDOMAIN cardinality per client. MITRE T1568.002.",
    "queryType": "scheduled",
    "queryLang": "2.0",
    "severity": "Medium",
    "status": "Active",
    "expirationMode": "Permanent",
    "treatAsThreat": "UNDEFINED",
    "networkQuarantine": false,
    "entityMappings": [{"columnName": "device_host"}, {"columnName": "src_ip"}],
    "scheduledParams": {
      "query": "dataSource.name='Akamai DNS' rcode='NXDOMAIN' | group nxdomains=count(), distinct_domains=estimate_distinct(query.hostname) by src_ip, device_host | filter distinct_domains >= 25 | columns nxdomains, distinct_domains, src_ip, device_host | sort -distinct_domains",
      "runIntervalMinutes": 60,
      "lookbackWindowMinutes": 60,
      "threshold": {"value": 0, "operator": "Greater"}
    }
  },
  "filter": {"accountIds": ["<accountId>"]}
}
```

## S1QL backslash escaping in `events` / `correlation` bodies

The detection engine matches against a SINGLE backslash. In the raw query text typed in the console
UI, write one backslash (`matches '(?i)\s-...\b'`, `in:anycase ('domain\user')`). In the JSON POST
body, double each backslash (`\\s`, `\\b`, `domain\\user`) so that after JSON decoding the engine
receives one. Validated 2026-06-24: a single-backslash `in:anycase ('corp\jdoe')`
excluded the account, while the double-backslash form let it leak through; `(?i)\s-no` matched live
command lines but `(?i)\\s-no` matched nothing.

## Deploy, enable, verify (all types)

1. `POST /web/api/v2.1/cloud-detection/rules` with the body. Scope via `filter.accountIds` (or `siteIds`); tenant scope requires tenant-level permissions.
2. New rules may land `Draft`/`Disabled`. Enable with `PUT /web/api/v2.1/cloud-detection/rules/enable`, body `{"filter": {"ids": ["<id>"]}}`.
3. A rule reports `Activating` then becomes `Active` within about an hour; events/correlation rules then evaluate streaming, scheduled rules on their interval. Confirm with `GET /web/api/v2.1/cloud-detection/rules?ids=<id>&isLegacy=false` until `status == "Active"`.
