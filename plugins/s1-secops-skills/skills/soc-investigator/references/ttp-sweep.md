# SOC Investigator: TTP Sweep Run Instructions

SWEEP answers "what MITRE-mapped TTPs are present in the logs over this window". It takes no alert
ID. It is a peer of SHORT / MEDIUM / LONG, not a cumulative extension of them.

The evidence discipline, verdict gate, confidence ladder, and mandatory query appendix in `SKILL.md`
and `references/evidence-and-verdict-discipline.md` apply unchanged. The hunt reasoning in
`references/correlation-and-hunt-methodology.md` applies; this file is the runbook that operationalises
it for a whole-window sweep.

## Phase 0: Scope confirmation (2 min)

Establish, and state back to the user, before any query:

1. The window, explicit UTC start and end. Never rely on a tool's default lookback.
2. The tenant and account scope. **If the operator has switched accounts or scopes mid-session,
   discard every prior finding and re-baseline.** Confirm with:

   ```text
   | group events=count() by account.name | sort -events | limit 20
   ```

3. Whether external threat-intel enrichment is permitted. If not, say so and cap every verdict at
   SUSPICIOUS - Pending Confirmation.

## Phase 1: Source enumeration and noise separation (3 min)

```text
| group events=count() by dataSource.name, dataSource.vendor | sort -events | limit 150
```

Run this over a 24h slice first if the window is long; a full-window enumeration on a busy tenant
will time out. Then classify every returned source as security-relevant or platform noise.

Events with no `dataSource.name` are frequently the largest single bucket and are usually ingestion
and container telemetry, not security logs. Identify them rather than assuming:

```text
!(dataSource.name = *) | group hits=count() by parser, serverHost | sort -hits | limit 30
```

Parsers such as `docker`, `agent-metrics`, `cribl`, `k3s-audit`, `hecRawParser` and hosts such as
`scalyr-agent-*` are platform telemetry. Record the excluded volume in the report; do not delete it
from the narrative.

## Phase 2: Per-source schema discovery (5 min)

Reuse the project schema cache only if its recorded tenant and account scope match this session's.
A cache built at another account scope is not valid here even on the same console, because parsers
and promoted fields differ per site.

For each security-relevant source you intend to query, discover fields before writing a hunt query.
PowerQuery's default projection returns only timestamp and message, so use the V1 full-event route
(`powerquery_schema_discover`). Two failure modes to expect:

- A source returns only `logVolume` / `logBytes` metric events. That means the real events exist but
  the discovery filter did not reach them. Fall back to probing candidate field names with a
  `| group ... by <candidate>` and keep the ones that return non-null.
- A source is absent from V1 discovery yet visible to PowerQuery grouping. Query it through
  PowerQuery and record the discrepancy.

Persist what you learn. Note the tenant and account scope alongside it.

## Phase 3: ATT&CK extraction from the alert stream (5 min)

The alert stream carries vendor-authored ATT&CK mappings and is the cheapest authoritative source
of technique labels. Two routes, and the first one that most people reach for does not work.

**Do not use bracketed array fields.** `finding_info.attacks[0].technique.uid` returns HTTP 400 on
current platform versions, in `group by` and in `columns` alike. Quoting the name does not help; the
parser treats `"finding_info.attacks[0].technique.uid"` as a string literal and returns the literal
back as the value.

**Route A, preferred.** `finding_info.attacks` is a flat field holding the attacks array as a JSON
string. Group on it and parse client-side:

```text
dataSource.name='alert' finding_info.attacks=* | group hits=count(), sites=estimate_distinct(s1_detection_metadata.site_name), maxsev=max(number(severity_id)) by finding_info.attacks, finding_info.analytic.category | sort -hits | limit 200
```

Each distinct value is one rule's mapping, so the group count stays small. Parse each JSON array,
take `sub_technique.uid` when present and `technique.uid` otherwise, and weight by the group's hit
count. De-duplicate techniques within a single group before weighting, or a rule mapped to the same
technique twice double-counts.

**Route B, cross-check.** The `| datasource alerts` command exposes flat `mitreTechniques` and
`mitreTactics` columns plus `analystVerdict`, `classification`, `alertType` and `severity`. Use it
to cross-check Route A and to pull verdicts:

```text
| datasource alerts | group hits=count() by analystVerdict, classification, alertType, severity | sort -hits | limit 40
```

Caution: `| datasource alerts` reports an unreliable `matchCount` on a grouped query. Reconcile with
a plain count before quoting any total:

```text
| datasource alerts | group n=count() | limit 1
```

**Two counts, never conflated.** `dataSource.name='alert'` counts alert *events*, which include
create and update activity per alert. `| datasource alerts` counts distinct *alerts*. On one
observed tenant the same window gave 207,483 events against 40,218 alerts. State which one every
figure refers to.

**Coverage is a finding.** Measure how much of the alert stream carries no mapping at all:

```text
dataSource.name='alert' !(finding_info.attacks = *) | group unmapped=count() | limit 1
```

An unmapped majority, typically endpoint behavioural detections, means any ATT&CK coverage dashboard
built on this field under-reports endpoint tactics. Report the ratio as a detection-engineering gap.

**Watch for truncated result sets.** A large group-by may be written to a side file and cut off with
a trailing "... and N more rows". Always reconcile the sum of the returned hit counts against the
query's match count and state the coverage percentage and the number of groups lost. A matrix built
on a silently truncated result is wrong, not merely short.

## Phase 4: Raw-log corroboration per technique (10 min)

The alert stream is signal, not ground truth. For each technique above a reporting threshold, run at
least one query against the underlying raw source and record the result, including empty results.
Corroborate the top techniques by tactic family; a worked mapping of behaviour family to technique
is in `references/correlation-and-hunt-methodology.md`.

Examples of the shape, adapted to whatever the session's schema discovery actually confirmed:

```text
dataSource.name='SentinelOne' event.type='Process Creation' tgt.process.cmdline=* | filter( tgt.process.cmdline contains:anycase("encodedcommand") or tgt.process.cmdline contains:anycase("frombase64string") or tgt.process.cmdline contains:anycase("downloadstring") ) | group hits=count(), hosts=estimate_distinct(endpoint.name) by tgt.process.name | sort -hits | limit 50
```

```text
dataSource.name='Windows Event Logs' winEventLog.id=* | group hits=count() by winEventLog.id | sort -hits | limit 35
```

On `Process Creation` the newly created process is `tgt.process.*` and its creator is
`src.process.*`; `src.process.parent.*` is the grandparent. Hunting the wrong side returns a clean
result on a dirty host.

A technique that the alert stream claims but no raw query corroborates is reported as **claimed by
detection, not corroborated in raw logs**. That is a finding about detection quality, not evidence
of the technique.

## Phase 5: Simulation and authorised-scanner suppression (5 min)

**This phase is what separates a useful sweep from an alarming one.** Breach-and-attack-simulation
platforms and cloud posture scanners produce real attack telemetry by design. Without this pass a
sweep reports a fleet-wide intrusion that does not exist.

Run both checks every time.

**Endpoint simulation.** Look for simulation agents and whether attack tooling is co-resident with
them, then check concentration:

```text
dataSource.name='SentinelOne' event.type='Process Creation' tgt.process.name=* | filter( tgt.process.name contains:anycase("picus") or tgt.process.name contains:anycase("atomic") or tgt.process.name contains:anycase("caldera") or tgt.process.name contains:anycase("mimikatz") or tgt.process.name contains:anycase("lazagne") or tgt.process.name contains:anycase("adfind") ) | group hits=count(), procs=estimate_distinct(tgt.process.name) by endpoint.name, site.name | sort -hits | limit 20
```

Attack tooling concentrated on a small number of hosts that also run a simulation agent is
adversary simulation, not an intrusion. Name the hosts and the agent.

**Cloud enumeration.** Alerts of the "potential enumeration activity" family are usually posture
scanning. Resolve the calling principal before reporting discovery techniques:

```text
dataSource.name='CloudTrail' unmapped.userIdentity.arn=* | group hits=count(), apis=estimate_distinct(unmapped.eventName) by unmapped.userIdentity.arn | sort -hits | limit 15
```

Assumed roles belonging to named posture or CASB products are authorised scanning. Report the
technique as suppressed and name the principal.

Suppression rules:

- Suppressed activity is reported in its own section with counts, never deleted.
- Suppression requires a named agent, host, or principal. "Looks like testing" is not suppression.
- Anything that survives suppression is reported at full weight.
- Findings unrelated to the simulation, for example root-account API use or an identity brute-force
  pattern, are pulled out of the suppressed bucket and reported separately.

## Phase 6: Synthesis and output (5 min)

Write to `investigation_<timestamp>/`:

- `ttp_matrix.csv` - one row per technique: `technique_uid, technique_name, tactic_uid, tactic_name,
  alert_events, corroborating_source, corroborating_count, suppressed, verdict, confidence`.
- `sweep_findings.json` - window, scope, sources enumerated, sources excluded with volume, mapped and
  unmapped alert counts, coverage percentage, groups lost to truncation, suppression decisions with
  their named evidence.
- `sweep_report.md` - headline verdict first, then tactic distribution, technique table with
  corroboration, suppressed activity, findings that are not simulation, detection gaps, and the
  **mandatory query appendix** with all five per-query fields.

Lead the report with the bottom line in one sentence, with its confidence rung and the count of
evidence behind it. "Adversary-simulation and authorised-scanner activity, not a live intrusion" and
"a real credential-attack pattern is present in the identity logs" can both be true; state both
rather than rounding to whichever is more comfortable.

## Performance notes

- A multi-day grouped scan on a busy tenant will time out through the standard PowerQuery MCP tool.
  Use the LRQ runner (`powerquery_run`), which manages the async launch-poll-cancel lifecycle.
- Enumerate over a short slice, then run targeted full-window queries. Never open with a full-window
  ungrouped scan.
- Avoid `array_agg_distinct` on command-line fields. It returns kilobytes per group and exhausts the
  context for no analytic gain. Use `estimate_distinct` for cardinality and a separate small
  `| limit 5` sample query when you need literal values.
