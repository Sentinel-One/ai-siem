# Solution: Custom Rules with MITRE Mapping

Solution for custom rules to carry MITRE mapping. SentinelOne library (platform) rules arrive in
Unified Alert Management with MITRE ATT&CK tactics and techniques. Custom Detection (STAR) rules do
not: the rule API has no MITRE field, so every custom alert shows an empty MITRE column, MITRE
dashboards undercount, and multi-tactic risk scoring ignores your own detections.

This solution gives a custom detection a real, queryable MITRE mapping. It runs the detection's
PowerQuery from a Hyperautomation watchdog and has the watchdog raise the UAM alert itself, with the
ATT&CK tactic and technique attached where UAM reads them. The result is an alert whose
`mitreTactics` and `mitreTechniques` are populated, exactly like a library-rule alert.

This is part of the `sdl-solutions` skill. Playbook:
[`sdl-solutions/references/custom-rule-mitre-mapping.md`](../../skills/sdl-solutions/references/custom-rule-mitre-mapping.md).

## The problem, measured

Tested on a live tenant on platform version S-26.3.4:

| Check | Result |
|---|---|
| Create a custom rule with a `mitre` field | HTTP 400 `Unknown field` |
| Create a custom rule with a `mitreTechniques` field | HTTP 400 `Unknown field` |
| MITRE on existing STAR alerts | empty on all 3,602 |
| MITRE on library rules | present (`mitre[]` with tactic, technique, sub-technique) |
| Ingested alert with `finding_info.attacks` | no MITRE in UAM |
| Ingested alert with `attacks[]` on each `finding_info.related_events[]` entry | MITRE populated: `mitreTactics ["Execution","Stealth"]`, `mitreTechniques ["T1059.001 PowerShell","T1027 Obfuscated Files or Information"]` |

## How it works

```text
 rule spec (JSON, in Git)
   name, severity, PowerQuery, lookback, interval, MITRE list
        |
        v  render_mitre_watchdog.py
 Hyperautomation flow (scheduled)
   1. run the PowerQuery through the LRQ API
   2. no rows  -> stop
   3. rows     -> POST one S1 Security Alert to /v1/alerts
                  with attacks[] on the inline indicator
        |
        v
 UAM alert with mitreTactics / mitreTechniques
```

Because the query runs through the LRQ API, the detection is not bound by the scheduled-rule
evaluator's limits: `datasource`, `savelookup`, joins and large intermediate results all work.

## Deploy it

Ask the skill, for example:

- "Map my encoded PowerShell custom rule to T1059.001 and T1027"
- "Convert the scheduled rule 'Windows logon brute force' into a MITRE-mapped watchdog, T1110"
- "Our custom alerts have no MITRE, fix that for these three rules"

The skill collects a rule spec (or reads an existing scheduled rule), renders the flow, shows you
the query, schedule and mapping, runs the query once so you see what would alert, then imports,
publishes, activates, runs the flow and confirms the alert carries the mapping.

A rule spec looks like this:

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

Put the entity (host or user) in the first column: it names the alert's resource. Examples ship in
`sdl-solutions/assets/mitre_rule_specs/`.

## Things to know

- **One alert per run.** The flow summarises every matching row in one alert. Group the query so a
  run returns one row per entity if you need one alert per entity.
- **No built-in suppression.** A condition that stays true alerts every interval. Set the lookback
  equal to the interval for "new in the last window" detections.
- **Tactic ids, not names.** UAM renders TA0005 as "Stealth" (ATT&CK v18), not "Defense Evasion".
  Group and filter on the tactic id.
- **Retire the original.** When converting a STAR rule, disable it once the watchdog is verified so
  the detection does not alert twice.
- **MITRE goes on the indicator.** Only `finding_info.related_events[].attacks[]` is read; the same
  array on `finding_info` is ignored.

## Verify

```text
| datasource alerts | filter detectionProduct = '<PREFIX> Custom Rule (MITRE)' | columns externalId, mitreTactics, mitreTechniques
```
