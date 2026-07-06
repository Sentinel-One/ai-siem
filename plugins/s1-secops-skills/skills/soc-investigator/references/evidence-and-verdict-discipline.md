# Evidence Discipline and Verdict Gates

Distilled from the Purple SOC Analyst operating standard. These rules govern every
investigation this skill runs, in every mode. They are what separate a defensible report from a
confident-sounding guess.

## What "data-driven" means

- A claim is made only after the data exists. No "approximately 30 endpoints" without an
  `estimate_distinct(agent.uuid)` result; no "this looks like APT-X tooling" without a
  threat-actor relationship lookup; no "third time this week" without a query proving it.
- Empty, null, and zero results are findings. "0 alerts of `severity_id >= 4` in 7 days" is a
  real datapoint, often more informative than a non-zero count. Never round 0 up, never silently
  drop an empty source from a summary.
- Tool errors are findings. A 500 from PowerQuery, a 403 from a scoped key, a missing SDL path,
  surface it. Do not paper over by switching sources silently and reporting as if the first worked.

## Flag every assumption

When you must reason past missing data, mark it:

> **Assumption:** the affected user is a human account, not a service account.
> **Falsified by:** an `account_status='ServiceAccount'` lookup, or `lastInteractiveLogon > 30d`.

If you can resolve the assumption with a tool call in the same session, do it. If the verdict
does not change when the assumption is falsified, say so.

## Confidence ladder

| Word | When to use |
|---|---|
| Confirmed | 2+ independent sources corroborate AND threat intel is positive (malicious verdict, actor attribution, or an MDR/analyst verdict in the alert notes). |
| Consistent with | The pattern matches a known TTP / family / actor, but enrichment is partial or corroboration is single-source. |
| Suggests | A single weak signal (heuristic alert, low detection ratio, anomalous timing). Investigate, do not escalate. |
| Possible / cannot rule out | No contradicting evidence, but none supporting either. Recommend collection, not action. |
| No evidence of | Queries were run and returned empty. The default for "did X happen?" when the query is clean. |

Do not use stronger language than the evidence supports. Leadership reads "confirmed" as ground
truth and may act on it, only use it when you have ground truth.

## Verdict gate (mandatory)

No finding is classified CRITICAL or TRUE POSITIVE on a detection-engine severity alone. A
detection, even at CRITICAL, is a hypothesis. Before escalating you MUST have at least one of:

1. Threat-intel confirmation, a malicious verdict from the threat-intel MCP (high detection
   ratio, confirmed actor, malicious behavioural analysis).
2. MDR / analyst confirmation, check `get_alert_notes` and `get_alert_history` FIRST. If MDR
   marked the alert False Positive or Benign, that verdict takes precedence over the engine
   severity. Do not override it without new evidence they did not have.
3. Multi-source corroboration, the same IOC or behaviour independently confirmed as malicious
   across 2+ unrelated sources (not the same engine firing repeatedly).

If none exist, the maximum classification is **SUSPICIOUS - Pending Confirmation**.

> Lesson learned: a PowerShell/ransomware alert (CRITICAL, Fileless engine) was initially treated
> as a confirmed true positive on the engine classification alone. MDR later confirmed it as
> False Positive - Benign. Detection-engine severity is never a final verdict.

`TRUE_POSITIVE_BENIGN` (detection real, cause benign) is treated like FP/Benign for precedence, do
not override without new evidence.

## IOC enrichment is mandatory and external-only

Every external IP, domain, URL, or file hash is enriched through the threat-intel MCP (VirusTotal
by default) before a verdict, then pivoted (contacted domains/IPs, dropped files, related threat
actors) to expand the picture. RFC1918 / internal / no-external-indicator events are
enrichment-N/A; state that explicitly and never fabricate a lookup.

## Session init before any query

- Enumerate `dataSource.name` live (`| group UniqueDataSourceNames = array_agg_distinct(dataSource.name) | limit 1000`).
  Reuse the project schema cache (`s1_sdl_schema_cache.json`) if it is within TTL; otherwise
  discover and cache.
- Discover each source's schema before querying it. Do not assume a field namespace
  (vendor-prefixed, OCSF `src.ip.address`, `unmapped.*`) applies until confirmed this session.
- Trailing-underscore fields (`severity_`, `status_`) are SDL's reserved-name rewrite and ARE the
  canonical queryable field; numeric OCSF variants (`severity_id`, `status_id`) live alongside.
- Cast string-prone numeric fields with `number()` before arithmetic or `>=` comparisons; SDL
  columns can be type-locked to string even when values look numeric.

## Anomaly checklist (apply to every log result)

Frequency (any entity far above expected), timing (off-hours, weekend, 3am), geolocation
(first-ever country/ASN), baseline deviation (does this host/user normally do this), volume
(bytes/connections/events vs peers), new entity (first appearance of an IP/domain/user/process),
privilege (low-priv account doing admin-only actions), chain (does the event make sense before and
after, e.g. PDF opened -> PowerShell -> outbound). Any "yes" -> enrich and cross-correlate before
closing.

## OCSF severity_id

0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal. Filter High+ with
`severity_id >= 4` (cast with `number()` if the column may be string-typed).

## PowerQuery syntax rules (non-negotiable)

- Sort descending `| sort -field`; ascending `| sort field`. Never `sort field desc`.
- Never a bare `*` as the initial filter (HTTP 500). Use a field-presence check like
  `event.time=*` or `dataSource.name=*`.
- Never `| head N` (invalid, 500). Use `| limit N`.
- `field contains 'x'` errors; use `field contains:anycase("x")`.
- Bracketed array fields (`resources[0].*`) work in `columns`/`group by` but NOT as a filter
  predicate. Split queries per `dataSource.name` rather than ANDing across schema families.

## Windows authentication triage (validated)

- `winEventLog.description` holds the full Target/Source/Status block; use it when
  `winEventLog.data.event.eventData.*` names are uncertain.
- Core IDs: 4625 fail, 4624 success, 4768/4769 Kerberos, 4771 pre-auth fail, 4776 NTLM, 4740 lockout.
- 4625 SubStatus: `0xC000006A` wrong password (user exists), `0xC0000064` no such user,
  `0xC0000234` locked, `0xC0000072` disabled, `0xC000006F`/`0xC0000070` time/workstation restriction.
- Pattern shapes: spray = 1 password x many accounts; brute = many passwords x 1 account (external
  source); benign service account = many rapid fails x 1 account from a known internal host that
  ALSO has same-day successful (often Kerberos) logons and no lockout. Confirm the shape before
  labelling a "password spray".
- DC determination: trust AD DN / OU placement and tags over an `is_dc_server` boolean (observed
  `false` on a confirmed DC). Identity/Ranger AD alert depth comes from DC Windows Security auth
  events, not EDR process storylines.

## Communication

Lead with the verdict, confidence word, and evidence count, then the support. Example: "True
positive, high confidence, based on 3 PowerQueries, threat-intel enrichment of 4 IOCs, and MDR's
closing note on the alert." Distinguish observation ("host X had 12 high-severity alerts in 24h")
from inference ("host X is likely compromised"), and cite the query behind each number inline.
