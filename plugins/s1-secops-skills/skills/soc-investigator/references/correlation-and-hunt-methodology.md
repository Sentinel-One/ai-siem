# Correlation and Hunt Methodology

Distilled from the SDL threat-hunt-and-correlation method. Use it whenever an investigation moves
past a single alert into hunting, cross-source correlation, or "is there a compromise?". The goal
is a small number of defensible conclusions, each traceable to ground-truth log evidence, not a
chase of every lead.

## Operating principles

1. **Reconcile everything to ground truth.** An alert, an offence, or a rule "firing" is a lead,
   not a finding. A claim becomes a finding only when traceable to specific raw log lines. If raw
   evidence is absent, say "unsubstantiated / unconfirmed"; do not upgrade a lead to a conclusion.
2. **Hold findings until the end.** Run the hunt, gather all evidence, then synthesize. Do not
   narrate a conclusion after the first interesting query.
3. **Separate two kinds of "alert".** (a) Alerts that actually fired in the data (e.g. an upstream
   SIEM's offences). (b) Detection rules you replay by intent because they cannot natively match
   the source. Never present (b) as if it were (a).
4. **Negative results are results.** Record what did NOT fire (no RC4 Kerberoasting, no LSASS
   dumping). This bounds the assessment and is as valuable as a hit.
5. **Do not over-correlate.** Two clusters sharing a time window is not causation. Assert a link
   only when an entity or artifact actually bridges them.

## The three correlation layers

- **Logs (ground truth)** - the raw events; the anchor for every conclusion.
- **Alerts / detections (signal)** - what fired, plus rules replayed by intent.
- **Threat intel / IOCs (context)** - reputation and relationships for external indicators, used to
  assign confidence and separate noise from targeted activity.

Build findings by correlating these three around shared entities (host, account, IP, artifact) and
time.

## Workflow

1. **Profile and parse the source.** Confirm data exists for the requested window (check the
   timestamp range; many sources default to last 24h). Establish schema: distinct upstream sources,
   event/alert types, volume, daily timeline. Aggregated SIEM feeds often arrive unparsed as
   CSV-in-`message` with `dataSource.name` null, identify the delimiter layout and plan to extract
   fields at query time.
2. **Inventory detections and test coverage.** List existing rules (SDL `/alerts/` files and
   console Custom Detection / STAR rules). For each, note the `dataSource.name` and fields it
   filters. Critical check: does any rule actually match the source under investigation? A rule
   keyed on a normalized `dataSource.name` cannot fire on an unnormalized feed, that gap is itself a
   finding.
3. **Generate candidate alerts (replay by intent).** For rules that do not natively cover the
   source, re-implement their logic against the parsed data: map selectors/thresholds onto the
   fields the source actually carries. Record FIRED / NOT-FIRED and the threshold used.
4. **Hunt the behaviour families.** Independently of existing rules: perimeter scanning / brute
   force; auth failures, spray, lockouts; Kerberos abuse; discovery / enumeration; persistence;
   credential dumping. Coverage of where you look matters more than cleverness.
5. **Hunt malicious code and commands across EVERY telemetry layer.** The most-missed step. A
   malicious command will not always sit where you first look:
   - Process command lines (Sysmon ProcessCreate / 4688 / Linux exec): encoded/obfuscated
     PowerShell (`-EncodedCommand`, `FromBase64String`, IEX download cradles), LOLBins (certutil,
     mshta, regsvr32, rundll32, bitsadmin), cmd caret/concat obfuscation, Linux `base64 -d | bash`,
     `eval`, `python -c`.
   - Web-server / application logs (IIS, Apache, WAF): injection in URLs and bodies, SQLi carrying
     OS commands (`xp_cmdshell`, `EXEC master..xp_`), web-shell access, command injection, path
     traversal.
   - Database logs: `xp_cmdshell` / `sp_OACreate`, suspicious stored-procedure use, to confirm
     whether a web-tier injection actually executed on the backend.
   - Scheduled tasks / services / cron: commands launched for persistence.

   Three rules that prevent a false "clean": (a) sweep broadly before scoping, do not restrict to
   events that already have a parsed field; (b) decode, do not count, confirm by reading decoded
   content, not a pattern count (percent-encoding, caret, base64 also occur benignly); (c) separate
   attempt from execution, a payload reaching an app is an attempt; confirm execution via backend
   logs before calling it a compromise, and never downgrade a genuine attempt to "nothing" just
   because execution is not proven.
6. **Correlate by entity and time.** Pivot leads onto shared keys to see whether independent
   signals converge on the same asset. Then order events to test for an attack chain (recon ->
   access -> execution -> persistence -> lateral).
7. **Enrich indicators with threat intelligence.** For notable external IPs / domains / hashes,
   pull reputation and relationships to promote or demote confidence; add confirmed-bad indicators
   to an IOC table.
8. **Disposition with raw evidence.** For each correlated cluster, pull the underlying raw events
   and decide true positive / false positive / benign. Name the disposition and the evidence.
   Watch for benign look-alikes (admin tooling, service accounts, vendor software), and do not
   dismiss a lead just because the obvious query came back empty (re-check parsing and scope first).
9. **Narrate, map to ATT&CK, and report.** Synthesize into a small set of findings, build a UTC
   timeline (reconcile local-time offsets in embedded logs), map to MITRE ATT&CK, record coverage
   gaps for detection engineering. For a Word deliverable use the `docx` skill.

## Incident report structure

```
Executive Summary (with a Key Verdicts table)
Scope & Data
Threat-Hunting & Correlation Methodology
Detection Coverage & Rule Inventory
Simulated Alerts - Rules Replayed by Intent
Key Findings (one per cluster; severity + disposition)
Correlation & Entity Analysis
Indicators of Compromise (with intel verdicts)
MITRE ATT&CK Mapping
Assessment & Conclusions (is there a compromise? say so plainly)
Recommendations (detection engineering / investigate / harden)
Appendix: method notes & caveats
```

Be plain about the bottom line. "No confirmed compromise" and "a real attack attempt occurred" can
both be true at once, state both rather than rounding to a reassuring or alarming headline.

## Honesty

This method exists to find the truth, not to confirm a hypothesis (the user's or your own). If
asked to "find the compromise" and the evidence shows only attempts, report attempts. If you miss
something and new evidence appears, own it and re-hunt. The credibility of the report rests on every
claim being backed by evidence.
