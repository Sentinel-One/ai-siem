# Solution: Alert Noise Reduction

Cut the noise in a SentinelOne alert queue. This solution finds the small number of sources and
signatures that dominate alert volume, separates ingested and already-actioned noise from real
detections, and deploys the fixes: an ingestion-filter recommendation, an auto-resolve
Hyperautomation flow, an optional exclusion or correlation rule, and a noise-vs-signal dashboard.

Most alert fatigue in a modern SIEM is not a detection-tuning problem, it is an ingestion problem:
a third-party source (a firewall, proxy, DNS or email gateway, cloud audit feed) forwards its own
threat logs and each line is materialised as an individual alert. This solution measures exactly how
much of the queue that accounts for, proves what the source already did with each event, and gives
the analyst a defensible plan to quiet the queue without losing signal.

This is part of the `sdl-solutions` skill. It orchestrates the primitive skills
(`powerquery` for the discovery queries, `sdl-dashboard` for the dashboard,
`hyperautomation` for the auto-resolve flow, `mgmt-console-api` for scope and
rule operations); it does not reimplement them.

## Discovery-first, nothing hardcoded

Every product, source, signature, severity split, action value, and count is discovered live in the
target tenant before any recommendation or deploy. The noisy source in one tenant is a firewall; in
the next it is a proxy or an email gateway. The templates carry placeholders only; the skill fills
them from what it measures this session. The one fixed value is the OCSF alert class
(`class_uid=99602001`, a SentinelOne Security Alert across every product), and even that is confirmed
live before use.

## How it decides what is noise

Each dominant (source, signature) pair is classified four ways:

- **Ingested vs S1-native.** A real SentinelOne detection carries an analytic rule id and rule/engine
  type; an ingested third-party log has none and carries the connector's log name. Ingested noise is
  not fixed by tuning an S1 rule.
- **Already-actioned at source.** Events the source itself already neutralised (firewall
  drop/deny/block/sinkhole/reset, proxy blocked, mail rejected) carry no residual risk. The action
  field name varies per source and is discovered.
- **Severity.** OCSF severity 1 to 5. High volume at Informational or Low from an ingested source is
  almost always noise; a single already-actioned signature tagged High is inflated, not urgent.
- **Signal worth keeping.** Some noisy categories (for example DNS lookups to C2 or DGA domains, even
  when sinkholed) are still an infection signal, and are preserved as one correlated detection rather
  than per-event alerts.

## Run it with one prompt

- *"My alert queue is flooded, reduce the noise"*
- *"Why do we have millions of alerts this month?"*
- *"Tune our alert ingestion and auto-close the already-blocked firewall alerts"*
- *"Run an alert optimization for the Acme site"*

## What it deploys

Recommendations, backed by the measured numbers: which ingestion severities to keep (the connector's
Alert Ingestion Filter is a console setting, not an API object, so this is a recommendation with the
exact volumes attached), and which already-actioned signatures to suppress or auto-resolve. Then, on
the tenant: a noise-vs-signal dashboard (`sdl_put_file`), an auto-resolve Hyperautomation flow that
closes already-mitigated alerts with an explanatory note (imported, published to a Shared Draft, left
inactive for review and connection binding before activation), and optionally a maintainable
exclusion lookup or a single correlation rule that preserves signal-worthy categories. The full
Claude-facing playbook, discovery queries, and templates are in
`references/alert-noise-reduction.md` and `assets/alertnoise_*.template.json`.
