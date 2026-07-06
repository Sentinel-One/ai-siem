# Playbook: Alert Noise Reduction

Cut alert-queue noise on an SDL tenant by finding the sources and signatures that dominate volume,
separating already-actioned or ingested noise from real detections, and deploying the fixes:
an ingestion-filter recommendation, an auto-resolve Hyperautomation flow, an optional exclusion
lookup or correlation rule, and a noise-vs-signal dashboard. Triggers: "reduce alert noise",
"my alert queue is flooded", "why so many alerts", "tune alert ingestion", "auto-close firewall
alerts", "alert optimization". Orchestration only; drives powerquery, sdl-dashboard,
hyperautomation, sdl-api, mgmt-console-api.

## Principle: discover, never assume

Nothing in this playbook hardcodes a product, source, signature, severity split, action value, or
count. Every one of those is discovered live in the target tenant before any recommendation or
deploy. The noisy source in one tenant is a firewall; in the next it is a proxy, an email gateway,
or a cloud audit feed. Run the discovery queries first, confirm the findings with the user, then
render the templates with the discovered values.

The only fixed fact is the canonical alert filter: `class_uid=99602001` is the OCSF class for a
SentinelOne Security Alert across every product and connector. Confirm it still returns rows in the
tenant before relying on it; if a tenant uses a different alert class, discover it with
`| group c=count() by class_uid, class_name | sort -c`.

## Model

An alert queue is dominated by a small number of (source, signature) pairs. Reducing noise is a
four-way classification of each pair:

1. **Ingested vs S1-native.** A real SentinelOne detection carries `finding_info.analytic.uid` and
   `finding_info.analytic.type = "Rule"` (STAR) or an engine type (EDR/CWS "Behavioral AI",
   "Static"). An ingested third-party log has a null `analytic.uid`, `analytic.type_id = 99`, and a
   `metadata.log_name` set by the connector. Ingested noise is not fixed by tuning an S1 rule; it is
   fixed at the source, at the ingestion filter, or by auto-resolution.
2. **Already-actioned at source.** Third-party events whose own action already neutralised the
   event (firewall `drop` / `deny` / `block` / `sinkhole` / `reset-both`, proxy `blocked`, mail
   `rejected`) carry no residual risk. The action field name varies per source and must be
   discovered (often `unmapped.action`).
3. **Severity.** OCSF `severity_id`: 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical. High
   volume at Informational/Low from an ingested source is almost always noise; a "High" that is a
   single already-actioned signature is inflated, not urgent.
4. **Signal worth keeping.** Some noisy categories (for example DNS to C2/DGA domains, even when
   sinkholed) are still an infection signal. Preserve them as a single correlated detection, not as
   per-event alerts.

## Parameters (ask few; default rest)

| Param | Default |
|---|---|
| window | 30d |
| alert filter | `class_uid=99602001` (confirm live) |
| noise threshold | any (source, signature) contributing > 1% of the window OR > 1,000/day |
| keep-severities (ingestion) | High + Critical (offer Critical-only for a near-silent source) |
| already-actioned action values | discover per source; typically drop, deny, block, sinkhole, reset-both, reset-client, reset-server |
| auto-resolve scope | the discovered already-actioned dominators, confirmed with the user |
| preserve-as-correlation | signal-worthy categories (e.g. C2/DGA), confirm with the user |
| note text | templated, states why the alert was auto-resolved |
| naming prefix | ask (e.g. customer code) |
| site/account scope | ask at deploy |

## Step 0: confirm the alert class and window

```
class_uid=99602001 | group c=count() | limit 1
```

If 0, discover the class: `| group c=count() by class_uid, class_name | sort -c | limit 20`. Use the
class the tenant's alerts actually carry for every query below. Reuse the project schema cache if one
exists (`s1_sdl_schema_cache.json`); otherwise enumerate sources first.

## Step 1: quantify the queue (all discovery, no assumptions)

Run these with the confirmed filter and window. Each is parameterized on `<ALERT_FILTER>` and the
window; none names a product.

Volume by product:
```
<ALERT_FILTER> finding_info.title=* | group Alerts=count() by Product=metadata.product.name | sort -Alerts
```

Ingested vs S1-native (the "is this even our detection" test):
```
<ALERT_FILTER> | group Alerts=count() by Product=metadata.product.name, LogName=metadata.log_name, AnalyticType=finding_info.analytic.type, TypeId=finding_info.analytic.type_id | sort -Alerts
```
Confirm ingestion for a suspected source with a rule-uid presence check (0 rows = ingested, not a
rule): `<ALERT_FILTER> metadata.product.name='<PRODUCT>' finding_info.analytic.uid=* | group c=count() | limit 1`.

Severity split:
```
<ALERT_FILTER> severity_id=* | group Alerts=count() by severity_id | sort severity_id
```

Noisiest signatures:
```
<ALERT_FILTER> finding_info.title=* | group Alerts=count() by Detection=finding_info.title, Product=metadata.product.name, Category=finding_info.analytic.category | sort -Alerts | limit 25
```

Time series (spot an onboarding spike that explains a step change in volume):
```
<ALERT_FILTER> | group Alerts=count() by timestamp=timebucket('1 day') | sort timestamp
```

## Step 2: discover the source action field, then classify

For the noisiest ingested source, schema-discover its raw feed (`dataSource.name='<SOURCE>'`) to find
the field that records what the source did with the event (commonly `unmapped.action`). Then break the
dominators down by signature x action x severity:
```
dataSource.name='<SOURCE>' finding_info.title=* | group Alerts=count() by Signature=finding_info.title, Action=<ACTION_FIELD>, Severity=severity_id | sort -Alerts | limit 25
```
Label each dominator: already-actioned (action in the discovered block/drop/sinkhole/reset set),
informational-only, or signal-worth-keeping. This table is the evidence for every recommendation.

## Step 3: recommend (evidence-backed, per finding)

- **Ingestion filter.** If the noise is an ingested third-party source, the cheapest fix is the
  connector's Alert Ingestion Filter (a console setting on the marketplace alert config, not an API
  object). Recommend keeping High + Critical and dropping Informational/Low/Medium, quantified from
  the Step 1 severity split. If the remaining High is dominated by already-actioned signatures, offer
  Critical-only and cover the residual with auto-resolution or a correlation rule.
- **Per-signature auto-resolution.** For already-actioned dominators that still need to appear (audit)
  but not triage, deploy the auto-resolve HA flow (Step 4) to close them with a note.
- **Preserve signal.** For signal-worthy categories, deploy one correlation rule (reuse the
  `custom-detection-exclusions` or a scheduled PowerQuery detection) that fires on an aggregate
  ("host made N C2/DGA lookups in an hour"), not per event.
- **Real detections.** Confirm the S1-native detections (STAR/EDR/CWS/identity/email) are the small
  remainder and route triage there.

State what is API-deployable (dashboard, HA flow, exclusion lookup, correlation rule) vs a console
recommendation (the marketplace connector's ingestion severity filter). Never claim to have changed a
setting that only a human can change in the console.

## Step 4: deploy artifacts (render templates with discovered values)

Deploy in this order through the primitive skills. Every artifact is prefixed with the naming prefix.

1. **Noise-vs-signal dashboard.** Render `assets/alertnoise_dashboard.template.json`, filling
   `<<ALERT_FILTER>>`, `<<NOISY_PRODUCT>>`, `<<NOISY_SOURCE>>`, `<<ACTION_FIELD>>`, `<<PREFIX>>`.
   Deploy with `sdl_put_file` to `/dashboards/<<PREFIX>> Alert Noise Reduction`. Validate every panel
   with the `sdl-dashboard` skill's checks before deploy.
2. **Auto-resolve HA flow.** Render `assets/alertnoise_autoresolve_ha.template.json`, filling
   `<<NOISY_PRODUCT>>`, the trigger match conditions (`<<MATCH_NAME>>`, `<<MATCH_CATEGORY>>`), and
   `<<NOTE_TEXT>>`. Import scoped, then publish to a Shared Draft in the SAME step (an imported flow is
   a Private Draft owned by the API user until published). Leave it inactive for the user to review,
   bind the SentinelOne connection, and activate. See the hyperautomation skill for the publish call.
3. **Optional exclusion lookup / correlation rule.** Use the `custom-detection-exclusions` solution
   for a maintainable CSV anti-join, or a scheduled PowerQuery detection for the preserve-as-signal
   correlation.

## Step 5: validate and hand off

- Re-run the dashboard panels and confirm they render (screenshots) and match the Step 1/2 numbers.
- Confirm the HA flow imported, published to Shared Draft, and is inactive.
- Report projected impact from the numbers: current volume, volume removed by the ingestion filter,
  volume auto-resolved, and the residual real-detection count. Use only measured values.
- Hand off the rendered configs and the recommendation email.

## Anti-patterns

- Do not name a product or signature in a query or template without discovering it first this session.
- Do not report a "% noise" or "alerts removed" figure without the query that produced it.
- Do not auto-resolve anything not confirmed already-actioned or benign; auto-resolution is closure,
  not investigation. Set status RESOLVED with a note; do not assert an analyst verdict the evidence
  does not support.
- Do not claim the connector ingestion filter was changed via API; it is a console setting.
- Do not treat a single already-actioned signature tagged "High" as an urgent High.
