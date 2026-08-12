# Common SDL data sources and event patterns

Source-by-source field patterns and starting-point queries for SDL dashboards. Referenced from `SKILL.md`. Always re-run live schema discovery before authoring panels; these are starting points, not a registry.

## Common SDL data sources and event patterns

> ⚠️ **Schemas drift between sessions and tenants.** The patterns below are
> starting points, not a registry. **Run live schema discovery (V1 query via
> `sdl-api` skill) on every source you'll query before authoring
> panels.** PowerQuery's default projection is `timestamp + message` only; it
> cannot discover schemas. Use the V1 `query` method which returns full event
> JSON.

### S1 internal SDL sources are OCSF-rich (NOT stubs)

`dataSource.name` values `alert`, `vulnerability`, `misconfiguration`, `asset`,
`Identity`, and `ActivityFeed` carry **rich OCSF events**, not metadata
stubs. The fields that *look* like they should exist based on the source name
(`alert.severity`, `alert.classification`, `vulnerability.kevAvailable`,
`misconfiguration.severity`) frequently do NOT exist, the actual queryable
fields are OCSF-namespaced.

| Source | OCSF class_uid | Severity field | Endpoint linkage | Notes |
|---|---|---|---|---|
| `alert` | 99602001 (S1 Security Alert) | `severity_id` (numeric 0-5) | `resources[].name`, `resources[].s1_metadata.site_name` (NOTE: `resources[N]` only readable via V1 query, not PowerQuery `columns`) | `finding_info.title` = alert name. `metadata.product.name` ∈ {STAR, EDR, Identity, CWS, EPP}. `class_name` = "S1 Security Alert" |
| `vulnerability` | 2002 (Vulnerability Finding) | `severity_id` + `severity_` (string, often empty) | `resource.s1_metadata.*`, `resource.uid` | `vulnerabilities[].cve.uid`, `vulnerabilities[].affected_packages[].{name,version,vendor_name}`. **No `kevAvailable` field in SDL**, KEV/EPSS metadata lives in the management console only |
| `misconfiguration` | 2003 (Compliance Finding) | `severity_id` | `resources[].s1_metadata.*` | `compliance.standards[]` (CIS_AKS, CIS_KUBERNETES, etc.), `compliance.requirements[]`, `policy.{name,uid,desc}`, `cloud.provider`, `finding_info.title` |
| `asset` | 3004 (Device Inventory) | `severity_id` + `severity_` | `device.agent.uuid`, `device.name`, `device.os.name` | 126 fields (live-confirmed). Rich endpoint inventory. Key fields: `device.agent.{uuid,version,network_status,network_status_title,is_active,is_decommissioned,is_uninstalled,network_quarantine_enabled,last_logged_in_user_name,scan_status}`, `device.os.{name,version,type}`, `device.ip_external`, `device.hw_info.*`, `device.network_interfaces[N].*`. `operation` = OPERATION_UPSERT. No `entity.uid`, no `entity_result.*`, no `agent.health.online` fields; use `device.agent.network_status` for connectivity state |
| `ActivityFeed` | n/a (Hyperautomation / mgmt activity audit) | n/a | `data.scope_id`, `site_id`, `account.id` | 41 fields (live-confirmed). Hyperautomation workflow execution audit log and management console activity log. Key fields: `activity_type` (numeric, e.g. 9207 = workflow execution event, NOT a string), `activity_uuid`, `primary_description`, `secondary_description`, `data.workflow_{id,name,execution_url}`, `data.{scope_id,scope_level,scope_name,site_name,user_id}`, `created_at`, `updated_at`, `context`. `sca:RetentionType = 'ACTIVITY_LOG'`. No `activityType` (camelCase) field. Not useful for threat hunting, use for Hyperautomation audit and compliance workflow tracking |
| `Identity` | 3002 (Authentication) | `severity_id`, `status_id` | `user.name`, `user.domain`, `src_endpoint.ip`, `dst_endpoint.hostname` | `auth_protocol` (Kerberos, NTLM), `ref_event_code` (Win Event ID like 4624), `unmapped.type` ("Logon Success"/"Logon Failure"), `type_name` ("Authentication: Logon") |
| `finding` | n/a: **NOT security findings** | n/a | n/a | `dataSource.category='metrics'`, `tag='ingestionHealth'`, `processor='ocsf-findings'`. This source is OCSF processor latency/batch metrics, not findings |

**OCSF severity_id mapping:** 0=Unknown, 1=Informational, 2=Low, 3=Medium,
4=High, 5=Critical, 6=Fatal. Filter via `severity_id >= 4` for High+Critical.

### Reserved-field rewrite (trailing underscore)

Field names ending in `_` (e.g. `severity_`, `status_`, `classification_`) are
SDL's auto-rename when source data carries a field name colliding with an SDL
reserved name. The underscored form **IS** the canonical, queryable field,
not a sparse alternate. The numeric OCSF variants (`severity_id`, `status_id`,
`class_uid`) live alongside the underscored string fields. The `severity_`
string can be case-mixed (`Critical` and `CRITICAL` both appear), see
`powerquery/references/pitfalls.md` for handling.

### EDR / XDR telemetry (endpoint events from `dataSource.name='SentinelOne'`)

```text
dataSource.category = 'security'
event.category in ('process', 'file', 'ip', 'dns', 'indicators', 'logins', 'url', 'registry')
```

`event.type='Behavioral Indicators'` carries `indicator.category`,
`indicator.name`, `agent.uuid`, `endpoint.name`, `src.process.{user,cmdline,image.path}`.

### Third-party sources

```text
dataSource.vendor = 'Microsoft'        // O365, Azure AD
dataSource.name = 'FortiGate'          // field namespaces differ per event.type, validate each type separately before authoring panels
                                       // traffic:   src_endpoint.ip, dst_endpoint.ip, app_name (populated), unmapped.action, traffic.bytes_out/in
                                       // vpn:       unmapped.srcip (NOT src_endpoint.ip which is null), unmapped.action, unmapped.dstip
                                       // app-ctrl:  app_name is null (not promoted by marketplace parser); extract via two-pass parse from message field
                                       // All types: unmapped.action for the raw action string
dataSource.name = 'Okta'               // unmapped.eventType='user.session.start', status='FAILURE'/'SUCCESS', actor.user.name, src_endpoint.ip, src_endpoint.location.country
dataSource.name = 'Zscaler Internet Access'   // http_request.url.categories
metadata.product.name = 'SharePoint'
```

Re-validate every third-party source schema in Step 2b of session init:
field namespaces vary by parser version and tenant.

### Common PowerQuery patterns for panels

**Top-N table** (always add a bar column with `showBarsColumn: "true"`):

```text
event.category='indicators' | group count=count() by indicator.name | sort -count | limit 20
```

**Timeline line chart** (use `timebucket` + `transpose`):

```text
event.type='process' | group count=count() by timestamp=timebucket('1h'), endpoint.os | transpose endpoint.os on timestamp
```

**Single number** (estimate_distinct for cardinality):

```text
| group estimate_distinct(agent.uuid)
```

**Geo enrichment**:

```text
| group count=count() by country=geo_ip_country(src.ip.address) | sort -count
```

**URL deep-link in table**:

```text
| let Threat_URL = format("https://your-console.sentinelone.net/incidents/threats/%s/overview", threat_id)
| columns Computer=data.computer_name, Threat_URL, Path=data.file_path
```

---
