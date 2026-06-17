# Common SDL PowerQuery Snippets for Dashboard Panels

Ready-to-paste queries for common security dashboard use cases. All work as `query` values in SDL dashboard JSON.

---

## Threat & Indicator Panels

**Active threats by severity (pie/donut)**
```
index = "activities" activity_type in ("18","19","20","2016","4003","4009","4108","4100","4109","4110","4111","4112")
| group count=count() by data.confidence_level
```

**Threat timeline by status (stacked bar, daily)**
```
index = "activities" activity_type in ("18","19","20","2016","4003","4009","4108","4100","4109","4110","4111","4112","2028")
| let status = (activity_type = 2028 ? data.new_incident_status_title : "Unresolved")
| group newest_status = newest(status) by threat_id, timestamp = timebucket("1 day")
| group count = count() by timestamp, newest_status
| transpose newest_status on timestamp
```

**Top noisiest endpoints by threat count (table)**
```
index = "activities" activity_type in ("18","19","20","2016","4003","4009","4108","4100","4109","4110","4111","4112")
| group count = count() by Computer_Name=data.computer_name
| sort -count
| limit 20
```

**Custom STAR rule alert timeline (stacked bar)**
```
index = "activities" activity_type = 3608 dataSource.category = 'security'
| group count = count() by RuleName=data.ruleName, timestamp = timebucket("1 day")
| transpose RuleName on timestamp
```

**HIFI indicator hits (table)**
```
event.category = 'indicators' indicator.name contains ("blockedMimikatz","bloodHound","maliciousPowershellScript","MetasploitNamedPipeImpersonation","ransomware","brute","samSave","SPNRequestFromPowershell") dataSource.category = 'security'
| group count=count() by indicator.category, indicator.name
| sort -count
```

---

## Network Panels

**Top outbound destinations (table with bar column)**
```
event.category = 'ip' event.network.direction = 'OUTGOING' !isempty(dst.ip.address) dataSource.category = 'security'
| group count = count() by dst.ip.address
| sort -count
| limit 20
```

**Outbound PowerShell (non-RFC1918) by destination IP (table)**
```
src.process.name contains 'powershell' dst.ip.address=* dataSource.category = 'security'
| let rfc1918 = not (dst.ip.address matches '((127\\..*)|(192\\.168\\..*)|(10\\..*)|(172\\.1[6-9]\\..*)|(172\\.2[0-9]\\..*)|(172\\.3[0-1]\\..*)).*')
| filter rfc1918 = true
| group hits=count() by IP=dst.ip.address
| sort -hits
```

**Network connections by direction (line chart)**
```
event.category = 'ip' dataSource.category = 'security'
| group count = count() by timestamp = timebucket("10m"), event.network.direction
| transpose event.network.direction on timestamp
```

**Possible outbound port scan (table)**
```
event.category = "ip" event.network.direction = "OUTGOING" dataSource.category = 'security'
| group distinct_dstport=estimate_distinct(dst.port.number) by dst.ip.address, endpoint.name, src.ip.address, src.process.name, src.process.storyline.id
| sort -distinct_dstport
| columns endpoint.name, src.process.storyline.id, src.process.name, src.ip.address, dst.ip.address, distinct_dstport
| limit 10
```

**Top DNS requests by process (table)**
```
event.category = "dns" dataSource.category = 'security'
| group count = count() by src.process.name, event.dns.request
| sort -count
```

---

## Process Panels

**Top parent processes (table)**
```
event.category = "process" dataSource.category = 'security'
| group count=count() by src.process.name
| sort -count
```

**Process timeline by user (line chart)**
```
event.category = "process" dataSource.category = 'security'
| group count=count() by src.process.user, timestamp = timebucket("1 minute")
| transpose src.process.user on timestamp
```

**Processes grouped by target command line (table)**
```
event.category = "process" dataSource.category = 'security'
| let tgt_details = format("(%s) %s (%s) -> %s", src.process.user, src.process.name, src.process.storyline.id, tgt.process.cmdline)
| group count = count() by tgt_details
| columns count, tgt_details
| sort -count
```

---

## Endpoint / Agent Panels

**Distinct active endpoints (number gauge)**
```
| group estimate_distinct(agent.uuid)
```

**New agents enrolled by site (stacked bar, daily)**
```
dataSource.name='ActivityFeed' activity_type = "17"
| let scope = format("%s / %s", account_name, site_name)
| group count = count() by timestamp = timebucket("1 day"), scope
| transpose scope on timestamp
```

**Agents decommissioned (table)**
```
dataSource.name='ActivityFeed' activity_type in ("47", "49", "50", "51", "52", "54")
| columns Time=created_at, Username=data.username, Scope=data.full_scope_details_path, type, Description=primary_description
| sort -Time
```

---

## User & Authentication Panels

**Login attempts timeline (line chart)**
```
dataSource.name='ActivityFeed' activity_type in ("133", "134", "138", "139", "27", "3629")
| let login_event = (activity_type = 27) ? "user logged in" : (activity_type = 133) ? "Login Failure (existing user)" : (activity_type = 134) ? "Login Failure (unknown user)" : "other"
| group count = count() by timestamp = timebucket("1 day"), login_event
| transpose login_event on timestamp
```

**Failed login count by user (table)**
```
dataSource.name='ActivityFeed' activity_type in ("133")
| group count = count() by Username=data.username, Comments=comments, IP_Address=data.ip_address
| sort -count
```

**Sensitive policy modifications by user (table)**
```
dataSource.name='ActivityFeed' activity_type in ("56","57","68","69","73","76","78","79","84","87","88","105","150")
| group count = count() by Username=data.username
| sort -count
```

---

## File Activity Panels

**File events timeline by type (line chart)**
```
event.category = 'file' dataSource.category = 'security'
| group count = count() by timestamp = timebucket("1 minute"), event.type
| transpose event.type on timestamp
```

**Distinct file interactions by process (table)**
```
event.category = "file" dataSource.category = 'security'
| group distinct_sha1_count = estimate_distinct(tgt.file.sha1), distinct_name_count = estimate_distinct(tgt.file.path) by src.process.name, src.process.image.sha1, event.type, tgt.file.extension
| sort -distinct_name_count
| limit 20
```

---

## Device & Network Control Panels

**USB block/allow timeline (line chart)**
```
dataSource.name='ActivityFeed' activity_type in ("5125", "5126")
| let usb_event = (activity_type = 5125) ? "USB-blocked" : "USB-allowed"
| group count = count() by timestamp = timebucket("1 day"), usb_event
| transpose usb_event on timestamp
```

**Firewall block timeline (line chart)**
```
dataSource.name='ActivityFeed' activity_type = "5232"
| group count = count() by timestamp = timebucket("10 minutes")
```

**Top agents with firewall blocks (stacked bar)**
```
dataSource.name='ActivityFeed' activity_type = "5232"
| group count = count() by data.computer_name
| sort -count
| limit 10
```

---

## RemoteOps / Forensics Panels

**Script executions (table)**
```
dataSource.name='ActivityFeed' activity_type in ("3618") dataSource.category = 'security'
| columns Time=created_at, Username=data.username, Scope=data.full_scope_details_path, type, Description=primary_description
| sort -Time
```

---

## Multi-Source / Enrichment Panels

**Events by data source vendor (pie)**
```
| group count=count() by dataSource.vendor
```

**Geo distribution of source IPs (table)**
```
event.category = 'ip' !isempty(src.ip.address) dataSource.category = 'security'
| group count = count() by country=geo_ip_country(src.ip.address)
| sort -count
```
