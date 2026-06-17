# Community Dashboard Examples

These are production-ready SDL dashboard JSON examples. Use them as starting points or copy panels directly. The format is JavaScript-literal (unquoted keys are OK in SDL: it accepts both).

---

## 1. Console Audit & KPI Dashboard

Multi-tab dashboard covering agent lifecycle, threat stats, policy changes, exclusions, network control, device control, Ranger, RemoteOps, Marketplace, and login events. Uses `dataSource.name='ActivityFeed'` for all audit panels.

**Key patterns used:**
- Stacked bar with `timebucket("1 day")` + `transpose` for timelines
- Table panels with `| columns` for clean column naming
- `activity_type in (...)` filtering with quoted string values
- `format(...)` for computed URL deep-links

**Tab: Agents & Scopes**: agent subscriptions by site/group/account/OS, agent updates, decommissions, scope moves.
```javascript
{
  tabs: [{"tabName":"Agents & Scopes",
graphs : [
  {
    graphStyle: "stacked_bar",
    query: "dataSource.name='ActivityFeed' activity_type = \"17\" \n| let scope = format(\"%s / %s\", account_name, site_name)\n| group count = count() by timestamp = timebucket(\"1 day\"), scope\n| transpose scope on timestamp",
    title: "New agents subscribed by site",
    xAxis: "time",
    yScale: "linear",
    layout: { h: 14, w: 20, x: 20, y: 0 }
  },
  {
    query: "dataSource.name='ActivityFeed' activity_type in (\"47\", \"49\", \"50\", \"51\", \"52\", \"54\") \n| columns Time=created_at, Username=data.username, Scope=data.full_scope_details_path, type, Description=primary_description\n| sort -Time",
    title: "Agents decommissioned or uninstalled",
    graphStyle: "",
    showBarsColumn: "false",
    layout: { h: 14, w: 60, x: 0, y: 42 }
  }
]}],
  configType: "TABBED"
}
```

**Tab: Threat Stats**: timeline by confidence/verdict/status, noisiest machines, failed mitigations, custom rule alerts.
```javascript
{
  graphStyle: "stacked_bar",
  query: "index = \"activities\" activity_type in (\"18\",\"19\",\"20\",\"2016\",\"4003\",\"4009\",\"4108\",\"4100\",\"4109\",\"4110\",\"4111\",\"4112\", \"2036\",\"2037\")\n| let confidence = (activity_type in (\"2036\",\"2037\") ? data.new_confidence_level : data.confidence_level)\n| group newest_confidence=newest(confidence) by threat_id, timestamp = timebucket(\"1 day\")\n| group count = count() by timestamp, newest_confidence\n| transpose newest_confidence on timestamp",
  title: "Threat timeline by confidence",
  xAxis: "time",
  yScale: "linear"
}
```

**Tab: Conf & Policy Changes**: sensitive policy mods by user/scope, device control changes, network quarantine, inheritance changes.
```javascript
{
  query: "dataSource.name='ActivityFeed' activity_type in (\"56\", \"57\", \"68\", \"69\", \"73\", \"76\", \"78\", \"79\", \"84\", \"105\", \"87\", \"88\", \"150\") \n| columns Time=created_at, Username=data.username, Scope=data.full_scope_details_path, type, Description=primary_description\n| sort -Time",
  title: "Sensitive policy modifications details",
  graphStyle: "",
  showBarsColumn: "false"
}
```

---

## 2. Purple AI Audit Dashboard

Tracks Purple AI usage by analyst.
```javascript
{
  description: "",
  tabs: [{"tabName":"PurpleAI","graphs":[
    {
      query: "serverHost='scalyr-metalog' action='addPurpleInputOutputMessage'\n| group count = count() by analyst=inputContent.userDetails.emailAddress\n| sort -count",
      title: "Count of PurpleAI questions by analyst",
      graphStyle: "",
      showBarsColumn: "true",
      layout: { h: 12, w: 15, x: 0, y: 0 }
    },
    {
      query: "source = \"scalyr\" action = 'addPurpleInputOutputMessage'\n| let output = (!isempty(outputContent.message) ? outputContent.message : outputContent.powerQuery.query)\n| columns timestamp, conversationId, analyst=inputContent.userDetails.emailAddress, inputContent.userInput, output \n| sort conversationId, +timestamp",
      title: "All questions to PurpleAI by user",
      graphStyle: "",
      showBarsColumn: "false",
      layout: { h: 17, w: 60, x: 0, y: 12 }
    },
    {
      graphStyle: "line",
      lineSmoothing: "straightLines",
      query: "source = \"scalyr\" serverHost='scalyr-metalog' action='addPurpleInputOutputMessage'\n| group count = count() by timestamp = timebucket(\"1 hour\"), status\n| transpose status on timestamp",
      title: "PurpleAI usage timeline by status",
      yScale: "linear",
      layout: { h: 12, w: 15, x: 45, y: 0 }
    },
    {
      graphStyle: "stacked_bar",
      query: "source = \"scalyr\" action = 'addPurpleInputOutputMessage'\n| let analyst=inputContent.userDetails.emailAddress\n| group count = count() by timestamp = timebucket(\"1 day\"), analyst\n| transpose analyst on timestamp",
      title: "PurpleAI query timeline by user",
      xAxis: "time",
      yScale: "linear",
      layout: { h: 12, w: 30, x: 15, y: 0 }
    }
  ]}],
  configType: "TABBED"
}
```

---

## 3. Alert Investigation Dashboard

Multi-tab investigation dashboard with filters for `endpoint.name` and `src.process.storyline.id`. Covers event overview, process tree, file activity, network, indicators, and lateral movement.

**Tab: Overview**: event category breakdown, indicator categories, file timeline, outbound IPs, DNS by process.
```javascript
{
  tabs: [{"tabName":"Overview","graphs":[
    {
      graphStyle: "stacked_bar",
      query: "event.category contains \"\" dataSource.category = 'security'\n| group count = count() by event.category\n| sort -count",
      title: "Count by event category",
      xAxis: "grouped_data",
      yScale: "linear"
    },
    {
      query: "event.category = \"ip\" event.network.direction = \"OUTGOING\" dataSource.category = 'security'\n| group count = count() by dst.ip.address, src.process.name\n| sort -count\n| columns src.process.name, dst.ip.address, count",
      title: "TOP outgoing IP connections by process",
      graphStyle: "",
      showBarsColumn: "true"
    },
    {
      query: "event.category = \"dns\" dataSource.category = 'security'\n| group count = count() by src.process.name, event.dns.request\n| sort -count",
      title: "TOP DNS petitions by process"
    }
  ],
  filters: [
    { facet: "endpoint.name", name: "Endpoint name" },
    { facet: "src.process.storyline.id", name: "Src storyline ID" }
  ],
  options: {layout: {locked: 1}}
  }],
  configType: "TABBED"
}
```

**Tab: File**: file event timeline, distinct file interactions by process, possible ransom notes detection.
```javascript
{
  query: "event.category = \"file\" dataSource.category = 'security' \n| let windows_path_array = array_split(tgt.file.path, \"\\\\\\\\\")\n| let windows_directory_path_array = array_slice(windows_path_array, 0, len(windows_path_array)-1)\n| let windows_directory_path_string = array_to_string(windows_directory_path_array, \"\\\\\")\n| let windows_filename_string = windows_path_array.get(len(windows_path_array)-1)\n| let unix_path_array = array_split(tgt.file.path, \"/\")\n| let unix_directory_path_array = array_slice(unix_path_array, 0, len(unix_path_array)-1)\n| let unix_directory_path_string = array_to_string(unix_directory_path_array, \"/\")\n| let unix_filename_string = unix_path_array.get(len(unix_path_array)-1)\n| let directory_path_string = (endpoint.os = \"windows\") ? windows_directory_path_string : unix_directory_path_string\n| let filename_string = (endpoint.os = \"windows\") ? windows_filename_string : unix_filename_string\n| group distinct_path_count = estimate_distinct(directory_path_string) by endpoint.name, src.process.name, src.process.image.sha1, event.type, tgt.file.extension, filename_string\n| sort -distinct_path_count\n| columns src.process.name, event.type, distinct_path_count, filename_string\n| limit 10",
  title: "Possible ransom notes"
}
```

**Tab: Network**: IP timeline by direction/status, outbound/inbound scan detection, top destinations/sources.
```javascript
{
  query: "event.category = \"ip\" and event.network.direction = \"OUTGOING\" dataSource.category = 'security'\n| group distinct_dstip=estimate_distinct(dst.ip.address) by endpoint.name, src.ip.address, src.process.name, src.process.storyline.id\n| sort -distinct_dstip\n| columns endpoint.name, src.process.storyline.id, src.process.name, src.ip.address, distinct_dstip\n| limit 10",
  title: "Possible outbound network scan"
}
```

**Tab: Indicators**: indicator category breakdown, HIFI (high-fidelity) indicators, full indicator list.
```javascript
{
  query: "event.category = 'indicators' indicator.name contains (\"appLockerBypass\",\"blockedMimikatz\",\"bloodHound\",\"maliciousPowershellScript\",\"MetasploitNamedPipeImpersonation\",\"ransomware\",\"brute\") dataSource.category = 'security'\n| group count=count() by indicator.category, indicator.name\n| sort -count",
  title: "HIFI Indicators"
}
```

---

## 4. O365 / Azure AD Dashboard

Multi-tab dashboard for Microsoft data sources. Tabs: O365 Alerts, Azure Login Activity, Azure AD lifecycle, SharePoint, OneDrive.

**Tab: O365 Alerts**
```javascript
{
  query: "dataSource.vendor = 'Microsoft' activity_name='newAlert'\n| columns metadata.original_time, severity=unmapped.severity, finding.types, finding.title, details=unmapped.userStates, url=finding.src_url\n| sort -metadata.original_time",
  title: "Microsoft Alerts",
  graphStyle: "",
  showBarsColumn: "false"
}
```

**Tab: Azure Login Activity**: logon status timeline, top 15 failing users, logins by country, failed logins by country, every login attempt detailed (with geo enrichment, OS, browser extraction from JSON arrays).
```javascript
{
  query: "dataSource.vendor='Microsoft' metadata.product.name='AzureActiveDirectory' event.type in ('Logon', 'UserLoginFailed') !isempty(actor.user.email_addr)\n| let ip_address = event.type='Logon' ? device.ip : unmapped.ActorIpAddress\n| let data_array = array_from_json(unmapped.DeviceProperties)\n| let os = json_object_value(data_array.get(0), \"Name\")=\"OS\" ? json_object_value(data_array.get(0), \"Value\") : \"not found\"\n| let browser = json_object_value(data_array.get(0), \"Name\")=\"BrowserType\" ? json_object_value(data_array.get(0), \"Value\") : \"not found\"\n| group count = count() by actor.user.email_addr, event.type, os, browser, ip_address, country=geo_ip_country(ip_address), unmapped.LogonError\n| sort -count",
  title: "Every login attempt detailed"
}
```

**Tab: OneDrive**: download timeline, top users downloading by GB and distinct file count.
```javascript
{
  query: "dataSource.vendor='Microsoft' metadata.product.name='OneDrive' event.type in ('FileDownloaded')\n| group downloaded_bytes = sum(unmapped.FileSizeBytes), distinct_files=estimate_distinct(unmapped.SourceFileName) by user=unmapped.UserId\n| let downloaded_gbytes = downloaded_bytes/1024/1024/1024\n| columns user, downloaded_gbytes, distinct_files\n| sort -distinct_files\n| limit 10",
  title: "Top users downloading by distinct file count"
}
```

---

## 5. Fortinet Dashboard

Single-tab dashboard with parameters for dynamic filtering. Covers source/destination IPs, bytes sent/received, URL categories, protocol breakdown.

Uses a hidden parameter pattern:
```javascript
{
  parameters: [
    {
      name: "base_search",
      options: { display: "hidden" },
      defaultValue: "dataSource.name='Fortigate'"
    }
  ],
  graphs: [
    {
      query: "dataSource.vendor='Fortinet' | group count = count() by dst_endpoint.location.country | sort -count | limit 20",
      title: "Top Destination Countries",
      graphStyle: "donut",
      maxPieSlices: 20,
      dataLabelType: "PERCENTAGE"
    },
    {
      query: "| parse \"$bytes_out{regex=\\\\d+}$\" from traffic.bytes_out\n| filter( dataSource.name == \"FortiGate\" AND event.type == \"traffic\" )\n| group TotalBytesSent = sum( bytes_out )\n| limit 1000",
      title: "Total Bytes Sent in Timeframe",
      graphStyle: "number",
      trendConfig: {
        enabled: true,
        indicators: {
          arrow: { enabled: true },
          number: { calculationType: "PERCENTAGE", enabled: true },
          upwardsMeaning: "POSITIVE"
        }
      }
    },
    {
      query: "dataSource.category = 'security' | filter( dataSource.name == \"FortiGate\" AND metadata.log_name == \"webfilter\" )\n| group URLCount = count() by http_request.url.categories | sort -URLCount | limit 1000",
      title: "URL Categories",
      graphStyle: "pie",
      maxPieSlices: 10
    }
  ],
  description: "Fortinet FortiGate traffic and security events"
}
```

---

## 6. Sankey Login Flow Dashboard

Shows external and internal login flows across country, process, user, host, and result stages. Uses `array(...).expand()` to fan each result row into multiple Sankey links.

**Key patterns:**
- `array(0, 1, 2, 3).expand()` to produce one link row per stage from a single aggregated row
- `sankeyColorMapping` with glob patterns (`"Inbound Login:*"`, `"*✅:*"`) for semantic coloring
- `| left join` to enrich with TI indicator matches before building links

```javascript
{
  configType: "TABBED",
  tabs: [{
    tabName: "Sankey",
    graphs: [
      {
        graphStyle: "sankey",
        title: "Top 35 External Login Events: Country → Process → User → Host → Result",
        colorMatching: "manual",
        sankeyColorScheme: "semantic",
        showNodeValues: "true",
        sankeyColorMapping: [
          { key: "positive", value: ["Success", "sshd"] },
          { key: "caution",  value: ["Process:*"] },
          { key: "warning",  value: ["Inbound Login:*"] },
          { key: "negative", value: ["Fail"] }
        ],
        query: "event.type == 'Login'\nAND event.login.type in:matchcase('REMOTE_INTERACTIVE', 'NETWORK', 'CACHED_REMOTE_INTERACTIVE')\nAND !net_private(src.endpoint.ip.address)\n| let country = geo_ip_country(src.endpoint.ip.address)\n| let process = src.process.name\n| let user = event.login.userName\n| let host = endpoint.name\n| let result = event.login.loginIsSuccessful ? 'Success' : 'Fail'\n| filter country != null && !(country in ('unknown', ''))\n| group c = count() by country, process, user, host, result\n| sort -c | limit 35\n| let link = array(0, 1, 2, 3).expand()\n| let source = link==0 ? 'Inbound Login: '+country : link==1 ? 'Process: '+process : link==2 ? user : host\n| let target = link==0 ? 'Process: '+process : link==1 ? user : link==2 ? host : result\n| group c = sum(c) by source, target\n| columns source, target, c",
        layout: { h: 29, w: 60, x: 0, y: 0 }
      },
      {
        graphStyle: "sankey",
        title: "Top 35 Connections by File Hash (With TI Match)",
        colorMatching: "manual",
        sankeyColorScheme: "semantic",
        showNodeValues: "true",
        sankeyColorMapping: [
          { key: "positive", value: ["*❌:*"] },
          { key: "caution",  value: ["File:*"] },
          { key: "warning",  value: ["Country:*"] },
          { key: "negative", value: ["*✅:*"] }
        ],
        query: "| left join\nmain = (\n  dst.ip.address=* src.process.activeContent.hash=*\n  AND !net_private(dst.ip.address)\n  | let fileName = src.process.image.originalFileName\n  | let sha1 = src.process.activeContent.hash\n  | let dstIP = dst.ip.address\n  | let country = geo_ip_country(dst.ip.address)\n  | group c = count() by fileName, sha1, dstIP, country\n  | sort -c | limit 35\n),\nti_sha1 = (\n  event.category = 'threat_intelligence_indicators' tiIndicator.type = 'Sha1'\n  | group tiSHA1Count = count() by sha1Value = tiIndicator.value\n),\nti_ip = (\n  event.category = 'threat_intelligence_indicators' tiIndicator.type = 'IPv4'\n  | group tiIPCount = count() by ipValue = tiIndicator.value\n)\non main.sha1 = ti_sha1.sha1Value, main.dstIP = ti_ip.ipValue\n| let sha1Label = tiSHA1Count != null ? 'SHA1 ✅: '+sha1 : 'SHA1 ❌: '+sha1\n| let ipLabel = tiIPCount != null ? 'IP ✅: '+dstIP : 'IP ❌: '+dstIP\n| let link = array(0, 1, 2, 3).expand()\n| let source = link==0 ? 'All Events (Source)' : link==1 ? 'File: '+fileName : link==2 ? sha1Label : ipLabel\n| let target = link==0 ? 'File: '+fileName : link==1 ? sha1Label : link==2 ? ipLabel : 'Country: '+country\n| group c = sum(c) by source, target\n| columns source, target, c",
        layout: { h: 30, w: 60, x: 0, y: 0 }
      }
    ]
  }]
}
```

---

## 7. Bullet Chart: MTTR vs SLA by Severity

Shows average time-to-respond per alert severity against SLA targets, with color zones. Use `coloringMode: "kpiReach"` when you want the whole bar to go red if SLA is missed.

```javascript
{
  configType: "TABBED",
  tabs: [{
    tabName: "SLA",
    graphs: [
      {
        graphStyle: "bullet",
        title: "Average MTTR by Severity vs SLA Target",
        query: "| datasource alerts | filter (status = 'RESOLVED')\n| group completion_minutes=avg(number(resolveSLOCompletion))/60 by severity\n| let slo_target = severity='CRITICAL' ? 60 : severity='HIGH' ? 120 : severity='MEDIUM' ? 180 : 300\n| let sev_sort = severity='CRITICAL' ? 5 : severity='HIGH' ? 4 : severity='MEDIUM' ? 3 : severity='LOW' ? 2 : 1\n| sort -sev_sort\n| columns completion_minutes, slo_target, severity",
        bulletColorScheme: "semantic",
        coloringMode: "kpiReach",
        colorSchemeOrder: "standard",
        aboveKPIColor: "negative",
        belowKPIColor: "positive",
        rangesCreation: "automatic",
        numberOfRanges: 4,
        bulletColorRangeConfig: { ranges: [] },
        layout: { h: 13, w: 30, x: 0, y: 0 }
      },
      {
        graphStyle: "bullet",
        title: "Semantic Manual Ranges",
        query: "| union\n( | limit 1 | let time_to_respond = 15, sla = 30, _severity = 'critical'),\n( | limit 1 | let time_to_respond = 45, sla = 60, _severity = 'high'),\n( | limit 1 | let time_to_respond = 180, sla = 120, _severity = 'medium'),\n( | limit 1 | let time_to_respond = 30, sla = 240, _severity = 'low')",
        bulletColorScheme: "semantic",
        coloringMode: "ranges",
        colorSchemeOrder: "standard",
        aboveKPIColor: "neutral",
        belowKPIColor: "negative",
        rangesCreation: "manual",
        numberOfRanges: 4,
        bulletRangeConfig: ["0", "22", "23", "34", "1000"],
        bulletColorRangeConfig: {
          ranges: [
            { color: "var(--g-dv-semantic-positive)", range: { min: "25", max: "30" }, value: "25" },
            { color: "var(--g-dv-semantic-warning)",  range: { min: "30", max: "50" }, value: "30" },
            { color: "var(--g-dv-semantic-negative)", range: { min: "50", max: "100" }, value: "100" },
            { color: "var(--g-dv-semantic-caution)",  range: { min: "100", max: "300" }, value: "220" }
          ]
        },
        layout: { h: 21, w: 30, x: 0, y: 13 }
      }
    ]
  }]
}
```

---

## 8. Bubble Chart: Port Scan and Network Outlier Detection

Bubble scatter charts for outlier detection. x = distinct ports, y = distinct destination IPs, bubble size = total connections. Upper-right outliers are active scanners.

```javascript
{
  configType: "TABBED",
  tabs: [{
    tabName: "Network Outliers",
    graphs: [
      {
        graphStyle: "scattered_bubble",
        title: "Internal Service Sweep (T1046): Source IPs",
        description: "Upper-right = active port scanners. Bubble size = total connections. Label = source IP for immediate action.",
        startTime: "4 hours",
        query: "event.network.direction = 'OUTGOING'\n| filter dst.ip.address != src.ip.address\n| filter dst.port.number in ('21','22','80','443','445','1433','3306','3389')\n| filter net_rfc1918(dst.ip.address) = true\n| group\n    tgt_port_count = estimate_distinct(dst.port.number),\n    tgt_ip_count   = estimate_distinct(dst.ip.address),\n    conn_count     = count()\n  by src.ip.address\n| filter tgt_port_count >= 2\n| sort -tgt_port_count\n| columns tgt_port_count, tgt_ip_count, conn_count, label=src.ip.address",
        scatteredBubbleConfig: { showLabel: true },
        layout: { h: 26, w: 30, x: 0, y: 0 }
      },
      {
        graphStyle: "scattered_bubble",
        title: "Count of Network Ports by Source Hosts",
        startTime: "2 hours",
        query: "event.type='IP Connect'\n| group proto=any(event.network.protocolName), count=count(), src_count=estimate_distinct(src.ip.address) by dst_port=dst.port.number\n| columns dst_port, src_count, count, label=dst_port",
        scatteredBubbleConfig: { showLabel: true },
        layout: { h: 26, w: 30, x: 30, y: 0 }
      }
    ]
  }]
}
```

---

## 9. Heatmap: Off-Hours Activity and Event Volume Spikes

```javascript
{
  configType: "TABBED",
  tabs: [{
    tabName: "Behavioral Heatmaps",
    graphs: [
      {
        graphStyle: "heatmap",
        title: "Off-Hours Process Execution by User (22:00–06:00)",
        description: "Dark cells = high activity outside business hours. Top 10 users during off-hours.",
        startTime: "7d",
        query: "| left join\ntimeseries = (\n  event.type = 'Process Creation'\n  | filter !(src.process.user contains:anycase 'SYSTEM') AND src.process.user != null\n  | let hour_local = number(strftime(event.time * 1_000_000, '%H', 'UTC'))\n  | filter hour_local >= 22 OR hour_local < 6\n  | group EventCount = count() by User = src.process.user, timestamp = timebucket('1h')\n),\ntop10 = (\n  event.type = 'Process Creation'\n  | filter !(src.process.user contains:anycase 'SYSTEM') AND src.process.user != null\n  | let hour_local = number(strftime(event.time * 1_000_000, '%H', 'UTC'))\n  | filter hour_local >= 22 OR hour_local < 6\n  | group Total = count() by User = src.process.user\n  | sort -Total | limit 10\n)\non User\n| filter !isempty(Total)\n| columns User, EventCount, timestamp\n| transpose User on timestamp",
        colorScheme: "red",
        colorSchemeOrder: "standard",
        numberOfRanges: 5,
        rangesCreation: "automatic",
        heatmapRangeConfig: ["-∞", "", "", "", "", "∞"],
        layout: { h: 14, w: 30, x: 0, y: 0 }
      }
    ]
  }]
}
```

---

## 10. Tabbed Table Panel

A single table panel with multiple query tabs toggled inside the panel: no extra dashboard tabs needed.

```javascript
{
  configType: "TABBED",
  tabs: [{
    tabName: "Event Explorer",
    graphs: [
      {
        graphStyle: "",
        title: "Event Activity",
        query: "event.category = 'process' | columns endpoint.name, src.process.name, event.type",
        tabbed: "true",
        tabVariant: "tile",
        tabs: [
          {
            title: "Process Events",
            query: "event.category=process | group count() by endpoint.name | sort -count"
          },
          {
            title: "Indicator Events",
            query: "event.category=indicators | group count() by endpoint.name | sort -count"
          },
          {
            title: "Network Events",
            query: "event.category=ip | group count() by src.process.name | sort -count"
          }
        ],
        layout: { h: 25, w: 60, x: 0, y: 0 }
      }
    ]
  }]
}
```

---

## 11. SOC KPI Overview Row (number + gauge + donut)

Standard 4-panel KPI row pattern. Width = 15 per panel × 4 = 60 total. Combine `number` (with sparkline), `gauge` (for queue health), and `donut` (for distribution).

```javascript
{
  configType: "TABBED",
  tabs: [{
    tabName: "SOC Overview",
    graphs: [
      {
        graphStyle: "number",
        title: "Agents In Scope",
        query: "| datasource assets where (surfaces = 'Endpoint') count_by 'category' | group sum(count)",
        options: { format: "commas" },
        sparklineConfig: { enabled: true },
        trendConfig: {
          enabled: true,
          upwardsMeaning: "POSITIVE",
          indicators: { arrow: { enabled: true }, number: { enabled: true, calculationType: "PERCENTAGE" } }
        },
        layout: { h: 10, w: 15, x: 0, y: 0 }
      },
      {
        graphStyle: "number",
        title: "New Unassigned Alerts",
        query: "| datasource alerts where (status in ('NEW') and !(assigneeUserId = *)) count_by assigneeUserId | group sum(count)",
        options: { format: "commas" },
        sparklineConfig: { enabled: true },
        trendConfig: {
          enabled: true,
          upwardsMeaning: "NEGATIVE",
          indicators: { arrow: { enabled: true }, number: { enabled: true, calculationType: "PERCENTAGE" } }
        },
        chartLinkConfig: { url: "/incidents/unified-alerts?alertsTable.filters=status%3DNEW%26assigneeUserId%3D" },
        layout: { h: 10, w: 15, x: 15, y: 0 }
      },
      {
        graphStyle: "gauge",
        title: "SOC Queue Health",
        query: "event.category = 'indicators' | group estimate_distinct(src.process.storyline.id)",
        colorRangeConfig: {
          ranges: [
            { color: "#1CAA5D", range: { min: 0,   max: 100  } },
            { color: "#E6752D", range: { min: 100, max: 500  } },
            { color: "#E0483C", range: { min: 500, max: 5000 } }
          ]
        },
        layout: { h: 10, w: 15, x: 30, y: 0 }
      },
      {
        graphStyle: "donut",
        title: "Agent Operational State",
        query: "| datasource assets from 'workstation, server' where (surfaces = 'Endpoint') count_by 'agentOperationalState' | group count=sum(count) by agentOperationalState | filter count > 0",
        maxPieSlices: 10,
        dataLabelType: "VALUE",
        totalNumberConfig: { enabled: true },
        layout: { h: 10, w: 15, x: 45, y: 0 }
      }
    ]
  }]
}
```

---

## 12. Dynamic Filtering: `filters[]` (TABBED) vs `#VarName#` (flat only)

SDL has two filtering mechanisms that work in different dashboard types.

### `filters[]` in TABBED dashboards — the correct approach

Declare `filters[]` inside a tab object. SDL populates the dropdown from live field values and applies the selection to all panels in that tab automatically. No query changes needed.

```javascript
{
  configType: "TABBED",
  tabs: [{
    tabName: "Alerts",
    filters: [
      { facet: "metadata.product.name", name: "Alert Product" },
      { facet: "endpoint.name", name: "Endpoint" }
    ],
    graphs: [
      {
        graphStyle: "",
        showBarsColumn: true,
        title: "Alerts by Title",
        query: "dataSource.name='alert' finding_info.title=*\n| group count=count() by finding_info.title, metadata.product.name\n| sort -count | limit 20",
        layout: { h: 22, w: 30, x: 0, y: 0 }
      }
    ]
  }]
}
```

Selecting "STAR" from the Alert Product dropdown filters all panels on the tab to `metadata.product.name='STAR'` without any query edits.

### `#VarName#` substitution — flat (non-TABBED) dashboards only

`#VarName#` query injection works only in flat dashboards (no `configType`, no `tabs`). The reference implementation is `parameter_examples-v1.0.json`. In a TABBED dashboard, `#VarName#` is passed literally to the query engine and throws `Don't understand [#]`.

Pre-quoting rule: string values must embed single quotes — `"'logVolume'"` so substitution produces `tag='logVolume'`. Use `"*"` for wildcard.

```javascript
{
  // NO configType, NO tabs — flat dashboard only
  parameters: [
    {
      name: "Specified Tag",
      values: [
        { label: "All", value: "*" },
        { label: "Log Volumes", value: "'logVolume'" },
        { label: "Sample", value: "'sample'" }
      ],
      defaultValue: "*"
    }
  ],
  graphs: [
    {
      graphStyle: "table",
      title: "Count by serverHost / Tag",
      query: "tag=#Specified Tag# | group count=count() by serverHost, tag | sort -count | limit 20",
      layout: { h: 14, w: 33, x: 0, y: 0 }
    }
  ]
}
```

---

## Panel Snippets Library

### Activity type quick reference (ActivityFeed)
Common activity types for audit dashboards:
- `"17"`: Agent subscribed (new enrollment)
- `"43"`: Agent updated
- `"47","49","50","51","52","54"`: Agent decommissioned/uninstalled
- `"18","19","20"`: Threat created/confirmed/mitigated
- `"2028"`: Threat resolved (use `data.new_incident_status_title`)
- `"2030"`: Analyst verdict set
- `"2036","2037"`: Threat confidence updated
- `"3608"`: Custom STAR rule alert
- `"27"`: User logged in
- `"133","134"`: Login failure (existing/unknown user)
- `"56","57","68","69","73","76","78","79","84","87","88","105","150"`: Sensitive policy modifications
- `"5125","5126"`: USB device blocked/allowed
- `"5232"`: Firewall connection blocked
- `"3001","3008"-"3011"`: Exclusions added
- `"3618"`: RemoteOps script executed

### Geo enrichment
```
| let country = geo_ip_country(src.ip.address)
| let state   = geo_ip_state(src.ip.address)
```

### RFC1918 filter (exclude private IPs)
```
| let rfc1918 = not (dst.ip.address matches '((127\\..*)|(192\\.168\\..*)|(10\\..*)|(172\\.1[6-9]\\..*)|(172\\.2[0-9]\\..*)|(172\\.3[0-1]\\..*)).*')
| filter rfc1918 = true
```

### Format deep-link URL
```
| let Threat_URL = format("https://your-console.sentinelone.net/incidents/threats/%s/overview", threat_id)
```

### Normalize values to 0–100 for honeycomb
```
| let max=overall_max(value), min=overall_min(value)
| let normalized = ((value - min)/(max - min))*100
```
