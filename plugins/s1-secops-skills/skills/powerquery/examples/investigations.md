# Investigation library

Ready-to-run PowerQueries for hunts and triage. Each block has:

- **Use it when**: the situation that calls for the query.
- **Query**: paste-able PowerQuery body.
- **Tune**: knobs to widen or narrow.
- **Pivot**: where to go after results.

All queries assume the EDR or XDR data view unless noted. They're written to be safe to run on a busy tenant — `limit` is set, group keys are bounded, and intermediate cardinality stays under 100k.

---

## Endpoint health and inventory

### Recent agents reporting in

**Use it when** you need to confirm a tenant has telemetry, or want a fast roll-up of active hosts.

```
| group last_seen = newest(timestamp), events = count() by endpoint.name, agent.uuid
| sort -last_seen
| limit 50
```

**Tune** — drop `agent.uuid` from the group keys for a cleaner host list.
**Pivot** — copy an `agent.uuid` and filter `agent.uuid = '…'` to scope further hunts to a single endpoint.

### Event volume by endpoint

**Use it when** triaging a noisy host or hunting for "the one machine that's different."

```
| group ct = count() by endpoint.name
| sort -ct
| let share_pct = percent_of_total(ct), running = running_percent(ct)
| limit 25
```

`percent_of_total` and `running_percent` produce the Pareto view — the first few rows usually account for most of the volume.

---

## Process activity

### PowerShell with outbound network

**Use it when** hunting for download cradles, C2 beaconing from PS, or general "PowerShell that talked to the internet."

```
event.type = 'Process Creation'
src.process.name in ('powershell.exe', 'pwsh.exe')
src.process.parent.name not in ('explorer.exe', 'svchost.exe', 'services.exe')
| group
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    cmdline   = any(src.process.cmdline),
    parent    = any(src.process.parent.name),
    net_out   = max(src.process.netConnOutCount)
  by agent.uuid, src.process.storyline.id
| filter net_out > 0
| sort -net_out
| limit 100
```

**Tune** — drop the parent-not-in filter to also catch interactive shells; raise `net_out > 5` for higher-confidence beaconing.
**Pivot** — for a hit, query `src.process.storyline.id = '…' and event.type = 'IP Connect'` to see destinations.

### Suspicious office-spawned children (Maldoc style)

**Use it when** triaging phishing, BEC follow-on, or first-stage payload delivery.

```
event.type = 'Process Creation'
src.process.parent.name in ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe')
src.process.name in ('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe', 'bitsadmin.exe')
| group
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    parent     = any(src.process.parent.name),
    child      = any(src.process.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 100
```

**Pivot** — for a hit, look at file activity in the same storyline: `src.process.storyline.id = '…' and event.category = 'file'`.

### Suspicious LOLBin invocations

**Use it when** broad LOLBin sweep — useful as a daily review.

```
event.type = 'Process Creation'
src.process.name in (
  'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'regsvr32.exe',
  'rundll32.exe', 'wmic.exe', 'cscript.exe', 'wscript.exe',
  'installutil.exe', 'msbuild.exe', 'msiexec.exe'
)
src.process.cmdline contains_any ('http://', 'https://', '\\\\', '-encodedcommand', 'frombase64string')
| group
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    bin       = any(src.process.name),
    cmdline   = any(src.process.cmdline),
    count     = count()
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

If `contains_any` isn't available on this tenant, expand to a chain of `or`:

```
... and (
  src.process.cmdline contains 'http://' or
  src.process.cmdline contains 'https://' or
  src.process.cmdline contains '\\\\' or
  src.process.cmdline contains '-encodedcommand' or
  src.process.cmdline contains 'frombase64string'
)
```

### Encoded PowerShell

**Use it when** specifically hunting `-enc` / `-EncodedCommand`.

```
event.type = 'Process Creation'
src.process.name in ('powershell.exe', 'pwsh.exe')
src.process.cmdline matches '(?i)\\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\\b'
| group
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    cmdline   = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 100
```

**Pivot** — copy the cmdline value into a base64 decoder. Most hits are admin scripts; the rest are payloads.

---

## Lateral movement

### SMB-style remote service creation

**Use it when** suspecting psexec / smbexec / remote Service Manager activity.

```
event.type = 'Process Creation'
src.process.parent.name = 'services.exe'
src.process.name in ('cmd.exe', 'powershell.exe', 'pwsh.exe')
src.process.cmdline contains '\\\\\\\\'
| group
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    cmdline   = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 50
```

The four backslashes match a literal `\\` in the command line (UNC prefix); see pitfalls.md for why this much escaping.

### Successful network logons by user (top sources)

**Use it when** investigating credential theft / lateral spread.

```
event.category = 'logins'
event.login.loginIsSuccessful = true
event.login.type in ('NETWORK', 'NETWORK_CLEAR_TEXT', 'REMOTE_INTERACTIVE')
| group
    logons    = count(),
    src_ips   = estimate_distinct(src.endpoint.ip.address),
    last_seen = newest(timestamp)
  by event.login.userName
| sort -logons
| limit 50
```

**Tune** — add `endpoint.name` to `by` to get per-host-per-user.
**Pivot** — for a high-source-count user, drill down: `event.login.userName = 'svc-foo' | group ct = count() by src.endpoint.ip.address | sort -ct`.

### Failed logon spike (likely brute-force)

**Use it when** triaging an authentication-failure alert.

```
event.category = 'logins'
event.login.loginIsSuccessful = false
| group
    fails     = count(),
    targets   = estimate_distinct(event.login.userName),
    last_seen = newest(timestamp)
  by src.endpoint.ip.address
| filter fails >= 10
| sort -fails
| limit 50
```

If `src.endpoint.ip.address` is null on a hit, fall back to the destination endpoint's hostname: `by endpoint.name`.

---

## Credential access

### LSASS memory access

**Use it when** investigating a `CredentialDumping` indicator or a tooling alert.

```
indicator.name in ('CredentialDumping', 'LSASSAccess')
| group
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    process    = any(src.process.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 100
```

**Pivot** — `src.process.storyline.id = '…'` to pull the full storyline. Normal admin tools occasionally trigger this; check `src.process.publisher` for "Microsoft" first.

### Suspicious credential utility use

**Use it when** sweeping for `mimikatz`, `secretsdump`, `procdump lsass`.

```
event.type = 'Process Creation'
(
  src.process.name in ('procdump.exe', 'procdump64.exe') and src.process.cmdline contains 'lsass'
  or src.process.cmdline matches '(?i)mimikatz'
  or src.process.cmdline matches '(?i)secretsdump'
)
| group
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    cmdline   = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 100
```

---

## Defense evasion / persistence

### EventLog clearing

**Use it when** investigating "logs went quiet" or a suspected post-exploitation cleanup.

```
event.type = 'Process Creation'
(
  src.process.cmdline contains 'wevtutil cl'
  or src.process.cmdline matches '(?i)Clear-EventLog'
  or src.process.cmdline matches '(?i)Clear-WinEvent'
)
| group
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    user      = any(src.process.user),
    cmdline   = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 50
```

### Scheduled task creation

**Use it when** persistence hunt.

```
event.type = 'Process Creation'
src.process.name in ('schtasks.exe', 'powershell.exe', 'pwsh.exe')
src.process.cmdline matches '(?i)(schtasks\\s+/create|new-scheduledtask|register-scheduledtask)'
| group
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    cmdline   = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 100
```

### Run-key / autorun registry writes

**Use it when** persistence hunt with registry data.

```
event.type = 'Registry Value Modified'
registry.keyPath matches '(?i)(\\\\Run\\\\|\\\\RunOnce\\\\|\\\\RunServices\\\\)'
| group
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    process   = any(src.process.name),
    cmdline   = any(src.process.cmdline),
    keypath   = any(registry.keyPath),
    value     = any(registry.value)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 100
```

---

## Network

### DNS to suspicious TLDs

**Use it when** sweeping for low-reputation DGA-style domains.

```
event.category = 'network'
event.type = 'DNS Resolved'
dns.request matches '(?i)\\.(top|xyz|tk|ml|cf|gq|ga|cn)$'
| group
    queries   = count(),
    last_seen = newest(timestamp),
    process   = any(src.process.name)
  by endpoint.name, dns.request
| sort -queries
| limit 100
```

### Outbound connections to non-RFC1918 destinations

**Use it when** scoping data exfiltration / C2 beaconing for a single host.

```
event.type = 'IP Connect'
event.network.direction = 'OUTGOING'
endpoint.name = 'EC2AMAZ-4158GRS'
| filter !net_rfc1918(dst.ip.address) and !net_private(dst.ip.address)
| group
    conns    = count(),
    bytes    = sum(net.bytes.tx),
    last     = newest(timestamp),
    process  = any(src.process.name)
  by dst.ip.address, dst.port.number
| sort -conns
| limit 100
```

**Tune** — replace `endpoint.name = '…'` with a broader filter for tenant-wide; that may need a longer window or tighter port filter.
**Pivot**, the heavy-hitter destination IPs go straight into the configured threat-intel MCP for an IP reputation lookup (in the default bundle that's `mcp__virustotal__get_ip_report`; substitute the equivalent tool if you've connected a different provider).

### Beaconing detection (regular intervals)

**Use it when** suspecting a C2 client. Buckets connections per 10-minute window per host+destination, looks for hosts with a high ratio of "active windows."

```
event.type = 'IP Connect'
event.network.direction = 'OUTGOING'
| filter !net_rfc1918(dst.ip.address)
| group windows = estimate_distinct(timebucket('10m')) by endpoint.name, dst.ip.address, dst.port.number
| filter windows >= 6
| sort -windows
| limit 100
```

A high `windows` value over a multi-hour query span suggests periodic / scheduled outbound traffic. Tighten `timebucket` (e.g., `'5m'`) for shorter beacon intervals.

---

## File activity

### Files dropped in temp by suspect parents

**Use it when** investigating dropper / payload staging.

```
event.type in ('File Creation', 'File Modification')
tgt.file.path matches '(?i)\\\\(Temp|AppData\\\\Local\\\\Temp|ProgramData)\\\\.+\\.(exe|dll|ps1|bat|vbs|js|hta)$'
src.process.name in ('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe')
| group
    files     = count(),
    last_seen = newest(timestamp),
    host      = any(endpoint.name),
    cmdline   = any(src.process.cmdline),
    paths     = array_agg_distinct(tgt.file.path, 5)
  by agent.uuid, src.process.storyline.id
| sort -files
| limit 100
```

### Mass file modification (ransomware-shaped)

**Use it when** hunting unfolding ransomware activity. Looks for one process touching many files quickly.

```
event.type in ('File Modification', 'File Rename')
| group
    file_count = estimate_distinct(tgt.file.path),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    process    = any(src.process.name)
  by agent.uuid, src.process.storyline.id
| filter file_count >= 200
| sort -file_count
| limit 50
```

`200` is a starting threshold — tune for your tenant. A backup process can also trip this.

---

## Indicator-driven hunts

### Today's behavioral indicators by category

**Use it when** wanting a high-level summary of what S1's behavioral engine has flagged.

```
indicator.category = *
| group
    count    = count(),
    hosts    = estimate_distinct(endpoint.name),
    samples  = array_agg_distinct(indicator.name, 10),
    last     = newest(timestamp)
  by indicator.category
| sort -count
| limit 25
```

### MITRE technique mention sweep

**Use it when** searching for activity tagged with a specific technique ID (the description field contains the mapping).

```
indicator.description contains 'T1055'
| group
    count = count(),
    hosts = estimate_distinct(endpoint.name),
    last  = newest(timestamp),
    name  = any(indicator.name)
  by indicator.name
| sort -count
| limit 100
```

`T1055` is process injection. Swap for any technique ID.

---

## Inventory and baselining

### Process names, ranked

**Use it when** baselining "what runs on this host" or "what's unique to this host."

```
event.type = 'Process Creation'
endpoint.name = 'LUCKY_NUCK'
| group ct = count() by src.process.name
| sort -ct
| limit 100
```

### Unsigned binaries running

**Use it when** sweeping for non-vendor-signed code.

```
event.type = 'Process Creation'
src.process.signedStatus in ('unsigned', 'unknown')
| group
    runs      = count(),
    hosts     = estimate_distinct(endpoint.name),
    last_seen = newest(timestamp),
    cmdline   = any(src.process.cmdline)
  by src.process.name, src.process.image.path
| sort -runs
| limit 100
```

### Active users on the tenant

**Use it when** scoping who's logged in where.

```
event.category = 'logins'
event.login.loginIsSuccessful = true
| group
    logons    = count(),
    last_seen = newest(timestamp),
    hosts     = estimate_distinct(endpoint.name)
  by event.login.userName
| sort -logons
| limit 100
```

---

## Correlation patterns

### Process tree of a known bad storyline

```
src.process.storyline.id = '<storyline-id>' or tgt.process.storyline.id = '<storyline-id>'
| sort timestamp
| columns timestamp, event.type, src.process.name, src.process.cmdline, tgt.process.name, tgt.file.path
| limit 500
```

If pivoting from any event in a storyline, this gives you the chronological feed.

### Find all events for a hash

```
#hash = '<sha256>'
| sort timestamp
| columns timestamp, endpoint.name, event.type, src.process.name, src.process.cmdline, tgt.file.path
| limit 100
```

### Two-stage join: indicator + outbound network

**Use it when** asking "did the host with the credential-dumping alert also reach out to the internet?"

```
| inner join
    creds = (
      indicator.name = 'CredentialDumping'
      | group last = newest(timestamp), host = any(endpoint.name)
        by agent.uuid, src.process.storyline.id
      | limit 500
    ),
    egress = (
      event.type = 'IP Connect'
      event.network.direction = 'OUTGOING'
      | filter !net_rfc1918(dst.ip.address)
      | group dst = any(dst.ip.address), conns = count()
        by agent.uuid, src.process.storyline.id
      | limit 500
    )
    on agent.uuid, src.process.storyline.id
| columns host, last, dst, conns
| sort -conns
| limit 100
```

---

## Time-series and rate

### Process creation rate per minute

```
event.type = 'Process Creation'
| group rate = count() / queryspan('minutes') by endpoint.name
| sort -rate
| limit 25
```

### Hourly buckets of an indicator

```
indicator.category = 'Persistence'
| group ct = count() by bucket = timebucket('1h')
| sort bucket
| limit 200
```

---

## When to use what

| Question | Start with |
|---|---|
| "Is this host doing X?" | `endpoint.name = '…'` + event-type filter, `| limit 100` |
| "Who's making the most noise?" | `| group ct = count() by endpoint.name \| sort -ct` |
| "How rare is this command line?" | `src.process.cmdline contains '…' \| group by endpoint.name` |
| "Who runs this binary?" | `src.process.name = '…' \| group by endpoint.name, src.process.user` |
| "What did this storyline do?" | `#storylineid = '…' \| sort timestamp` |
| "Did anything use this hash?" | `#hash = '…'` |
| "Who reached out to this IP?" | `dst.ip.address = '…'` |
