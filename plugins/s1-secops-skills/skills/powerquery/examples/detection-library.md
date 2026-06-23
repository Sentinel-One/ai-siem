# Detection rule library

Ready-to-deploy PowerQuery bodies for STAR / Custom Detection / PowerQuery Alerts. Each rule:

- Is sized for the 1,000-row / 1 MB alert budget.
- Uses no `nolimit`, no `compare`, no subqueries.
- Emits `agent.uuid` + `src.process.storyline.id` (or an equivalent asset key) so the detection engine maps the finding to the right asset.
- Carries `oldest(timestamp)` / `newest(timestamp)` as first / last seen.
- Ends with `| sort -count | limit N` to cap alert volume.

Before deploying, run the body in Event Search over 24 hours and walk the threshold down until it's below real activity but above benign noise. See `references/detection-rules.md` for the checklist.

---

## Initial access

### Macro-spawned LOLBin (MITRE T1566.001 + T1059)

```
event.type = 'Process Creation'
src.process.parent.name in ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe')
src.process.name in ('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe', 'bitsadmin.exe')
| group
    count      = count(),
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

### HTA execution from Office or mail client (T1218.005)

```
event.type = 'Process Creation'
src.process.name = 'mshta.exe'
src.process.parent.name in ('winword.exe', 'excel.exe', 'outlook.exe', 'explorer.exe')
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    parent     = any(src.process.parent.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

---

## Execution

### Encoded PowerShell (T1059.001)

```
event.type = 'Process Creation'
src.process.name in ('powershell.exe', 'pwsh.exe')
src.process.cmdline matches '(?i)\\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\\b'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### Suspicious LOLBin with download-like args (T1105)

```
event.type = 'Process Creation'
src.process.name in ('certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe')
(src.process.cmdline contains 'http://' or src.process.cmdline contains 'https://' or src.process.cmdline contains 'frombase64string')
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    bin        = any(src.process.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### Rundll32 launching `javascript:` (T1055 / T1218.011)

```
event.type = 'Process Creation'
src.process.name = 'rundll32.exe'
src.process.cmdline matches '(?i)javascript:'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

---

## Persistence

### Run-key / RunOnce registry write (T1547.001)

```
event.type = 'Registry Value Modified'
registry.keyPath matches '(?i)(\\\\Run\\\\|\\\\RunOnce\\\\|\\\\RunServices\\\\)'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    process    = any(src.process.name),
    keypath    = any(registry.keyPath),
    value      = any(registry.value)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### Scheduled task created from script host (T1053.005)

```
event.type = 'Process Creation'
src.process.cmdline matches '(?i)(schtasks\\s+/create|new-scheduledtask|register-scheduledtask)'
src.process.parent.name not in ('msiexec.exe', 'svchost.exe', 'services.exe')
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### WMI event subscription persistence (T1546.003)

```
event.type = 'Process Creation'
src.process.cmdline matches '(?i)(__EventFilter|CommandLineEventConsumer|FilterToConsumerBinding)'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

---

## Privilege escalation

### UAC bypass via fodhelper / computerdefaults (T1548.002)

```
event.type = 'Registry Value Modified'
registry.keyPath matches '(?i)\\\\Classes\\\\ms-settings\\\\Shell\\\\Open\\\\command'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    process    = any(src.process.name),
    keypath    = any(registry.keyPath),
    value      = any(registry.value)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### Printspoofer / tokenvator / juicypotato (T1134)

```
event.type = 'Process Creation'
src.process.cmdline matches '(?i)(printspoofer|juicypotato|tokenvator|getsystem)'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 50
```

---

## Defense evasion

### EventLog clearing (T1070.001)

```
event.type = 'Process Creation'
(
  src.process.cmdline contains 'wevtutil cl'
  or src.process.cmdline matches '(?i)Clear-EventLog'
  or src.process.cmdline matches '(?i)Clear-WinEvent'
)
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### Defender tampering (T1562.001)

```
event.type = 'Process Creation'
src.process.cmdline matches '(?i)(Set-MpPreference\\s+-Disable|Add-MpPreference\\s+-ExclusionPath|sc\\s+(config|stop)\\s+WinDefend)'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### Shadow copy deletion (pre-ransomware, T1490)

```
event.type = 'Process Creation'
(
  src.process.cmdline matches '(?i)vssadmin\\s+delete\\s+shadows'
  or src.process.cmdline matches '(?i)wmic\\s+shadowcopy\\s+delete'
  or src.process.cmdline matches '(?i)Remove-.*-VolumeShadowCopy'
)
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 50
```

---

## Credential access

### Mimikatz / secretsdump / procdump lsass (T1003.001)

```
event.type = 'Process Creation'
(
  (src.process.name in ('procdump.exe', 'procdump64.exe') and src.process.cmdline contains 'lsass')
  or src.process.cmdline matches '(?i)(mimikatz|sekurlsa|secretsdump|comsvcs\\.dll)'
)
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### Failed logon spike (T1110)

```
event.category = 'logins'
event.login.loginIsSuccessful = false
| group
    fails      = count(),
    targets    = estimate_distinct(event.login.userName),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name)
  by agent.uuid, src.endpoint.ip.address
| filter fails >= 25 and targets >= 3
| sort -fails
| limit 100
```

**Note** — `by agent.uuid, src.endpoint.ip.address` gives one row per (target host, source IP) pair. Tune `fails >= 25` to your environment; most orgs want 10–50.

### S1 built-in CredentialDumping indicator

```
indicator.name = 'CredentialDumping'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    process    = any(src.process.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

---

## Discovery

### Burst of recon commands in one storyline (T1082 / T1087 / T1016)

```
event.type = 'Process Creation'
src.process.name in ('whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe', 'systeminfo.exe', 'hostname.exe', 'ipconfig.exe', 'tasklist.exe', 'quser.exe', 'arp.exe', 'route.exe')
| group
    recon_count = count(),
    distinct_bins = estimate_distinct(src.process.name),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user)
  by agent.uuid, src.process.storyline.id
| filter distinct_bins >= 4
| sort -recon_count
| limit 100
```

A single storyline running whoami + net user + nltest + systeminfo in quick succession is much more interesting than any one of them alone.

---

## Lateral movement

### Remote service creation via SMB (T1021.002)

```
event.type = 'Process Creation'
src.process.parent.name = 'services.exe'
src.process.name in ('cmd.exe', 'powershell.exe', 'pwsh.exe')
src.process.cmdline contains '\\\\\\\\'
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -count
| limit 100
```

### PSEXESVC.exe execution (T1021.002)

```
event.type = 'Process Creation'
src.process.parent.name in ('PSEXESVC.exe', 'paexec.exe', 'csexec.exe')
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    user       = any(src.process.user),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| sort -last_seen
| limit 100
```

---

## Command and control

### Rare-destination beaconing

Detects hosts with many regular outbound connections to a narrow set of external destinations — classic C2 shape.

```
event.type = 'IP Connect'
event.network.direction = 'OUTGOING'
| filter !net_rfc1918(dst.ip.address) and !net_private(dst.ip.address)
| group
    windows = estimate_distinct(timebucket('10m')),
    conns   = count(),
    last    = newest(timestamp)
  by agent.uuid, endpoint.name, dst.ip.address, dst.port.number
| filter windows >= 6 and conns >= 50
| sort -windows
| limit 100
```

### DNS to low-reputation TLD

```
event.category = 'network'
event.type = 'DNS Resolved'
dns.request matches '(?i)\\.(top|xyz|tk|ml|cf|gq|ga)$'
| group
    queries    = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    process    = any(src.process.name)
  by agent.uuid, dns.request
| filter queries >= 5
| sort -queries
| limit 100
```

---

## Exfiltration / impact

### Mass file modification (ransomware shape, T1486)

```
event.type in ('File Modification', 'File Rename')
| group
    files      = estimate_distinct(tgt.file.path),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    process    = any(src.process.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| filter files >= 500
| sort -files
| limit 50
```

Backups and installers can also trip this — pair with an allowlist `lookup` on `src.process.image.path`.

### Archive creation in unusual location (T1560)

```
event.type in ('File Creation', 'File Modification')
tgt.file.path matches '(?i)\\.(7z|rar|zip|tar\\.gz|tgz)$'
tgt.file.path matches '(?i)\\\\(Temp|AppData\\\\Local\\\\Temp|ProgramData|Users\\\\Public)\\\\'
tgt.file.size > 10000000
| group
    files      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    process    = any(src.process.name),
    paths      = array_agg_distinct(tgt.file.path, 5),
    total_size = sum(tgt.file.size)
  by agent.uuid, src.process.storyline.id
| sort -total_size
| limit 50
```

---

## Correlation (join-based)

### Credential theft followed by egress

Fires when the same storyline that tripped the `CredentialDumping` indicator also had outbound traffic to a non-internal IP.

```
| inner join
    creds = (
      indicator.name = 'CredentialDumping'
      | group
          cred_last = newest(timestamp),
          host      = any(endpoint.name),
          process   = any(src.process.name)
        by agent.uuid, src.process.storyline.id
      | limit 500
    ),
    egress = (
      event.type = 'IP Connect'
      event.network.direction = 'OUTGOING'
      | filter !net_rfc1918(dst.ip.address)
      | group
          dst_last = newest(timestamp),
          dst_ip   = any(dst.ip.address),
          conns    = count()
        by agent.uuid, src.process.storyline.id
      | limit 500
    )
    on agent.uuid, src.process.storyline.id
| columns agent.uuid, host, process, cred_last, dst_ip, dst_last, conns
| sort -dst_last
| limit 100
```

### Recon burst + remote logon

Matches a host doing recon AND then seeing a remote interactive logon — "someone ran whoami then logged into another box."

```
| inner join
    recon = (
      event.type = 'Process Creation'
      src.process.name in ('whoami.exe', 'net.exe', 'nltest.exe', 'systeminfo.exe')
      | group recon_count = count(), recon_last = newest(timestamp), host = any(endpoint.name)
        by agent.uuid
      | filter recon_count >= 3
      | limit 500
    ),
    logons = (
      event.category = 'logins'
      event.login.loginIsSuccessful = true
      event.login.type = 'REMOTE_INTERACTIVE'
      | group logon_last = newest(timestamp), logon_user = any(event.login.userName)
        by agent.uuid
      | limit 500
    )
    on agent.uuid
| columns agent.uuid, host, recon_count, recon_last, logon_user, logon_last
| sort -logon_last
| limit 100
```

---

## Allowlisted rules

When a rule is otherwise correct but fires on 1–2 known-good patterns, use a `lookup` against a config datatable to suppress.

```
<filters producing candidate rows>
| group
    count      = count(),
    first_seen = oldest(timestamp),
    last_seen  = newest(timestamp),
    host       = any(endpoint.name),
    cmdline    = any(src.process.cmdline)
  by agent.uuid, src.process.storyline.id
| lookup is_allowed = allowed from allowlist_processes by src.process.image.path
| filter is_allowed = null
| sort -count
| limit 100
```

The allowlist datatable needs a column `allowed` (any truthy value) keyed by the process image path. Keep it ≤ 400 KB and prefer opt-in allowlist over opt-out denylist — it's bounded.

---

## Tuning checklist before deployment

1. Run the body in Event Search over 24h. Expect 0–5 rows in a typical environment; 10+ usually means the filter is too loose.
2. Confirm the `group` intermediate never exceeds 1,000 rows — the filter needs to cut hard upstream.
3. Walk the threshold `count >= N` down until you see a row, then set `N` slightly above benign noise.
4. Run over 7 days to estimate alert volume (expected × 7 ≈ weekly).
5. If the rule depends on a 2-hop indicator chain, prefer `inner join` over layering filters — joins have bounded cost.
6. Set the alert severity and MITRE mapping in the UI using the fields you've carried in the output.
