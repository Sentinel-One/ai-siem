# Fields and schema

Common field paths in SentinelOne EDR / XDR data. When in doubt about a field name, the fastest way to confirm it is to run a small exploratory query:

```
event.type = 'Process Creation'
| limit 3
| columns timestamp, endpoint.name, src.process.name, src.process.cmdline
```

and look at what comes back. Typos in field names don't raise errors — missing fields become `null`, so the query "works" but returns nulls.

---

## Core event fields

| Field | Meaning |
|---|---|
| `event.type` | High-level event category: `Process Creation`, `File Creation`, `File Deletion`, `File Modification`, `File Rename`, `Registry Value Modified`, `IP Connect`, `DNS Resolved`, `Module Load`, `Windows Event Log Creation`, `Login`, etc. |
| `event.category` | OCSF-aligned category (`process`, `file`, `network`, `logins`, …) |
| `event.id` | Unique event ID |
| `event.time` | Human-readable event time |
| `timestamp` | Nanoseconds since epoch; renders as datetime in results |
| `agent.uuid` | SentinelOne Agent UUID — the stable per-endpoint identifier |
| `agent.version` | Agent version string |
| `endpoint.name` | Endpoint hostname |
| `endpoint.os.name` | OS name |
| `endpoint.ip.address` / `src.endpoint.ip.address` | Endpoint IP |
| `site.name` | Site / team the endpoint belongs to |

---

## Process fields

Processes have a source (`src.process.*`), target (`tgt.process.*`), and parent (`src.process.parent.*`) side.

| Field | Meaning |
|---|---|
| `src.process.name` | Executable name (e.g., `powershell.exe`) |
| `src.process.cmdline` | Full command line |
| `src.process.image.path` / `tgt.process.image.path` | Full file path of the process image |
| `src.process.pid` / `tgt.process.pid` | PID |
| `src.process.uid` / `tgt.process.uid` | Process UID (SentinelOne's stable process identity) |
| `src.process.signedStatus` | `signed` / `unsigned` / `unknown` |
| `src.process.signatureStatus` / `src.process.signatureValidation` | Signature validation |
| `src.process.publisher` | Signer publisher |
| `src.process.user` | Process user (username) |
| `src.process.sessionId` | Session ID |
| `src.process.childProcCount` | Child process count (counters on the source process) |
| `src.process.crossProcessCount` | Cross-process access count |
| `src.process.netConnInCount` / `src.process.netConnOutCount` | Inbound / outbound connection count |
| `src.process.tgtFileCreationCount` / `src.process.tgtFileModificationCount` | File activity counters |
| `src.process.storyline.id` | The SentinelOne storyline that groups related events. `tgt.process.storyline.id`, `src.process.parent.storyline.id`, etc. also exist. Use `#storylineid` to search them all. |
| `src.process.parent.name` / `src.process.parent.cmdline` | Parent process |

For identifying a unique process for pivoting/joining: `src.process.uid` is stable; combining with `agent.uuid` and `src.process.pid` is strongest.

---

## File fields

`event.category = 'file'` events populate target-file fields.

| Field | Meaning |
|---|---|
| `tgt.file.path` | Full file path |
| `tgt.file.oldPath` | Previous path (on rename / move) |
| `tgt.file.size` | Size in bytes |
| `tgt.file.type` | File type |
| `tgt.file.sha1`, `tgt.file.sha256`, `tgt.file.md5` | Hashes |
| `tgt.file.modification.date` | Last modified |
| `tgt.file.creation.date` | Created |

Use `#hash = '…'` to find a hash anywhere (MD5, SHA1, or SHA256).

---

## Network fields

`event.type = 'IP Connect'` / `event.category = 'network'`.

| Field | Meaning |
|---|---|
| `src.ip.address` | Source IP (process side) |
| `dst.ip.address` | Destination IP |
| `dst.port.number` | Destination port |
| `event.network.direction` | `INCOMING` / `OUTGOING` |
| `event.network.protocolName` | `tcp`, `udp`, `http`, `tls`, etc. |
| `url.address` | URL (HTTP / TLS / similar) |
| `dns.request` / `dns.response` | DNS query / response (use `#dns` to search all DNS fields) |

Detect internal vs external: `net_rfc1918(dst.ip.address)` (IPv4 private), `net_private(dst.ip.address)` (IPv4 or IPv6 private), or explicit `net_ipsubnet(dst.ip.address, '10.0.0.0/8')`.

---

## Login and identity

`event.category = 'logins'`.

| Field | Meaning |
|---|---|
| `event.login.userName` | Username |
| `event.login.type` | `NETWORK`, `NETWORK_CLEAR_TEXT`, `NETWORK_CREDENTIALS`, `CACHED_REMOTE_INTERACTIVE`, `INTERACTIVE`, `REMOTE_INTERACTIVE`, `UNLOCK`, `SERVICE`, `BATCH`, … |
| `event.login.loginIsSuccessful` | Boolean |
| `event.login.sessionId` | Session ID |
| `src.endpoint.ip.address` | Source endpoint IP on network logins |

---

## Windows Event Logs (`winEventLog.*`) and SIDs

Two distinct Windows sources can be present. They are NOT interchangeable:

- **`dataSource.name='Windows Event Logs'`** (plural, vendor `SentinelOne`): carries the raw Windows SID (`S-1-5-...`) and rich `winEventLog.*` fields. Use this for any SID work.
- **`dataSource.name='Windows Event Log'`** (singular, OCSF-mapped, vendor `Microsoft`): its `account.id` is a numeric value, NOT the `S-...` SID. Do not expect raw SIDs here.

Confirmed fields on the plural `Windows Event Logs` source:

| Field | Example | Meaning |
|---|---|---|
| `winEventLog.data.event.eventData.subjectUserSid` | `S-1-5-18` | Structured subject SID. Authoritative; present where the event schema carries it. |
| `winEventLog.data.event.eventData.subjectUserName` | `THIB-DC01$` | Structured subject account name. |
| `winEventLog.data.event.eventData.subjectDomainName` | `LETIBE` | Structured subject domain. |
| `winEventLog.description.securityId` | `S-1-5-18` | Parsed from the description text. Broader coverage but only the first ("Subject") Security ID. |
| `winEventLog.description.userid` | `THIB-DC01$` | Parsed account name. |
| `winEventLog.description.accountDomain` | `LETIBE` | Parsed domain. |
| `winEventLog.id` / `winEventLog.data.event.system.eventID` | `4624`, `4625`, `4985` | Windows Event ID. |
| `winEventLog.channel` | `Security` | Event channel. |
| `endpoint.name`, `agent.uuid`, `site.name` | | Standard host/agent context. |

Well-known SIDs (`S-1-5-18` SYSTEM, `S-1-5-19` LOCAL SERVICE, `S-1-5-20` NETWORK SERVICE, `S-1-0-0` NULL SID, `S-1-5-7` ANONYMOUS LOGON) are reused on every host and present as the local machine account, so they are not 1:1 with a username. Domain SIDs (`S-1-5-21-<domain>-<RID>`) map uniquely to one account. For a SID-to-username lookup, resolve well-known SIDs to canonical names and map domain SIDs to the observed user. A full enrichment build is in `references/automatic-lookups.md`.

---

## Indicator (behavioral detection) fields

SentinelOne's built-in behavioral indicators.

| Field | Meaning |
|---|---|
| `indicator.category` | `InfoStealer`, `Evasion`, `Exploitation`, `General`, `Injection`, `Malware`, `Persistence`, `Privilege Escalation`, `RansomwareProcess`, `Ransomware` … |
| `indicator.name` | Specific indicator (`EventViewerTampering`, `PreloadInjection`, `RawVolumeAccess`, …) |
| `indicator.description` | Longer description — use `contains` on this to find MITRE technique references, e.g., `indicator.description contains 'T1082'` |
| `indicator.metadata` | Additional context |

---

## Registry, DNS, and module load

Registry: `event.type = 'Registry Value Modified'` and friends. Field paths: `registry.keyPath`, `registry.valueName`, `registry.value`.

DNS: `#dns`, or `dns.request = 'example.com'`.

Module load: `event.type = 'Module Load'`, with `module.path`, `module.sha256`, `module.signedStatus`.

---

## Shortcut fields (one more time)

Repeated from the syntax reference because they save real time:

| Shortcut | Expands to |
|---|---|
| `#cmdline` | All process command-line fields |
| `#filepath` | All file path fields |
| `#hash` | All MD5/SHA1/SHA256 fields |
| `#ip` | All IP address fields |
| `#name` | All process name fields |
| `#storylineid` | All storyline ID fields |
| `#username` | All process user fields |
| `#dns` | All DNS request/response fields |

---

## OCSF alignment

SentinelOne fields are increasingly OCSF-aligned. Many queries also work with OCSF categories (`event.category`). When exploring a new data source in **All Data** view, read a couple of raw events first to see which fields are populated — log sources outside EDR/XDR (e.g., SentinelOne Collector logs) don't follow the EDR schema and often put the unparsed text in `message`.

For those `message`-style sources, use:
- `$"regex"` shorthand for `message matches "regex"` (single-escape)
- Explicit `message contains 'text'` for non-regex
- `| parse "…$field$…"` to extract fields on the fly

---

## Finding fields you don't know

If you don't know the field name, either:

1. **Use Purple AI first.** `mcp__purple-mcp__purple_ai(query="show me processes that accessed lsass.exe")` — it knows the schema and returns a working PQ.
2. **Explore a single event.** `event.type = 'Registry Value Modified' | limit 1` — the Event Search UI will show every parsed field; in the MCP call, follow up with `| columns registry.keyPath, registry.valueName, registry.value, timestamp` to confirm your guesses.
3. **Use `* contains 'value'` as an initial filter** to find which fields mention a known value, then pivot.
