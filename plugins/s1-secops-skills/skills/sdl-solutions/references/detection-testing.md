# Detection testing: EDR, CWS and SIEM detections

Prove that a detection works before it goes live, and record which results came from simulated data and which from real data. The playbook covers:

- SentinelOne EDR detections on Windows, Linux and macOS endpoints.
- Cloud Workload Security (CWS) detections on Linux servers and cloud workloads.
- SIEM detections over third-party sources in the Singularity Data Lake.

It applies to new custom rules, migrated or converted rules (for example Sigma rules or KQL hunts converted to PowerQuery), and tuning changes to existing rules.

Use it when the user asks to test, validate, prove or A/B a detection, to migrate a detection library, or before enabling a batch of custom rules.

## Contents

1. Parameters and prerequisites
2. The flow at a glance
3. Step 1: check platform coverage first
4. Step 2: validate against real data
5. Step 3: query proof with synthetic events
6. Step 4: alert proof
7. Step 5: real telemetry on endpoints
8. Step 6: native detections versus custom
9. Step 7: A/B against the current rule
10. Step 8: record the evidence
11. Deploying the proven rules
12. Converting Sigma rules (reference)
13. EDR field facts that break detections
14. Third-party field checks
15. PowerQuery facts that break detections
16. Cleanup
17. Troubleshooting

## 1. Parameters and prerequisites

| Parameter | Meaning | Default |
| --- | --- | --- |
| Rules | The detections to test: rule bodies (PowerQuery or S1QL), or Sigma rules to convert first | none |
| Test scope | The account or site that receives test events and temporary rules | ask; never a production site |
| Run prefix | Name prefix for every temporary rule, unique per run | `DTEST-<run id>` |
| Run tag field | Field added to every synthetic event | `dtest_run` |
| Endpoints | Optional test endpoints with the SentinelOne agent: a Windows endpoint, a Linux VM or host | none |
| Window | Real-data validation window | 72 hours; 7 days for low-volume sources |
| Alert wait | How long to wait for an alert before calling a rule silent | 60 minutes |

Prerequisites:

- s1-secops-mcp in read-write mode for every write step (`hec_ingest`, `s1_api_post`, `s1_api_put`, `s1_api_delete`). Steps 1, 2, 6 and the A/B query are read only.
- An HEC Log Write Key (`S1_HEC_TOKEN`) that belongs to the test account or site. The events land in the scope the key belongs to.
- A console token with rights to create, enable and delete Custom Detection rules in the test scope. For real-telemetry tests on Windows, also RemoteOps rights.
- For read-only real-data checks, any credentials that can query the consoles carrying the sources. More consoles and accounts give better field coverage evidence.

## 2. The flow at a glance

| Step | Data | Writes | Proves |
| --- | --- | --- | --- |
| 1. Platform coverage | Rule metadata | No | Whether a platform or existing custom rule already covers the behaviour |
| 2. Real-data validation | Real production data | No | The body runs, its fields are populated, the expected volume |
| 3. Query proof | Synthetic events | HEC events | The logic matches positives and ignores near misses |
| 4. Alert proof | Synthetic events | Temporary rules | The rule deploys, activates and raises a UAM alert |
| 5. Real telemetry | Real agent telemetry from harmless lookalikes | Endpoint activity | The agent records what the rule reads |
| 6. Native versus custom | Real agent telemetry | No | What the platform raised on its own |
| 7. A/B | Same synthetic and real data | Optional shadow rules | Which rule to keep |
| 8. Evidence | All of the above | No | A reviewer can rerun every result |

Run the steps in order. Steps 2 and 3 can run in parallel; step 4 needs step 3; step 6 needs step 5.

## 3. Step 1: check platform coverage first

Before writing or deploying a custom rule, look for an equivalent that already exists.

**Platform rules.** `GET /web/api/v2.1/detection-library/platform-rules` with `scopeLevel=site&scopeId=<site id>&limit=1000` (repeat at the account level). The endpoint caps `limit` and `skip` at 1000, so page per severity as in `mgmt-console-api/references/tags/Platform_Detection_Rules.md` ("Full-catalog recipe"). Add `hideQuery=Shown` to get the query bodies. For each candidate read `name`, `status`, `queryType`, `techniques`, `sources` and `severity`. The per-scope enable state is on the platform rule settings endpoint.

- Some platform rules do not return a query body, even with `hideQuery=Shown`. Compare those by name, ATT&CK technique and data source, and record that the comparison was by metadata.
- A platform rule that is disabled, or not available in the scope, is not coverage. Record its state.
- An Active platform rule is not proof that a given artifact is covered. Test the artifact (step 5) or A/B the two rules (step 7) before deciding that a custom rule is redundant.

**Custom rules.** `GET /web/api/v2.1/cloud-detection/rules?isLegacy=false` (always pass `isLegacy=false`; without it, scheduled PowerQuery rules are left out). Search by name, technique and the fields the body reads.

**Decide per rule:**

| Finding | Action |
| --- | --- |
| A platform rule covers the same behaviour and source | Enable or tune the platform rule; do not deploy the custom rule |
| Partial overlap (same technique, different artifacts or sources) | Keep the custom rule; A/B it against the platform rule (step 7) |
| A custom rule already covers it | Update that rule instead of adding a second one |
| No coverage | Continue with step 2 |

Record the decision and the platform rule names it was based on.

## 4. Step 2: validate against real data (read only)

Run every rule body over real data for the window, with synthetic test events excluded. Run it on every console and account you have read access to that carries the rule's sources.

```text
!(dtest_run = *) (<rule initial filter>) | <rest of the body>
```

For a quick per-source view:

```text
!(dtest_run = *) (<rule initial filter>) | group n = count() by dataSource.name | limit 20
```

For hunts and bodies that open with `| join` or `| union`, add `!(dtest_run = *)` inside every subquery. Also add `tag != 'logVolume'` inside each subquery anchored only on `dataSource.name`: `powerquery_run` adds the metering exclusion automatically to ordinary queries but not inside a leading `union`.

Check and record three things per rule and per console:

1. **It runs.** No error. A query that errors on real data is a rule that never fires. Re-run a query that hits a transient network or token error before recording a failure.
2. **Its fields are populated.** For each field the rule reads, count coverage on each source:

   ```text
   dataSource.name='<source>' tag != 'logVolume'
   | group n = count(), f1 = count(<field1> != null), f2 = count(<field2> != null)
   ```

   Aim for at least 90 percent coverage on the event class the rule targets. A field name that exists but is empty on the onboarded parser never matches. Where sources use different names for the same value, list each of them in the rule and match any. Also check the value format (for example registry path roots, DNS trailing dots, Windows path case, user name format, numeric or text status codes).
3. **Expected volume.** A body that returns many rows or many distinct entities on real data is a tuning lead (an exclusion, a baseline, a higher threshold) to resolve before it is enabled, not a confirmed incident.

Rows a query returns on real data are leads to review, never findings to report as activity.

## 5. Step 3: query proof with synthetic events

### Write the test events

For each rule write:

- **Positives:** at least one event per selection branch of the rule, so every `or` branch is proven.
- **Near misses:** the closest benign variants that must not match: the right process with the wrong parent, one of two required substrings, a lookalike domain, the right value in the wrong field, a value one character short of a suffix.
- **Correlations:** a burst that meets the threshold inside the window for the positive case, and the same burst one event short for the near miss, with every group-by and counted field set.

Use synthetic values only: `example.com` domains, documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and a test host name such as `dtest-host`.

### Shape the events like the real source

- **EDR:** `dataSource.name='SentinelOne'`, `event.type` and `event.category` with their exact values (see section 13), `endpoint.name`, `endpoint.os`, and the fields the rule reads: `src.process.*`, `src.process.parent.*`, `tgt.process.*`, `tgt.file.*`, `registry.keyPath`, `registry.value`, `event.dns.request`, `dst.ip.address`, `dst.port.number`.
- **Third-party:** the OCSF fields the onboarded parser writes, for example `class_uid`, `activity_name`, `http_request.url.path`, `http_request.url.query_string`, `http_request.user_agent`, `query.hostname`, `api.operation`, `actor.user.name`, `src_endpoint.ip`, `status_code`, plus a `dataSource.name` and `dataSource.vendor` that match the real source.
- Send flat dotted keys (`"src.process.cmdline": "..."`), not nested objects, with `isParsed=true` and `dataSource.category=security`.

### Tag and send

1. Tag every event with a unique run value: `dtest_run=<run>-<rule>-p` for positives and `dtest_run=<run>-<rule>-n` for near misses. A run id per execution keeps reruns apart.
2. Send with `hec_ingest` (`isParsed=true`). Batch events per request to stay inside the HEC payload limit.
3. **EDR-shaped events are visible to every rule, dashboard and automation on the console**, and they look like agent telemetry. Send them only to a test account or site, and only when the user has agreed. Real agent telemetry always carries `agent.uuid`; synthetic events do not, which is how to tell them apart later.
4. Test events cannot be deleted. They age out with the account's retention. The run tag keeps them out of real-data checks (`!(dtest_run = *)`).

### Wait until every event is searchable

Poll until every count matches what was sent; do not use a fixed sleep (indexing time varies from seconds to several minutes):

```text
dtest_run contains '<run>-' | group n = count() by dtest_run | limit 1000
```

### Run the tagged body

Add the tag to the body and run it:

- **Ordinary body:** `dtest_run='<run>-<rule>-p' (<initial filter>) | <rest of the body>`. Wrap the whole original initial filter in parentheses so a top-level `or` cannot widen it past the tag.
- **Body that opens with `| join` or `| union`:** add the tag inside every subquery.
- **Positive passes** when every positive event is matched. For a body that groups (`| group hits = count() by <entity>`), sum `hits` over the rows and compare with the number of positives sent.
- **Near miss passes** when the same body with the `-n` tag returns no rows.

### Time-based logic

For rate, rhythm, beacon or correlation logic:

- Keep each event's own timestamp and its spacing. Accept ISO 8601 and epoch timestamps.
- Shift the whole case by a whole number of hours so it lands in the recent window and every event keeps its position relative to hour-aligned time buckets.
- Open the query window at the earliest event in the case, not at a fixed offset from now.

### Correlations

Converted correlation rules use a bucketed group (section 12). The positive burst must fall inside one bucket. Prove `event_count` and `value_count` rules with the threshold met and with one event, or one distinct value, short.

## 6. Step 4: alert proof

A query match does not show that the rule deploys, activates or raises an alert. For each rule that passed step 3:

1. **Create a temporary rule** that reads only its tagged positive events: `POST /web/api/v2.1/cloud-detection/rules` with

   ```json
   {
     "data": {
       "name": "<run prefix> <rule title>",
       "queryType": "scheduled",
       "queryLang": "2.0",
       "severity": "Low",
       "status": "Active",
       "treatAsThreat": "UNDEFINED",
       "networkQuarantine": false,
       "description": "<rule description>",
       "entityMappings": [{"columnName": "<entity column>"}],
       "scheduledParams": {
         "query": "<tagged body>",
         "runIntervalMinutes": 5,
         "lookbackWindowMinutes": 120,
         "threshold": {"value": 0, "operator": "Greater"}
       }
     },
     "filter": {"accountIds": ["<test account>"]}
   }
   ```

   Keep the lookback-to-interval ratio at or under 96. `treatAsThreat` must be `UNDEFINED` and `networkQuarantine` false on scheduled rules. Read the rule back by the `data.id` the POST returns.
2. **Enable every new rule**, whatever status the create asked for: `PUT /web/api/v2.1/cloud-detection/rules/enable` with `{"filter": {"ids": [...], "accountIds": [...]}}`. A new rule can be stored as a draft; the call is harmless on a rule that is already activating. Do not put `isLegacy` in an action body (HTTP 400).
3. **Keep the events inside the lookback.** A scheduled rule reads its lookback window on each run, so events sent before activation count if they are still inside the lookback at the first run. While rules activate, send the positive events again every 10 minutes.
4. **Poll the alert stream** once a minute:

   ```text
   dataSource.name='alert' finding_info.title contains '<run prefix>'
   | columns time, finding_info.title, finding_info.uid
   | limit 1000
   ```

   Match each alert to its rule by the title. Also accept a match on the first 60 characters of the title, in case a long title is shortened.
5. **Budget time.** Alerts arrive about 5 to 50 minutes after the rule is created, and longer under load; the UAM alert lands a few minutes after the detection time. Allow at least 60 minutes before calling a rule silent.
6. **Delete every temporary rule** as soon as its alert arrives, and the rest at the deadline: `DELETE /web/api/v2.1/cloud-detection/rules` with `{"filter": {"ids": [...], "accountIds": [...]}}` (a `DELETE` on `/rules/{id}` returns 405). Read back with `GET /web/api/v2.1/cloud-detection/rules?ids=<id>&isLegacy=false` and repeat up to 3 times until it is gone: a rule that is still activating may need the delete repeated. Run the delete in a `finally` block so an interrupted run still cleans up, and fail the run if any rule is left behind.
7. **Batch large rule sets.** Each enabled scheduled rule counts against the scope's limit on enabled scheduled rules: check the limit on the console before enabling a large set. Run large libraries in groups and delete each group before the next.

Hunts are run by hand and have no alert proof; prove them with step 3 only.

## 7. Step 5: real telemetry on endpoints (EDR and CWS)

Simulated events prove the logic. Real telemetry proves that the agent records the event, with the field names and value formats the rule reads. Run harmless lookalikes of the behaviour on a test endpoint, then run the rules over that endpoint's telemetry.

### Getting an agent

- Package list: `GET /web/api/v2.1/update/agent/packages` (filter by OS and architecture). Download: `GET /web/api/v2.1/update/agent/download/{siteId}/{packageId}` (with `s1_api_download`).
- The site registration token is on `GET /web/api/v2.1/sites/{siteId}` (`registrationToken`). Never print it; pass it to the install command from a file or variable.
- Put lab agents in a dedicated test site with the policy you want to test (detect or protect).

### Windows (EDR)

Run one script once on one test endpoint with Remote Script Orchestration:

1. **Upload:** multipart `POST /web/api/v2.1/remote-scripts` with `scriptName`, `scriptType=action`, `osTypes=windows`, `inputRequired=false`, `scopeLevel` (`account` or `site`), `scopeId`, `scriptRuntimeTimeoutSeconds` and the `file`.
2. **Check (read only):** `POST /web/api/v2.1/remote-scripts/guardrails/check` with `{"data": {"scriptId": "<id>", "agentIds": ["<agent id>"]}}`.
3. **Run:** `POST /web/api/v2.1/remote-scripts/execute` with `{"data": {"scriptId": "<id>", "taskDescription": "<text>", "outputDestination": "SentinelCloud"}, "filter": {"ids": ["<agent id>"], "accountIds": ["<account id>"]}}`. `filter` sits at the top level, not inside `data`.
4. **Poll:** `GET /web/api/v2.1/remote-scripts/status?parentTaskId=<parent task id>` (the id returned by `execute`).
5. **Remove the script:** `DELETE /web/api/v2.1/remote-scripts` with `{"filter": {"ids": ["<script id>"], "accountIds": ["<account id>"]}}`.

Lookalikes use built-in tools with the attack command line, and remove everything they create:

- A discovery command with the attack arguments (for example `tasklist /s localhost`).
- An `echo` of a tool's command line, so the process creation event carries it.
- An empty file with an artifact name (for example a web-shell file name).
- A copy of a signed system binary under an unusual name or location (for example `where.exe` copied to `svchost.exe` outside System32), run once.

Notes:

- RemoteOps scripts run as SYSTEM, so `HKCU` in a script is the SYSTEM account's hive, not a user's. Test user-hive registry rules from a user session.
- Real-time (`events`) rules scoped to the endpoint prove the real-time form. Create them with `queryType: "events"`, `queryLang: "2.0"`, the converted filter in `s1ql`, and a scope filter on the endpoint. The 2.0 operators work as they are, including `in:anycase`, `ends_with` and `matches:matchcase`. An `s1ql` body takes a single backslash where a PowerQuery string takes two, so halve the backslashes when moving a filter into `s1ql` (see "S1QL string escaping" in `powerquery/references/detection-rules.md`). An omitted `queryLang` is stored as `1.0`, where 2.0 operators match nothing.

### Linux (EDR and CWS)

**Use a Linux VM or host with the agent installed normally** (systemd, host kernel). The Linux agent records endpoint telemetry when it is installed on the host. A plain Docker container is not a supported test target: protect container workloads with the supported container or Kubernetes deployment, and run detection tests on a VM.

On macOS, Lima gives an Ubuntu VM in a few minutes:

```bash
limactl start --name=dtestlab --vm-type=vz --cpus=4 --memory=4 template://ubuntu-24.04
limactl shell dtestlab
```

Inside the VM, install the agent package for the VM's architecture (`dpkg -i` or `rpm -i`), then:

```bash
sudo /opt/sentinelone/bin/sentinelctl management token set "$(cat /path/to/token-file)"
sudo /opt/sentinelone/bin/sentinelctl control start
sudo /opt/sentinelone/bin/sentinelctl control status
```

Remove the token file after registration. `limactl stop` and `limactl start` keep the agent for later runs.

Lookalike rules for Linux:

- **Stand-ins, not tools.** Copy `/bin/true` to the tool's path (or under a lab folder when the path holds a real system binary) and run it with the attack command line. For parent-child rules, run it under a parent made from a copy of `/bin/sh` placed at the parent's path. Keep parent stand-ins and child stand-ins in separate folders, so a child is never a copy of a shell.
- **One action, one unit.** Run each lookalike in its own transient systemd unit: `systemd-run --wait --collect -- <cmd>`. In protect mode, Behavioral AI may stop a lookalike by ending its whole process tree. A separate unit keeps the runner and your shell session alive. Run the runner itself as a systemd unit too. The mitigation is a native detection to record in step 6.
- **DNS sink.** Point the VM's resolver at a local dnsmasq that forwards only `*.sentinelone.net` upstream and answers every other name with `127.0.0.1`, so lookups of attacker domains never leave the machine. Run each lookup with `getent hosts <name>` so the agent records a DNS event.
- **File markers.** Write content to marker files (one line of text). Check which file events the agent records under the site's policy before relying on file-event rules:

  ```text
  dataSource.name='SentinelOne' endpoint.name='<host>' event.category='file'
  | group n = count() by event.type, tgt.file.extension
  ```

  If the policy records only executable file creation, file-event rules for plain-text artifacts stay proven by simulated events only; record that.
- **Wait for telemetry** by polling for the endpoint's events, not with a fixed sleep:

  ```text
  dataSource.name='SentinelOne' endpoint.name='<host>' | group n = count() by event.type
  ```

### Run the rules over the endpoint's telemetry

For each rule, run its body scoped to the endpoint over the run window:

```text
dataSource.name='SentinelOne' endpoint.name='<host>' agent.uuid=* (<rule initial filter>) | <rest of the body>
```

`agent.uuid=*` keeps synthetic events out. A rule passes when it matches the lookalike it was written for. A rule that does not match is either a field or value-format difference (fix the rule and rerun step 3), or activity the agent does not record under the policy (record it as simulated only).

### macOS

The same approach applies: stand-ins at the tool's path and a DNS sink. A macOS VM needs Apple Virtualization (Lima `vz` with a macOS template, or another hypervisor). Without one, macOS rules stay proven by simulated events; record that.

## 8. Step 6: native detections versus custom

For the same activity, record what SentinelOne raised on its own and what only the custom rules caught.

- **Threats:** `GET /web/api/v2.1/threats?agentIds=<agent id>&createdAt__gte=<run start>`. Read `threatInfo.threatName`, `classification`, `confidenceLevel`, `detectionEngines`, `mitigationStatus` and `filePath`.
- **Alerts on the host:**

  ```text
  dataSource.name='alert' * contains '<host>'
  | group n = count() by finding_info.title, metadata.product.name
  | sort -n
  ```

  `metadata.product.name` tells the source: `CWS` for Cloud Workload Security on Linux servers, `STAR` for custom rules, and other names for platform rules and solutions that re-post alerts.
- **Map each native detection** back to the lookalike that caused it (file path, process name or command line).

Report per rule: native detection (yes or no, which engine), custom rule match (yes or no), and whether the custom rule adds coverage.

## 9. Step 7: A/B against the current rule

Before a new or tuned rule replaces the current one (a platform rule, an existing custom rule, or the previous version):

### Same data, side by side

Run both bodies over the same real window and the same synthetic events, grouped by the same entity:

```text
| union
    ((<rule A body up to its final group>) tag != 'logVolume' | group a = count() by endpoint.name),
    ((<rule B body up to its final group>) tag != 'logVolume' | group b = count() by endpoint.name)
| group a = sum(a), b = sum(b) by endpoint.name
| let side = (a > 0 && b > 0) ? 'both' : (a > 0 ? 'only_a' : 'only_b')
| group entities = count(), a_hits = sum(a), b_hits = sum(b) by side
```

- Drop the last `group` to read the `only_a` and `only_b` rows: they show what each rule misses.
- Add `bucket = timebucket('1h')` to both groups and to the merge to compare by entity and time.
- When a body cannot go inside `union` (a platform rule whose query is not published, or a body that returns more than 1,000 rows), run the two separately and merge on the entity keys, or compare the platform rule's UAM alerts over the same window.
- For step 3 and step 5 data, record which of the positives each rule matched.

### Shadow mode

Deploy the candidate next to the current rule with its own name prefix and Low severity (or in a test site), and let both run for an agreed period, for example 7 days. Compare alert volume, analyst verdicts on the alerts (true and false positives), and time to alert. Promote one, retire the other. A shadow rule uses an enabled-rule slot.

### Regression for tuning

When you add an exclusion or change a threshold, run the old and new bodies over the same history and over the tagged positive and near-miss events. The new body must still match every positive. List every entity the change removes and check it against analyst verdicts on past alerts for the rule (`uam_list_alerts`, any `TRUE_POSITIVE_*` verdict except `TRUE_POSITIVE_BENIGN`): a removed entity with a true-positive verdict blocks the change.

### Converted rules that overlap a platform rule

A/B them on real data and on the step 5 lookalikes, then keep the custom rule, fold it into a tuning of the platform rule, or drop it.

Record the window, both queries, the counts, the overlap table, the shadow-run verdicts and the decision.

## 10. Step 8: record the evidence

Keep, per rule:

| Field | Example content |
| --- | --- |
| Rule | Path or id, title, ATT&CK technique |
| Query | The exact body that was tested |
| Platform coverage | Matching platform rules and the decision (step 1) |
| Real data | Consoles and window, runs without error, field coverage per field, rows and distinct entities |
| Query proof | Positives sent and matched, near misses sent and matched |
| Alert proof | Temporary rule id, alert id, minutes from rule creation to alert |
| Real telemetry | Endpoint OS, lookalike, matched or not, reason if not |
| Native detection | Threat or alert name, engine, product |
| A/B | Overlap counts and decision |
| Label | Simulated, real telemetry, or real data, for each result |

Also record the run id, run start and end, the counts per step, and what was not covered (for example no macOS endpoint, file events not recorded under the policy, a source whose parser keeps the value only in `message`).

Report three kinds of evidence separately: simulated events on a real console (query proof, alert proof); real telemetry from harmless lookalikes on test endpoints; and read-only runs on real production data (field coverage, volume). Say which rules have which.

Keep tenant names, console names, account and site ids, host names and tokens out of anything shared outside the team. Use neutral labels (test account, test endpoint, lab host).

## 11. Deploying the proven rules

When the user wants the proven rules on a production scope:

- Prefer Detection as Code (the detection-as-code solution) for a rule library kept in Git.
- For a one-off import script: accept the console URL only as `https://<host>` under `.sentinelone.net` (or an explicit allow list), with no user info or path, and refuse redirects so the token cannot be forwarded.
- Retry GETs on 429 and 5xx. Never retry a POST that creates a rule: the first attempt may have landed. Read back by name instead.
- Mark every rule the script creates (a fixed line in the description) and update or delete only rules that carry the mark. Make deletion of rules missing from the content opt-in.
- Validate every field name taken from contributed content against `^[A-Za-z_][A-Za-z0-9_.:]*$` before building a query from it.
- Create rules disabled, show the plan (create, update, unchanged, remove) before applying, and enable each rule once its source is onboarded and step 2 is clean.
- Set severity, `entityMappings` that name the asset, and the ATT&CK technique (in the description, or on the alert with the MITRE mapping solution: rule bodies cannot carry it).

## 12. Converting Sigma rules (reference)

### Value matching

| Sigma | PowerQuery | Why |
| --- | --- | --- |
| Plain value or value list | `f in:anycase ('a', 'b')` | `=` and `in` are case-sensitive; Sigma is not |
| `\|contains` | `f contains 'x'` | Case-insensitive |
| `\|startswith` / `\|endswith` | `f starts_with 'x'` / `f ends_with 'x'` | Not `contains`, which widens the match |
| Value with inner wildcards | `f matches '^...$'` | `matches` is an unanchored search; anchor it |
| `\|re` | `f matches:matchcase '...'` | Sigma regex is case-sensitive unless it sets the `i` flag |
| `\|cidr` | `net_ipsubnet(f, '10.0.0.0/8')` | There is no `net_incidr` |
| `\|exists: true` / `f: null` | `f = *` / `!(f = *)` | `f == null` fails |
| `not`, `1 of ... and not` | `!( ... )` | `not f contains 'x'` returns 0 rows with no error |
| Numeric `\|gt`, `\|lt` | `number(f) > n` | Columns can be string-typed |
| Numeric value list | `f in (4624, 4625)` | Numbers are not quoted |

Double every backslash inside a string literal or regex (`ends_with '\\svchost.exe'`).

### Scheduled rule body

- A single-event rule becomes the filter plus `| group hits = count() by <entity>`: one alert per host, address or identity per run, with `entityMappings` on the entity columns.
- `event_count`: `| group event_count = count() by bucket = timebucket('<timespan>'), <keys> | filter event_count >= N`.
- `value_count`: two chained groups for an exact count:
  `| group per_value = count() by bucket = timebucket('<timespan>'), <field>, <keys> | group value_count = count() by bucket, <keys> | filter value_count >= N`.
  `estimate_distinct` is approximate, so a threshold on it can miss or misfire at the boundary.
- Timing for correlations: `runIntervalMinutes = max(5, min(timespan, 60))` and `lookbackWindowMinutes = 2 x timespan + 5` (at least the interval), so every bucket is read whole by at least one run. Keep lookback divided by interval at or under 96.
- Scheduled bodies accept only simple aggregates inside `group` (`count()`, not `count_distinct`).

### Log source anchors

- **Endpoint** (`process_creation`, `file_event`, `registry_*`, `dns_query`, `network_connection`): `dataSource.name='SentinelOne'`. `file_event` reads `File Creation`, `File Modification` and `File Rename` (not `File Deletion`). `registry_set` and `registry_event` read `Registry Value Create` and `Registry Value Modified`.
- **Third-party sources:** `tag != 'logVolume' !(dataSource.name in ('alert', 'indicator', 'ActivityFeed'))`, so metering rows and SentinelOne's own alert, indicator and activity records (which carry the same IOC strings) do not match. Pin to one `dataSource.name` once the source is known.
- **Web proxy and web server:** also require a URL field and exclude `class_uid in (3001, 3002, 3003, 3004, 3005, 3006, 6003)`: sign-in, account and API activity records carry `http_request.user_agent` too.
- **DNS names:** accept an optional trailing dot on exact and suffix matches (`\\.?$`).

## 13. EDR field facts that break detections

Check these on the tenant before relying on them; they decide whether a rule can ever match.

| Topic | Use | Not |
| --- | --- | --- |
| DNS query and answer | `event.dns.request`, `event.dns.response` (empty on `DNS Unresolved`) | `dns.request`, `dns.response` |
| Network categories | `event.category` `ip` (`IP Connect`, `IP Listen`), `dns` (`DNS Resolved`, `DNS Unresolved`), `url` (event type is the HTTP method) | `event.category = 'network'` |
| New registry value (for example a new Run entry) | `event.type in ('Registry Value Create', 'Registry Value Modified')` | `Registry Value Modified` alone |
| Registry path | `registry.keyPath` holds the key and the value name, with `MACHINE\` or `USER\<SID>\` roots; match the key segment unanchored, or the full key and value name with `ends_with`. Value data in `registry.value` | `HKLM\`, `HKU\` roots; `registry.valueName` |
| Process image name | `tgt.process.name` (a renamed binary matches by its new name). `tgt.process.displayName` is the file description | `tgt.process.image.originalFileName` |
| Event type case | `event.type = 'Process Creation'` | `event.type = 'process creation'` (returns 0) |
| Real versus synthetic | Real agent events always carry `agent.uuid` | Trusting `dataSource.name='SentinelOne'` alone |

Other EDR event types worth knowing: `Registry Value Delete`, `Registry Key Create`, `Registry Key Delete`, `Named Pipe Creation`, `Named Pipe Connection`, `Task Register`, `Task Update`, `Task Start`, `Task Delete`, `Task Trigger`, `Open Remote Process Handle`, `Duplicate Process Handle`, `Driver Load`, `Command Script`, `Behavioral Indicators`.

## 14. Third-party field checks

Field placement varies by parser and connector version. Before a rule reads one of these, check coverage with `count(<field> != null)` on the source:

- **CloudTrail:** a parser can write class 4002 rather than 6003 (API Activity). The caller ARN can be only in `unmapped.userIdentity.arn`; the event name in `activity_name` or `unmapped.eventName`.
- **Netskope:** user agent, URL and domain can be only in `unmapped.*`.
- **AWS WAF:** path in `web_resources.url.path`, query in `http_request.args`, the user agent only inside `http_request.http_headers`.
- **Zeek DNS and some Entra ID connector versions** keep values inside `message`: map them in the parser before writing rules.
- **Entra ID `status_code`** is numeric on one connector and text on another: compare with `string(status_code)` or check the type first.
- **Sign-in, Office 365 and API activity records** carry `http_request.user_agent`: a user-agent rule meant for web traffic must also require a URL field and exclude the classes listed in section 12.
- **SentinelOne `alert`, `indicator` and `ActivityFeed` records** quote command lines, domains and hashes: exclude them from third-party rules and IOC hunts. A hit in these streams is not independent corroboration.

## 15. PowerQuery facts that break detections

- `=` and `in` are exact and case-sensitive; use `in:anycase (...)` for case-insensitive exact matches. `contains`, `starts_with`, `ends_with` and `matches` ignore case; add `:matchcase` for case-sensitive.
- `matches` searches anywhere in the value, like `contains`. Anchor with `^` and `$` for a whole-value match.
- Write negation as `!(...)`. `not f contains 'x'` and `f not in (...)` return 0 rows with no error.
- `!` before a bare field or `let` name in `filter` is a text search and keeps almost every row. Write `| filter x = true` or `| filter !(x = true)`. `!` before a function call (`| filter !net_rfc1918(dst.ip.address)`) works.
- Presence counts: `count(f != null)` works; `count(f = *)` and `count(!(f = *))` return HTTP 400.
- Null checks: `f = *` (present) and `!(f = *)` (absent). `f == null` fails.
- `net_ipsubnet(ip, cidr)` exists; `net_incidr` does not.
- Alias a function used as a group key: `by bucket = timebucket('10m')`.
- Cast string-prone numbers with `number(f)` before comparisons and arithmetic.
- Exclude ingest-metering rows with `tag != 'logVolume'` in every persisted rule body anchored only on `dataSource.name`.
- S1QL 1.0 operators (`ContainsCIS`, `StartsWithCIS`, `EndsWithCIS`) match nothing in a 2.0 body.
- `| union` and `| join` must be the first command; indexed array fields (`f[0]`) are rejected.

## 16. Cleanup

- **Temporary rules:** deleted and read back (step 4). Fail the run if any remain.
- **RemoteOps scripts:** deleted.
- **Endpoint artifacts:** stand-ins, marker files and lab folders removed by the runner.
- **Test agents:** decommission with `POST /web/api/v2.1/agents/actions/decommission` (`{"filter": {"ids": ["<agent id>"]}}`) once the console shows the agent offline; an online agent returns `affected: 0`. Remove lab containers and images. Keep a lab VM for later tests, or delete it (`limactl delete`).
- **Token files:** deleted after agent registration.
- **HEC test events:** stay until retention removes them; the run tag keeps them out of real-data checks.

## 17. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Positive not matched in step 3 | Field name or value format differs from the rule; tag not applied to every subquery | Compare the event with the rule; fix the event shape or the rule |
| Near miss matched | Rule too broad (`contains` for `endswith`, unanchored `matches`, top-level `or` outside the tag) | Tighten the rule; wrap the initial filter in parentheses |
| Step 3 passes, no alert in step 4 | Rule still a draft, events outside the lookback at the first run, rule name not matched | Call enable, re-send events every 10 minutes, poll by the run prefix |
| HTTP 400 on rule create | Mitigation fields on a scheduled rule, `count_distinct`, wrong `queryLang` | `treatAsThreat: "UNDEFINED"`, `networkQuarantine: false`, simple aggregates, `queryLang: "2.0"` |
| Real-data run errors | Function or syntax the engine rejects, transient token or network error | Fix the body, or re-run the transient failure before recording it |
| No endpoint events from a Linux test agent | Agent installed in a plain container rather than on a VM or host | Use a VM or host install |
| Runner or shell killed during a Linux run | Behavioral AI ended the process tree in protect mode | One `systemd-run` unit per action; run the runner as a unit |
| File-event rule never matches real telemetry | Policy does not record that file type | Record as simulated only; test with an executable artifact if the rule allows |
| User-hive registry rule never matches on Windows | Value written to `HKCU` from a SYSTEM script, which is the SYSTEM account's hive | Write from a user session |
| Decommission returns `affected: 0` | Agent still online | Stop the agent, wait until offline, retry |
