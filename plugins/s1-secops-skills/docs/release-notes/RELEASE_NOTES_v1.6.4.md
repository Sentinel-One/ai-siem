## secops-mcps image 1.6.4

Image **1.6.4** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) runs
`s1-secops-mcp` 1.6.4 on the same distroless base as 1.6.3. It adds Case Management: Claude can
find the case an alert belongs to, investigate the case as one incident, and record its findings,
tasks, indicators and verdict on the case. With plugin `s1-secops-skills` 1.4.5, the skills use
cases throughout triage, automation and onboarding.

Case Management support follows the platform's Case Management capabilities and will be extended
as they evolve.

### New: Case Management tools

- **Read** (allowed in read-only mode): `case_list` (filter, sort and page cases), `case_get` (a
  case with its notes, tasks, linked IOCs, collaboration messages and, optionally, its alerts),
  `case_for_alert`, `case_metadata`, and `case_rules` (creation rules and whether a scope
  inherits them).
- **Write** (need write enabled): open a case from alerts (`case_create`), update or triage one or
  many cases (`case_update`, `case_triage`), add notes, tasks, IOCs and collaboration messages
  (`case_add_note`, `case_task`, `case_iocs`, `case_post_message`), add or remove alerts
  (`case_alerts`), and manage creation rules (`case_rule_apply`, `case_rules_scope`).
- **Safe by design:**
  - every write re-reads the case or rule and reports `verified`;
  - updates keep the fields you did not change;
  - an alert that already belongs to another case is reported, not silently skipped;
  - closing a case requires a reason;
  - changing how a scope inherits its creation rules requires explicit confirmation.
- **Case and alert state stay separate.** Case tools change the case only. `case_triage` applies a
  status, verdict or assignee to the case's alerts as well when asked to.

### Skills (plugin 1.4.5)

- **SOC Investigator:** triage starts from the alert's case, investigates every alert in it as one
  incident, reads the case's notes and verdict first, and offers to write the findings back to the
  case.
- **Mgmt Console API:** a Case Management reference covering the tools, request shapes, filters,
  creation rules and the behaviour to know before acting.
- **Hyperautomation:** workflows that write their results to the alert's case (note, collaboration
  message, IOCs, status) or open one, with values passed as typed GraphQL variables. Also:
  condition rules for string inputs and non-empty tests, scalar variables, and the agent move
  endpoints.
- **SDL Solutions:** Case Management onboarding: six starter creation rules mapped to MITRE ATT&CK
  tactics (critical, ransomware, credential access, lateral movement, command and control,
  exfiltration or impact) with grouping and default tasks, proven end to end with a test alert.

### Security and fixes

- **Base image updated** to the current distroless Node 24 build (Node 24.22.3, current Debian 13 glibc).
  Docker Scout reports no critical or high vulnerabilities, and no fixable ones at any severity.
- **Read-only mode:** the classification of GraphQL documents ignores text inside string literals, so
  a document is judged by its operations alone.

### Upgrade

Install the 1.6.4 launcher, which writes the 1.6.4 image into your client config:

```bash
mkdir -p ~/.local/bin && curl -fsSL https://raw.githubusercontent.com/Sentinel-One/ai-siem/main/mcp/docker/s1-secops-mcp-launch.sh -o ~/.local/bin/s1-secops-mcp-launch.sh && sh ~/.local/bin/s1-secops-mcp-launch.sh install   # add --read-write if you use write access
```

Or keep your launcher and pin the image:
`~/.local/bin/s1-secops-mcp-launch.sh install --image sentinelone/secops-mcps:1.6.4`. Install plugin
1.4.5, then quit and reopen Claude Desktop. Credentials, profiles, output folders and read-only mode
carry over. Details, including Windows: [upgrading.md](../upgrading.md#163-to-164-plugin-145).
