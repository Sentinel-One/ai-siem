# Integration action catalog: what workflows use

A usage corpus of **1,205 workflows / 17,899 action steps**: which integrations real workflows
call, which of their actions, and how often. Use it to see which action people rely on for a job.
For the complete list of packaged actions, and for every id you put in a workflow, use the action
library: [`action-library-index.md`](action-library-index.md) (one row per integration) and
`scripts/find_action.py` (search). Ready-made workflows are listed in
[`marketplace-templates.md`](marketplace-templates.md).

## How Hyperautomation integrations work (read this first)

Two kinds of integration-backed HTTP action exist, and the difference matters when you
generate JSON:

| | Packaged action | Ad-hoc action |
|---|---|---|
| `data.public_action_id` | the `public_action_id` of an action library entry | `null` |
| `data.url_path` | pre-filled by the pack, e.g. `/api/chat.postMessage` | you write it |
| `data.url` | `{{Connection.protocol}}{{Connection.url}}<@/api/chat.postMessage@>` | anything |
| Share of corpus | **3,822 of 5,418 http_requests (71%)** | 1,596 (29%) |

So an integration **is** an action pack, plus a named authenticated connection. Every built-in
integration ships a set of packaged actions (3,690 across 226 integrations in the action
library). Custom (user-defined) integrations ship none, so every call against them is ad-hoc.

The `<@...@>` wrapper inside `data.url` is the console's link markup for the packaged path, and
`<<name>>` marks a value the author fills in. Keep `url`, `url_path` and `public_action_id`
consistent with each other when authoring by hand.

### Packaged actions: take the ids from the action library

1. Find the action: `python3 scripts/find_action.py <terms>`, or `--integration <name> <terms>`.
   Every term must match the integration, action name, path or description.
2. Copy `public_action_id`, `method` and `url_path` into the action's `data`. Copy `url` and
   `payload` too when the entry has them; when it has no `url`, use
   `{{Connection.protocol}}{{Connection.url}}` followed by the `url_path`. Set
   `integration_id` and the connection fields by the import rule in
   `building-blocks-catalog.md` (section A13, "Hard rule for generation").
3. Replace each `<<name>>` placeholder in the `url` and `payload` with a value or a
   `{{...}}` expression.

Built-in `integration_id` values and library `public_action_id` values are the same on every
console. An exported workflow can carry a `public_action_id` that is not a current library entry;
`find_action.py --id <id>` returns the entry derived from it when there is one. The console
accepts such an id on import; use the current entry's id in anything you author.

### The action library API

All paths are under `/web/api/v2.1/hyper-automate/api/v1`. Call them with `s1_api_get`.

| Call | Returns |
|---|---|
| `GET /public-actions` | every packaged action in one response (no paging): `id` (the `public_action_id`), `integration_id`, `description`, and the action's `data` (`name`, `method`, `url`, `url_path`, `payload`, `headers`). The body is several MB: save it with `outputFile` |
| `GET /integrations/all` | built-in integrations: `id`, `vendor_name`, `product_name`, `product_key` |
| `GET /integrations/{integration_id}` | one integration, including ones `/integrations/all` leaves out |
| `GET /templates?limit=200` | the marketplace templates (`skip` and `limit` page through them) |
| `GET /connections/scope` | the connections in your scope, i.e. which integrations this console has set up |
| `GET /integrations` | `405`: there is no plain list, use `/integrations/all` |

The shipped library is built from these calls by `tools/ha_action_library.py` in the
s1-secops-skills source repo (not shipped). If an id from it is missing on a console, pull
`/public-actions` there and search the response.

**To see which integrations a console has set up**: `GET /connections/scope`, collect the distinct
`integration_id` values and resolve each with `GET /integrations/{id}`. Some workflows reference an
integration that has no connection in your scope; the `integration_id` on their actions shows it.

---

## Corpus totals

| Metric | Value |
|---|---:|
| Workflows exported | 1,205 |
| Action steps | 17,899 |
| `http_request` steps | 5,418 |
| ... integration-backed | 4,701 (87%) |
| ... core, no integration | 717 (13%) |
| ... using a packaged action | 3,822 (71%) |
| Connections configured | 81 |
| Distinct integrations referenced | 114 |
| Built-in (have a `product_key`) | 62 |
| Custom / user-defined (`product_key: null`) | 52 |
| Distinct packaged actions seen (`public_action_id`) | 266 |

`product_key` is the built-in vs custom discriminator. Custom integrations carry a
`vendor_name` only, with `product_name: ""` and `product_key: null`, and often duplicate a
built-in (a hand-rolled `Okta` alongside built-in `Okta / Okta`; `Fortigate FW` alongside
`Fortinet / FortiGate`). **Prefer the built-in when one exists**, you get the action pack.

---

## Built-in integrations (62)

| Vendor / Product | `product_key` | Packaged actions seen | Packaged uses | Ad-hoc uses | Connections |
|---|---|---:|---:|---:|---:|
| SentinelOne / SentinelOne | `sentinelone` | 46 | 739 | 179 | 25 |
| SentinelOne GraphQL / SentinelOne GraphQL | `sentinelonegraphql` | 29 | 318 | 39 | 5 |
| Slack / Slack | `slack` | 28 | 1760 | 222 | 3 |
| VirusTotal / VirusTotal | `virustotal` | 12 | 125 | 113 | 4 |
| Okta / Okta | `okta` | 12 | 42 | 0 | 0 |
| Atlassian / Jira Cloud | `jira-cloud` | 11 | 50 | 29 | 2 |
| Google / Sheets | `sheets` | 10 | 218 | 0 | 2 |
| Microsoft / Office365 (MSGraph) | `office365-(msgraph)` | 9 | 30 | 0 | 0 |
| DataSet / DataSet | `dataset` | 8 | 94 | 0 | 7 |
| Microsoft / Entra ID | `entra-id` | 7 | 22 | 0 | 0 |
| AlienVault / OTX | `alienlans-otx` | 7 | 19 | 53 | 0 |
| SentinelOne SDL / SentinelOne SDL | `sentinelonesdl` | 5 | 91 | 33 | 5 |
| Palo Alto Networks / Firewall | `pa-firewall` | 5 | 21 | 1 | 2 |
| ServiceNow / ServiceNow | `servicenowincidentresponse` | 4 | 38 | 0 | 1 |
| Zendesk / Support | `support` | 4 | 31 | 1 | 0 |
| Google / Drive | `drive` | 4 | 27 | 0 | 0 |
| Microsoft / Teams | `teams` | 4 | 12 | 0 | 0 |
| AWS / EC2 | `ec2` | 3 | 18 | 0 | 3 |
| Google / Gmail | `gmail` | 3 | 8 | 0 | 0 |
| Fortinet / FortiGate | `fortigate` | 3 | 5 | 0 | 0 |
| Hybrid Analysis / Hybrid Analysis | `hybrid-analysis` | 3 | 3 | 0 | 1 |
| abuse.ch / Malware Bazaar | `malware-bazaar` | 2 | 11 | 2 | 0 |
| Freshdesk / Freshdesk | `freshdesk` | 2 | 8 | 0 | 0 |
| IOC Parser / IOC Parser | `ioc-parser` | 2 | 8 | 0 | 0 |
| AWS / S3 | `amazon-s3` | 2 | 7 | 0 | 1 |
| Recorded Future / Recorded Future | `recorded-future` | 2 | 3 | 0 | 0 |
| GitHub / GitHub | `github` | 2 | 2 | 8 | 0 |
| Tenable / Tenable.io | `tenable-io` | 2 | 2 | 0 | 0 |
| Tenable / Web App Scanning | `web-app-scanning` | 2 | 2 | 0 | 0 |
| Abuse IPDB / Abuse IPDB | `abuse-ipdb` | 1 | 23 | 0 | 1 |
| Abnormal Security / Abnormal Security | `abnormal-security` | 1 | 7 | 0 | 0 |
| Cloudflare / Cloudflare | `cloudflare` | 1 | 7 | 37 | 0 |
| Freshservice / Freshservice | `freshservice` | 1 | 3 | 0 | 0 |
| OpenAI / OpenAI | `openai` | 1 | 3 | 1 | 0 |
| Anthropic / Anthropic | `anthropic` | 1 | 2 | 0 | 0 |
| Atlassian / Confluence | `confluence` | 1 | 2 | 0 | 0 |
| Microsoft / MSGraph Security | `msgraph-security` | 1 | 2 | 0 | 0 |
| Shodan / Shodan | `shodan` | 1 | 2 | 0 | 1 |
| Twilio / Twilio | `twilio` | 1 | 2 | 0 | 0 |
| Atlassian / Jira Server | `jira-server` | 1 | 1 | 0 | 0 |
| Cisco / Duo | `duo` | 1 | 1 | 0 | 0 |
| Microsoft / Intune | `intune` | 1 | 1 | 12 | 0 |
| Opsgenie / Opsgenie | `opsgenie` | 1 | 1 | 0 | 0 |
| Proofpoint / Protection Server | `protection-server` | 1 | 1 | 0 | 0 |
| Zscaler / Zscaler | `zscaler` | 1 | 1 | 0 | 0 |
| abuse.ch / URLHaus | `urlhaus` | 1 | 1 | 0 | 0 |
| AWS / AWS | `aws` | 0 | 0 | 1 | 1 |
| DocuSign / eSignature | `esignature` | 0 | 0 | 1 | 0 |
| Google / Workspace | `google-workspace` | 0 | 0 | 1 | 0 |
| Jamf / Jamf | `jamf` | 0 | 0 | 7 | 0 |
| OneLogin / OneLogin | `one-identity` | 0 | 0 | 1 | 0 |
| PagerDuty / PagerDuty | `pagerduty` | 0 | 0 | 2 | 0 |
| AWS / EBS | `ebs` | 0 | 0 | 0 | 1 |
| AWS / CloudTrail | `cloudtrail` | 0 | 0 | 0 | 1 |
| AWS / COMPREHEND | `comprehend` | 0 | 0 | 0 | 1 |
| AWS / SQS | `sqs` | 0 | 0 | 0 | 1 |
| AWS / WAF | `aws-waf-acl` | 0 | 0 | 0 | 1 |
| AWS / IAM | `iam` | 0 | 0 | 0 | 1 |
| Smartsheet / Smartsheet | `smartsheet` | 0 | 0 | 0 | 1 |
| AWS / DynamoDB | `dynamodb` | 0 | 0 | 0 | 1 |
| Email / IMAP | `imap` | 0 | 0 | 0 | 0 |
| AWS / SNS | `sns` | 0 | 0 | 0 | 1 |

Integrations showing 0 have a connection configured but no workflow action in this corpus.
Their action packs still exist in the console; this corpus just has no example.

---

## Packaged actions per integration

`n` = times used across the corpus. For the `public_action_id` of any of these actions, look it up
in the action library (`scripts/find_action.py --integration <name> <terms>`). Each heading gives
the number of distinct actions seen in workflows and the number in the library. The seen count can
be the higher one: it includes ids from an earlier version of a pack.

**Read the Action column with care.** It is the most common *author-assigned* step name, not the
pack's label, because authors rename steps freely. Where a name and a path disagree (`Export
Workflow` against `/web/api/v2.1/agents`, for instance), trust the path. The path shown is the
most common `data.url_path` for that action; a small number of authors edit the path after
inserting a packaged action.

### SentinelOne / SentinelOne

`product_key: sentinelone` | `integration_id`: `ef645af9-ed60-4efd-882e-bf534442ce86` | 46 actions seen in workflows, 64 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 113 | Add Note to Alert | POST | `/web/api/v2.0/threats` |
| 97 | Get Agents | GET | `/web/api/v2.1/agents` |
| 51 | Get Exclusions | GET | `/web/api/v2.1/exclusions` |
| 48 | Write TI to Sentinelone | POST | `/web/api/v2.1/firewall-control` |
| 39 | Run Remote Script | POST | `/web/api/v2.1/remote-scripts/execute` |
| 37 | Export Workflow | GET | `/web/api/v2.1/agents` |
| 36 | Disconnect Endpoint From Network | POST | `/web/api/v2.1/agents/actions/disconnect` |
| 36 | Get Agent by UUID | GET | `/web/api/v2.1/agents` |
| 23 | Dynamic Mitigation Call | POST | `/web/api/v2.1/threats/mitigate/remediate` |
| 18 | List Users | GET | `/web/api/v2.0/users` |
| 17 | Get Alert GraphQL | POST | `/web/api/v2.0/threats` |
| 14 | Send message to agent | POST | `/web/api/v2.1/agents/actions/broadcast` |
| 14 | Get Agents with active threat | GET | `/web/api/v2.1/agents` |
| 13 | Get Activities | GET | `/web/api/v2.1/activities` |
| 12 | Reconnect Endpoint to Network | POST | `/web/api/v2.1/agents/actions/connect` |
| 12 | Search Domain using Power Query | POST | `/web/api/v2.1/dv/init-query` |
| 12 | Get Script Status | GET | `/web/api/v2.1/agents/count` |
| 11 | Get DV Events | GET | `/web/api/v2.1/dv/events/pq-ping` |
| 10 | Create Power Query | POST | `/web/api/v2.1/dv/events/pq` |
| 10 | Get Agents Details | GET | `/web/api/v2.1/agents` |
| 10 | Get Agent by Hostname | GET | `/web/api/v2.1/agents` |
| 9 | Get Scripts | GET | `/web/api/v2.1/remote-scripts` |
| 9 | Get Query Status | GET | `/web/api/v2.1/dv/events/pq-ping` |
| 8 | Create Blocklist Item | POST | `/web/api/v2.0/restrictions` |
| 8 | Get Firewall Rules | GET | `/web/api/v2.1/firewall-control` |
| 7 | Create Temp Group | GET | `/web/api/v2.0/installed-applications` |
| 6 | Add IOCs | POST | `/web/api/v2.1/threat-intelligence/iocs` |
| 6 | Mitigate Threats  Kill | POST | `/web/api/v2.1/threats/mitigate/kill` |
| 6 | Move Agent to Temp Group | PUT | `/web/api/v2.1/agents` |
| 6 | Disconnect Endpoint From Network | POST | `/web/api/v2.1/agents/actions/disconnect` |
| 6 | Restart Endpoints | POST | `/web/api/v2.1/agents/actions/restart-machine` |
| 5 | Get Accounts | GET | `/web/api/v2.0/private/accounts` |
| 5 | Mitigate Threats  Rollback Remediation | POST | `/web/api/v2.1/threats/mitigate/rollback-remediation` |
| 4 | Get Application Inventory | GET | `/web/api/v2.1/agents/actions/broadcast` |
| 3 | Mitigate Threats - Quarantine | POST | `/web/api/v2.1/threats/mitigate/quarantine` |
| 2 | Get CVEs For Installed Applications | GET | `/web/api/v2.1/installed-applications/cves` |
| 2 | Get Tag ID | POST | `/web/api/v2.1/activities/types` |
| 2 | Ingest Alert | POST | `/web/api/v2.0/threats` |
| 2 | Get Recent Threats | GET | `/web/api/v2.0/threats` |
| 2 | Initiate Scan on Agents | POST | `/web/api/v2.1/agents/actions/initiate-scan` |
| 2 | Shutdown Agents | POST | `/web/api/v2.1/agents/actions/shutdown` |
| 2 | Disable STAR Rule | PUT | `/web/api/v2.0/restrictions` |
| 1 | Get Detection Rules | GET | `/web/api/v2.1/agents` |
| 1 | Fetch Files | POST | `/web/api/v2.1/agents/<<agentId>>/actions/fetch-files` |
| 1 | Initiate Scan on Agents | POST | `/web/api/v2.1/agents/actions/initiate-scan` |
| 1 | Get Agents Installed Applications | GET | `/web/api/v2.1/agents/applications` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /web/api/v2.1/threats/notes` (n=34)
- `POST https://<console>.sentinelone.net/web/api/v2.1/unifiedalerts/graphql` (n=12)
- `POST https://ingest.us1.sentinelone.net/v1/alerts` (n=11)
- `POST (dynamic)` (n=11)
- `POST /web/api/v2.1/threat-intelligence/iocs` (n=9)
- `POST https://<console>.sentinelone.net/web/api/v2.1/threat-intelligence/iocs` (n=8)
- `POST /web/api/v2.1/dv/events/pq` (n=7)
- `GET /web/api/v2.1/threat-intelligence/iocs` (n=5)

### SentinelOne GraphQL / SentinelOne GraphQL

`product_key: sentinelonegraphql` | `integration_id`: `3e274c5a-f574-462f-8685-5eed98e90fbb` | 29 actions seen in workflows, 46 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 94 | Add Note to Alert | POST | `/web/api/v2.0/threats` |
| 32 | Start AI Investigation | POST | `/web/api/v2.0/threats` |
| 31 | Add Note Dismissed | POST | `/web/api/v2.0/threats` |
| 19 | Add Alert to Exclusions Site Scope | POST | `/web/api/v2.0/threats` |
| 15 | Pull first 1000 Misconfigurations | POST | `/web/api/v2.0/threats` |
| 14 | Add Note to Vulnerability | POST | `/web/api/v2.1/remote-scripts/execute` |
| 14 | Verdict False Positive Benign | POST | `/web/api/v2.1/unifiedalerts/graphql` |
| 14 | Verdict True Positive Malware | POST | `/web/api/v2.1/unifiedalerts/graphql` |
| 14 | Status In Progress | POST | `/web/api/v2.1/unifiedalerts/graphql` |
| 10 | Get Available Response Actions | POST | `/web/api/v2.0/threats` |
| 8 | Get all alert IDs | POST | `/web/api/v2.0/threats` |
| 8 | Set Alert Status to Resolved | POST | `/web/api/v2.0/threats` |
| 7 | Resolve Alert as False Positive Benign | POST | `/web/api/v2.0/threats` |
| 6 | Set Vulnerability Status to Resolved True Positive | POST | `/web/api/v2.1/remote-scripts/execute` |
| 6 | Resolve Alert as True Positive Undefined | POST | `/web/api/v2.0/threats` |
| 5 | Set Alert Status to In Progress | POST | `/web/api/v2.0/threats` |
| 3 | Set Vulnerability Status to To Be Patched | POST | `/web/api/v2.1/remote-scripts/execute` |
| 3 | Resolve Alert as True Positive Malware | POST | `/web/api/v2.0/threats` |
| 3 | Gmail Note | POST | `/web/api/v2.0/threats` |
| 2 | Assign Alert | POST | `/web/api/v2.0/threats` |
| 2 | Get Agentic Investigation Summary | POST | `/web/api/v2.1/unifiedalerts/graphql` |
| 1 | Set Alert Status to New | POST | `/web/api/v2.0/threats` |
| 1 | Get RAW Indicators | POST | `/web/api/v2.0/threats` |
| 1 | Get CVE Remediation Insights | POST | `/web/api/v2.1/remote-scripts/execute` |
| 1 | Set Vulnerability Status to Resolved | POST | `/web/api/v2.1/remote-scripts/execute` |
| 1 | Set Analyst Verdict as True Positive Policy Violation | POST | `/web/api/v2.0/threats` |
| 1 | Trigger Agentic Investigation | POST | `/web/api/v2.1/unifiedalerts/graphql` |
| 1 | Get Available Response Action | POST | `/web/api/v2.0/threats` |
| 1 | get alert eventseq | POST | `/web/api/v2.0/threats` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /web/api/v2.1/unifiedalerts/graphql` (n=32)
- `POST /web/api/v2.1/xspm/findings/vulnerabilities/graphql` (n=3)
- `POST /web/api/v2.1/graphql` (n=2)
- `POST https://ingest.us1.sentinelone.net/v1/alerts` (n=1)
- `POST https://<console>.sentinelone.net/web/api/v2.1/unifiedalerts/graphql` (n=1)

### Slack / Slack

`product_key: slack` | `integration_id`: `43d27b10-ea4f-4829-a6d2-5de254dec613` | 28 actions seen in workflows, 18 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 382 | Post Timeout | POST | `/api/chat.postMessage` |
| 211 | Post Message | POST | `/api/chat.postMessage` |
| 205 | Create Channel | POST | `/api/conversations.create` |
| 202 | Set Channel Description | POST | `/api/bookmarks.edit` |
| 147 | Update Message Mitigation Cancel | POST | `/api/chat.postMessage` |
| 121 | Post Message | POST | `/api/chat.postMessage` |
| 114 | Find User by Email Address | GET | `/api/users.lookupByEmail` |
| 113 | Ask For Disconnect | POST | `/api/chat.postMessage` |
| 104 | Invite User To Channel | POST | `/api/conversations.invite` |
| 24 | Send Interactive Message | POST | `/api/chat.postMessage` |
| 18 | Find User by Email Address | GET | `/api/users.lookupByEmail` |
| 14 | Invite Users To a Channel | POST | `/api/conversations.invite` |
| 13 | Fetch Conversation History | POST | `/api/conversations.history` |
| 11 | Post user not found | POST | `/api/chat.postEphemeral` |
| 11 | Create Public Channel | POST | `/api/conversations.create` |
| 11 | Post Message In a Thread 2 | POST | `/api/chat.postMessage` |
| 10 | Invite Users To a Channel | POST | `/api/conversations.invite` |
| 9 | List Slack Users | GET | `/api/users.list` |
| 9 | Send Interactive Message | POST | `/api/chat.postMessage` |
| 8 | Create Private Channel | POST | `/api/conversations.create` |
| 5 | Create Private Channel | POST | `/api/conversations.create` |
| 5 | Create Public Channel | POST | `/api/conversations.create` |
| 4 | List Channels and Conversations | GET | `/api/conversations.list` |
| 3 | Get Conversation History | GET | `/api/bookmarks.edit` |
| 2 | Get User Presence Information | GET | `/api/users.list` |
| 2 | Archive Channel 2 | POST | `/api/conversations.create` |
| 1 | Get info about channel | POST | `/api/conversations.history` |
| 1 | Send a File to a Channel | POST | `/api/files.upload` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /api/chat.postMessage` (n=221)
- `POST /api/admin.users.invite` (n=1)

### VirusTotal / VirusTotal

`product_key: virustotal` | `integration_id`: `9b735fa3-69db-4430-bca0-347b57a8604d` | 12 actions seen in workflows, 67 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 67 | Search File Hash | GET | `/api/v3/files/<<file_hash>>` |
| 27 | VirusTotal Search IP | GET | `/api/v3/ip_addresses/{{local_var.src_ip}}` |
| 9 | Get Analysis | GET | `/api/v3/analyses/<<analysis-id>>` |
| 4 | Upload a File for Scanning | POST | `/api/v3/files` |
| 4 | Scan URL | POST | `/api/v3/urls` |
| 3 | Get comments on a file | GET | `/api/v3/files/<<file-id>>/comments` |
| 3 | Get comments on an IP address | GET | `/api/v3/ip_addresses/<<ip-id>>/comments` |
| 3 | Get a URL analysis report | GET | `/api/v3/urls/<<url-id>>` |
| 2 | Get a summary of all behavior reports for a file | GET | `/api/v3/files/<<file-id>>/behaviour_summary` |
| 1 | Search Domain | GET | `/api/v3/domains/<<domain>>` |
| 1 | Send file to VT | POST | `/api/v3/urls/<<url-id>>/analyse` |
| 1 | Get Votes of a File | GET | `/api/v3/files/<<file-id>>/votes` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `GET /api/v3/files/<<file_hash>>` (n=112)
- `GET /api/v3/ip_addresses/<<ip>>` (n=1)

### Okta / Okta

`product_key: okta` | `integration_id`: `5ce5b70d-f12d-4955-8cbb-cce8e5dd9ad5` | 12 actions seen in workflows, 24 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 7 | Search Users by Email | GET | `/api/v1/users/` |
| 6 | Suspend User | POST | `/api/v1/users/<<id>>/lifecycle/suspend` |
| 6 | Suspend a User | POST | `/api/v1/users/<<id>>/lifecycle/suspend` |
| 5 | Revoke all User Sessions | DELETE | `/api/v1/groups/<<group_id>>/users/<<user_id>>` |
| 3 | Activate a User | POST | `/api/v1/users/<<okta_id>>/lifecycle/activate` |
| 3 | Search Users by Email | GET | `/api/v1/users/` |
| 3 | Deactivate a User | POST | `/api/v1/users/<<okta_id>>/lifecycle/activate` |
| 3 | Get Okta Logins | GET | `/api/v1/logs` |
| 3 | Retrieve a User | GET | `/api/v1/users/<<okta_user_id>>` |
| 1 | Unsuspend a User | POST | `/api/v1/users/<<id>>/lifecycle/unsuspend` |
| 1 | Unsuspend a User | POST | `/api/v1/users/<<id>>/lifecycle/unsuspend` |
| 1 | Create a User | POST | `/api/v1/users` |
### Atlassian / Jira Cloud

`product_key: jira-cloud` | `integration_id`: `0a9250ea-11da-4427-977f-8a4aef183a09` | 11 actions seen in workflows, 79 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 22 | Create issue in HYP project via 0auth | POST | `/rest/api/2/issue` |
| 10 | Add alert details to ticket | POST | `/rest/api/2/issue/<<issueIdOrKey>>/comment` |
| 5 | Get Projects | GET | `/rest/api/2/project/<<projectIdOrKey>>` |
| 2 | Update Issue | PUT | `/rest/api/2/issue/<<issueIdOrKey>>` |
| 2 | Search for issues with indicator | POST | `/rest/api/2/search` |
| 2 | Create issue | POST | `/rest/api/2/issue` |
| 2 | Transition issue to Open | POST | `/rest/api/2/issue/<<issueIdOrKey>>/transitions` |
| 2 | Add comment | POST | `/rest/api/2/issue/<<issueIdOrKey>>/comment` |
| 1 | Get issue | GET | `/rest/api/2/issue/<<issueIdOrKey>>` |
| 1 | Create issue | POST | `/rest/api/2/issue` |
| 1 | Search for existing issues using JQL | POST | `/rest/api/2/search` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /rest/api/2/issue/<<issueIdOrKey>>/comment` (n=17)
- `PUT /rest/api/2/issue/<<issueIdOrKey>>` (n=7)
- `POST /rest/api/2/issue` (n=4)
- `POST /rest/api/2/user` (n=1)

### Google / Sheets

`product_key: sheets` | `integration_id`: `f66b2029-ddbf-4faa-94e3-999856d95f0b` | 10 actions seen in workflows, 17 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 96 | Get Column Configuration Values | GET | `/v4/spreadsheets/<<spreadsheet_id>>/values/B2:clear` |
| 36 | Get Values | GET | `/v4/spreadsheets/<<spreadsheet_id>>/values/1:10000` |
| 30 | Update protein | PUT | `/v4/spreadsheets/<<spreadsheet_id>>/values/A1:A2` |
| 26 | Append Values | POST | `/v4/spreadsheets/<<spreadsheet_id>>/values/1%3A10000:append` |
| 11 | Batch Update | POST | `/v4/spreadsheets/<<spreadsheet_id>>/` |
| 7 | Clear Values | POST | `/v4/spreadsheets/<<spreadsheet_id>>/values/B2:clear` |
| 7 | Populate Sheet 1 row titles | POST | `/v4/spreadsheets/<<spreadsheet_id>>/values/A1:A2` |
| 3 | Create spreadsheet | POST | `/v4/spreadsheets` |
| 1 | GetValuesFromWorkday | GET | `/v4/spreadsheets/<<spreadsheet_id>>/values/1:10000` |
| 1 | Get Values | GET | `/v4/spreadsheets/<<spreadsheet_id>>/values/B2:clear` |
### Microsoft / Office365 (MSGraph)

`product_key: office365-(msgraph)` | `integration_id`: `7f98b9aa-7e5c-4b55-a14d-e197e7064823` | 9 actions seen in workflows, 50 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 6 | Get Specific Message | GET | `/v1.0/me/messages/<<messageId>>` |
| 4 | AD Disable User | PATCH | `/v1.0/users/<<user>>` |
| 4 | Revoke User Sessions | POST | `/v1.0/users/<<userID>>/revokeSignInSessions` |
| 4 | Update User Password | PATCH | `/v1.0/users/<<userID>>` |
| 3 | Get Outlook Email UserId | GET | `/v1.0/me/messages` |
| 3 | Get completed folder ID | GET | `/v1.0/me/mailFolders/Inbox/messages` |
| 2 | Get Manager by Email Address | GET | `/v1.0/users/<<userEmail>>/manager` |
| 2 | Get Users By Department | GET | `/v1.0/users` |
| 2 | Send Email to Manager | POST | `/v1.0/me/sendMail` |
### DataSet / DataSet

`product_key: dataset` | `integration_id`: `92cfc975-2e0f-4c96-be29-00ea2fa91805` | 8 actions seen in workflows, 19 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 38 | Query | POST | `/api/timeseriesQuery` |
| 18 | Power Query | POST | `/api/timeseriesQuery` |
| 17 | Add Events | POST | `https://ingest.us1.sentinelone.net/services/collector/raw` |
| 8 | Add Events | POST | `/api/addEvents` |
| 8 | Put File | POST | `/api/putFile` |
| 3 | PQ Detection Rule | POST | `/api/timeseriesQuery` |
| 1 | Run Query | POST | `/api/timeseriesQuery` |
| 1 | Retrieve the Custom Monitors Config | POST | `/api/getFile` |
### Microsoft / Entra ID

`product_key: entra-id` | `integration_id`: `73475bd9-3762-4f17-aab5-c544ec5ec31b` | 7 actions seen in workflows, 13 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 10 | Revoke Session | PATCH | `graph.microsoft.com/v1.0/users/` |
| 3 | Get Mail Forwarding Rule | GET | `/v1.0/users//mailFolders/inbox/messageRules` |
| 3 | Get Sharepoint Site Info | GET | `/v1.0/sites/<tenant>.sharepoint.com:/sites/<site>` |
| 2 | List Users | GET | `/v1.0/users/<!!>` |
| 2 | Get User | GET | `/v1.0/users/` |
| 1 | Delete a User | DELETE | `/v1.0/users/<<user-id>>` |
| 1 | List Messages | GET | `/v1.0/teams/9c53c2c3-88b5-45e6-a3d5-ccee2ce25f72/channels/19:2a2e6849497040a898aab38784c963e8@thread.tacv2/messages` |
### AlienVault / OTX

`product_key: alienlans-otx` | `integration_id`: `99c539d6-9597-4e8e-97df-a2e802fd6387` | 7 actions seen in workflows, 43 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 5 | Get File Hash analysis | POST | `/api/v1/indicators/file/<<file-hash>>/analysis` |
| 4 | Submit a File for Analysis | POST | `/api/v1/indicators/submit_file` |
| 4 | Lookup File Hash | POST | `/api/v1/indicators/file/<<file-hash>>/general` |
| 3 | Get Subscribed Pulses | GET | `/api/v1/pulses/related` |
| 1 | Find Pulses Related to Adversary | GET | `/api/v1/pulses/related` |
| 1 | Submit a File for Analysis 1 | POST | `/api/v1/indicators/submit_file` |
| 1 | Retrieve Pulse Indicators | GET | `/api/v1/pulses/<<pulse_id>>/indicators` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /api/v1/indicators/file/<<file-hash>>/general` (n=53)

### SentinelOne SDL / SentinelOne SDL

`product_key: sentinelonesdl` | `integration_id`: `ea6018b7-2a2f-44ca-b9b6-27a0434b0503` | 5 actions seen in workflows, 10 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 47 | SDL Query | POST | `/sdl/api/query` |
| 24 | SDL Add Events Skill | POST | `/sdl/api/addEvents` |
| 18 | SDL Power Query | POST | `/sdl/api/powerQuery` |
| 1 | Timeseries Query | POST | `/sdl/api/timeseriesQuery` |
| 1 | Get lookup table | POST | `/sdl/api/getFile` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /sdl/v2/api/queries` (n=13)
- `GET /sdl/v2/api/queries/` (n=10)
- `POST https://ingest.us1.sentinelone.net/v1/indicators` (n=3)
- `POST https://ingest.us1.sentinelone.net/v1/alerts` (n=3)
- `POST https://xdr.<region>.sentinelone.net/api/powerQuery` (n=2): **deprecated V1 endpoint**, sunsets 2027-02-15. Observed in existing flows only; new flows use LRQ (`/sdl/v2/api/queries`), see catalog B8.
- `POST https://ingest.us1.sentinelone.net/services/collector/event` (n=1)
- `POST /web/api/v2.1/unifiedalerts/graphql` (n=1)

This is a census of what existing flows call, not a list of what still works. Two entries are
dead ends for new flows:

- **`/v1/indicators` cannot be driven by any credential.** It refuses the console API token
  (`403 "User token not allowed for this endpoint"`) and the SDL Log Write Key (`401`) alike.
  Carry indicators inline in the alert, in `finding_info.related_events[]`, in a single
  `POST /v1/alerts`, which is also what populates the console Indicators tab. `/v1/alerts` itself
  is unchanged and still takes the console API token.
- **`/services/collector/*` takes an SDL Log Write Key.** The write key returns
  `HTTP 200 {"text":"Success","code":0}`. The console API token is not a reliable substitute: on
  some consoles it returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}` without an
  `S1-Scope` header and is accepted with one, on others it returns
  `HTTP 403 {"text":"User token not allowed for this endpoint","code":4}` either way. Use the write
  key in both cases. The key is minted for one account or site and that fixes where the events
  land, so it needs no `S1-Scope` header.

### Palo Alto Networks / Firewall

`product_key: pa-firewall` | `integration_id`: `63cfa20c-f77d-4404-9744-3d78cb92d7bd` | 5 actions seen in workflows, 11 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 15 | Add IP to Block List | POST | `/api/` |
| 3 | Commit Configuration | POST | `/api/` |
| 1 | Update URL Filtering Profile | POST | `/api/` |
| 1 | End Palo Alto GlobalProtect VPN Session | GET | `/api/` |
| 1 | Create Security Policy | POST | `/api/` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST https://gns-palo.free.beeceptor.com/paloblocklist` (n=1)

### ServiceNow / ServiceNow

`product_key: servicenowincidentresponse` | `integration_id`: `854385b9-2e7e-48f2-b7c7-2a2fdb89e2cb` | 4 actions seen in workflows, 14 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 23 | Create New Incident Ticket | POST | `/api/now/v1/table/incident` |
| 12 | Update Incident Ticket | PUT | `/api/now/v1/table/incident/<<incident_id>>` |
| 2 | Perform a Global Search for Keyword | GET | `/api/now/globalsearch/search` |
| 1 | Get Incident | GET | `/api/now/table/<<tableName>>/<<sys_id>>` |
### Zendesk / Support

`product_key: support` | `integration_id`: `af8487dd-a473-4277-a458-fa64da7cfb23` | 4 actions seen in workflows, 12 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 13 | Create Ticket | POST | `/api/v2/tickets.json` |
| 11 | List Tickets | GET | `/api/v2/tickets.json` |
| 5 | Update Ticket | PUT | `/api/v2/tickets/<<_ticket_id>>.json` |
| 2 | Add Comment to Ticket | PUT | `/api/v2/tickets/<<_ticket_id>>.json` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /api/v2/users.json` (n=1)

### Google / Drive

`product_key: drive` | `integration_id`: `a5d80eb2-6f8b-431a-9f99-cf1854e7722f` | 4 actions seen in workflows, 14 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 12 | Get Router Prompt | GET | `/drive/v3/files` |
| 7 | List Prompts in Obsidian Vault | GET | `/drive/v3/files` |
| 5 | Create File Report | POST | `/drive/v3/files` |
| 3 | Update Context File | PATCH | `/drive/v3/files/<<file_id>>` |
### Microsoft / Teams

`product_key: teams` | `integration_id`: `afe4fbed-e8ee-4c6d-823f-6c7077af7fd7` | 4 actions seen in workflows, 15 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 8 | Send Failed chatMessage in Channel | POST | `/v1.0/teams/<<team_id>>/channels/<<channel_id>>/messages` |
| 2 | Create Channel In Team | POST | `/v1.0/teams/<<team_id>>/channels` |
| 1 | Create group chat | POST | `/v1.0/chats` |
| 1 | Send chatMessage In Chat | POST | `/v1.0/chats/<<chat_id>>/messages` |
### AWS / EC2

`product_key: ec2` | `integration_id`: `5bd2c922-6c64-4586-ad01-8b72d75491f8` | 3 actions seen in workflows, 11 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 15 | Revoke Security Group Rules Ingress | GET | `/` |
| 2 | Describe Security Groups | GET | `/` |
| 1 | Revoke Security Group Rules Ingress | GET | `/` |
### Google / Gmail

`product_key: gmail` | `integration_id`: `1d5ae5b6-3dce-48e4-beec-6c3134d5ce87` | 3 actions seen in workflows, 42 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 5 | Delete Message | DELETE | `/gmail/v1/users/<<user>>/messages/<<emailId>>` |
| 2 | Get Social | GET | `/gmail/v1/users/<<user>>/messages` |
| 1 | Get Promotions | GET | `/gmail/v1/users/<<user>>/messages` |
### Fortinet / FortiGate

`product_key: fortigate` | `integration_id`: `84b7a30c-5e9f-48dd-b4e9-c7a42f3d8a1b` | 3 actions seen in workflows, 38 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 2 | Get Object Name | GET | `/api/v2/cmdb/firewall/address` |
| 2 | Retrieve Address Group Contents | GET | `/api/v2/cmdb/firewall/addrgrp` |
| 1 | Add Firewall Policy | POST | `/api/v2/cmdb/firewall/policy` |
### Hybrid Analysis / Hybrid Analysis

`product_key: hybrid-analysis` | `integration_id`: `ec2d72f8-18d6-49e5-8ada-4e10a479e16a` | 3 actions seen in workflows, 7 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Upload a File | POST | `/api/v2/submit/file` |
| 1 | Get Sandbox Report Summary | GET | `/api/v2/report/<<job_id>>/summary` |
| 1 | Search Hash | POST | `/api/v2/search/hash` |
### abuse.ch / Malware Bazaar

`product_key: malware-bazaar` | `integration_id`: `63c4fa5d-c67a-450a-b245-846b31dfad5e` | 2 actions seen in workflows, 7 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 10 | Query a Malware Sample | POST | `/api/v1/` |
| 1 | Query malwares by signature | POST | `/api/v1/` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /api/v1/` (n=2)

### Freshdesk / Freshdesk

`product_key: freshdesk` | `integration_id`: `0f8051d4-28eb-4ed3-8868-fe8a1cee29f0` | 2 actions seen in workflows, 9 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 4 | Create a Ticket | POST | `/helpdesk/tickets.json` |
| 4 | Resolve Ticket | PUT | `/api/v2/tickets/<<id>>` |
### IOC Parser / IOC Parser

`product_key: ioc-parser` | `integration_id`: `cdfe1ad0-f0cb-4985-b7e7-8f109c6bb39e` | 2 actions seen in workflows, 4 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 5 | Parse IOCs from URL | POST | `/url` |
| 3 | IOC | POST | `/text` |
### AWS / S3

`product_key: amazon-s3` | `integration_id`: `39a29be6-4456-4232-925d-25a08c09cb73` | 2 actions seen in workflows, 2 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 5 | Modify S3 Public Access | PUT | `/<<object_key>>` |
| 2 | Get S3 publicAccessBlock Settings | GET | `/` |
### Recorded Future / Recorded Future

`product_key: recorded-future` | `integration_id`: `7e2b34bc-daf3-471b-8453-d5f8b86a320f` | 2 actions seen in workflows, 42 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 2 | Hash Lookup | GET | `/v2/hash/<<hash>>` |
| 1 | IP Lookup | GET | `/v2/ip/<<ip-address>>` |
### GitHub / GitHub

`product_key: github` | `integration_id`: `bed78455-3b7b-48cc-8e9e-c63a2f076bc6` | 2 actions seen in workflows, 47 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Get repository content | GET | `/repos/<<owner>>/<<repository>>/contents` |
| 1 | Invite Github user to Organization | POST | `/orgs/<<org>>/code-scanning/alerts` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `GET (dynamic)` (n=5)
- `GET /repos/Sentinel-One/ai-siem/contents/workflows/community` (n=1)
- `GET /repos/Sentinel-One/ai-siem/releases/latest` (n=1)
- `GET /repos/Sentinel-One/ai-siem/contents/workflows/community/` (n=1)

### Tenable / Tenable.io

`product_key: tenable-io` | `integration_id`: `6e33bcbc-34c7-48aa-85fa-9759e4b7db62` | 2 actions seen in workflows, 20 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | List Asset Vulnerabilities | GET | `/workbenches/assets/<<agent_uuid>>/vulnerabilities` |
| 1 | Scan Details | GET | `/scans/<<scan_uuid>>` |
### Tenable / Web App Scanning

`product_key: web-app-scanning` | `integration_id`: `0a264681-0e39-45d9-a869-dfb2c831d180` | 2 actions seen in workflows, 11 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Get Web App Scan Notes | GET | `/was/v2/scans/<<scan_id>>/notes` |
| 1 | Search Web App Vulnerabilities for Scan | POST | `/was/v2/scans/<<scan_id>>/vulnerabilities/search` |
### Abuse IPDB / Abuse IPDB

`product_key: abuse-ipdb` | `integration_id`: `75af0459-ecea-48eb-9a62-7ec2e68a4c73` | 1 actions seen in workflows, 4 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 23 | AbuseIPDB Check IP | GET | `/api/v2/check` |
### Abnormal Security / Abnormal Security

`product_key: abnormal-security` | `integration_id`: `870d40d6-248b-4ae7-bc83-3d81cd9398e8` | 1 actions seen in workflows, 10 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 7 | Get Cases | GET | `/v1/threats/<<threatId>>` |
### Cloudflare / Cloudflare

`product_key: cloudflare` | `integration_id`: `0dedd07c-0b9a-4205-9215-03ab1a95eb3a` | 1 actions seen in workflows, 51 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 7 | Cloudflare Block IP | POST | `/client/v4/user/firewall/access_rules/rules` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /client/v4/zones/cf4d15af4a7eb86b033f859aefec1047/firewall/access_rules/rules` (n=7)
- `GET /client/v4/zones/cf4d15af4a7eb86b033f859aefec1047` (n=5)
- `GET /client/v4/zones/cf4d15af4a7eb86b033f859aefec1047/firewall/access_rules/rules?per_page=100` (n=4)
- `POST /client/v4/zones/cf4d15af4a7eb86b033f859aefec1047/rulesets/47e1f8f7826b485498964c658c551f22/rules` (n=4)
- `GET /client/v4/zones/cf4d15af4a7eb86b033f859aefec1047/rulesets/47e1f8f7826b485498964c658c551f22` (n=4)
- `GET /client/v4/ips` (n=2)
- `GET /client/v4/accounts/b8e637d5097fff0c694c3290ba81563e/gateway/rules` (n=2)
- `PATCH /client/v4/zones/cf4d15af4a7eb86b033f859aefec1047/settings/security_level` (n=2)

### Freshservice / Freshservice

`product_key: freshservice` | `integration_id`: `cd77a67b-b9fc-44b8-85c4-592ff8625235` | 1 actions seen in workflows, 13 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 3 | Create a Ticket | POST | `/api/v2/tickets` |
### OpenAI / OpenAI

`product_key: openai` | `integration_id`: `e1a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c` | 1 actions seen in workflows, 4 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 3 | Final Analysis | POST | `/v1/responses` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST https://api.openai.com/v1/chat/completions` (n=1)

### Anthropic / Anthropic

`product_key: anthropic` | `integration_id`: `e2b3c4d5-f6a7-4b8c-9d0e-1f2a3b4c5d6e` | 1 actions seen in workflows, 4 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 2 | Create message | POST | `/v1/messages` |
### Atlassian / Confluence

`product_key: confluence` | `integration_id`: `bc64acb7-008a-49f8-9d0b-46a9acb22922` | 1 actions seen in workflows, 5 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 2 | Get pages | GET | `/wiki/rest/api/content` |
### Microsoft / MSGraph Security

`product_key: msgraph-security` | `integration_id`: `fd2422cd-001f-4603-ba6e-bc17f1869e2f` | 1 actions seen in workflows, 22 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 2 | Retrieve Alerts with Category 'Impossible Login Velocity' | GET | `/v1.0/security/alerts` |
### Shodan / Shodan

`product_key: shodan` | `integration_id`: `6c8b70cb-2c9d-42ed-a2f4-c931a3e0d8f4` | 1 actions seen in workflows, 27 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 2 | Search Shodan | GET | `/shodan/host/search` |
### Twilio / Twilio

`product_key: twilio` | `integration_id`: `5076573f-9086-4076-90f4-3a64345801d3` | 1 actions seen in workflows, 11 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 2 | Send a Text Message to User | POST | `/2010-04-01/Accounts/<<twilio_account_id>>/Messages.json` |
### Atlassian / Jira Server

`product_key: jira-server` | `integration_id`: `b01188c3-13ea-45ec-bc86-77ea751e2515` | 1 actions seen in workflows, 48 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Create issue | POST | `/rest/api/2/issue` |
### Cisco / Duo

`product_key: duo` | `integration_id`: `0e57ea51-6fbe-4d0c-b785-861ee752c4a4` | 1 actions seen in workflows, 33 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Retrieve Users | GET | `/admin/v1/users` |
### Microsoft / Intune

`product_key: intune` | `integration_id`: `babd39bf-783a-4c61-abd2-02d9f25b96a9` | 1 actions seen in workflows, 25 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | List Managed Devices | GET | `/beta/deviceManagement/managedDevices` |
Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /beta/deviceManagement/deviceManagementScripts` (n=4)
- `POST /beta/admin/windows/updates/deploymentAudiences` (n=1)
- `POST /beta/admin/windows/updates/deploymentAudiences//updateAudience` (n=1)
- `GET /beta/admin/windows/updates/catalog/entries` (n=1)
- `POST /beta/admin/windows/updates/updatePolicies` (n=1)
- `POST /v1.0/groups` (n=1)
- `GET /v1.0/devices` (n=1)
- `POST /v1.0/groups//members/$ref` (n=1)

### Opsgenie / Opsgenie

`product_key: opsgenie` | `integration_id`: `b6370881-4103-463d-8775-74ad6234834e` | 1 actions seen in workflows, 60 in the library <!-- trufflehog:ignore (integration instance id, not a credential) -->

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Add Tags to Alert | POST | `/v2/alerts/<<identifier_id>>/tags` |
### Proofpoint / Protection Server

`product_key: protection-server` | `integration_id`: `e1d0593e-132e-4a37-a27e-21cc98cec385` | 1 actions seen in workflows, 12 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Delete Quarantined Message | POST | `/rest/v1/quarantine` |
### Zscaler / Zscaler

`product_key: zscaler` | `integration_id`: `18c67901-6aaf-4d0b-89ef-ea765005bea9` | 1 actions seen in workflows, 48 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Add URLs to Blocklist | POST | `/api/v1/security/advanced/blacklistUrls` |
### abuse.ch / URLHaus

`product_key: urlhaus` | `integration_id`: `04ec38ee-2fd3-42f2-b42a-75f7b4f94ea2` | 1 actions seen in workflows, 9 in the library

| n | Action | Method | Path |
|--:|---|---|---|
| 1 | Query URL information | POST | `/v1/host/` |
---

## Custom integrations (52)

User-defined integrations have no action pack: every call against them is ad-hoc, with a URL
you write. The corpus holds 52 of them, carrying 184 ad-hoc calls. Twelve of them duplicate a
built-in (for example a hand-rolled Okta, FortiGate, Zscaler, OpenAI or Microsoft Teams
integration). When a user asks for a custom integration, check the action library first:
`python3 scripts/find_action.py --list-integrations <vendor>`. **Prefer the built-in when one
exists**, you get the action pack.
