# Integration Action Catalog, mined from a live tenant

Ground truth for **which integrations exist and what actions run against each**. Mined from
**1,205 exported workflows / 17,899 action steps** on a production SentinelOne tenant,
2026-08-06. Supersedes the 643-workflow figures previously quoted in `building-blocks-catalog.md`.

## How Hyperautomation integrations actually work (read this first)

Two kinds of integration-backed HTTP action exist, and the difference matters when you
generate JSON:

| | Packaged action | Ad-hoc action |
|---|---|---|
| `data.public_action_id` | a UUID from the vendor's action pack | `null` |
| `data.url_path` | pre-filled by the pack, e.g. `/api/chat.postMessage` | you write it |
| `data.url` | `{{Connection.protocol}}{{Connection.url}}<@/api/chat.postMessage@>` | anything |
| Share of corpus | **3,822 of 5,418 http_requests (71%)** | 1,596 (29%) |

So an integration **is** an action pack, plus a named authenticated connection. Every built-in
integration ships a fixed set of packaged actions; **266 distinct `public_action_id` values
across 45 integrations** appear in this corpus. Custom (user-defined) integrations ship none,
every call against them is ad-hoc.

The `<@...@>` wrapper inside `data.url` is the console's link markup for the packaged path. Keep
`url`, `url_path` and `public_action_id` consistent with each other when authoring by hand.

### There is no API to list the action packs

Verified live, 2026-08-06:

| Call | Result |
|---|---|
| `GET /hyper-automate/api/v1/integrations` | `405 Method Not Allowed`, no list endpoint |
| `GET /hyper-automate/api/v1/integrations/{uuid}` | `200`, connection/auth metadata only, **no actions** |
| `GET /hyper-automate/api/v1/integrations/{id}/actions` | `404` |
| `/operations`, `/templates`, `/methods`, `/capabilities`, `/endpoints`, `/catalog`, `/schema` | all `404` |
| `GET /hyper-automate/api/v1/integrations/<non-uuid>` | `422 uuid_parsing`, the `{integration_id}` route shadows every static sub-path |
| `GET /hyper-automate/api/v1/connections/scope` | `200`, **this** is how you enumerate integrations in use |

Because the packs are not queryable, **this file is the catalog**. It is mined from what the
packs actually emitted into 1,205 workflows.

**To enumerate integrations on a new tenant**: `GET /connections/scope`, collect distinct
`integration_id`, resolve each with `GET /integrations/{id}`. Union with the `integration_id`
values on actions from `GET /api/public/workflows`; some integrations are referenced by
workflows without a connection in your scope.

---

## Tenant totals

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
| Distinct packaged actions (`public_action_id`) | 266 |

`product_key` is the built-in vs custom discriminator. Custom integrations carry a
`vendor_name` only, with `product_name: ""` and `product_key: null`, and often duplicate a
built-in (a hand-rolled `Okta` alongside built-in `Okta / Okta`; `Fortigate FW` alongside
`Fortinet / FortiGate`). **Prefer the built-in when one exists**, you get the action pack.

---

## Built-in integrations (62)

| Vendor / Product | `product_key` | Packaged actions | Packaged uses | Ad-hoc uses | Connections |
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

Integrations showing 0 have a connection configured but no workflow action on this tenant.
Their action packs still exist in the console; this corpus just has no example.

---

## Packaged actions per integration

`n` = times used across the corpus. `public_action_id` is stable per action pack, so it is
portable across tenants; `integration_id` is **not**, resolve it per console.

**Read the Action column with care.** It is the most common *author-assigned* step name, not the
pack's canonical label, because authors rename steps freely. Where a name and a path disagree
(`Export Workflow` against `/web/api/v2.1/agents`, for instance), trust `public_action_id` and
`Path`. The path shown is likewise the most common `data.url_path` for that id; a small number of
authors edit the path after inserting a packaged action.

### SentinelOne / SentinelOne

`product_key: sentinelone` | `integration_id` on this tenant: `ef645af9-ed60-4efd-882e-bf534442ce86` | 46 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 113 | Add Note to Alert | POST | `/web/api/v2.0/threats` | `a1863e01-cfa4-4544-ae32-ca1a37442340` |
| 97 | Get Agents | GET | `/web/api/v2.1/agents` | `afe978b7-6a52-4e4b-9871-c0c738971b6f` |
| 51 | Get Exclusions | GET | `/web/api/v2.1/exclusions` | `1219e0d6-3b5a-4342-8035-a8192b7078df` |
| 48 | Write TI to Sentinelone | POST | `/web/api/v2.1/firewall-control` | `fecff713-56be-4f9b-8e64-0af3d46ad8aa` |
| 39 | Run Remote Script | POST | `/web/api/v2.1/remote-scripts/execute` | `3de49850-54d7-403c-a9a7-f8e72129f64b` |
| 37 | Export Workflow | GET | `/web/api/v2.1/agents` | `a798599d-940b-4eb2-98cb-fb3fbbe43ed2` |
| 36 | Disconnect Endpoint From Network | POST | `/web/api/v2.1/agents/actions/disconnect` | `6cb9568b-029a-46b1-910f-e4734d0ea155` |
| 36 | Get Agent by UUID | GET | `/web/api/v2.1/agents` | `60af5d30-fa9c-40d8-866b-bc5139a412fd` |
| 23 | Dynamic Mitigation Call | POST | `/web/api/v2.1/threats/mitigate/remediate` | `8f2d917e-f265-4ef4-b782-2faa97783857` |
| 18 | List Users | GET | `/web/api/v2.0/users` | `3e1b65da-0b9d-48ca-aa28-700b9c2a37ac` |
| 17 | Get Alert GraphQL | POST | `/web/api/v2.0/threats` | `34049bba-98b5-4b78-9de5-968251b550f9` |
| 14 | Send message to agent | POST | `/web/api/v2.1/agents/actions/broadcast` | `6b80f826-3ecc-4ef5-9cfc-2c8a9f19acb8` |
| 14 | Get Agents with active threat | GET | `/web/api/v2.1/agents` | `af9116da-24f5-4453-a014-5a8e93e18bd6` |
| 13 | Get Activities | GET | `/web/api/v2.1/activities` | `34a53bc6-4f63-423b-8955-549e53827a35` |
| 12 | Reconnect Endpoint to Network | POST | `/web/api/v2.1/agents/actions/connect` | `332d15f9-8bb5-4df4-a020-45a0a9cf3e0b` |
| 12 | Search Domain using Power Query | POST | `/web/api/v2.1/dv/init-query` | `8d823fbd-87bc-47cc-a950-05959a50b553` |
| 12 | Get Script Status | GET | `/web/api/v2.1/agents/count` | `b99a37a3-bee6-4f4b-9ff7-9c3bec334b9d` |
| 11 | Get DV Events | GET | `/web/api/v2.1/dv/events/pq-ping` | `014e1093-4466-4fa4-8cd7-317a8dac18c2` |
| 10 | Create Power Query | POST | `/web/api/v2.1/dv/events/pq` | `26adfd4c-0f20-4e2d-8e63-2905b0a20092` |
| 10 | Get Agents Details | GET | `/web/api/v2.1/agents` | `8dfd1f8e-eb7f-427d-a61d-ccc8b36d2256` |
| 10 | Get Agent by Hostname | GET | `/web/api/v2.1/agents` | `869d0ecc-7768-47f0-9fd9-aba99883547b` |
| 9 | Get Scripts | GET | `/web/api/v2.1/remote-scripts` | `cd0ee9ad-98cb-4914-8fed-9628e17fdf7b` |
| 9 | Get Query Status | GET | `/web/api/v2.1/dv/events/pq-ping` | `6b7c9ea5-cf53-4a27-986a-5bc0b627e0f8` |
| 8 | Create Blocklist Item | POST | `/web/api/v2.0/restrictions` | `07e21f3c-3e9e-4685-83a4-fd599910dd3e` |
| 8 | Get Firewall Rules | GET | `/web/api/v2.1/firewall-control` | `20bc9ffd-6904-4163-8cbc-d63c60046d01` |
| 7 | Create Temp Group | GET | `/web/api/v2.0/installed-applications` | `468eea9f-07bd-4c9c-8887-7eea4a0a8349` |
| 6 | Add IOCs | POST | `/web/api/v2.1/threat-intelligence/iocs` | `282ae683-5ab1-46c1-b5b2-d6ff270627d4` |
| 6 | Mitigate Threats  Kill | POST | `/web/api/v2.1/threats/mitigate/kill` | `fd024552-57c7-486e-96db-8cba89a56331` |
| 6 | Move Agent to Temp Group | PUT | `/web/api/v2.1/agents` | `87d498f0-46e3-4df9-9db7-d2ddf15ff278` |
| 6 | Disconnect Endpoint From Network | POST | `/web/api/v2.1/agents/actions/disconnect` | `c0eca0c4-31cd-400b-9a98-f88a1daa3876` |
| 6 | Restart Endpoints | POST | `/web/api/v2.1/agents/actions/restart-machine` | `30fa7849-e6f3-47c0-9d2f-1b43e06f9025` |
| 5 | Get Accounts | GET | `/web/api/v2.0/private/accounts` | `ed12a7e8-0ba0-4850-8039-368b5edab65e` |
| 5 | Mitigate Threats  Rollback Remediation | POST | `/web/api/v2.1/threats/mitigate/rollback-remediation` | `4de74424-12dc-4f81-97b2-c6d819d17f37` |
| 4 | Get Application Inventory | GET | `/web/api/v2.1/agents/actions/broadcast` | `d124a191-8fca-4f21-81e3-23a96c5b7f1b` |
| 3 | Mitigate Threats - Quarantine | POST | `/web/api/v2.1/threats/mitigate/quarantine` | `7c6a2088-8d36-419d-bddf-3fb358d2618e` |
| 2 | Get CVEs For Installed Applications | GET | `/web/api/v2.1/installed-applications/cves` | `647cc5ea-b630-4703-ac17-0e433c6441b2` |
| 2 | Get Tag ID | POST | `/web/api/v2.1/activities/types` | `f198505f-c193-40ff-8dc8-51897d9f9300` |
| 2 | Ingest Alert | POST | `/web/api/v2.0/threats` | `fd3d7a4b-27fa-4f35-bfd1-91460d38bb8a` |
| 2 | Get Recent Threats | GET | `/web/api/v2.0/threats` | `d0895800-45d1-476a-8291-f8fb6b810c2e` |
| 2 | Initiate Scan on Agents | POST | `/web/api/v2.1/agents/actions/initiate-scan` | `0ca5039b-8b1a-47d7-8e58-5c2a709ee1ca` |
| 2 | Shutdown Agents | POST | `/web/api/v2.1/agents/actions/shutdown` | `0547ee5f-84d1-47dd-9fd9-b95da5521035` |
| 2 | Disable STAR Rule | PUT | `/web/api/v2.0/restrictions` | `86a933ba-edeb-4a90-96e0-ba947a2ad703` |
| 1 | Get Detection Rules | GET | `/web/api/v2.1/agents` | `24e13cf4-ff24-4011-8ee5-7d6d4f339579` |
| 1 | Fetch Files | POST | `/web/api/v2.1/agents/<<agentId>>/actions/fetch-files` | `462b4aa9-7fbf-476a-bb27-0811d1b1d146` |
| 1 | Initiate Scan on Agents | POST | `/web/api/v2.1/agents/actions/initiate-scan` | `b7faafda-9de1-4afb-baea-7237e2c29287` |
| 1 | Get Agents Installed Applications | GET | `/web/api/v2.1/agents/applications` | `3bc7c1a4-dc65-49bb-a100-b92f48744acd` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /web/api/v2.1/threats/notes` (n=34)
- `POST https://usea1-purple.sentinelone.net/web/api/v2.1/unifiedalerts/graphql` (n=12)
- `POST https://ingest.us1.sentinelone.net/v1/alerts` (n=11)
- `POST (dynamic)` (n=11)
- `POST /web/api/v2.1/threat-intelligence/iocs` (n=9)
- `POST https://usea1-purple.sentinelone.net/web/api/v2.1/threat-intelligence/iocs` (n=8)
- `POST /web/api/v2.1/dv/events/pq` (n=7)
- `GET /web/api/v2.1/threat-intelligence/iocs` (n=5)

### SentinelOne GraphQL / SentinelOne GraphQL

`product_key: sentinelonegraphql` | `integration_id` on this tenant: `3e274c5a-f574-462f-8685-5eed98e90fbb` | 29 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 94 | Add Note to Alert | POST | `/web/api/v2.0/threats` | `c4d87734-41d0-4f0a-890c-6411de0796d3` |
| 32 | Start AI Investigation | POST | `/web/api/v2.0/threats` | `806addd1-5f1a-4337-8937-99faef836832` |
| 31 | Add Note Dismissed | POST | `/web/api/v2.0/threats` | `34de543f-a745-42ac-84ec-6c2a87c26f60` |
| 19 | Add Alert to Exclusions Site Scope | POST | `/web/api/v2.0/threats` | `6f06eb91-9a16-45f3-ab9d-670c16e7355d` |
| 15 | Pull first 1000 Misconfigurations | POST | `/web/api/v2.0/threats` | `443ac7cc-4cdd-477b-9ec1-d4f56886eeac` |
| 14 | Add Note to Vulnerability | POST | `/web/api/v2.1/remote-scripts/execute` | `6c833c0d-cf4f-4cbc-b7ec-895fdb8401d0` |
| 14 | Verdict False Positive Benign | POST | `/web/api/v2.1/unifiedalerts/graphql` | `fb264d94-644a-4075-b127-cede3f545ee0` |
| 14 | Verdict True Positive Malware | POST | `/web/api/v2.1/unifiedalerts/graphql` | `8ec867d8-bb74-459f-8a17-d328d2e6776b` |
| 14 | Status In Progress | POST | `/web/api/v2.1/unifiedalerts/graphql` | `b9658ad8-24a1-4a6f-a490-f22a93445069` |
| 10 | Get Available Response Actions | POST | `/web/api/v2.0/threats` | `88abf485-75d8-42c1-8050-409c7290a993` |
| 8 | Get all alert IDs | POST | `/web/api/v2.0/threats` | `d0ad9752-3ba1-4f58-9360-680b48efb424` |
| 8 | Set Alert Status to Resolved | POST | `/web/api/v2.0/threats` | `cef56759-7230-42c7-af8d-2215f6500ff2` |
| 7 | Resolve Alert as False Positive Benign | POST | `/web/api/v2.0/threats` | `695e0289-009b-45e8-ad3d-96fec49b8c7e` |
| 6 | Set Vulnerability Status to Resolved True Positive | POST | `/web/api/v2.1/remote-scripts/execute` | `c782cbe3-d292-45ed-9a74-f9383e0f1388` |
| 6 | Resolve Alert as True Positive Undefined | POST | `/web/api/v2.0/threats` | `d9a21a34-82db-41fe-9f97-fb9ca54a27a1` |
| 5 | Set Alert Status to In Progress | POST | `/web/api/v2.0/threats` | `35d76e2a-52d5-4fc7-ae2b-cf685ba9ee03` |
| 3 | Set Vulnerability Status to To Be Patched | POST | `/web/api/v2.1/remote-scripts/execute` | `0a09f605-a5e6-4686-96d7-266b4ae4bf3d` |
| 3 | Resolve Alert as True Positive Malware | POST | `/web/api/v2.0/threats` | `2c03fe1f-caa9-459a-9189-185296ae0fa8` |
| 3 | Gmail Note | POST | `/web/api/v2.0/threats` | `8d9ad1a9-2a9d-4107-abe8-fa801cd0c2f9` |
| 2 | Assign Alert | POST | `/web/api/v2.0/threats` | `afd633c0-0cca-4915-8f4a-a4476167da87` |
| 2 | Get Agentic Investigation Summary | POST | `/web/api/v2.1/unifiedalerts/graphql` | `288d7810-3e36-4aa0-a5a7-1c201c08020a` |
| 1 | Set Alert Status to New | POST | `/web/api/v2.0/threats` | `35d60379-a6d7-42b0-9f5d-b34732839780` |
| 1 | Get RAW Indicators | POST | `/web/api/v2.0/threats` | `a63b1151-6816-4aaf-a07e-f09744a8d9c3` |
| 1 | Get CVE Remediation Insights | POST | `/web/api/v2.1/remote-scripts/execute` | `a535710e-b91c-429a-bb85-1b3f1e28a08e` |
| 1 | Set Vulnerability Status to Resolved | POST | `/web/api/v2.1/remote-scripts/execute` | `3cfd35ef-8867-4053-baf2-79afe61c18bd` |
| 1 | Set Analyst Verdict as True Positive Policy Violation | POST | `/web/api/v2.0/threats` | `1ecfcddf-b31d-43ac-ad59-7d155505f044` |
| 1 | Trigger Agentic Investigation | POST | `/web/api/v2.1/unifiedalerts/graphql` | `99dd0d16-8eb5-4db9-8701-223e4e281f53` |
| 1 | Get Available Response Action | POST | `/web/api/v2.0/threats` | `738ed06f-b559-49ca-a0dd-c79ccf3ce8da` |
| 1 | get alert eventseq | POST | `/web/api/v2.0/threats` | `b907f209-e11b-4948-b028-62ef3a851477` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /web/api/v2.1/unifiedalerts/graphql` (n=32)
- `POST /web/api/v2.1/xspm/findings/vulnerabilities/graphql` (n=3)
- `POST /web/api/v2.1/graphql` (n=2)
- `POST https://ingest.us1.sentinelone.net/v1/alerts` (n=1)
- `POST https://usea1-purple.sentinelone.net/web/api/v2.1/unifiedalerts/graphql` (n=1)

### Slack / Slack

`product_key: slack` | `integration_id` on this tenant: `43d27b10-ea4f-4829-a6d2-5de254dec613` | 28 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 382 | Post Timeout | POST | `/api/chat.postMessage` | `7ba3a388-2f27-4083-a7e9-3508535fbe38` |
| 211 | Post Message | POST | `/api/chat.postMessage` | `111468a0-a8b8-49e9-be90-8f9e644a6160` |
| 205 | Create Channel | POST | `/api/conversations.create` | `aa7a9cc7-e927-42a1-b1f1-5100797eb759` |
| 202 | Set Channel Description | POST | `/api/bookmarks.edit` | `c7e9f3ea-1541-40a2-9b69-2233fd166ee1` |
| 147 | Update Message Mitigation Cancel | POST | `/api/chat.postMessage` | `c7228cc6-a068-4d98-b915-914cc89c4394` |
| 121 | Post Message | POST | `/api/chat.postMessage` | `1a5289f8-e910-4228-a079-100bcbea03c2` |
| 114 | Find User by Email Address | GET | `/api/users.lookupByEmail` | `b14cc540-248a-4cd7-ae35-2a5c60706a34` |
| 113 | Ask For Disconnect | POST | `/api/chat.postMessage` | `6bfaf3a6-1b7f-43e3-af8b-2cbad21c1466` |
| 104 | Invite User To Channel | POST | `/api/conversations.invite` | `eb4c00d9-d3c2-43ca-a76b-2821125c6c48` |
| 24 | Send Interactive Message | POST | `/api/chat.postMessage` | `43c970e2-4519-4eef-84d4-80566c7a5532` |
| 18 | Find User by Email Address | GET | `/api/users.lookupByEmail` | `5a42f231-04b7-469b-9364-39e6f0719ef9` |
| 14 | Invite Users To a Channel | POST | `/api/conversations.invite` | `6d77ce30-a739-465c-8afb-08991387e298` |
| 13 | Fetch Conversation History | POST | `/api/conversations.history` | `3ab3461f-fd71-48d0-913d-f4937e131054` |
| 11 | Post user not found | POST | `/api/chat.postEphemeral` | `d4080fc1-1bc3-4364-bee4-af1045b720e5` |
| 11 | Create Public Channel | POST | `/api/conversations.create` | `b6ecb1f3-af3e-4b52-b3d4-304553e95d6f` |
| 11 | Post Message In a Thread 2 | POST | `/api/chat.postMessage` | `42723783-cdfc-408d-9d0a-c78306ba4156` |
| 10 | Invite Users To a Channel | POST | `/api/conversations.invite` | `3554242f-6aa0-4495-a88e-d713c5a726e7` |
| 9 | List Slack Users | GET | `/api/users.list` | `ec47262e-97ea-40c8-b6bd-0ad6754fe859` |
| 9 | Send Interactive Message | POST | `/api/chat.postMessage` | `bd22c27e-8dc8-4e4d-a97a-61b02b2a4849` |
| 8 | Create Private Channel | POST | `/api/conversations.create` | `cfba9db9-5b29-4eef-89b4-25c7d15520ca` |
| 5 | Create Private Channel | POST | `/api/conversations.create` | `89d2081d-0cd5-4308-a880-18d6fc079b6c` |
| 5 | Create Public Channel | POST | `/api/conversations.create` | `888f47c5-8a9f-4390-9465-a7f59d97aded` |
| 4 | List Channels and Conversations | GET | `/api/conversations.list` | `63b7896d-1093-4367-b3e6-6c7b7e5b8558` |
| 3 | Get Conversation History | GET | `/api/bookmarks.edit` | `d8923b4c-b6b2-4ebd-84fe-18b7c471b725` |
| 2 | Get User Presence Information | GET | `/api/users.list` | `535c3a07-4a0d-40ac-83ed-d8f50b5334e4` |
| 2 | Archive Channel 2 | POST | `/api/conversations.create` | `d2444c31-3e29-47fc-b4a8-ffbbd8874daa` |
| 1 | Get info about channel | POST | `/api/conversations.history` | `634e4311-1e03-42da-b5f1-2676dafaf49f` |
| 1 | Send a File to a Channel | POST | `/api/files.upload` | `ebc31122-72c3-4f6c-b35b-28a7349d2993` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /api/chat.postMessage` (n=221)
- `POST /api/admin.users.invite` (n=1)

### VirusTotal / VirusTotal

`product_key: virustotal` | `integration_id` on this tenant: `9b735fa3-69db-4430-bca0-347b57a8604d` | 12 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 67 | Search File Hash | GET | `/api/v3/files/<<file_hash>>` | `bb65ec26-0d88-4f9e-9369-4ceba0e738bd` |
| 27 | VirusTotal Search IP | GET | `/api/v3/ip_addresses/{{local_var.src_ip}}` | `25394f56-6862-4ba7-9843-5d6c5fa3ac04` |
| 9 | Get Analysis | GET | `/api/v3/analyses/<<analysis-id>>` | `0ce5be8c-12db-43fd-8535-1a392dcca594` |
| 4 | Upload a File for Scanning | POST | `/api/v3/files` | `56753ffc-0da5-4afd-803a-7849af562e4b` |
| 4 | Scan URL | POST | `/api/v3/urls` | `f7178631-7c35-4244-b038-222b2a300763` |
| 3 | Get comments on a file | GET | `/api/v3/files/<<file-id>>/comments` | `71043bc0-d7a4-4377-b28c-b550ebf6249d` |
| 3 | Get comments on an IP address | GET | `/api/v3/ip_addresses/<<ip-id>>/comments` | `986a90f4-0ea6-4af5-a05e-c03904eb9114` |
| 3 | Get a URL analysis report | GET | `/api/v3/urls/<<url-id>>` | `d32362a5-35b4-4609-810d-a7d4b21f766b` |
| 2 | Get a summary of all behavior reports for a file | GET | `/api/v3/files/<<file-id>>/behaviour_summary` | `3a7bb87c-0f71-4cf9-9d05-720b94807828` |
| 1 | Search Domain | GET | `/api/v3/domains/<<domain>>` | `202e00f0-426e-41ea-9235-1c136413abf1` |
| 1 | Send file to VT | POST | `/api/v3/urls/<<url-id>>/analyse` | `5e8c8b62-b7cc-4ba0-97cc-312e0c4ac49d` |
| 1 | Get Votes of a File | GET | `/api/v3/files/<<file-id>>/votes` | `75fb16c7-4c36-4e11-b277-177efc50b30e` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `GET /api/v3/files/<<file_hash>>` (n=112)
- `GET /api/v3/ip_addresses/<<ip>>` (n=1)

### Okta / Okta

`product_key: okta` | `integration_id` on this tenant: `5ce5b70d-f12d-4955-8cbb-cce8e5dd9ad5` | 12 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 7 | Search Users by Email | GET | `/api/v1/users/` | `d650cc87-1fb1-43ae-ac3c-3c5d03495c21` |
| 6 | Suspend User | POST | `/api/v1/users/<<id>>/lifecycle/suspend` | `83994945-c560-4db3-b06b-c8ce3b9431ec` |
| 6 | Suspend a User | POST | `/api/v1/users/<<id>>/lifecycle/suspend` | `783377c4-4482-4073-9574-1e001a2482a2` |
| 5 | Revoke all User Sessions | DELETE | `/api/v1/groups/<<group_id>>/users/<<user_id>>` | `51c3a920-036a-4776-93db-f16aa4427067` |
| 3 | Activate a User | POST | `/api/v1/users/<<okta_id>>/lifecycle/activate` | `8a74e2a6-1709-4b64-81fe-81d42cc5ff16` |
| 3 | Search Users by Email | GET | `/api/v1/users/` | `e5b5cfb4-a4b8-43ab-8932-d3cdebf6d068` |
| 3 | Deactivate a User | POST | `/api/v1/users/<<okta_id>>/lifecycle/activate` | `19095018-b286-4b24-b02b-5861e11417b8` |
| 3 | Get Okta Logins | GET | `/api/v1/logs` | `e0e20b8d-4957-491a-b463-d87424e2f91d` |
| 3 | Retrieve a User | GET | `/api/v1/users/<<okta_user_id>>` | `58c2957e-a02e-4703-a46c-f622e3270927` |
| 1 | Unsuspend a User | POST | `/api/v1/users/<<id>>/lifecycle/unsuspend` | `b4a61fb0-7af6-4858-bda3-cdb1f9af15e9` |
| 1 | Unsuspend a User | POST | `/api/v1/users/<<id>>/lifecycle/unsuspend` | `2c119346-d667-450a-89f4-ac62bd68cd0d` |
| 1 | Create a User | POST | `/api/v1/users` | `ee384d10-55ac-446b-8366-61b590c6762f` |

### Atlassian / Jira Cloud

`product_key: jira-cloud` | `integration_id` on this tenant: `0a9250ea-11da-4427-977f-8a4aef183a09` | 11 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 22 | Create issue in HYP project via 0auth | POST | `/rest/api/2/issue` | `6202e9d0-487a-43d9-aea8-8b16a8d1be54` |
| 10 | Add alert details to ticket | POST | `/rest/api/2/issue/<<issueIdOrKey>>/comment` | `86ec2498-2567-4da9-abb7-f74bc743430e` |
| 5 | Get Projects | GET | `/rest/api/2/project/<<projectIdOrKey>>` | `8a5c7c97-1d5f-49fb-81ab-6c9a66222b5a` |
| 2 | Update Issue | PUT | `/rest/api/2/issue/<<issueIdOrKey>>` | `82fb5328-95af-46e7-a56d-3c6b8ee1d43b` |
| 2 | Search for issues with indicator | POST | `/rest/api/2/search` | `46cbb6b6-9ce0-4300-9602-7aca37e3702d` |
| 2 | Create issue | POST | `/rest/api/2/issue` | `4e778159-dcf9-40d2-a9d8-5d55d8df522d` |
| 2 | Transition issue to Open | POST | `/rest/api/2/issue/<<issueIdOrKey>>/transitions` | `fc4d7b2b-94cb-46d9-8b04-ee3a6b089095` |
| 2 | Add comment | POST | `/rest/api/2/issue/<<issueIdOrKey>>/comment` | `5aaa81dc-5780-4a9e-91d8-3b5c1009bdd9` |
| 1 | Get issue | GET | `/rest/api/2/issue/<<issueIdOrKey>>` | `876c1d57-2ebb-45e0-86f6-8de3e00f982c` |
| 1 | Create issue | POST | `/rest/api/2/issue` | `dd442559-ff38-4af8-b96a-ea6a131fcd00` |
| 1 | Search for existing issues using JQL | POST | `/rest/api/2/search` | `0ce09360-a0ef-41f5-89f9-0ffa95eab408` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /rest/api/2/issue/<<issueIdOrKey>>/comment` (n=17)
- `PUT /rest/api/2/issue/<<issueIdOrKey>>` (n=7)
- `POST /rest/api/2/issue` (n=4)
- `POST /rest/api/2/user` (n=1)

### Google / Sheets

`product_key: sheets` | `integration_id` on this tenant: `f66b2029-ddbf-4faa-94e3-999856d95f0b` | 10 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 96 | Get Column Configuration Values | GET | `/v4/spreadsheets/<<spreadsheet_id>>/values/B2:clear` | `55557a23-7afe-4719-bab2-ef98542d693a` |
| 36 | Get Values | GET | `/v4/spreadsheets/<<spreadsheet_id>>/values/1:10000` | `eb2d897f-0d7c-4a0d-914a-09b0f51a0636` |
| 30 | Update protein | PUT | `/v4/spreadsheets/<<spreadsheet_id>>/values/A1:A2` | `a9484f20-9e3a-40a3-aeff-19a2d285edb6` |
| 26 | Append Values | POST | `/v4/spreadsheets/<<spreadsheet_id>>/values/1%3A10000:append` | `d88421ef-0ac2-4d5d-ba75-8d4261bc25a5` |
| 11 | Batch Update | POST | `/v4/spreadsheets/<<spreadsheet_id>>/` | `45f36d0e-ea0b-4954-b795-1059dfa1a025` |
| 7 | Clear Values | POST | `/v4/spreadsheets/<<spreadsheet_id>>/values/B2:clear` | `ad8e19b5-0daf-4846-bc83-9c18fccbced5` |
| 7 | Populate Sheet 1 row titles | POST | `/v4/spreadsheets/<<spreadsheet_id>>/values/A1:A2` | `83555309-6f1b-4880-bb7a-f8ee61749a7e` |
| 3 | Create spreadsheet | POST | `/v4/spreadsheets` | `66532c22-beac-4a2c-b7ab-21e3890f73f7` |
| 1 | GetValuesFromWorkday | GET | `/v4/spreadsheets/<<spreadsheet_id>>/values/1:10000` | `2c1ed2bd-0533-4e11-8bfc-e3e837cab172` |
| 1 | Get Values | GET | `/v4/spreadsheets/<<spreadsheet_id>>/values/B2:clear` | `e2689415-a777-4573-8891-0621d2f27b71` |

### Microsoft / Office365 (MSGraph)

`product_key: office365-(msgraph)` | `integration_id` on this tenant: `7f98b9aa-7e5c-4b55-a14d-e197e7064823` | 9 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 6 | Get Specific Message | GET | `/v1.0/me/messages/<<messageId>>` | `817b16e1-5c22-4711-979f-ccbe66f49862` |
| 4 | AD Disable User | PATCH | `/v1.0/users/<<user>>` | `499ef9bb-2924-43d8-9b0a-a37469b1cfd6` |
| 4 | Revoke User Sessions | POST | `/v1.0/users/<<userID>>/revokeSignInSessions` | `ececb141-bada-4a33-8b95-a0ff51351905` |
| 4 | Update User Password | PATCH | `/v1.0/users/<<userID>>` | `bb0fa49f-a3af-49fa-9980-41cfc425e8e4` |
| 3 | Get Outlook Email UserId | GET | `/v1.0/me/messages` | `ac2eea69-d5c6-4d33-aa88-960b5dac0b6d` |
| 3 | Get completed folder ID | GET | `/v1.0/me/mailFolders/Inbox/messages` | `aabf9833-6b17-4b23-855e-10d73f151185` |
| 2 | Get Manager by Email Address | GET | `/v1.0/users/<<userEmail>>/manager` | `11d6bd22-d1b7-4994-8647-d38455e0b399` |
| 2 | Get Users By Department | GET | `/v1.0/users` | `25c432e0-9916-49bb-b89b-ab4a19584a53` |
| 2 | Send Email to Manager | POST | `/v1.0/me/sendMail` | `86135f68-fb8d-4a5a-ad9c-5a5fe4c76d24` |

### DataSet / DataSet

`product_key: dataset` | `integration_id` on this tenant: `92cfc975-2e0f-4c96-be29-00ea2fa91805` | 8 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 38 | Query | POST | `/api/timeseriesQuery` | `6d962526-ca65-439f-8e8b-64eb7c72d3d5` |
| 18 | Power Query | POST | `/api/timeseriesQuery` | `6e45734c-a920-48e3-9f30-4d491878801b` |
| 17 | Add Events | POST | `https://ingest.us1.sentinelone.net/services/collector/raw` | `49f9eb6d-ac3b-4efb-b635-009cda2e27ef` |
| 8 | Add Events | POST | `/api/addEvents` | `5e734867-14ea-42ff-924f-cf632805895b` |
| 8 | Put File | POST | `/api/putFile` | `34c10393-d701-4c49-8260-b0e6c19af7d1` |
| 3 | PQ Detection Rule | POST | `/api/timeseriesQuery` | `83933cbe-d64c-414b-8300-6d2b4e56e579` |
| 1 | Run Query | POST | `/api/timeseriesQuery` | `210bcca1-372e-4920-bb0f-9553f6d11f1a` |
| 1 | Retrieve the Custom Monitors Config | POST | `/api/getFile` | `e23cb5ce-e374-4b55-9e7f-373e7b2ec16b` |

### Microsoft / Entra ID

`product_key: entra-id` | `integration_id` on this tenant: `73475bd9-3762-4f17-aab5-c544ec5ec31b` | 7 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 10 | Revoke Session | PATCH | `graph.microsoft.com/v1.0/users/` | `35220c9e-be3b-465c-a232-fbc1fd11b39d` |
| 3 | Get Mail Forwarding Rule | GET | `/v1.0/users//mailFolders/inbox/messageRules` | `abca408b-b70e-4463-8dc0-ebf57f4188a7` |
| 3 | Get Sharepoint Site Info | GET | `/v1.0/sites/testorion.sharepoint.com:/sites/BadSharpoint` | `bbd0f71a-ba9c-419f-9b5a-23f75d93a02c` |
| 2 | List Users | GET | `/v1.0/users/<!!>` | `b9e8dcc5-2ac2-4fc8-b38b-be83aacbec8c` |
| 2 | Get User | GET | `/v1.0/users/` | `0b794ce4-c25a-46b9-ab8d-53bce4482828` |
| 1 | Delete a User | DELETE | `/v1.0/users/<<user-id>>` | `4655ebdf-59b6-4994-a213-2fc4603c3371` |
| 1 | List Messages | GET | `/v1.0/teams/9c53c2c3-88b5-45e6-a3d5-ccee2ce25f72/channels/19:2a2e6849497040a898aab38784c963e8@thread.tacv2/messages` | `003b4e1f-2b4b-4e41-b5c3-b90540eedb88` |

### AlienVault / OTX

`product_key: alienlans-otx` | `integration_id` on this tenant: `99c539d6-9597-4e8e-97df-a2e802fd6387` | 7 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 5 | Get File Hash analysis | POST | `/api/v1/indicators/file/<<file-hash>>/analysis` | `42f770a6-1881-423e-98dd-77ec14622cb8` |
| 4 | Submit a File for Analysis | POST | `/api/v1/indicators/submit_file` | `007165d4-ba10-4e2c-8bc4-383de669ffc0` |
| 4 | Lookup File Hash | POST | `/api/v1/indicators/file/<<file-hash>>/general` | `d22a7e1f-2fa9-482a-bb76-7db787a3aa6a` |
| 3 | Get Subscribed Pulses | GET | `/api/v1/pulses/related` | `95b58375-5b2a-46c4-a1ac-5b5f1344aa84` |
| 1 | Find Pulses Related to Adversary | GET | `/api/v1/pulses/related` | `f28f99cd-764c-467c-9437-d210570f9c2a` |
| 1 | Submit a File for Analysis 1 | POST | `/api/v1/indicators/submit_file` | `eabb048e-7dfe-46b2-9b69-3e5802f88ac4` |
| 1 | Retrieve Pulse Indicators | GET | `/api/v1/pulses/<<pulse_id>>/indicators` | `b7440434-fa7b-4f53-b66d-fa72181628c6` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /api/v1/indicators/file/<<file-hash>>/general` (n=53)

### SentinelOne SDL / SentinelOne SDL

`product_key: sentinelonesdl` | `integration_id` on this tenant: `ea6018b7-2a2f-44ca-b9b6-27a0434b0503` | 5 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 47 | SDL Query | POST | `/sdl/api/query` | `5864fb04-634a-4cf9-96e8-6b898f26880a` |
| 24 | SDL Add Events Skill | POST | `/sdl/api/addEvents` | `b63603fa-41a9-4e30-aab7-41707a6e5281` |
| 18 | SDL Power Query | POST | `/sdl/api/powerQuery` | `3b276194-7801-476f-856f-8a8a997f779e` |
| 1 | Timeseries Query | POST | `/sdl/api/timeseriesQuery` | `085c68ca-8586-450f-b6ff-b656a325ba0d` |
| 1 | Get lookup table | POST | `/sdl/api/getFile` | `79b172e2-d8e3-4d7d-8c7a-6e7ffc4c6ec4` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /sdl/v2/api/queries` (n=13)
- `GET /sdl/v2/api/queries/` (n=10)
- `POST https://ingest.us1.sentinelone.net/v1/indicators` (n=3)
- `POST https://ingest.us1.sentinelone.net/v1/alerts` (n=3)
- `POST https://xdr.us1.sentinelone.net/api/powerQuery` (n=2)
- `POST https://ingest.us1.sentinelone.net/services/collector/event` (n=1)
- `POST /web/api/v2.1/unifiedalerts/graphql` (n=1)

### Palo Alto Networks / Firewall

`product_key: pa-firewall` | `integration_id` on this tenant: `63cfa20c-f77d-4404-9744-3d78cb92d7bd` | 5 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 15 | Add IP to Block List | POST | `/api/` | `852dafb5-d61e-42c5-95d9-ef16b768b48b` |
| 3 | Commit Configuration | POST | `/api/` | `7d521acc-8253-4920-893b-aab77cac391d` |
| 1 | Update URL Filtering Profile | POST | `/api/` | `ef3e99e2-db3a-4649-b28e-5a05a3fa3e53` |
| 1 | End Palo Alto GlobalProtect VPN Session | GET | `/api/` | `0557e9d2-1797-4405-b723-5dea85de3dbe` |
| 1 | Create Security Policy | POST | `/api/` | `2e8f33c4-dad2-413b-b84f-3d160418493d` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST https://gns-palo.free.beeceptor.com/paloblocklist` (n=1)

### ServiceNow / ServiceNow

`product_key: servicenowincidentresponse` | `integration_id` on this tenant: `854385b9-2e7e-48f2-b7c7-2a2fdb89e2cb` | 4 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 23 | Create New Incident Ticket | POST | `/api/now/v1/table/incident` | `b04ffa28-bca4-4f45-b530-2678f884eaed` |
| 12 | Update Incident Ticket | PUT | `/api/now/v1/table/incident/<<incident_id>>` | `dafb290c-dace-4e10-a8e5-10de108c0432` |
| 2 | Perform a Global Search for Keyword | GET | `/api/now/globalsearch/search` | `1b43f998-b601-474b-a764-c4e90a976810` |
| 1 | Get Incident | GET | `/api/now/table/<<tableName>>/<<sys_id>>` | `57319f75-5c9e-466a-88e1-fc2e1879954e` |

### Zendesk / Support

`product_key: support` | `integration_id` on this tenant: `af8487dd-a473-4277-a458-fa64da7cfb23` | 4 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 13 | Create Ticket | POST | `/api/v2/tickets.json` | `50da8e44-b3f7-415d-aad2-966091516af4` |
| 11 | List Tickets | GET | `/api/v2/tickets.json` | `8a91ec27-205a-4f61-8a30-98560830fb67` |
| 5 | Update Ticket | PUT | `/api/v2/tickets/<<_ticket_id>>.json` | `63f10574-4722-4a84-8082-8f134fad3f6f` |
| 2 | Add Comment to Ticket | PUT | `/api/v2/tickets/<<_ticket_id>>.json` | `12c986fa-e4fe-47b8-aeab-01af984c8226` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /api/v2/users.json` (n=1)

### Google / Drive

`product_key: drive` | `integration_id` on this tenant: `a5d80eb2-6f8b-431a-9f99-cf1854e7722f` | 4 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 12 | Get Router Prompt | GET | `/drive/v3/files` | `b6f8bbee-2c2f-4072-a2db-580456cf94e9` |
| 7 | List Prompts in Obsidian Vault | GET | `/drive/v3/files` | `76226aaf-c78a-4ab2-880c-2a91388ac533` |
| 5 | Create File Report | POST | `/drive/v3/files` | `06a543e5-32ff-4f67-81b8-ec4ec051c722` |
| 3 | Update Context File | PATCH | `/drive/v3/files/<<file_id>>` | `91241412-1875-46c5-a243-6a7e058a637c` |

### Microsoft / Teams

`product_key: teams` | `integration_id` on this tenant: `afe4fbed-e8ee-4c6d-823f-6c7077af7fd7` | 4 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 8 | Send Failed chatMessage in Channel | POST | `/v1.0/teams/<<team_id>>/channels/<<channel_id>>/messages` | `bc4a56cc-cc94-4106-a460-d2c30c746570` |
| 2 | Create Channel In Team | POST | `/v1.0/teams/<<team_id>>/channels` | `9552f4d1-13c0-45ca-89b2-2e4d7f4438b5` |
| 1 | Create group chat | POST | `/v1.0/chats` | `4cfe3426-a9fd-4bed-bf04-35ffa59ea06f` |
| 1 | Send chatMessage In Chat | POST | `/v1.0/chats/<<chat_id>>/messages` | `47463860-fb23-49c1-a98e-27360fdd024d` |

### AWS / EC2

`product_key: ec2` | `integration_id` on this tenant: `5bd2c922-6c64-4586-ad01-8b72d75491f8` | 3 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 15 | Revoke Security Group Rules Ingress | GET | `/` | `a82cd2e2-dfdb-4222-9d16-ff04766c5b4a` |
| 2 | Describe Security Groups | GET | `/` | `6cd83dd2-ec31-4468-bf7c-18f0a960c26e` |
| 1 | Revoke Security Group Rules Ingress | GET | `/` | `4eba35f8-4636-4f35-8ce9-f50b62c1d70b` |

### Google / Gmail

`product_key: gmail` | `integration_id` on this tenant: `1d5ae5b6-3dce-48e4-beec-6c3134d5ce87` | 3 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 5 | Delete Message | DELETE | `/gmail/v1/users/<<user>>/messages/<<emailId>>` | `af2a2b04-a448-459d-9d61-e56df55ace82` |
| 2 | Get Social | GET | `/gmail/v1/users/<<user>>/messages` | `f94bea40-a431-4f94-b5aa-942a344a3cca` |
| 1 | Get Promotions | GET | `/gmail/v1/users/<<user>>/messages` | `865f51b3-08b4-407f-bc85-50c488262fff` |

### Fortinet / FortiGate

`product_key: fortigate` | `integration_id` on this tenant: `84b7a30c-5e9f-48dd-b4e9-c7a42f3d8a1b` | 3 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 2 | Get Object Name | GET | `/api/v2/cmdb/firewall/address` | `a3f7e885-03d1-4bc1-b2f3-c39505070bec` |
| 2 | Retrieve Address Group Contents | GET | `/api/v2/cmdb/firewall/addrgrp` | `0cbd915a-9047-43a8-a95e-704cb7934f35` |
| 1 | Add Firewall Policy | POST | `/api/v2/cmdb/firewall/policy` | `58c8f72d-2825-4caf-9a0d-074e6d1c0b9e` |

### Hybrid Analysis / Hybrid Analysis

`product_key: hybrid-analysis` | `integration_id` on this tenant: `ec2d72f8-18d6-49e5-8ada-4e10a479e16a` | 3 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Upload a File | POST | `/api/v2/submit/file` | `e64f6b1e-46ac-46e8-ac06-68fdcf006445` |
| 1 | Get Sandbox Report Summary | GET | `/api/v2/report/<<job_id>>/summary` | `ceef10f2-1687-4f00-abc1-004592e3805a` |
| 1 | Search Hash | POST | `/api/v2/search/hash` | `3234d0ef-0708-4abd-9f2b-a7ce67df778a` |

### abuse.ch / Malware Bazaar

`product_key: malware-bazaar` | `integration_id` on this tenant: `63c4fa5d-c67a-450a-b245-846b31dfad5e` | 2 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 10 | Query a Malware Sample | POST | `/api/v1/` | `af92bb3d-332c-4424-bbb3-0d20051acd84` |
| 1 | Query malwares by signature | POST | `/api/v1/` | `fece3e35-bba1-48ec-bb9f-047ffc953690` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST /api/v1/` (n=2)

### Freshdesk / Freshdesk

`product_key: freshdesk` | `integration_id` on this tenant: `0f8051d4-28eb-4ed3-8868-fe8a1cee29f0` | 2 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 4 | Create a Ticket | POST | `/helpdesk/tickets.json` | `2c3b510f-8ce1-409c-a4df-9f2c6defbafb` |
| 4 | Resolve Ticket | PUT | `/api/v2/tickets/<<id>>` | `e5ee3fbc-195a-4c5b-8938-44f836461237` |

### IOC Parser / IOC Parser

`product_key: ioc-parser` | `integration_id` on this tenant: `cdfe1ad0-f0cb-4985-b7e7-8f109c6bb39e` | 2 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 5 | Parse IOCs from URL | POST | `/url` | `11a81c82-f140-459e-9ea7-3f5c949ca2f6` |
| 3 | IOC | POST | `/text` | `7bf7d37b-dc44-402c-a9fd-3138d597c7d8` |

### AWS / S3

`product_key: amazon-s3` | `integration_id` on this tenant: `39a29be6-4456-4232-925d-25a08c09cb73` | 2 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 5 | Modify S3 Public Access | PUT | `/<<object_key>>` | `5817ede7-4f67-4e9e-9001-bc7dc6cdda8b` |
| 2 | Get S3 publicAccessBlock Settings | GET | `/` | `35eea4a3-28e3-4100-a3da-e0bd6ecd583a` |

### Recorded Future / Recorded Future

`product_key: recorded-future` | `integration_id` on this tenant: `7e2b34bc-daf3-471b-8453-d5f8b86a320f` | 2 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 2 | Hash Lookup | GET | `/v2/hash/<<hash>>` | `0d40a431-3fd3-4579-b4d0-0fa5fe33c2e4` |
| 1 | IP Lookup | GET | `/v2/ip/<<ip-address>>` | `87c2bfab-a584-40cb-8bd3-49b04be05a99` |

### GitHub / GitHub

`product_key: github` | `integration_id` on this tenant: `bed78455-3b7b-48cc-8e9e-c63a2f076bc6` | 2 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Get repository content | GET | `/repos/<<owner>>/<<repository>>/contents` | `de62783b-0d48-40e6-9799-b75ba6d19e15` |
| 1 | Invite Github user to Organization | POST | `/orgs/<<org>>/code-scanning/alerts` | `40bdc309-9402-4b70-b937-a21218973af8` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `GET (dynamic)` (n=5)
- `GET /repos/Sentinel-One/ai-siem/contents/workflows/community` (n=1)
- `GET /repos/Sentinel-One/ai-siem/releases/latest` (n=1)
- `GET /repos/Sentinel-One/ai-siem/contents/workflows/community/` (n=1)

### Tenable / Tenable.io

`product_key: tenable-io` | `integration_id` on this tenant: `6e33bcbc-34c7-48aa-85fa-9759e4b7db62` | 2 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | List Asset Vulnerabilities | GET | `/workbenches/assets/<<agent_uuid>>/vulnerabilities` | `4a256d0c-3a3c-45c9-bdbb-452ae1532079` |
| 1 | Scan Details | GET | `/scans/<<scan_uuid>>` | `cee026c3-5f09-463b-80d5-3569f85b1e6b` |

### Tenable / Web App Scanning

`product_key: web-app-scanning` | `integration_id` on this tenant: `0a264681-0e39-45d9-a869-dfb2c831d180` | 2 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Get Web App Scan Notes | GET | `/was/v2/scans/<<scan_id>>/notes` | `1daa563b-df26-430f-8278-e1ac480897ca` |
| 1 | Search Web App Vulnerabilities for Scan | POST | `/was/v2/scans/<<scan_id>>/vulnerabilities/search` | `b970e89d-2a2f-402d-9c6a-619d739d0e3b` |

### Abuse IPDB / Abuse IPDB

`product_key: abuse-ipdb` | `integration_id` on this tenant: `75af0459-ecea-48eb-9a62-7ec2e68a4c73` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 23 | AbuseIPDB Check IP | GET | `/api/v2/check` | `6ea08101-8a9f-4559-8194-0af800acd620` |

### Abnormal Security / Abnormal Security

`product_key: abnormal-security` | `integration_id` on this tenant: `870d40d6-248b-4ae7-bc83-3d81cd9398e8` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 7 | Get Cases | GET | `/v1/threats/<<threatId>>` | `2fbd9e7c-f212-4a2b-b63d-ee030a283fb2` |

### Cloudflare / Cloudflare

`product_key: cloudflare` | `integration_id` on this tenant: `0dedd07c-0b9a-4205-9215-03ab1a95eb3a` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 7 | Cloudflare Block IP | POST | `/client/v4/user/firewall/access_rules/rules` | `9db31c31-8713-4cff-924c-5d8dc392c8f2` |

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

`product_key: freshservice` | `integration_id` on this tenant: `cd77a67b-b9fc-44b8-85c4-592ff8625235` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 3 | Create a Ticket | POST | `/api/v2/tickets` | `0f612a56-20d9-4c36-bf0e-e56aaf55a52d` |

### OpenAI / OpenAI

`product_key: openai` | `integration_id` on this tenant: `e1a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 3 | Final Analysis | POST | `/v1/responses` | `3ffbc50e-be6d-442d-ac2d-9708f53eb5cc` |

Ad-hoc calls also seen against this integration (no `public_action_id`):

- `POST https://api.openai.com/v1/chat/completions` (n=1)

### Anthropic / Anthropic

`product_key: anthropic` | `integration_id` on this tenant: `e2b3c4d5-f6a7-4b8c-9d0e-1f2a3b4c5d6e` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 2 | Create message | POST | `/v1/messages` | `9b6fc18d-93e7-4a41-868a-45b8575cd90a` |

### Atlassian / Confluence

`product_key: confluence` | `integration_id` on this tenant: `bc64acb7-008a-49f8-9d0b-46a9acb22922` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 2 | Get pages | GET | `/wiki/rest/api/content` | `21e07e83-2ce4-4b1f-8071-5eb52641958f` |

### Microsoft / MSGraph Security

`product_key: msgraph-security` | `integration_id` on this tenant: `fd2422cd-001f-4603-ba6e-bc17f1869e2f` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 2 | Retrieve Alerts with Category 'Impossible Login Velocity' | GET | `/v1.0/security/alerts` | `a2bada3c-deea-497b-968f-a5d9418cc7cd` |

### Shodan / Shodan

`product_key: shodan` | `integration_id` on this tenant: `6c8b70cb-2c9d-42ed-a2f4-c931a3e0d8f4` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 2 | Search Shodan | GET | `/shodan/host/search` | `93d77985-92fc-4583-a09a-30ae0966ab85` |

### Twilio / Twilio

`product_key: twilio` | `integration_id` on this tenant: `5076573f-9086-4076-90f4-3a64345801d3` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 2 | Send a Text Message to User | POST | `/2010-04-01/Accounts/<<twilio_account_id>>/Messages.json` | `bf04d35f-a5a5-4e75-bd6f-e9b0ee82ce4c` |

### Atlassian / Jira Server

`product_key: jira-server` | `integration_id` on this tenant: `b01188c3-13ea-45ec-bc86-77ea751e2515` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Create issue | POST | `/rest/api/2/issue` | `af7802ed-6c2b-4e6e-9b34-85c2739a01a4` |

### Cisco / Duo

`product_key: duo` | `integration_id` on this tenant: `0e57ea51-6fbe-4d0c-b785-861ee752c4a4` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Retrieve Users | GET | `/admin/v1/users` | `7c89178a-ccbf-425b-b16b-828c1ae1ec32` |

### Microsoft / Intune

`product_key: intune` | `integration_id` on this tenant: `babd39bf-783a-4c61-abd2-02d9f25b96a9` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | List Managed Devices | GET | `/beta/deviceManagement/managedDevices` | `f086cfc0-d83e-4d5b-b66e-2cb38870658e` |

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

`product_key: opsgenie` | `integration_id` on this tenant: `b6370881-4103-463d-8775-74ad6234834e` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Add Tags to Alert | POST | `/v2/alerts/<<identifier_id>>/tags` | `1e934e3c-0bb0-4432-822c-c4b3038603d9` |

### Proofpoint / Protection Server

`product_key: protection-server` | `integration_id` on this tenant: `e1d0593e-132e-4a37-a27e-21cc98cec385` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Delete Quarantined Message | POST | `/rest/v1/quarantine` | `00a5beb8-743e-4fa3-a1de-687a57e97aa0` |

### Zscaler / Zscaler

`product_key: zscaler` | `integration_id` on this tenant: `18c67901-6aaf-4d0b-89ef-ea765005bea9` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Add URLs to Blocklist | POST | `/api/v1/security/advanced/blacklistUrls` | `3f7d7da1-5cc0-427d-8ecb-33f49ef86cac` |

### abuse.ch / URLHaus

`product_key: urlhaus` | `integration_id` on this tenant: `04ec38ee-2fd3-42f2-b42a-75f7b4f94ea2` | 1 packaged actions

| n | Action | Method | Path | `public_action_id` |
|--:|---|---|---|---|
| 1 | Query URL information | POST | `/v1/host/` | `3dcfa5a5-1cef-4aa8-a3bc-88e9f4ca9c65` |

---

## Custom integrations (52)

User-defined; no action pack, every call is ad-hoc. Listed so you recognise them and steer
users to a built-in equivalent where one exists.

| Integration | Ad-hoc calls | Connections | Built-in equivalent |
|---|---:|---:|---|
| Glean | 46 | 0 | - |
| Pyxis DDN | 16 | 0 | - |
| ZeroNetworks | 8 | 0 | - |
| Callback Server | 6 | 0 | - |
| Proxmox | 6 | 0 | - |
| Pyxis | 6 | 0 | - |
| Pyxis Marco | 6 | 0 | - |
| SentinelOne Custom | 6 | 0 | `SentinelOne / SentinelOne` |
| Cisco Webex | 5 | 0 | - |
| Fortigate FW | 5 | 0 | `Fortinet / FortiGate` |
| ManageEngine Patch Manager Plus | 5 | 0 | - |
| Nucleus | 5 | 0 | - |
| OpnSense | 5 | 0 | - |
| SentinelOne AI-SIEM | 5 | 0 | `SentinelOne SDL / SentinelOne SDL` |
| FS-ISAC Automated Threat Intel | 4 | 0 | - |
| OpenCTI | 4 | 0 | - |
| Pyxis | 4 | 0 | - |
| Pyxis | 4 | 0 | - |
| Airtop | 3 | 0 | - |
| Miele | 3 | 0 | - |
| Z Scaler | 3 | 0 | `Zscaler / Zscaler` |
| Dropbox | 2 | 0 | - |
| Fortigate | 2 | 0 | `Fortinet / FortiGate` |
| Grok AI | 2 | 0 | - |
| OpenAI | 2 | 0 | `OpenAI / OpenAI` |
| Proof Point | 2 | 0 | `Proofpoint / Protection Server` |
| Star Wars API | 2 | 0 | - |
| ChatGPT | 1 | 0 | `OpenAI / OpenAI` |
| Cisco Duo | 1 | 0 | `Cisco / Duo` |
| Customer MS Teams Integration | 1 | 0 | `Microsoft / Teams` |
| Cyware - MS-ISAC | 1 | 0 | - |
| EY | 1 | 0 | - |
| Fake Firewall API | 1 | 0 | - |
| Filescan.io | 1 | 0 | - |
| HEC Event Ingestion | 1 | 0 | `SentinelOne SDL / SentinelOne SDL` |
| My Beta PNA Test | 1 | 0 | - |
| My Custom RoarinApp Integration | 1 | 0 | - |
| N8N | 1 | 0 | - |
| Okta | 1 | 0 | `Okta / Okta` |
| Pyxis | 1 | 0 | - |
| STP - Integrations for Corp | 1 | 0 | - |
| SWAPI | 1 | 0 | - |
| Unified Alert API  | 1 | 0 | - |
| Whois | 1 | 0 | - |
| 1VanAllenIntegration | 0 | 1 | - |
| Censys | 0 | 1 | - |
| SKO-HA-Nick | 0 | 1 | - |
| SKO-HA-kbains-connection | 0 | 1 | - |
| Threat Intel Lookback | 0 | 1 | - |
| Vattelappesca | 0 | 1 | - |
| brodsky_paladin1 | 0 | 1 | - |
| xyz | 0 | 1 | - |
