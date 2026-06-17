# Capability map

Compact per-tag capability summary showing the common verb+resource shapes across all 781 operations. Use this as your first stop when you know *what* you want to do ("list", "count", "isolate") but not the exact path. For a specific endpoint use `search_endpoints.py` instead.

Symbols: L=list (GET collection), G=get-one (GET /{id}), C=count (GET /count or GET list?countOnly=true — always GET, never POST), E=export (GET /export — always GET, never POST), A=action (POST /actions/…), F=filters/facets, S=search (POST free-text or autocomplete), X=create/update/delete (mutating), ✓=confirmed working on this tenant (see tenant_capabilities.md).

| Tag | Resource | Ops | Capabilities | On this tenant |
|---|---|---:|---|---|
| Accounts | `accounts` | 11 | GLX | 2/11✓ |
| Accounts | `export` | 1 | E | 1/1✓ |
| Activities | `activities` | 2 | L | 2/2✓ |
| Activities | `export` | 1 | E | 1/1✓ |
| Activities | `last-activity-as-syslog` | 1 | L | 1/1✓ |
| Agent Actions | `agents` | 38 | A | 0/38✓ |
| Agent Support Actions | `agents` | 1 | A | 0/1✓ |
| Agents | `agents` | 11 | CFGLX | 4/11✓ |
| Agents | `export` | 3 | EX | 2/3✓ |
| Agents Repository (Beta) | `agent-artifacts` | 3 | LX | 0/3✓ |
| Application Management | `application-management` | 16 | ELX | 7/16✓ |
| Application Management Settings | `application-management` | 2 | LX | 1/2✓ |
| Application Risk | `export` | 1 | E | 0/1✓ |
| Application Risk (Deprecated) | `installed-applications` | 2 | L | 2/2✓ |
| Auto Upgrade Policy | `upgrade-policy` | 13 | LX | 0/13✓ |
| Cloud Funnel | `cloud-funnel` | 8 | LX | 0/8✓ |
| Cloud Resources | `cloudnative` | 2 | EL | 0/2✓ |
| Config Overrides | `config-override` | 5 | LX | 1/5✓ |
| Custom Detection Rule | `cloud-detection` | 6 | LX | 1/6✓ |
| Datalake Unified Actions | `xdr` | 4 | X | 0/4✓ |
| Deep Visibility | `dv` | 9 | GLX | 0/9✓ |
| Default Reports | `report-tasks` | 3 | LX | 1/3✓ |
| Default Reports | `reports` | 5 | GLX | 2/5✓ |
| Default Reports | `sentinelonerss` | 1 | L | 1/1✓ |
| Device Control | `device-control` | 12 | ELX | 2/12✓ |
| Dynamic tag rules | `xdr` | 5 | LX | 1/5✓ |
| Exclusions and Blocklist | `exclusions` | 7 | GLX | 1/7✓ |
| Exclusions and Blocklist | `export` | 2 | E | 2/2✓ |
| Exclusions and Blocklist | `restrictions` | 7 | GLX | 1/7✓ |
| Exclusions v2.1 | `unified-exclusions` | 8 | ELX | 2/8✓ |
| Filters | `filters` | 9 | F | 2/9✓ |
| Filters | `xdr` | 5 | F | 2/5✓ |
| Firewall Control | `firewall-control` | 17 | EGLX | 4/17✓ |
| Forensics | `applications` | 4 | EG | 0/4✓ |
| Gateways | `ranger` | 3 | LX | 1/3✓ |
| Graph | `xdr` | 3 | X | 0/3✓ |
| Graph Query Builder | `xdr` | 8 | LS | 4/8✓ |
| Graph Query Management | `xdr` | 6 | LX | 3/6✓ |
| Groups | `groups` | 10 | GLX | 3/10✓ |
| Hashes | `hashes` | 1 | G | 1/1✓ |
| Hyperautomation | `hyper-automate` | 13 | EGLX | 2/13✓ |
| ISPM | `ranger-ad` | 6 | LX | 0/6✓ |
| Inventory | `xdr` | 9 | ELX | 1/9✓ |
| Inventory AI ML | `xdr` | 5 | ELX | 1/5✓ |
| Inventory AI ML Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Account | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Account Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Application Integration | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Application Integration Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Cloud Application | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Cloud Application Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Cloud Surface | `xdr` | 4 | ELX | 1/4✓ |
| Inventory Cloud Surface Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Container | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Container Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Data Analysis | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Data Analysis Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Data Store | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Data Store Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Developer Tool | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Developer Tool Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Device | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Device Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Endpoint Surface | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Endpoint Surface Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Filters | `xdr` | 4 | CFS | 1/4✓ |
| Inventory Function | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Function Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Governance | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Governance Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Identity | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Identity Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Identity Surface | `xdr` | 4 | ELX | 1/4✓ |
| Inventory Identity Surface Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Network | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Network Discovery Surface | `xdr` | 4 | ELX | 1/4✓ |
| Inventory Network Discovery Surface Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Network Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Notes | `xdr` | 2 | X | 0/2✓ |
| Inventory Server | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Server Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Storage | `xdr` | 5 | ELX | 1/5✓ |
| Inventory Storage Filters | `xdr` | 3 | CFS | 1/3✓ |
| Inventory Tags | `xdr` | 4 | CFLX | 3/4✓ |
| Inventory Unified Actions | `xdr` | 3 | A | 0/3✓ |
| Inventory Workstation | `xdr` | 8 | CEFLSX | 2/8✓ |
| Live Updates | `content-updates-inventory` | 1 | L | 0/1✓ |
| Locations | `locations` | 4 | LX | 1/4✓ |
| Log Collection | `log-collection` | 9 | EGLX | 4/9✓ |
| Long Running Query | `sdl` | 3 | GX | 0/3✓ |
| Mobile Integration | `mobile-integration` | 11 | LX | 2/11✓ |
| Network Discovery | `ranger` | 9 | EGLX | 3/9✓ |
| Network Discovery Self Enablement | `ranger` | 5 | LX | 0/5✓ |
| Network Quarantine Control | `firewall-control` | 15 | EGX | 4/15✓ |
| Platform Detection Rules | `detection-library` | 12 | LSX | 5/12✓ |
| Policies | `accounts` | 2 | GX | 1/2✓ |
| Policies | `groups` | 2 | GX | 1/2✓ |
| Policies | `sites` | 2 | GX | 0/2✓ |
| Policies | `tenant` | 2 | LX | 1/2✓ |
| RBAC | `rbac` | 6 | GLX | 1/6✓ |
| Remote Ops MMS | `remote-ops` | 13 | GLX | 1/13✓ |
| RemoteOps Forensics | `remote-ops` | 10 | GLX | 0/10✓ |
| RemoteOps Scripts | `remote-scripts` | 16 | LX | 3/16✓ |
| Saved Searches | `sdl` | 3 | LX | 0/3✓ |
| Sentinel Deploy | `ranger` | 7 | LX | 2/7✓ |
| Service Users | `export` | 1 | E | 1/1✓ |
| Service Users | `service-users` | 7 | GLX | 2/7✓ |
| Settings | `settings` | 27 | LX | 0/27✓ |
| Sites | `export` | 1 | E | 1/1✓ |
| Sites | `site-with-admin` | 1 | X | 0/1✓ |
| Sites | `sites` | 15 | GLX | 1/15✓ |
| System | `system` | 7 | LX | 5/7✓ |
| Tag Manager | `tag-manager` | 3 | X | 0/3✓ |
| Tags | `tags` | 5 | LX | 0/5✓ |
| Tasks | `tasks-configuration` | 7 | ELX | 0/7✓ |
| Threat Intelligence | `threat-intelligence` | 7 | LX | 1/7✓ |
| Threat Notes | `threats` | 4 | GX | 1/4✓ |
| Threats | `export` | 2 | EG | 1/2✓ |
| Threats | `threats` | 20 | AEGLX | 5/20✓ |
| Unprotected Endpoints Discovery | `rogues` | 4 | LX | 2/4✓ |
| Updates | `update` | 6 | GLX | 1/6✓ |
| Updates | `upload` | 3 | X | 0/3✓ |
| Users | `export` | 1 | E | 1/1✓ |
| Users | `user` | 1 | L | 0/1✓ |
| Users | `users` | 39 | GLX | 5/39✓ |
| VCS Integration | `cnapp` | 20 | CFGLX | 0/20✓ |
| alerts | `cloud-detection` | 3 | LX | 1/3✓ |
| licenses | `licenses` | 1 | X | 0/1✓ |
| marketplace | `singularity-marketplace` | 9 | GLX | 2/9✓ |
| overview | `xdr` | 1 | X | 0/1✓ |

## Common "I want to…" → start here

| I want to… | Start here |
|---|---|
| list threats | Threats — `GET /web/api/v2.1/threats` |
| count threats | Threats — `GET /web/api/v2.1/threats?countOnly=true` → `{"data":[],"pagination":{"totalItems":N}}`. Or check `pagination.totalItems` from any list call. No POST equivalent exists. |
| export all threats to CSV | Threats — `GET /web/api/v2.1/threats/export` (no extra params; returns full CSV stream) |
| list agents/endpoints | Agents — `GET /web/api/v2.1/agents` |
| count agents | Agents — `GET /web/api/v2.1/agents/count` → `{"data":{"total":N}}`. No POST equivalent exists. |
| get agents by IDs | Agents — `GET /web/api/v2.1/agents?ids=<id1>,<id2>` (comma-separated query param, not a POST body) |
| count anything (generic) | Append `/count` to the list path for resources that have a dedicated count endpoint (agents, groups, sites). For resources without `/count`, pass `countOnly=true` as a query param to the list GET. Do not use POST for counting — there is no read-side POST in this API. |
| isolate an endpoint | Agent Actions — `POST /web/api/v2.1/agents/actions/disconnect` |
| reconnect an endpoint | Agent Actions — `POST /web/api/v2.1/agents/actions/connect` |
| uninstall an agent | Agent Actions — `POST /web/api/v2.1/agents/actions/uninstall` |
| move agent to group | Agent Actions — `POST /web/api/v2.1/agents/actions/move-to-group` |
| run a RemoteOps script | RemoteOps Scripts — `POST /web/api/v2.1/remote-scripts/execute` |
| hunt across Deep Visibility | Long Running Query — `POST /sdl/v2/api/queries` (queryType="LOG" for S1QL or "PQ" for PowerQuery), then `GET /sdl/v2/api/queries/{id}` to poll. The legacy /dv/init-query + /dv/query-status + /dv/events flow is deprecated (sunset 2027-02-15). |
| run a PowerQuery | Long Running Query — `POST /sdl/v2/api/queries` (queryType="PQ"), then `GET /sdl/v2/api/queries/{id}` to poll. The legacy /dv/events/pq + /dv/events/pq-ping flow is deprecated (sunset 2027-02-15). |
| see tenant structure | Accounts/Sites/Groups — `GET /web/api/v2.1/{accounts,sites,groups}` |
| see what the token can do | RBAC — `GET /web/api/v2.1/rbac/role` and `GET /web/api/v2.1/users` |
| audit who did what | Activities — `GET /web/api/v2.1/activities` |
| find an exclusion | Exclusions v2.1 / Exclusions and Blocklist |
| list firewall rules | Firewall Control — `GET /web/api/v2.1/firewall-control` |
| list custom detection rules | Custom Detection Rule / Platform Detection Rules |
| see Hyperautomation workflows | Hyperautomation — `GET /web/api/v2.1/hyperautomation/workflows` |
| list installed agent packages | Updates — `GET /web/api/v2.1/update/agent/packages` |

## Paths that do not exist

These paths produce HTTP 404 and have never been in the v2.1 spec. They look plausible but are wrong — do not use them:

| Wrong path | Correct alternative |
|---|---|
| `POST /web/api/v2.1/agents/ids` | `GET /web/api/v2.1/agents?ids=<id1>,<id2>` |
| `POST /web/api/v2.1/threats/summary` | `GET /web/api/v2.1/threats?countOnly=true` |
| `POST /web/api/v2.1/export/threats` | `GET /web/api/v2.1/threats/export` |
| `POST /web/api/v2.1/threats/count` | `GET /web/api/v2.1/threats?countOnly=true` |
| `POST /web/api/v2.1/agents/summary` | `GET /web/api/v2.1/agents/count` |

The S1 REST API does not use POST for read, count, or export operations. All data retrieval is GET. Before calling `s1_api_post`, confirm the path appears in `search_endpoints.py` output.