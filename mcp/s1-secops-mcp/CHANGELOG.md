# Changelog

## Unreleased: host launchers only (image and MCP unchanged at 1.5.3)

### Added

- **`install` and `config` on both launchers.** `install` copies the launcher to
  `~/.local/bin/` (Windows: `%USERPROFILE%\bin\`), adds `s1-secops-mcp`, `purple-mcp` and
  `virustotal` to the Claude Desktop config with the real path, keeps every other entry and a dated
  backup, pulls the image and runs `setup` when no token is stored. `config` prints the same
  entries for any MCP client. Both take `--image`, `--profile`, `--output-dir` and `--claude-md`
  (Windows: `-Image`, `-Profile`, `-OutputDir`, `-ClaudeMd`). Nobody types a home path into JSON
  any more, which was the most common first-run failure, and a launcher left under `~/Documents`
  on macOS is moved out of the folders Claude Desktop cannot run scripts from.
- **No-clone install.** The docs lead with a one-line download from ai-siem followed by `install`.
- **`mcp/docker/launcher-test.sh` and `mcp/docker/launcher-test.ps1`:** hermetic tests for both commands.

## 1.5.3

One global token drives any account or site under it (issue #111). Tool count stays 35.

Measured live on 2026-10-09 against a service user spanning 385 accounts, with an
account-level token as the control.

### Fixed

- **`scope` now narrows PowerQuery on a global or multi-account token.** `lrqRun` launched
  every query with `tenant: true` and sent the scope only as an `S1-Scope` header, which
  `/sdl/v2/api/queries` ignores for a multi-account user. `scope: "<A>"` returned 19 accounts
  (20 unscoped) and `scope: "<A>:<S>"` 29 account:site pairs. A scope is now sent as
  `tenant: false, accountIds: ["<A>"]`, and a site adds `site.id='<S>'` to the initial filter
  (the API has no site field). After the fix: 1 account and 1 account:site pair. On the
  account-level token the new body matches the old header exactly (184 = 184 for the account,
  106 = 106 for a site). Applies to `powerquery_run` (PQ, LOG and every slice),
  `powerquery_enumerate_sources` and the `powerquery_schema_discover` fallback. The response
  carries `scopeApplied` (`mode`, `accountIds`, `siteFilter`), and `effectiveQuery` shows the
  site term. For a leading `| join` or `| union` the term is added to every subquery
  (lookup-table subqueries are left as they are), and `| datasource vulnerabilities` /
  `misconfigurations` get `| filter siteId='<S>'`; all three matched the header ground truth on an
  account-level token (union 37,106 = 37,106, join identical per source, misconfigurations 0
  against 711 account-wide). Lookup tables need no filter: the same path at account and at
  site scope is two files, and the `S1-Scope` header (still sent) picks the copy `| dataset`
  reads, on the global token too (with `accountIds` and no header it found no table). A site
  scope is refused only for `| datasource alerts`, which has no site column. An account the token cannot reach is a clear error (HTTP 403
  "Not allowed to access requested resource" plus a hint); with a site scope the query retries
  with `tenant: true` and keeps the site term, for a site-level token.
- **`powerquery_schema_discover` falls back to an LRQ LOG search** when the V1 query returns no
  events. Unscoped, V1 returned 0 for every source on the global token; the fallback returned
  127 fields for `SentinelOne`. `via` reports which path answered (`v1-query` or `lrq-log`), and
  a failed fallback is reported as `fallbackError` instead of failing the call.
- **`uam_available_actions` defaults to the alert's own account**, as the write tools do. It
  used the first 100 accounts only, so an alert in account 101+ was offered 0 actions with no
  error (now 7). The write tools' all-accounts fallback follows the `/accounts` cursor too
  (`allAccountIds`).

### Added

- `uam_list_alerts`: `scopeIds` and `scopeType` (`ACCOUNT` default, or `SITE`), sent as the UAM
  `scope` argument. Unscoped the global token listed 135,303 alerts across accounts; scoped to
  one account 120,777, all in it; scoped to a site, all in that site. Each alert now carries
  `accountId` and `siteId`.
- `ha_list_workflows`: `accountIds`. One account returned 15 workflows (14 account-level, 1
  site-level); its sites via `siteIds` returned 1, and unscoped returned 105.
- `ha_list_workflows`: `nameContains`, sent as `name__contains`, the only name filter the API
  honours (`name`, `search` and `query` return the unfiltered page). Live: 83 workflows, 1 match.
- `ha_delete_workflow`: an ACTIVE workflow is refused with HTTP 400, so the tool now deactivates
  it and retries once, reporting `deactivatedFirst: true` (live: 204 after deactivation).
- `powerquery_schema_discover`: the LRQ fallback also reports session-level fields
  (`account.id`, `site.id`, `serverHost`), which LOG returns under `serverInfo` for `addEvents`
  and agent-shipped data.
- `sdl_create_dashboard`: `config` may be an object as well as a JSON string.
- `tools/live_learnings_check.mjs` (repo, host-only): re-checks every API behaviour the skills
  document as measured live; `--lab <accountId>:<siteId>` adds reversible writes.

### Docs

- Tool descriptions state that an unscoped call on a global token spans every account, and to
  pass the account or site the user named. `ha_export_workflow` notes that an unscoped export
  holds every account's workflows (253 KB against 26 KB for one account).
- The three `lrq-api.md` copies, `powerquery/SKILL.md`, `mgmt-console-api` (SKILL.md,
  UNIFIED_ALERTS.md, querying-logs.md), `hyperautomation/SKILL.md`, `query-slicing.md`,
  `CLAUDE.md`, `docs/mcp-tools.md` and the MCP README replace the old claim that `tenant: true`
  means "a default account" with the measured behaviour, and document scoping per tool.
- Skills (plugin 1.3.13) fold the API behaviours confirmed live on 2026-10-09 on several
  consoles; each has an invariant test. Detection library: the settings posture read, paging
  limits and the severity recipe, `core` labels, inheritance (500 while inheriting, per-rule site
  copies, independent scopes), `Activating` to `Active`, no backfill, back-dated events, activity
  3776, asset linking by `agent.uuid`. UAM: optional but answer-changing `scope` on
  `alertAvailableActions`, `alertName` filter, `sort`, introspection, AI Investigation
  availability. Hyperautomation: list filters and paging, run-now body `{"data": {}}`, deactivate
  and delete paths, response-trigger limits and conversion, connections by API and by name at
  run time, `send_email` per console, `GENERATE_UUID4`, JQ features.
  SDL: collector auth per console, scope attribution checks, `addEvents` behaviour, per-scope
  datatables, GraphQL introspection. PowerQuery: the scheduled-rule toggle, `disableStreaksLogic`
  placement, inventory site columns, `site.id` types, correlation alerts per seed.
- Code comments in `lib/hec.js` and `lib/credentials.js` now match the collector measurements.

## 1.5.2

One console token, a setup check that matches the tools, and a docs and code sync. Tool count
stays 35.

### Changed

- **`S1_CONSOLE_API_TOKEN_SINGLE_SCOPE` and `tokenKind` are removed** from the MCP, the
  launchers, the entrypoint allowlist, the `.mcpb` manifest, the Python clients
  (`S1Client(token_kind=...)` is gone) and the docs. Every call uses `S1_CONSOLE_API_TOKEN`.
  Live check 2026-10-08: IOC create, list and delete succeed with the regular token of a
  service user scoped to one account. A 403 with code 4030010 (a token whose user spans several
  accounts) now carries a hint: use a token minted at a single account or site, in its own
  keychain profile (`setup --profile <name>`), and a second MCP entry with `S1_PROFILE=<name>`.
  A stored `<profile>:S1_CONSOLE_API_TOKEN_SINGLE_SCOPE` item is no longer read, listed or
  removed by `forget`; delete it by hand (see docs/upgrading.md).
- **`S1_SCOPE` setup accepts `<accountId>` or `<accountId>:<siteId>` only** (`setup`, both
  launchers, Python `keychain_set`). A group part used to be accepted and then rejected by every
  SDL and PowerQuery tool (`Invalid S1-Scope`).
- `setup` accepts every environment alias the server resolves (`S1_BASE_URL`,
  `SDL_CONSOLE_API_TOKEN`, `S1_UAM_ALERT_INTERFACE_URL`, `SDL_S1_SCOPE`, `VT_API_KEY`, ...):
  `cli.js` now builds its alias map from `credentials.js`.
- Docker: `docker/.dockerignore` was never read (the build context is the repo root). It is now
  `docker/Dockerfile.dockerignore`, with root-relative patterns.
- **Licence: AGPL-3.0** (was MIT), matching ai-siem: the repo `LICENSE`, `package.json`, the
  `.mcpb` manifest, the plugin and marketplace entries, and the image label
  `org.opencontainers.image.licenses`.

### Docs

- Dashboards: first deploy is `sdl_create_dashboard {name, config, isPublic: true, scope}`,
  updates are `sdl_get_file` then `sdl_put_file {udoId, content, expectedVersion}` (SKILL.md,
  docs/skills.md and CLAUDE.md said `sdl_put_file` by path).
- Catalogs list all 8 skills and 10 sdl-solutions; docs/mcp-tools.md lists all 33 purple-mcp
  tools and the previously undocumented tool parameters; docs/testing.md lists all 35
  s1-secops-mcp tools; the Windows launcher's `versions`, `help` and `S1_CLAUDE_MD_PATH` support
  is documented; a troubleshooting step no longer prints a secret; broken in-text references
  fixed; release notes before 1.4.6 removed (this CHANGELOG is the full history).

### Plugin

- The plugin build leaves each skill's `tests/` and `evals/` out of the package, except files the
  skill's own SKILL.md or references name as user tools.

## 1.5.1

Security patch for the image. No tool, parameter or behaviour change in s1-secops-mcp; the tool
count stays 35.

- **Image `sentinelone/secops-mcps:1.5.1`:** the bundled VirusTotal MCP fork is repinned to
  `97ca2b8`, which overrides two transitive npm dependencies:
  - `proxy-addr` 2.0.7 to 2.0.8, CVE-2026-90711 (critical, CVSS 9.1);
  - `@modelcontextprotocol/sdk` 1.26.0 to 1.32.1, CVE-2026-104850 (high, CVSS 7.5).

  Neither was reachable: the VirusTotal server runs on stdio, never loads Express or `proxy-addr`
  (checked with a module-load hook through `tools/list`), and the SDK advisory excludes servers and
  stdio clients. Both are fixed anyway so that image scans come back clean. The remaining Scout
  findings are Debian 13 packages with no fixed version yet (expat, zlib, plus lows).
- The launchers default to `sentinelone/secops-mcps:1.5.1`, and the docs pin it.
- CI: `docker-publish.yml` carried `S1_MCP_VERSION: '1.4.0'`, which fails its own check against
  `docker/build.sh`; it now matches. `docker/README.md` lists the actual VirusTotal and Purple
  pins.

## 1.5.0

Credentials move to the OS keychain; plaintext files and the HTTP transport are gone.
Every change below was verified live on an S-26.3.4 tenant on 2026-10-07/08 (A/B against
1.4.0 and image 1.4.10). Tool count 35 (new: `s1_api_download`, `uam_set_verdict`,
`uam_assign_alert`).

### Breaking

- **No credentials file, anywhere.** The `credentials.json` discovery chain (`S1_CREDS_FILE`,
  `COWORK_WORKSPACE`, cwd walk-up, `~/mnt/*`, `CLAUDE_CONFIG_DIR/sentinelone`,
  `~/.config/sentinelone`) is removed. Values resolve per name from environment variables,
  then the OS keychain (service `sentinelone-mcp`, account `<profile>:<NAME>`, profile from
  `S1_PROFILE`, default `default`). Migrate with `s1-secops-mcp setup --import-json <file>`,
  check with `s1-secops-mcp status`, then delete the file.
- **stdio only.** The Streamable HTTP transport, bearer tokens (`MCP_BEARER_TOKENS*`) and the
  team VM deployment (`deploy/`: install.sh, systemd, Caddy, bridge) are removed.
  `--transport http` and `MCP_TRANSPORT=http` now exit 2 instead of starting.
- **Docker: secrets over stdin.** `-e S1_CONSOLE_API_TOKEN` still works but is readable through
  `docker inspect`. The new host launcher `docker/s1-secops-mcp-launch.sh` (macOS/Linux) and
  `.ps1` (Windows) read the keychain and send the values over stdin
  (`S1_SECRETS_STDIN=1` in `entrypoint.sh`), so the MCP client config holds no secret.
  Measured: secret hits in `docker inspect` and `ps eww` went from 3 to 0 per server.

### New

- Keychain backends: macOS `/usr/bin/security` (writes via `security -i` on stdin), Linux
  `secret-tool` (stdin; headless, missing-tool, locked and timeout cases give a clear reason
  and never fall back to a file), Windows Credential Manager via the optional
  `@napi-rs/keyring` dependency. `S1_KEYCHAIN=off` disables it.
- CLI: `setup` (no-echo prompts, or `NAME=value` lines on stdin; validates values; reads back
  every write), `status` (source per value, secrets masked), `forget`, and `exec -- <cmd>`,
  which runs purple-mcp or the VirusTotal MCP natively with keychain values mapped to
  `PURPLEMCP_*` and `VT_API_KEY`.
- purple-mcp threat intelligence enabled from the same keychain VT key. The launchers
  (`s1-secops-mcp-launch.sh` / `.ps1`) now send `VIRUSTOTAL_API_KEY` to purple-mcp, the
  entrypoint maps it to `PURPLEMCP_VT_API_KEY` for purple-mcp only and then unsets
  `VIRUSTOTAL_API_KEY` / `VT_API_KEY` in that container, and `exec` sets
  `PURPLEMCP_VT_API_KEY` too. Verified live 2026-10-08. The VirusTotal MCP stays the primary
  enrichment and pivot server; use purple-mcp `threat_intel_search` for VT Intelligence hunts
  and never call `threat_intel_get_file_relationships` or `threat_intel_get_file_behavior`
  (0.8M to 27M characters per call). See docs/mcp-tools.md.
- Redaction: configured secret values are masked in all tool output and logs; error output and
  logs also mask `ApiToken`/`Bearer`/`Basic`/`Splunk` token-shaped values.
- `powerquery_run`: `queryType: "LOG"` (raw events, every parsed field, `truncatedByServerCap`),
  `slices` (2-15, parallel) with `merge {keys,sum,min,max}`; a trailing `| sort` / `| limit` is
  applied after the merge, other post-group commands and non-additive aggregates are refused.
  Live: 2/8/15 slices match unsliced exactly over 24h and 7d.
- `outputFile` on `powerquery_run` (.csv/.jsonl/.json), `s1_api_get`, `ha_export_workflow` (ZIP),
  and the new `s1_api_download` (binary GET to file). Paths must be absolute and inside
  `S1_OUTPUT_DIRS` (default home and temp), no overwrite unless asked, no symlinks (including
  dangling ones), files mode 0600, path validated before the API call.
- `tokenKind: "single_scope"` on `s1_api_*` uses `S1_CONSOLE_API_TOKEN_SINGLE_SCOPE` (IOC
  writes); never falls back to the default token.
- Optional Claude Desktop extension (`mcpb/`), sensitive fields stored by Desktop in the OS store.
- UAM alert management matches the console. `uam_set_verdict` (S1/alert/analystVerdictUpdate,
  the 20 AnalystVerdict values, `TRUE_POSITIVE` / `FALSE_POSITIVE` / `SUSPICIOUS` refused before
  any request) and `uam_assign_alert` (S1/alert/assignUser by numeric `userId`, by `email`
  resolved through `GET /users?email=`, or `unassign: true`, which sends `value: null`). These
  and `uam_set_status` send the console's `alertTriggerActions` document verbatim, captured from
  a console HAR: `?opname=AlertTriggerActions`, `scope` = the alert's own account, `viewType:
  ALL`, one action, filter by id. Each reads the alert first, re-reads it afterwards, and fails
  unless the alert shows the requested value; the result has `outcome`
  (`applied`/`already_set`/`scheduled`), `verified`, `before` and `after`. Optional
  `scopeIds`/`scopeType` override the scope.
- `MISSING_PERMISSION` names the RBAC permission for the alert type ("Unified Alerts > STAR /
  Endpoint / Identity / Mobile / Generic Alerts: Manage", plus the legacy STAR Rule Alerts
  permissions for STAR), the console path to grant it, and, when the token can read its own
  role (`GET /user`, `GET /rbac/role/{id}`), which Manage permissions that role lacks. It also
  re-reads the alert and reports that it is unchanged. Live: STAR alert writes succeeded and an
  ingested alert's writes failed with a role that has no Unified Alerts Manage permission;
  the request shape (with or without `scope` / `viewType`) did not change either outcome.

### Fixed

- Ids beyond 2^53 returned as JSON numbers (SDL shareResource dashboard ids) were rounded,
  so a follow-up get or delete missed the dashboard. Responses are now parsed with exact
  integers (`lib/json.js`), and `sdl_share_dashboard` returns the id it was given.
- `powerquery_run` results are parsed the same way: ids and nanosecond timestamps beyond 2^53
  come back as exact strings instead of rounded numbers, and sliced merges add and compare
  them exactly (BigInt). Float literals such as `1e21` stay numbers.
- LRQ launch retries 429/502/503/504 (not a plain 500, which SDL returns for some invalid
  queries).
- `edrStrict: true` no longer fails with "Unknown EDR field 'tag'": the metering filter is not
  added to strict EDR queries.
- `uam_list_alerts` `searchText` matched nothing (`fieldId '*'` is rejected); it now matches
  `alertName`.
- `s1_api_post` reports a GraphQL `errors[]` response with no data as an error.
- LRQ: a poll answered 404 "Requested token=... not found" (seen in three A/B runs; a rerun
  always succeeded) relaunches the query once instead of failing it. A second 404 is fatal.
- `uam_set_status` now verifies by re-reading the alert, and an invalid status is refused before
  any request.
- `uam_get_alert` returns `assignee.userId` and `ticketId`.
- `uam_available_actions` no longer offers `scopeType: GLOBAL` (the API rejects it);
  `uam_list_alerts` accepts `viewType: DLP`.
- `uam_post_alert`: the `alert` parameter description no longer tells callers to reference a
  previously posted indicator by uid (that endpoint is gone); it describes the inline
  `related_events[]` shape, the single `resources[]` entry and the Fingerprint-array hashes.

## 1.4.0

From the S-26.2.x / S-26.3.x release-note review, each verified on a live S-26.3.4 tenant on
2026-10-05. Tool count stays 32.

### `powerquery_run`: optional `edrStrict`

`edrStrict: true` sends the LRQ launch with a top-level `scheme: "edr"`. An unknown or wrongly
cased EDR field (for example `Endpoint.name`) then fails with HTTP 400 `Unknown EDR field: ...`
instead of silently returning 0 rows; correct fields return the same rows (6,709 with or without
it on the test query). Without it, and with an `i.scheme="edr"` filter inside the query, a typo
still returns 0 rows. The parameter must be top level: inside `pq` the API answers 400
`Invalid JSON`. Default off, so existing calls are unchanged.

### `engines.node` is `>=24`

Node 18 and 20 are end of life. CI and the image already run Node 24.

## 1.3.10

Fixes from a field smoke test (2026-10-02), each reproduced and verified on a live
tenant on 2026-10-03. Tool count stays 32.

### SDL ingest-metering rows are excluded by default

Every ingest writes receive-time accounting rows under the source's own
`dataSource.name`: `tag='logVolume'`, with `metric` / `value` / `path1`, and they also
carry `sca:bytesToCharge` and `sca:ingestTime`. They inflated per-source counts and
made a silent source look live. Over a fixed 12h window they were 7,390 of 383,044 rows.

- `powerquery_run` and `powerquery_enumerate_sources` add `tag != 'logVolume'` to the
  initial filter (new `lib/metering.js`), where dropping rows costs least, and return
  `effectiveQuery`. `!=` keeps rows that have no `tag`; the older
  `(tag != 'logVolume' OR !(tag = *))` form returned the same 375,654 rows. The filter
  is not added when the query mentions `logVolume` or starts with `| datasource`,
  `| dataset`, `| join` or `| union`. `includeMetering: true` opts out.
- `powerquery_schema_discover` over-fetches and drops metering rows client-side, and
  reports `excludedMeteringRows`. Before this, a sample could be partly or entirely
  metering (42 to 64% of rows on 4 sources), so the reported schema included fields
  the source doesn't have.

### `sdl_create_dashboard`: tab label key is `tabName`

A tab labelled with `name` was refused by the API as "one of the tabs in dashboard
has a blank name", which doesn't say which key it wanted. The tool now catches this
before sending and names the key. The description shows the `tabName` shape and the
60-column panel grid.

### `sdl_save_dashboard_layout` only moves and resizes panels

Tested live on four dashboards: titles, markdown and queries in the payload were
ignored, and only the layouts were applied, matched by position in the array. A
shorter payload changed nothing, and a longer one was refused ("Index 4 out of bounds
for length 4"). The tool now reads the tab first and refuses a payload whose panel
count differs. It also warns when content changes would be dropped. The description
no longer says the tool can add or remove panels.

## 1.3.9

Three defects from a field smoke test, plus the delivery-channel fault that kept
the last two releases from reaching the person who reported them. Tool count
stays 32.

### Image tags are strictly increasing and never reused

The image version stays its own counter, independent of the MCP versions inside
it. What changes is the discipline around it: an image tag now strictly
increases and is never republished. Rationale and the incident behind it:
[docker/README.md](../docker/README.md).

The documented Docker config moves to `:latest` with **`--pull=always`**. Version
tags remain available and are now genuinely immutable, for reproducible demos and
support. Because the image number does not encode what is inside it, verify
rather than infer:

    docker run --rm --entrypoint npm <image> ls -g --depth=0

The CI bump guard had two holes and both are closed. It tested that the
`IMAGE_VERSION` line *changed* rather than that the version *increased*, which
is how the backwards move passed; it now requires a strict semver increase. And
it permitted a publish whenever the tag was absent from the registry, which made
"delete the tag, republish different bytes" a supported route; that escape hatch
is gone. A tag someone already pulled does not become safe to reuse by being
deleted.

### Fixed

- **`ha_import_workflow` double-wrapped the payload.** The endpoint's body is
  `{"data": {...}}`, the hyperautomation skill's smoke-test example showed that
  correctly, and this tool adds the envelope itself, so pasting the documented
  example sent `{"data":{"data":{...}}}` and the API answered
  `422 body.data.name Field required`, which reads like a broken workflow rather
  than one extra level of nesting. Both artifacts were right in isolation and
  nothing ever executed one against the other.

  The tool now unwraps a wrapped payload when it is unambiguous, a `data` object
  present and no top-level `name`, and says so in the response rather than
  silently accepting both shapes. A workflow that legitimately owns a `data` key
  keeps it. The skill now prints both forms, labelled: Form A the raw API body,
  Form B the bare object this tool wants.

- **`sdl_list_dashboards` had no limit.** Measured on an MSSP account it returned
  442,581 characters across 17,111 lines, past any usable context budget. It now
  takes `limit` (default 100, clamped to 1000), `offset` and `namesOnly`, and
  reports `totalCount`, `hasMore` and `nextOffset`. `namesOnly` returns `{id,
  name}` and is about four times smaller, measured, which covers the common case
  of resolving a name to an id. `sdl_list_files` gets the same treatment,
  default 500, with `count` still reporting the full post-filter total so
  existing callers read the number they expect.

- **`ha_export_workflow` could not be scoped.** It sent no scope parameter, while
  `ha_import_workflow` already documents that an unscoped call on a scoped tenant
  returns a misleading `403 Insufficient permissions`. It now accepts
  `accountIds` / `siteIds`, and an unscoped 403 names scope as a possible cause
  instead of leaving the reader to conclude "missing role" and stop.

### Documented, not fixed here

**Omitted parameters that declare a default are rejected by the client.** Calling
`powerquery_run`, `uam_list_alerts`, `ha_list_workflows` and four others without
passing every argument fails with `expected nonoptional, received undefined`
before the request reaches this server. That is not this package: it has no
dependencies and does not use zod, those are Zod v4 codes from the host, and the
error arrives pre-dispatch. The host maps a JSON-Schema property carrying
`default` to a non-optional field, validating against the schema's output type
rather than its input type. 7 of 32 tools and 16 parameters are affected, listed
in the README with the pass-every-parameter workaround. Reported upstream.

**A dashboard `id` is often null, and that is its age, not a fault.** Only
dashboards created through the `dashboardsV2` surface carry a udoId; ones created
the older name-addressed way do not. On an established account most predate it,
measured 397 of 1,555 with an id, and `sdl_list_files` reports exactly the same
397. Address a legacy dashboard by its `/dashboards/<name>` path. Recorded in the
`sdl_list_dashboards` description, along with the fact that results are ordered by
name and that order is stable across calls, so page on `name` and not on `id`.

The `limit`, `offset` and `namesOnly` parameters added above deliberately carry
no `default` keyword for this reason; their defaults live in the handler and are
stated in the descriptions. A new test pins the set of default-bearing
properties so the blast radius cannot grow by accident.

### Tests

132 JS (+14). The 1.3.8 suite asserted structure, tool count, names, description
keywords, with the HTTP layer mocked, and all four defects lived in the space
that left uncovered. Four new classes:

- **Executable doc examples.** Both JSON blocks in the hyperautomation skill's
  smoke-test section are parsed out of the markdown and run through
  `ha_import_workflow`, asserting the outbound body carries exactly one `data`
  envelope. A documented payload that cannot survive the tool beside it now fails
  the build.
- **Outbound wire shape.** Assert the body that is sent, not merely that a call
  was made.
- **Client-parity schema lint.** Every tool must be callable with only its
  `required` fields; no property may be both required and defaulted; and the set
  of default-bearing properties is frozen against the known list.
- **Response budget.** List tools are driven with MSSP-scale fixtures, 1,200
  dashboards and 2,000 config files, and must stay under 200,000 characters.
  Cardinality is a property of the tenant, so only a fixture can supply it.

### Docker

Bundle image **1.3.6**, pinning npm 1.3.9.

1.3.4 shipped first with the same npm pin. Two bumps followed, both for the same
reason and neither for an MCP change: `CLAUDE.md` is COPY'd into the image, so
editing it changes the image bytes. 1.3.5 came from one such edit, and 1.3.6 from
a second, a blockquote that was rendering as two stacked quotes because a blank
line had split it. CI refused to republish over either, which is the guard doing
exactly its job. The image number tracks image content, not the MCP version, and
a published tag is never reused.

The npm package, the plugin and the image are three independent streams. Image
1.3.6 bundles npm 1.3.9 and ships alongside plugin 1.3.7; none of those numbers
predicts another.

## 1.3.7

Minor, not patch: a tool is gone and the log-ingest credential changed. Both
break an existing caller, so the version says so.

### Log ingest needs an SDL Log Write Key

`hec_ingest` now authenticates with **`S1_HEC_TOKEN`**, an SDL Log Write Key,
and no longer sends an `S1-Scope` header. The Management Console API token is
refused by the event collector. Measured on a live tenant, same request, same
endpoint:

    write key      -> HTTP 200 {"text":"Success","code":0}
    console token  -> HTTP 400 {"text":"Missing S1-Scope header","code":5}

The key is minted per account or site and writes only there, so it fixes the
destination and there is nothing for a scope header to override. Mint it at
Console > Singularity Data Lake > API Keys > Log Write Key; no API creates one.
`S1_HEC_TOKEN` is optional, because only raw log ingest needs it, and it is named
to match the deployer repos so one value covers both.

UAM alert ingest and IOCs are NOT affected. They still use
`S1_CONSOLE_API_TOKEN`, and `/v1/alerts` still requires `S1-Scope`.

### Indicators ride inside the alert

**`uam_post_indicators` is removed** (32 tools -> 31). Indicators can no longer
be ingested on their own: `/v1/indicators` refuses the console user token and the
Log Write Key alike, so no credential can drive it. They now travel inline in
`finding_info.related_events[]` on a single `POST /v1/alerts`, which is also what
the console Indicators tab reads.

`uam_ingest_alert` posts once, inline. The `inline` parameter is still accepted
so existing callers do not crash, but it is forced to true and a false value
comes back with a note saying it was ignored, rather than quietly doing something
different. The old two-call flow, its ~3s sleep and its ordering contract are
deleted rather than left throwing: a code path that can only fail invites callers
to keep it alive.

Verified end to end on a live tenant: one alert carrying four indicators inline
in a single POST surfaced in UAM with all four rendered and every uid matching.

### Also

- `Indicator` in the UAM GraphQL schema has fields `type, uid, title,
  description, message, severity`. There is no `name` and no `category`;
  querying either returns `FieldUndefined`. Examples across the docs used them.
- `sdlToken`'s missing-credential test now runs in a child process. It deleted an
  env var, but credentials are resolved once at import and fall back to a file,
  so the exception it asserted could only be thrown on a machine with no
  credentials at all. It passed in CI for exactly that reason.

## 1.3.6 - 2026-08-17

Behaviour change, found by deploying to a real site and not being able to see the
result.

### Changed

- **`isPublic` / `public` now defaults to TRUE on dashboard creation** in both
  clients, where the raw `createDashboardV2` API defaults it to false.

  `access.owner` is set to the calling identity. With an API service-account
  token that is `serviceuser-<uuid>@mgmt-<n>.sentinelone.net`, not a person, so a
  private dashboard is readable through the API and **invisible in the console to
  the human operator at any scope**. That is indistinguishable from a failed
  deploy: the tool reports success, the object exists, and the user sees nothing.

  Verified live: the identical config at the identical site scope went from
  invisible to visible purely by recreating it with `public: true`, and every
  pre-existing dashboard at that site carried `public: true`.

  Pass `isPublic: false` / `public=False` deliberately for a dashboard that
  should stay private to the service account. `shareResource` to a scope does not
  flip `public`; the two are independent.

### Documented

- **Dashboard names reject punctuation, with only `Invalid name` as the error.**
  Probed one character class at a time against a live tenant:

  | Accepted | Rejected |
  |---|---|
  | letters, digits, space, `-`, `_`, `.`, `/` | `(` `)` `[` `]` `{` `}` `:` `,` `&` `'` `%` `#` |

  So `My Dashboard (prod)` fails with no indication of which character offended.
  Recorded in the tool description, both client docstrings,
  `sdl-api/references/config-file-graphql.md` and
  `sdl-dashboard/references/deployment.md`.

### Tests

115 JS (+1), 61 Python client (+2), 19 panel-safety. The two default-value
assertions were updated and paired with explicit-false cases, so an accidental
revert of the default fails the suite.

### Docker

Bundle image stays **1.3.2**; its npm pin moves to 1.3.6.

## 1.3.5 - 2026-08-17

Completes the scope work in 1.3.4. **Upgrade from 1.3.4 is recommended.**

### Fixed

- **Query methods ignored `scope`.** 1.3.4 added the `scope` argument to the
  config-file and dashboard operations but not to the query paths, even though
  log reads are filtered by the same `S1-Scope` header. A hunt or a
  panel-validation query run without the intended scope silently answered for
  the token default, which is the worst shape of this bug: a plausible number
  for the wrong boundary, with no error.

  Scope now threads through `lrqRun` (launch **and** poll, so the forward-tagged
  follow-ups stay on the same scope) and through all five Python query methods:
  `query`, `power_query`, `facet_query`, `numeric_query`, `timeseries_query`.
  Exposed on the `powerquery_run`, `powerquery_enumerate_sources` and
  `powerquery_schema_discover` tools.

  Found by using the shipped 1.3.4 client to discover schema at a site scope and
  getting `power_query() got an unexpected keyword argument 'scope'`.

- **`scopeHeaders` is now exported from `lib/sdl.js`** and imported by the LRQ
  path in `lib/s1.js`, rather than each surface resolving scope its own way. A
  second implementation would drift, and the validation rules (numeric ids,
  `null` suppresses the default) have to be identical on both.

### Tests

- 4 new JS cases: `v1Query` header presence and absence, malformed-scope
  rejection before any request, and a direct contract test on the exported
  `scopeHeaders`.
- 8 new Python cases covering all five query methods, unscoped omission,
  malformed-scope rejection, and `scope=None` suppression.
- Totals: 114 JS, 59 Python client, 19 panel-safety. No regressions.

### Docker

Bundle image stays **1.3.2**; its npm pin moves to 1.3.5.

## 1.3.4 - 2026-08-17

Adds site-level dashboard lifecycle. Two gaps closed: SDL GraphQL calls never
sent an `S1-Scope` header, and the dashboard operations the console itself uses
were not wrapped at all. **26 tools → 32.**

### Added

- **`S1-Scope` on every SDL GraphQL and V1-query call.** Optional `scope`
  argument on `configFiles`, `configFile`, `putConfigFile`, `deleteConfigFile`
  and `v1Query`, and on the four `sdl_*_file` tools. Falls back to a new
  `S1_SCOPE` credential; `scope: null` suppresses that default and sends no
  header. Format `"<accountId>"` or `"<accountId>:<siteId>"`, validated before
  the request so a typo cannot silently widen the read.
- **Six dashboard-lifecycle tools** on the `dashboardsV2` surface:
  `sdl_list_dashboards`, `sdl_get_dashboard`, `sdl_create_dashboard`,
  `sdl_share_dashboard`, `sdl_save_dashboard_layout`, `sdl_delete_dashboard`.
- **`sdl_create_dashboard`** takes the whole dashboard document as one `config`
  string, the path the console uses. It parses the JSON first, so the UI
  stub-append failure (`{graphs: []}{...}` → "Content is invalid json /
  Additional text after JSON object", leaving an empty dashboard behind) is
  reported as a caller error instead of filing a broken shell.
- **`sdl_share_dashboard`** wraps `shareResource`, the only SDL operation that
  takes an explicit scope target. This is how an account-scoped dashboard is
  pushed to a site without recreating it. Scope targets are validated up front,
  because the server accepts a malformed entry, shares nothing, and reports
  success.
- **`S1_SCOPE`** added to `getCreds()`. It was absent, so any credentials-file
  default would have been read and then dropped.

### Fixed

- **Scope-sensitive call sites now scope consistently.** Absence
  disambiguation re-lists at the scope of the failed lookup, the `/dashboards/`
  duplicate guard lists at the scope of the write, and delete verification
  re-reads at the scope of the delete. Mixing scopes across these steps reports
  a live site-scoped file as deleted, which is the same false-negative class
  1.3.3 fixed for error text.

### Corrected documentation

- `sdl-api/references/config-file-graphql.md` claimed the `s1-scope` header was
  "ignored, not rejected" on `/sdl/v2/graphql`. **That was wrong.** Measured on
  `<console>`, same token and query: `configFiles` returned 113 files at
  account scope and 4 at a site scope. Config listings and dashboard reads are
  scope-FILTERED, so a dropped header changes which objects appear to exist.
  `auth_and_limits.md` corrected to match.

### Dashboard skill

- **`site.id`, not `site.name`, is the scoping predicate.** For one site over
  24h, `site.id='<id>'` matched 60,410 events of which 510 carried the site id
  with a null `site.name`: `ActivityFeed` 172, `asset` 111, unattributed 99,
  `SentinelOne` 70, `Windows Event Logs` 48, `alert` 10. A `site.name` filter
  silently drops alert and asset records. `site.id` is also the same value as
  the `S1-Scope` `siteId` and survives a site rename.
- **New scope doctrine in `sdl-dashboard/SKILL.md`:** deployment scope and query
  scope are separate decisions, and a site-deployed dashboard scopes its panels
  to that site unless the user explicitly asks for account-wide queries.
- **`panel_safety_check.py --site-id <id>`** adds rule **S01** (query panel with
  no, or wrong, `site.id` predicate on a site-targeted dashboard; opt out with
  `--allow-account-scope-queries`) and rule **S02** (`site.name` used as a
  scoping filter; never suppressed, the substitution is wrong at any scope).
- Recorded that the console's XDR selector injects
  `preFilter: "dataSource.category = 'security'"` into every panel query.

### Python client (`sdl-api/scripts/sdl_client.py`)

- Per-call `scope` on `config_files`, `config_file`, `put_config_file`,
  `delete_config_file`, with the same `_UNSET`-vs-`None` distinction.
- Six new methods mirroring the JS layer: `list_dashboards`, `get_dashboard`,
  `create_dashboard`, `share_dashboard`, `save_dashboard_layout`,
  `delete_dashboard`.
- `get_dashboard` treats both a null result and a GraphQL error as absence,
  disambiguated against the listing. Assuming only the null form is what broke
  every delete in 1.3.2; the confirming re-read threw on the success path.

### Tests

- 24 new cases in `tests/sdl-graphql.test.mjs`: header presence and absence,
  credentials fallback, `scope: null` suppression, malformed-scope rejection
  before any request, scope consistency across the guard / disambiguation /
  delete-verify paths, the six dashboard operations, stub-append rejection, and
  the `getDashboard` absence matrix.
- New `sdl-dashboard/tests/test_panel_safety_check.py`: 19 cases over S01 and
  S02 including the wrong-site case, the opt-out flag, exempt panel types, and
  a regression guard that existing rules still fire.
- Tool-count assertions updated 26 → 32 across the smoke, stdio, HTTP and
  origin-guard suites.

## 1.3.3 - 2026-08-07

Fixes a user-facing regression in 1.3.2 found by running the live MCP tools
against a tenant for the first time. **Upgrade from 1.3.2 is recommended.**

### Fixed

- **Every successful `sdl_delete_file` reported an error in 1.3.2.** The delete
  verification added in 1.3.2 re-reads the file to confirm removal, but the server
  reports absence as a GraphQL error rather than a null result, so the confirming
  read threw on exactly the success path. The delete itself always worked; only the
  reported outcome was wrong. Verified live: three deletes across `/dashboards/`,
  `/datatables/` and `/logParsers/` all removed their file and all three surfaced
  as errors.
- **`sdl_get_file` on a missing path returned a raw GraphQL error** instead of the
  actionable "this may be udoId-addressed, list it and retry" hint. The hint branch
  was unreachable because the library threw before returning.
- **Absence is now detected reliably on both address forms.** The error text differs:
  a missing name gives "Config file with name X not found.", a missing `udoId` gives
  the generic "Something went wrong. Please try again...", which is also what a
  version conflict returns. `configFile` normalises the explicit form and
  disambiguates the generic one against the file listing, so a deleted dashboard
  reads as absent while a genuine server error still propagates.
- **An out-of-range numeric `udoId` is no longer swallowed by the absence path.**
  Validation now runs before the lookup, so a caller bug surfaces as a caller bug.
- **A transport error is never read as "file absent".** Absence detection now requires a
  GraphQL-layer error, so a 404 page or WAF block whose body contains the words "not found"
  no longer satisfies it. Without this a delete could confirm itself against a file it
  never checked.
- **A failing listing during absence disambiguation keeps the original error** instead of
  replacing it with the listing failure.
- **The duplicate guard is no longer bypassed by case.** Its namespace test was
  case-sensitive while its name comparison was not, so `/Dashboards/AI Usage` skipped the
  guard entirely. Both now share one normaliser.
- **`v1Query` keeps its backoff.** Restricting status retry to idempotent methods removed it
  from this read-only POST, which schema discovery iterates once per data source.

### Python client (`sdl-api/scripts/sdl_client.py`)

Brought to parity with the JS client:

- Status retry is restricted to idempotent methods. The Python client was retrying POST
  mutations, which is the mechanism that duplicates a dashboard on a re-sent write.
- `Retry-After` is capped at 30s; an unbounded value parked the process.
- The duplicate guard fails closed on an empty listing.
- Absence detection, name normalisation and delete verification match the JS behaviour.

### Tests

- `tests/sdl-graphql.test.mjs`: 86 cases, adding the transport-error-is-not-absence case,
  listing-failure error preservation, the case-variant guard bypass, and `v1Query` retry.
- `sdl-api/tests/test_client.py`: new. 19 cases over a stubbed session, so the Python client
  is no longer invisible to CI. Runs in ~0.01s with no network.
- Live regression through the real MCP stdio protocol: handshake, 26 tools, and full
  create/read/update/stale-reject/delete/confirm-absent cycles for `/datatables/` and
  `/dashboards/`, plus the duplicate guard, the notFound hint, and `/automaticLookups`.

## 1.3.2 - 2026-08-07

Config-file operations move from the legacy REST endpoints to GraphQL. Tool count unchanged at
26, and all four tool names are unchanged, so no caller needs to change.

### Fixed

- **`sdl_list_files` no longer returns an incomplete listing.** The REST `/sdl/api/listFiles`
  endpoint omits every udoId-addressed dashboard. Measured live on `<console>`: REST returned
  1,914 paths against `configFiles`' 2,264, a 350-file gap consisting entirely of `/dashboards/`
  files that carry a `udoId`. REST `getFile` on any of them returns `success/noSuchFile`. The
  practical impact was a false negative: a dashboard that existed in the console was reported as
  not found. All four config-file tools now run on `POST /sdl/v2/graphql`.
- **`sdl_list_files` description no longer claims to return "all" files.** It did not, and the
  claim was load-bearing: an agent reading it had no reason to look further after an empty result.
- **`sdl_get_file` / `sdl_put_file` / `sdl_delete_file` can now address dashboards.** New `udoId`
  parameter. The console's Configuration Files grid displays a dashboard as
  `/dashboards/id/<udoId>/<name>`; that string is not a path, and reading it as one returns
  `no file exists at path`.

### Added

- **`lib/sdl.js`: `configFiles`, `configFile`, `putConfigFile`, `deleteConfigFile`** over
  `POST /sdl/v2/graphql`. GraphQL reports failure as HTTP 200 with an `errors` array, so the
  wrapper raises on that array rather than trusting the status code.
- **Duplicate guardrail on dashboard writes.** `addConfigFile(name:)` updates in place for a
  name-addressed file but creates a duplicate for a dashboard (both verified live). `sdl_put_file`
  now refuses a name-addressed write to an *existing* dashboard and names the `udoId`s already
  holding it, while still allowing the initial create, which has no `udoId` yet. The tenant this
  was found on already carries 256 surplus dashboard copies from this behaviour, including 152 of
  `/dashboards/AI Usage`.
- **`pathPrefix` filter on `sdl_list_files`**, so callers can scope to `/dashboards/` or
  `/logParsers/` without pulling the full listing into context.

### Notes

- `udoId` is assigned by namespace, verified live: only `/dashboards/` files get one. `/lookups/`,
  `/datatables/`, `/logParsers/` and `/automaticLookups` are name-addressed with `udoId` null.
- `expectedVersion` is enforced on both address forms. A stale value is rejected with
  "There are conflicting changes in the file." and the stored content is left untouched.
- A `deleteConfigFile` returning `null` with no `errors` array is success, not failure.
- The scoped SDL keys (`SDL_CONFIG_READ_KEY` and friends) are retired; the console API token
  covers every SDL operation.

## 1.2.4 - 2026-07-31

Hardening release from the 2026-07-31 code review. Tool count unchanged at 26.

### Fixed

- **Missing `Retry-After` header no longer sleeps 0ms before retrying.** `Number(null)` is 0, so `lib/s1.js`, `lib/hec.js`, and `lib/uam-ingest.js` treated an absent header as "wait 0ms" and hammered the backend. All three now use the validated pattern from `lib/sdl.js`: honor the header only when present and parseable as a finite number of seconds (capped at 30s), otherwise fall back to the exponential delay. Numeric headers behave exactly as before.
- **`uam_set_status` no longer reports silent success.** The `alertTriggerActions` mutation selected only `__typename`, so a skipped or failed action still returned as if it worked (observed live: status unchanged after a "successful" call). The selection now mirrors the full `actions { success failure skip }` shape and the client throws when the backend reports a failure entry, skips the action without a success, or returns an empty actions list (nothing applied, e.g. the filter matched no alert). `uam_add_note` was audited for the same pattern; it already verifies via the returned note list.
- **LRQ polling tolerates transient poll errors.** A single 429/5xx poll response used to throw and cancel the running query. Transient statuses now keep polling (interval doubles up to 5s) until the existing 5-minute deadline; other 4xx responses remain fatal.
- **`hasSdlCreds()` recognizes read-only key deployments.** It required `SDL_CONFIG_WRITE_KEY` or the console token; tenants configured with only `SDL_LOG_READ_KEY` / `SDL_CONFIG_READ_KEY` were reported as unconfigured. All chain keys now count.
- **HTTP transport: oversized bodies get their 413.** The request was destroyed before the response was written, so clients saw a connection reset instead of the 413 JSON error. The server now stops reading, sends the 413, then drops the connection after the response is flushed.
- **HTTP transport exits nonzero on any listen-time server error** (EACCES, EADDRNOTAVAIL, ...), not only EADDRINUSE, so systemd/Docker restart policies see the failure.
- **`powerquery_schema_discover` escapes backslashes before quotes** in the data-source name; quote-only escaping let a trailing backslash re-open the V1 filter string.
- **`s1_api_get` honors an inline `?isLegacy=` already present in the path** instead of appending a conflicting `isLegacy=false` query param, matching `_maybe_inject_islegacy` in the Python twin.
- **SDL `config_read` key chain reordered to least-privilege first** (config_read, config_write, console JWT), matching the Python `SDLClient` the header claims to mirror.

### Changed

- **Removed dead exports `purpleAiQuery` and `purpleAiInvestigate`** from `lib/s1.js`; their MCP tools were removed 2026-05-03 (browser-session teamToken requirement) and nothing referenced the library functions. Corrected stale doc text that pointed at a nonexistent `uam_set_analyst_verdict` tool: the analyst verdict is set via a raw `alertTriggerActions` mutation with the `analystVerdictUpdate` action through `s1_api_post`.
- **Deploy docs: credentials.json changes require `systemctl restart`.** SIGHUP reload only re-reads bearer tokens; the installer output and systemd unit comment said reload was enough. `deploy/install.sh` also sets `umask 077` so token/credential files are never world-readable at creation (the explicit `chmod 600` lines remain).
- **Claude Desktop bridge hardening:** 120s fetch timeout (`AbortSignal.timeout`), notification responses are drained so keep-alive sockets are released, and the URL constant no longer shadows the global `URL` constructor.
- **Docker entrypoint passes extra args through** to the selected server binary (e.g. `s1-secops-mcp --transport http`); no-args behavior is unchanged.
- **`const status = response.error ? 200 : 200`** simplified; JSON-RPC errors still return HTTP 200 with an error envelope.

### Tests

- New `tests/regressions-2026-07-31.test.mjs` (mocked fetch, no network): missing `Retry-After` uses the exponential delay, `uamSetStatus` throws on failure/skip results, inline `?isLegacy=` is honored. Both regression suites are now part of `npm test`.
- Transport and smoke tests read the expected version from `package.json` instead of a hardcoded string.

## 1.2.3 - 2026-07-29

Correctness release from the 2026-07-29 defect review. Fixes two bugs that produced plausible-but-wrong query results, hardens the SDL auth chain and HTTP retry paths, corrects the HEC `/event` content type, and adds a regression suite. Tool count unchanged at 26. (The Docker bundle image moved to 1.2.4 pinning `S1_MCP_VERSION=1.2.3`; the image tag stays ahead of the npm tag as it has since the split.)

### Fixed

- **`powerquery_run` no longer collapses a caller-supplied time window.** The old code overwrote BOTH `startTime` and `endTime` with the last-`hours` default whenever either was missing, so a startTime-only call silently ran over the last 24 hours. Each bound now defaults independently. Live A/B: a startTime-only 7.4-day query returned 73,755 events on the fixed server vs 12,911 (the 24h control) on the old one.
- **`powerquery_run` now reports `matchCount`.** It was read from the top level of the LRQ response and came back `null` on every call; it lives inside the `data` block on current engines.
- **SDL auth chain falls through on 401/403.** `lib/sdl.js` treated an auth failure on the first configured key as fatal even when a later key (e.g. the console JWT) would work. It now advances through the chain and raises only when exhausted.
- **HEC `/event` ingestion uses `application/json`,** so per-event `time` backdating is honored instead of the envelope being indexed as opaque text at receive time.

### Changed

- **Write requests no longer auto-retry on 5xx.** Retry is restricted to idempotent methods (GET/HEAD); read-only POSTs (GraphQL queries, Purple AI launches) opt back in via `allowRetry`. HEC raw ingest no longer retries 5xx (no idempotency key); UAM ingest still retries because `metadata.uid` dedupes.
- **`Retry-After` parsing hardened:** an HTTP-date value no longer collapses to `sleep(NaN)`; waits are validated and capped at 30s.
- **`uam_add_note` returns the correct note** (matches by text, tiebreaks on newest `createdAt`) instead of assuming newest-last ordering.
- **`uam_post_alert` schema help corrected** to require `class_uid 99602001` (the S1 Security Alert extension class); generic OCSF `2002` is silently dropped by the stitcher.
- **`ha_export_workflow` no longer implies it returns the archive** (metadata only).
- **`powerquery_schema_discover` escapes single quotes** in the data-source name before building the V1 filter.

### Tests

- New `tests/regressions-2026-07-29.test.mjs` (mocked fetch, no network): independent time-bound defaults, `matchCount` extraction, SDL 401/403 fall-through, HEC per-endpoint content type, write-vs-read retry semantics.

## 1.2.2 - 2026-06-13

### Changed

- **Renamed `ha_archive_workflow` to `ha_delete_workflow`.** The old tool hit `POST /hyper-automate/api/v1/workflows/archive`, which returns HTTP 500 on this tenant. The replacement uses the validated `DELETE /hyper-automate/api/v1/workflows/{id}` endpoint (a soft, recoverable delete equivalent to clicking Delete in the Hyperautomation UI). Scope the call with `accountIds` or `siteIds`; a 404 "Object not found" means the id is not under that scope or is already deleted. Updated `README.md`, the tools-table regenerator, and the smoke test in lockstep.
- **`powerquery_run` description now documents the `datasource` and `savelookup` capabilities** (querying SentinelOne-managed inventory such as assets/alerts/vulnerabilities/misconfigurations, and persisting a result as a reusable lookup table), pointing at the new `powerquery/references/datasource-command.md`.

### Notes

- Tool count unchanged at 26 (the Hyperautomation tool was renamed, not added or removed).
- `SERVER_INFO.version` bumped in lockstep with `package.json` (the drift that forced the 1.2.0 -> 1.2.1 re-release).

## 1.2.1 - 2026-06-11

Supersedes 1.2.0, which was deprecated on npm. The 1.2.0 build shipped with a stale internal `SERVER_INFO.version` of `1.1.0` despite a `1.2.0` package version, so the server announced the wrong version on `initialize`. 1.2.1 is identical in features and corrects the reported runtime version. The content below is unchanged from the 1.2.0 work.

### Added

- **`hec_ingest` tool**: raw-log/event ingestion into the Singularity Data Lake via the HEC (HTTP Event Collector) endpoint (`/services/collector/raw` and `/services/collector/event`). Supports `parser` (-> `?sourcetype=`), custom `fields` (query params), **required** `scope` (S1-Scope header), gzip compression, and `isParsed` (-> `?isParsed=true`, indexes already-structured JSON with no SDL parser). Replaces the removed `sdl_upload_logs`. Validated live across the full HEC matrix (both endpoints, gzip on/off, parser field extraction, multi-line, batched, reserved-field handling, scope enforcement, isParsed). Grounded in the S-26.1 HEC docs (p.4723-4726).

### Removed

- **`sdl_upload_logs` tool** plus the underlying SDL `uploadLogs`/`addEvents` library functions and `SDL_LOG_WRITE_KEY` plumbing. SDL raw-log ingestion moves to the HEC path (`hec_ingest`). The `sdl-api` skill is now query + configuration only; the `sdl-log-parser` validation loop uses HEC ingest.

### Changed

- Tool count unchanged at 26 (removed `sdl_upload_logs`, added `hec_ingest`).
- Skill docs corrected: scheduled detection rules bind the Target Asset via `entityMappings` ("Entity column mapping"); the full scheduled-rule option set (UI <-> API) is catalogued in `powerquery/references/detection-rules.md`.

## 1.1.0 - 2026-05-28 (rebuilt 2026-05-31)

### Fixed (rebuild)

- **`s1_api_get` now auto-injects `isLegacy=false` for `/cloud-detection/rules` listings.** Without `isLegacy=false` the S1 API silently omits `queryType="scheduled"` PowerQuery rules from the response; no error, no warning, the response just lies by omission. The handler now guards against this when the caller forgets, and the tool description loudly flags the requirement. This eliminates the "I see zero scheduled detections" failure mode that was producing wrong verdicts when listing Custom Detection rules. Same `1.1.0` version per the rebuild request.

### Added

- **Streamable HTTP transport.** New `--transport http` mode (default stays `stdio`). Single-endpoint POST `/mcp` per the MCP 2024-11-05 spec, plus `/healthz` for load balancer probes. Implementation is pure `node:http`, no new dependencies.
- **Per-user bearer token auth.** New `MCP_BEARER_TOKENS_FILE` env var pointing at a `{ "<name>": "<token>" }` JSON file gives each team member a stable name in audit logs and supports rotation. SIGHUP reloads tokens without dropping connections. `MCP_BEARER_TOKENS` env var (comma-separated raw tokens) is a fallback for small or quick-test setups.
- **Audit logging.** Every authenticated HTTP request emits `[audit] <ts> | <name> | <method> | <param-summary> | <status>` to stderr; systemd captures it via journald.
- **`S1_CREDS_FILE` credential resolver.** Highest-priority explicit path for credentials, useful for VM deployments and secret-store integrations (Vault, Doppler, 1Password Connect, sealed-secrets).
- **Deploy artifacts** under `deploy/`:
  - `install.sh`: one-shot installer for Mac and Linux. `--user` mode for individuals, `--server` mode for Linux VMs (creates `mcp` system user, generates an initial bearer token, installs systemd unit, starts the service).
  - `systemd/s1-secops-mcp.service`: hardened unit with `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, SIGHUP-as-reload.
  - `caddy/Caddyfile.example`: TLS reverse proxy template with bearer header gate and streaming-friendly flush.
  - `README.md`: full topology guide (single-user local, single-user HTTP, team VM-hosted) with day-2 operations.
- **Test suite.** Three new files under `tests/`, runnable via `npm test`:
  - `smoke.test.mjs`: source-of-truth tool inventory (26 tools by name).
  - `stdio-transport.test.mjs`: JSON-RPC round trip via spawned stdio process.
  - `http-transport.test.mjs`: HTTP transport end-to-end, bearer auth happy/sad paths.
- **README auto-regenerator** at `scripts/regen-readme-tools-table.mjs`. `npm run regen:readme` keeps the README table in sync with `ALL_TOOLS`. `npm run regen:readme -- --check` fails when stale (suitable for CI).

### Fixed

- **README tool table.** Previous count was 19; actual is 26. Auto-generated now.
- **Header comment in `index.js`.** Previously said 21; updated to 26.
- **`purple_ai_query`** removed from the documentation. The tool itself was removed 2026-05-03 because the underlying API requires a browser-session `teamToken` that service-account API tokens never obtain. The README, `index.js`, and `docs/mcp-tools.md` no longer reference it.
- **`uam_set_status` documentation.** Doc previously said valid status values include `CLOSED`. The source enum is `NEW`, `IN_PROGRESS`, `RESOLVED`; doc now matches.

### Changed

- **Refactored** dispatch out of `index.js` into `lib/server-core.js` so both transports use one code path. `lib/stdio-transport.js` is the extracted stdio loop; `lib/http-transport.js` is new.
- **package.json**:
  - `version` 1.0.0 → 1.1.0
  - new scripts: `start:http`, `test`, `regen:readme`
  - new files included in the npm tarball: `deploy/`, `scripts/`, `CHANGELOG.md`

### Compatibility

- Default invocation is unchanged: `npx -y @pmoses-s1/s1-secops-mcp` still produces a stdio MCP server with identical behaviour to 1.0.0.
- Existing `claude_desktop_config.json` and `.mcp.json` configs work without modification.
- The 26 tools, 2 resources, and 2 prompts are unchanged from the late-1.0.0 line; only the documentation now matches reality.

## 1.0.0 - 2026-05-07

Initial public release.

- 19 tools across PowerQuery, S1 Mgmt REST, UAM, SDL API, Hyperautomation.
- stdio transport only.
- Credentials via env vars or auto-discovered `credentials.json`.
