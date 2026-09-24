## s1-secops-mcp bundle image 1.3.2

Docker bundle image **1.3.2**, pinning npm **@pmoses-s1/s1-secops-mcp 1.3.6**,
purple-mcp **v0.7.0** and virustotal-mcp **1.0.21**. Plugin **1.3.2**. Tool count
32.

The image version and the npm version are independent. The image version tracks
the Dockerfile, the dispatcher and the bundled `CLAUDE.md`; the npm version tracks
the server itself.

**Headline: site-level dashboard lifecycle.** Two gaps closed. SDL GraphQL calls
never sent an `S1-Scope` header, so every config-file and dashboard operation
landed at whatever scope the token defaulted to. And the dashboard operations the
console itself uses were not wrapped at all, so there was no way to create a
dashboard from a full config document or to share one to a site.

### What changed

**Six new tools** on the `dashboardsV2` surface, the one the console drives:
`sdl_list_dashboards`, `sdl_get_dashboard`, `sdl_create_dashboard`,
`sdl_share_dashboard`, `sdl_save_dashboard_layout`, `sdl_delete_dashboard`.

**A `scope` argument** on those six plus the four existing `sdl_*_file` tools.
Format `"<accountId>"` for account scope or `"<accountId>:<siteId>"` for site
scope. It falls back to a new `S1_SCOPE` credential, and is validated before the
request so a typo cannot silently widen a read.

**`sdl_create_dashboard`** accepts the whole dashboard document (`configType`,
`duration`, `description`, `tabs[]`) as one `config` string. It parses the JSON
before sending, which turns the console's stub-append failure into a caller error
instead of a broken dashboard. Creating an empty dashboard in the UI starts from a
`{graphs: []}` stub; pasting after it rather than replacing it produces
`{graphs: []}{...}` and the server answers `Content is invalid json` /
`Additional text after JSON object`, leaving an empty shell that reads as a
rendering bug.

**`sdl_share_dashboard`** wraps `shareResource`, the only SDL operation that takes
an explicit scope target. Everything else infers scope from the header. This is how
an account-scoped dashboard is pushed to a site without recreating it.

### Scope is a filter, not a label

A previous revision of `sdl-api/references/config-file-graphql.md` stated that the
`s1-scope` header was "ignored, not rejected" on `/sdl/v2/graphql`. That was wrong,
and it produced real false negatives. Measured on a live tenant, same token, same
query:

| `S1-Scope` | `configFiles` | of which `/dashboards/` |
|---|---|---|
| absent (token default) | 2,273 | 1,516 |
| `<accountId>` | 2,273 | 1,515 |
| `<accountId>:<siteId>` | **20** | **7** |

A dashboard created at site scope is invisible to an account-scoped listing, and
`configFile` on its `udoId` reports it absent. **Every "not found" is
scope-relative.** Three call sites therefore thread the scope explicitly: absence
disambiguation re-lists at the scope of the failed lookup, the `/dashboards/`
duplicate guard lists at the scope of the write, and delete verification re-reads
at the scope of the delete. Mixing scopes across those steps reports a live file as
deleted.

### Dashboard skill: `site.id`, not `site.name`

Deployment scope (where the object is filed) and query scope (what the panels read)
are separate decisions. A site-deployed dashboard now scopes its panels to that
site with `site.id='<siteId>'` unless the user explicitly asks for account-wide
queries.

`site.name` is not a safe substitute. For one site over 24h, `site.id='<id>'`
matched 60,410 events, of which **510 carried the site id with a null
`site.name`**: `ActivityFeed` 172, `asset` 111, unattributed 99, `SentinelOne` 70,
`Windows Event Logs` 48, **`alert` 10**. A `site.name` filter silently drops alert
and asset records, which is what a SOC dashboard leans on hardest. `site.id` is
also the same identifier as the `S1-Scope` `siteId` and `shareResource`'s
`scopeId`, and it survives a site rename.

`panel_safety_check.py` enforces both halves:

```bash
python3 scripts/panel_safety_check.py dash.json --site-id <siteId>
python3 scripts/panel_safety_check.py dash.json --site-id <siteId> \
    --allow-account-scope-queries
```

- **S01**: a site-targeted dashboard has a query panel with no `site.id`
  predicate, or one scoped to a different site. Opt out with
  `--allow-account-scope-queries`.
- **S02**: `site.name` used as a scoping filter with no `site.id` alongside it.
  Never suppressed; the substitution is wrong at any scope.

Also recorded: the console's XDR data-source selector injects
`preFilter: "dataSource.category = 'security'"` into every panel query, so under
XDR anything outside `category='security'` is silently excluded.

### Python client

`sdl-api/scripts/sdl_client.py` gains a per-call `scope` on `config_files`,
`config_file`, `put_config_file` and `delete_config_file`, and the six dashboard
methods `list_dashboards`, `get_dashboard`, `create_dashboard`, `share_dashboard`,
`save_dashboard_layout`, `delete_dashboard`. Omitting `scope` inherits the client
default; passing `None` deliberately sends no header, which keeps an unscoped
listing requestable once a default is configured.

### Install

```bash
docker pull ghcr.io/pmoses-s1/s1-mcps:1.3.2
```

```json
"s1-secops-mcp": {
  "command": "docker",
  "args": ["run", "-i", "--rm", "--pull=missing",
           "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN", "-e", "S1_HEC_INGEST_URL",
           "ghcr.io/pmoses-s1/s1-mcps:1.3.2", "s1-secops-mcp"]
}
```

The same image serves `purple-mcp` and `virustotal-mcp`; pass the server name as the
final argument. `--pull=missing` means nothing updates until the tag string changes,
so re-pull explicitly after a rebuild and restart Claude Desktop.

Direct npm install, without Docker:

```bash
npm install -g @pmoses-s1/s1-secops-mcp@1.3.6
```

Optional, to default every SDL call to one scope:

```json
{ "S1_SCOPE": "<accountId>:<siteId>" }
```

### Verification

Expect `serverInfo.name = "s1-secops-mcp-server"`, `version = "1.3.6"`, and
`tools/list` returning 32 tools.

- 115 JavaScript tests (`npm test`), 29 of them new: header presence and absence,
  credentials fallback, `scope: null` suppression, malformed-scope rejection before
  any request, scope consistency across the guard / disambiguation / delete-verify
  paths, the six dashboard operations, stub-append rejection, and the
  `getDashboard` absence matrix
- 61 Python unit tests (`sdl-api/tests/test_client.py`), 42 of them new
- 19 Python unit tests (`sdl-dashboard/tests/test_panel_safety_check.py`, new):
  S01 and S02 including the wrong-site case, the opt-out flag, exempt panel types,
  and a guard that the existing rules still fire
- **Live lifecycle regression, 28 checks, 0 failures**, against a real tenant:
  full create → read → share → layout → delete → confirm-absent cycles at **both**
  site and account scope, plus scope-isolation assertions in both directions, the
  unscoped default path, and the three pre-flight guards

### Deploy-time traps worth knowing

**`isPublic` defaults to true in these clients**, deliberately diverging from the
raw API's false. `access.owner` is the calling identity, so with a service-account
token a private dashboard is readable via API and invisible in the console to a
human at any scope: a success that looks like a failure. Pass `isPublic: false`
for a genuinely private one.

**Dashboard names reject punctuation** with only `Invalid name` as the error.
Accepted: letters, digits, space, `-`, `_`, `.`, `/`. Rejected: `( ) [ ] { } : , & ' % #`.

### Upgrade notes

No breaking changes. `scope` is optional everywhere and omitting it reproduces
pre-scope behaviour exactly, which is the token default.

Note that npm **1.3.4 shipped an incomplete version of this work**: `scope` was
accepted on the config-file and dashboard operations but silently absent from the
query methods, so scoped hunts answered for the token default. Use 1.3.5.

One caveat worth knowing. An `S1-Scope` naming an account the token has no
entitlement to returns `403 forbidden` from the server, and the message does not
mention scope. If scoped calls 403 while unscoped calls succeed, check that the
account id belongs to the token's own tenant before suspecting the code:
`GET /web/api/v2.1/accounts` lists what the token can actually reach.
