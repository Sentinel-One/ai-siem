# SDL Config File API (GraphQL)

GraphQL API for reading and writing SDL configuration files: dashboards, parsers, lookups,
datatables, automatic lookups, monitors, alerts, and partition rules.

This is the **canonical** config-file surface. The legacy REST endpoints (`/sdl/api/listFiles`,
`getFile`, `putFile`) are incomplete, see "Why not REST" below.

Every claim here was verified live against `<console>` on 2026-08-07.

## Endpoint and authentication

```text
POST https://<console>/sdl/v2/graphql
```

Two headers, and only two:

```text
Authorization: Bearer <S1_CONSOLE_API_TOKEN>
Content-Type: application/json
```

| Detail | Value |
|---|---|
| Auth scheme | `Bearer`. `ApiToken` returns `unauthenticated`. |
| Token | A standard console API token, already a JWT. |
| `?opname=` and `?requestId=` | Optional, correlation only. The server routes on the request body. |
| `s1-scope` header | **Required in practice on a multi-scope token, and it is NOT ignored.** See "Scope" below. |

Errors come back as **HTTP 200 with an `errors` array**. Check `errors`, not the status code.

## Scope

**Corrected 2026-08-17.** An earlier revision of this file said the `s1-scope` header was "ignored, not rejected" on this endpoint. That was wrong and it caused real false negatives: config listings and dashboard reads ARE scope-filtered.

Measured on `<console>`, same token, same query, one header apart. Absolute counts are
per-token (a token scoped to a larger tenant sees more); the *ratio* is the point:

| `S1-Scope` | `configFiles` returned | of which `/dashboards/` |
|---|---|---|
| absent (token default) | 113 | 20 |
| `<accountId>` (account) | 113 | 20 |
| `<accountId>:<siteId>` (site) | **4** | 4 |

A dashboard created at site scope is **invisible** to an account-scoped listing, and `configFile` on its `udoId` reports it absent. So a missing header is not a neutral default; it silently changes which objects exist as far as the caller can tell. Console traffic capture confirms the UI sends `s1-scope` on all 23 SDL GraphQL operations.

Format:

- Account scope: `S1-Scope: <accountId>`
- Site scope: `S1-Scope: <accountId>:<siteId>`

Ids come from `GET /web/api/v2.1/accounts` and `GET /web/api/v2.1/sites`. Group scope does not exist in SDL: the console silently promotes a Group selection to the Site above it.

**Consequences for correctness, not just visibility:**

1. Absence checks must re-list at the **same** scope as the failed lookup. Disambiguating a site-scoped miss against an account-scoped listing reports a live file as deleted.
2. The `/dashboards/` duplicate guard must list at the scope of the write, or it will either miss a same-named sibling or block a legitimate create.
3. "File not found" is always scope-relative. Before concluding an object is gone, re-check at the scope it was created in.

`SDLClient` and the `sdl_*` MCP tools take an explicit `scope` argument, defaulting to `S1_SCOPE` from credentials. Passing `scope=None` / `scope: null` deliberately suppresses that default and sends no header, which is what a token-default listing needs.

## Why not REST

| | REST `/sdl/api/*File` | GraphQL `configFiles` |
|---|---|---|
| Files listed (live tenant) | 1,914 | 2,264 |
| Dashboards visible | 1,160 | 1,510 |
| udoId-addressed dashboards | **0**, `getFile` returns `success/noSuchFile` | 350 |
| Plain files (lookups, parsers, datatables, automaticLookups) | Works | Works |

The 350-file gap is entirely udoId-addressed dashboards. REST cannot see or modify any of them,
which makes a REST listing unsafe for any "does this file exist" decision.

**Tripwire.** If a file is not found by name, or a listing count disagrees with the console,
re-check with `configFiles` before reporting "not found".

## The `udoId` rule

The console displays a dashboard in its Configuration Files grid as:

```text
/dashboards/id/6554761743556608/AI Usage
              ^^^^^^^^^^^^^^^^ this is the udoId
```

That display string is **not a path**. Reading it as one returns `no file exists at path`. Pass
`6554761743556608` as `udoId`; the file's real `name` is `/dashboards/AI Usage`.

`udoId` is assigned by **namespace**, not by creation method:

| Namespace | `udoId` on create | Address by |
|---|---|---|
| `/dashboards/` | assigned | `udoId` |
| `/lookups/` | `null` | `name` |
| `/datatables/` | `null` | `name` |
| `/logParsers/` | `null` | `name` |
| `/automaticLookups` | `null` | `name` |

## Operations

| Operation | Type | Address by | Returns |
|---|---|---|---|
| `configFiles` | query | n/a | array of `{udoId, name, readOnly, version}` |
| `configFile` | query | `id` or `udoId` | one file including `content` |
| `addConfigFile` | mutation | `name` to create, `udoId` to update | `{udoId, name, version}` |
| `deleteConfigFile` | mutation | `id` or `udoId` | `null` on success |
| `formatConfigFile` | mutation | `id` or `udoId` | formatted string |

### List

```bash
curl -sS -X POST "https://$S1_CONSOLE/sdl/v2/graphql?opname=getConfigurationFiles" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $S1_TOKEN" \
  -d '{"query":"query getConfigurationFiles { configFiles { udoId name readOnly version } }"}'
```

`version` is required for any later update or delete. Cache it.

### Read

By name for plain files, by `udoId` for dashboards:

```json
{
  "query": "query f($udoId: ID!) { configFile(udoId: $udoId) { udoId name content version } }",
  "variables": { "udoId": "96200328708096" }
}
```

`content` is HJSON: unquoted keys and relaxed commas are both accepted.

**Absence is reported as an error, not as a null result**, and the text differs by address form:

| Address form | Message when the file does not exist |
|---|---|
| by `name` / `id` | `Config file with name /x/y not found.` |
| by `udoId` | `Something went wrong. Please try again and if the issue persists contact Support.` |

The `udoId` message is generic and is **also what a version conflict returns**, so absence cannot
be decided from the message alone on that form. Disambiguate against `configFiles`: absent from
the listing means gone, present means the error was real and must propagate. A transport failure
whose body happens to contain "not found" must never be treated as absence. `SDLClient.config_file()`
and the `sdl_get_file` tool handle all of this and return `None` / a `notFound` status.

### Create, update, delete

```json
{
  "query": "mutation f($name: String, $content: String!) { addConfigFile(name: $name, content: $content) { udoId name version } }",
  "variables": { "name": "/dashboards/Alert Volume", "content": "{\"graphs\":[]}" }
}
```

Update addresses by `udoId` and passes the current `version` as `expectedVersion`. Delete uses
`deleteConfigFile` with the same address form.

**A delete returning `null` with no `errors` array is SUCCESS.** The deleted object is not echoed
back. Treating that null as a failure is the most common mistake against this operation.

## Write semantics: the duplicate trap

`addConfigFile(name:)` behaves differently by namespace. Both branches verified live:

| Target | `addConfigFile(name:)` on an existing file |
|---|---|
| `/lookups/`, `/datatables/`, `/logParsers/` | **Updates in place.** One file, new version. |
| `/dashboards/` | **Creates a duplicate.** Two files sharing the name, two `udoId`s. |

So: create a dashboard by name once (no `udoId` exists yet), then address it by `udoId` forever
after.

This is not theoretical. On the live tenant, 1,510 dashboard files carry only 1,254 distinct
names, **256 surplus copies**, including **152 copies of `/dashboards/AI Usage`**, 25 of
`EDR Data Collection Analysis`, and 21 of `FIM for PCI DSS v4.0.1 Compliance`. Every duplicated
name is a stock template dashboard; hand-authored names have none. Each install of a template
creates another file, so a shared tenant accumulates copies over time.

`expectedVersion` is honoured on **both** address forms. A stale value is rejected with
`{"errors":[{"message":"There are conflicting changes in the file."}],"data":{"addConfigFile":null}}`
and the stored content is left untouched (verified 2026-08-07 on a name-addressed
`/datatables/` write). Always pass it on an update; omitting it is last-write-wins.

## Client

Use `SDLClient` from `scripts/sdl_client.py`:

```python
from sdl_client import SDLClient

c = SDLClient()

files = c.config_files()                                   # all 2,264, including dashboards
dash  = [f for f in files if f["name"].startswith("/dashboards/")]

# read a dashboard the REST surface cannot see
d = c.config_file(udo_id="96200328708096")

# safe dashboard update
c.put_config_file(udo_id=d["udoId"], content=new_json, expected_version=d["version"])

# plain files address by name
c.put_config_file(name="/lookups/assets.csv", content="k,v\na,1\n")

c.delete_config_file(udo_id=d["udoId"], expected_version=d["version"])
```

`put_config_file` refuses a name-addressed write to an existing `/dashboards/` file and tells you
which `udoId`s already hold that name.

## The `dashboardsV2` surface (dashboard lifecycle)

**Added 2026-08-17** from a console network capture (280 requests, 23 operations, `<console>`).

The same `POST /sdl/v2/graphql` endpoint carries a second, higher-level surface that the console itself drives. Everything above operates on raw config files; these operations are dashboard-aware.

| Operation | Type | Purpose |
|---|---|---|
| `dashboardsV2` | query | List dashboards with `access { public users owner }` |
| `getDashboardV2(id, dashboardName, resolveParameters)` | query | One dashboard incl. tabs, duration, authorship |
| `createDashboardV2(dashboardName, config, public)` | mutation | Create from a full dashboard-JSON string |
| `saveDashboardLayout(id, dashboardName, graphs, options, tabName)` | mutation | Replace the panels of ONE tab |
| `shareResource(id, users, scopes)` | mutation | Share to scopes and/or users |
| `deleteDashboard(id, dashboardName)` | mutation | Delete; returns a bare boolean |

**`id` here IS `udoId` there.** Dashboard `meta1` is `id 6999000578736128` in `getDashboardV2` and `udoId 6999000578736128` / `name "/dashboards/meta1"` in `configFile`. Same object, two views.

### Which surface to use

- **Creating a dashboard** → `createDashboardV2`. It takes the whole document (`configType`, `duration`, `description`, `tabs[]`) as one `config` string.
- **Updating a whole dashboard** → `addConfigFile(udoId:, expectedVersion:)`. Only the config-file layer exposes the numeric CAS token.
- **Nudging panels on one tab** → `saveDashboardLayout`.
- **Anything about sharing or ownership** → `dashboardsV2` / `shareResource`. The config-file layer has no concept of either.

### Two version fields, do not cross them

`getDashboardV2` returns `version: ""`, a display string that is empty in practice. `configFile` returns `version: 215771284`, the optimistic-locking token. **Only the `configFile` value is valid as `expectedVersion`.**

### `shareResource` is the only scope-targeting operation

Every other operation infers scope from the `S1-Scope` header. `shareResource` takes explicit targets, which is how you push an account-scoped dashboard down to a site without recreating it:

```json
{
  "operationName": "ShareDashboard",
  "variables": {
    "id": "6999150597128192",
    "users": [],
    "scopes": [{ "scopeType": "site", "scopeId": "2547662415802335157", "operation": "ADD" }]
  },
  "query": "mutation ShareDashboard($id: ID!, $users: [UserSharingCommand], $scopes: [ScopeSharingCommand]) { shareResource(id: $id, users: $users, scopes: $scopes) { id name } }"
}
```

`scopeType` is `site` | `account` | `global`; `operation` is `ADD` | `REMOVE`; `scopeId` is the numeric id. A malformed entry is accepted and shares nothing, which reads as success, so validate before sending.

### Tab payloads are JSON strings

`tabs[].graphs`, `.parameters`, `.filters` and `.options` come back as **strings**, not objects; the console parses them client-side. `saveDashboardLayout` expects `graphs` shaped `{"graphs":[...]}` **including the wrapper key**, even though the response echoes a bare array.

### Trap: the UI stub-append

Creating an empty dashboard in the console and pasting JSON into its editor starts from a `{graphs: []}` stub. Pasting *after* the stub instead of replacing it produces `{graphs: []}{...}`, and `addConfigFile` rejects it:

```json
{"errors":[{"path":["addConfigFile"],"details":{"content":"Additional text after JSON object","lineNumber":2,"columnNumber":12},"message":"Content is invalid json"}]}
```

The dashboard survives as an empty shell (`configType: "NOT_SPECIFIED"`, `graphs: []`), which looks like a rendering bug rather than a rejected write. `createDashboardV2` cannot hit this class of error; prefer it.

### Site-level lifecycle, end to end

Two equivalent routes:

1. **Create in place**: call `createDashboardV2` with `S1-Scope: <accountId>:<siteId>`.
2. **Create then share**: create at account scope, then `shareResource` with a `site` target. Use this when the calling token sits at account scope.

Then verify: `dashboardsV2` at the site scope must list it, and at account scope it must be absent (or present-but-shared, depending on route). Confirming at only one scope proves nothing.

## Credentials

The console API token alone covers every SDL operation. The scoped SDL keys
(`SDL_CONFIG_READ_KEY`, `SDL_CONFIG_WRITE_KEY`, `SDL_LOG_READ_KEY`, `SDL_LOG_WRITE_KEY`) are
retired and are not used by this skill. Note that auth scheme differs by surface: `Bearer` for
`/sdl/v2/graphql`, `<console>/sdl/api/*` and HEC; `ApiToken` for the Management API at
`/web/api/v2.1/*`.

### `createDashboardV2` gotchas (verified live 2026-08-17)

**1. `public` defaults to false, and a private service-user dashboard is invisible to humans.**

`createDashboardV2(dashboardName, config, public)` files the dashboard with `access.owner` set to the *calling identity*. With an API service-account token that is something like `serviceuser-<uuid>@mgmt-<n>.sentinelone.net`, not a person. If `public` is false, the dashboard exists, is readable through the API, and is **invisible in the console to the human operator**, even at the correct scope. It looks exactly like a failed deploy.

Pass `public: true` for anything a person is meant to open. Verified: the same dashboard at the same scope went from invisible to visible in the console purely by recreating it with `public: true`, and every pre-existing dashboard at that site carried `public: true`.

`shareResource` with a scope target does **not** flip `public`; the two are independent.

**2. Dashboard names reject several punctuation characters, with only `Invalid name` as the error.**

Probed one character class at a time against a live tenant:

| Accepted | Rejected |
|---|---|
| letters, digits, space, `-`, `_`, `.`, `/` | `(` `)` `[` `]` `{` `}` `:` `,` `&` `'` `%` `#` |

The failure is `{"errors":[{"message":"Invalid name"}]}` with no indication of which character offended, so a name like `My Dashboard (prod)` fails opaquely. Strip punctuation to spaces or hyphens before creating.
