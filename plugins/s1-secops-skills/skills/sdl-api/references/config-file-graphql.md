# SDL Config File API (GraphQL)

GraphQL API for reading and writing SDL configuration files: dashboards, parsers, lookups,
datatables, automatic lookups, monitors, alerts, and partition rules.

This is the **canonical** config-file surface. The legacy REST endpoints (`/sdl/api/listFiles`,
`getFile`, `putFile`) are incomplete, see "Why not REST" below.

Every claim here was verified live against `usea1-purple` on 2026-08-07.

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
| `s1-scope` header | Not required. It is ignored, not rejected, so sending one is harmless. |

Errors come back as **HTTP 200 with an `errors` array**. Check `errors`, not the status code.

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

## Credentials

The console API token alone covers every SDL operation. The scoped SDL keys
(`SDL_CONFIG_READ_KEY`, `SDL_CONFIG_WRITE_KEY`, `SDL_LOG_READ_KEY`, `SDL_LOG_WRITE_KEY`) are
retired and are not used by this skill. Note that auth scheme differs by surface: `Bearer` for
`/sdl/v2/graphql`, `<console>/sdl/api/*` and HEC; `ApiToken` for the Management API at
`/web/api/v2.1/*`.
