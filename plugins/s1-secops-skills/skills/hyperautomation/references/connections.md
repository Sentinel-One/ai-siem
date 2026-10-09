# Connections: creating integration connections via API

Integration-backed actions (`tag: "integration"`) need a connection under their `integration_id`.
An existing connection can be bound programmatically (bind the integration id, set
`use_authentication_data: true`). A connection can also be **created** via the API, but creating
one requires supplying the integration's secret (an API token) in the request body. That secret is
supplied by the human operator; do not hard-code, echo, or store it.

## Endpoint

```text
POST /web/api/v2.1/hyper-automate/api/v1/connections?siteIds=<id>     (or ?accountIds=<acct>)
```

Returns `201` with the connection (`id`, `scope_level`, `site_name`; measured 2026-10-09, see
`api-integration.md` section 16 for the full measured body and error codes). Scope with `siteIds` / `accountIds` to place the connection
where the flow lives; connections are per-scope, so a site flow needs a connection in that site
(or an account-level one that covers it).

## Body (SentinelOne first-party connections)

All three SentinelOne connections share one body shape; they differ only in `name`,
`integration_id`, and the auth **prefix**:

```json
{
  "data": {
    "name": "<connection name>",
    "url": "<console-host>",
    "port": 443,
    "protocol": "https://",
    "integration_id": "<action-pack id for this integration>",
    "is_default": true,
    "authentication_data": {
      "way_to_pass": "header",
      "way_to_pass_input": "Authorization",
      "way_to_pass_prefix": "Bearer",
      "authentication_type": "api_key",
      "api_key": "<console API token, operator supplies>"
    }
  }
}
```

| Connection | `name` | Auth prefix | Used for |
|---|---|---|---|
| **SentinelOne SDL** | `SentinelOne SDL connection` | `Bearer` | SDL LRQ / PowerQuery (`/sdl/…`), UAM alert ingest (`/v1/alerts`) |
| **SentinelOne GraphQL** | `SentinelOne GraphQL connection` | `Bearer` | Unified Alerts GraphQL, agentic-investigation, alert write-backs (`/web/api/v2.1/unifiedalerts/graphql`) |
| **SentinelOne** (mgmt) | `SentinelOne connection` | `ApiToken` | Mgmt REST (`/web/api/v2.1/…`): sign as `ApiToken`, NOT `Bearer` |

- SDL and GraphQL sign `Bearer`; the mgmt "SentinelOne" connection signs `ApiToken`, set
  `way_to_pass_prefix` accordingly. Binding the wrong one is the classic `HTTP 500
  "Header must start with Bearer"` (mgmt token on an SDL endpoint) failure.
- `api_key` is the console API token for all three.

### Connections are resolved by name at the workflow's own scope, at run time

Measured 2026-10-09: an `http_request` action bound by name (`use_connection_name: true`,
`connection_name: "<name>"`) imported and ACTIVATED (204) at a scope where no connection of that
name existed, so activation does not check it. At run time the same workflow imported at the account,
while the connection lived at a site under it, failed with "Connection with name '<name>' could not
be found."; imported at the site it reached the connection (the call itself then ran with that
connection's credential). Import a workflow at the scope that owns its connections, and treat a
clean activation as no proof that its connections resolve: run it.

### HEC event-collector ingest needs a fourth, separate connection

`POST {HEC_INGEST_URL}/services/collector/event` and `/raw` take an **SDL Log Write Key**. A
Hyperautomation connection passes its stored credential through verbatim as
`Authorization: Bearer <value>`, so the binding is a `Bearer` connection created with the same body
shape above but `api_key` set to the Log Write Key rather than the console token. Measured live
2026-10-09: the write key returns `HTTP 200 {"text":"Success","code":0}` on every console where
ingest worked. A connection holding the console token behaves exactly like the console token, and
that differs per console: on some it returns `HTTP 400 {"text":"Missing S1-Scope header","code":5}`
without an `S1-Scope` header and is accepted with one (the header then decides where events land);
on others it returns `HTTP 403 {"text":"User token not allowed for this endpoint","code":4}` with or
without the header. A `400 Missing S1-Scope header` means the action carried the console token
without a scope header; a `403 code 4` means this console does not accept user tokens at the
collector. Use the write key in both cases. Send **no** `S1-Scope` header on collector actions: the
key is minted for one account or site and that fixes where events land; the header does not change
it.

Mint the key at Console → Singularity Data Lake → API Keys → Log Write Key; no API creates one. Keep
this connection distinct from "SentinelOne SDL", a flow that both queries SDL and ingests to the
collector needs both bound, one per action.

`POST {HEC_INGEST_URL}/v1/alerts` (UAM alert ingest) is the opposite case on the same host: console
API token **and** the `S1-Scope` header. Do not conflate the two.

- **Find the `integration_id`** without hard-coding it: `GET /connections/scope?<scope>` on a scope
  that already has the connection and read each connection's `integration_id`, or list the tenant's
  integrations. Reuse that id when creating the same connection type in another scope.

## Cloning a connection to another site

To replicate a connection from one site to another (e.g. copy Site A's setup to Sites B and C):
`GET` the source connection, reuse its `name`, `url`, `port`, `protocol`, `integration_id`, and the
`authentication_data` shape, and `POST` to the target site scope with the `api_key` filled in.
Everything except the secret comes straight from the source connection.

## Binding + activation

Bind the **integration** id on `http_request` actions (`integration_id`), set
`use_authentication_data: true`, and rely on a connection existing under that integration in the
action's scope. Do NOT bind a specific connection id; that imports/activates but fails at runtime
(`"Must provide connection…"`). If no connection exists for a bound integration in the target scope,
activation fails `400 "requires configuration"`, create the connection there first, then activate.
