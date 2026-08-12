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

Returns `200` with a connection id. Scope with `siteIds` / `accountIds` to place the connection
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
| **SentinelOne SDL** | `SentinelOne SDL connection` | `Bearer` | SDL LRQ / PowerQuery / HEC ingest (`/sdl/…`, `/services/collector`) |
| **SentinelOne GraphQL** | `SentinelOne GraphQL connection` | `Bearer` | Unified Alerts GraphQL, agentic-investigation, alert write-backs (`/web/api/v2.1/unifiedalerts/graphql`) |
| **SentinelOne** (mgmt) | `SentinelOne connection` | `ApiToken` | Mgmt REST (`/web/api/v2.1/…`): sign as `ApiToken`, NOT `Bearer` |

- SDL and GraphQL sign `Bearer`; the mgmt "SentinelOne" connection signs `ApiToken`, set
  `way_to_pass_prefix` accordingly. Binding the wrong one is the classic `HTTP 500
  "Header must start with Bearer"` (mgmt token on an SDL endpoint) failure.
- `api_key` is the console API token for all three.
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
