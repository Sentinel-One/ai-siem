# Authentication, scopes, and rate limits

## Key types

The SDL API recognises four scoped key types plus the SentinelOne Console user API token (Mgmt version Z SP5+).

| Key type                | Where to generate (SDL UI: user menu → API Keys) | Methods unlocked |
|-------------------------|---------------------------------------------------|------------------|
| Log Read Access         | API Keys → Log Access Keys                        | `query`, `numericQuery`, `facetQuery`, `timeseriesQuery`, `powerQuery` |
| Configuration Read      | API Keys → Configuration Access Keys              | All Log Read methods + `listFiles`, `getFile` |
| Configuration Write     | API Keys → Configuration Access Keys              | All of the above + `putFile` |
| Console User API token  | S1 Console → Settings → Users → My User → API Token | All query + config methods. |

Notes:

- SDL API keys are **scope-specific**. A site-scoped key only sees data and configs in that site. Switch the scope in the top-left of the SDL Console before generating.
- Console user API tokens are **NOT** scope-specific and respect RBAC across multi-site/multi-account access. They expire and are refreshed via the console.
- Legacy console tokens (pre Z SP5) are not accepted by SDL. Generate a new one.

## Sending the token

Header: `Authorization: Bearer <token>`. Sending the key in the JSON body as `"token": "..."` also works but is discouraged (it ends up in logs, `curl --trace`, etc.).

## `S1-Scope` header (console tokens only)

Required when a console token has access to multiple sites or accounts:

- Site scope:    `S1-Scope: <accountScopeId>:<siteScopeId>`
- Account scope: `S1-Scope: <accountScopeId>`

Without the header on a multi-scope token, the request returns no data. Find the IDs in the S1 Console → Settings → Accounts / Sites.

The `SDLClient` only sets `S1-Scope` when (a) a console token was selected for the request and (b) `s1_scope` is configured.

## Query rate limiting (CPU leaky bucket)

`/api/query`, `/api/powerQuery`, `/api/timeseriesQuery`, `/api/numericQuery`, and `/api/facetQuery` all share a CPU-second budget per account.

- Each call returns `cpuUsage` (ms) on success — that's how much it cost.
- The bucket leaks at `cpuUsageRefillRate` CPU sec/sec. When `cpuUsageCapacity >= 1`, queries are rejected until it drains.
- A 429 carries:
  ```json
  {
    "rateLimit": {
      "cpuUsageRefillRate": 0.0001,
      "cpuUsageCapacity": 3.939,
      "cpuUsageLimit": 0.01,
      "cpuUsageSecondsToWait": 211.614
    },
    "message": "...",
    "status": "error/server/backoff"
  }
  ```
- Headers also surface state: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-RefillRate`.

`priority: low` (the default) gets a more generous bucket than `priority: high`. Audit trail: search `tag='audit' cpuUsage=*` for query audit events.

CPU cost scales with: time range, data volume in that range, number of fields scanned, caching. Timeseries queries with `foundExistingSeries: true` cost almost nothing.

## Other rate limits

From **2026-03-19**, all SDL query methods cap at **8 queries/sec** per tenant.

Non-query operations:

- Per-operation, per-account: starting budget **200 requests**, refill **100 req/s**.
- Per IP address: starting budget **1,600 requests**, refill **800 req/s**.
- Aggregate request bytes per operation: starting budget **30 MB**, refill **4 MB/s**.
- **12 concurrent requests** max from the same API key.

### Ingestion (moved to HEC)

Raw-log/event ingestion is no longer part of this skill; use the HEC ingest path. HEC ingest limits are documented with the HEC tooling.

## Retry strategy

The SDLClient retries automatically on:
- HTTP 429
- HTTP 5xx
- HTTP 200 with body `status` starting `error/server/backoff`

It honours `Retry-After` when present and otherwise uses `min(2**attempt, 30)` seconds. For long-running ingest pipelines, prefer the binary truncated exponential backoff loop in `integration_patterns.md` — it is designed to (a) stop on `discardBuffer` and (b) slowly relax wait time after success.

## Audit references

- Query CPU audit: `tag='audit' cpuUsage=*`
- Ingestion failures: `tag='ingestionFailure'`
