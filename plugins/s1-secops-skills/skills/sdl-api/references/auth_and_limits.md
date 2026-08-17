# Authentication, scopes, and rate limits

## Key types

The SDL API authenticates with the SentinelOne Console user API token.

| Key type                | Where to generate (SDL UI: user menu → API Keys) | Methods unlocked |
|-------------------------|---------------------------------------------------|------------------|
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

Find the IDs via `GET /web/api/v2.1/accounts` and `GET /web/api/v2.1/sites`, or in the S1 Console → Settings → Accounts / Sites. Group scope does not exist in SDL; a Group selection is silently promoted to the Site above it.

**The header applies to `/sdl/v2/graphql` config-file and dashboard operations too, not only to queries and ingest.** Verified on `usea1-purple` 2026-08-17: `configFiles` returned 113 files at account scope and 4 at a site scope, same token and same query. A dashboard created at site scope does not appear in an account-scoped listing and `configFile` on its `udoId` reports it absent. Treat every "not found" as scope-relative.

Because a dropped header changes results rather than erroring, three call sites need the scope threaded through explicitly:

- absence disambiguation must re-list at the scope of the failed lookup;
- the `/dashboards/` duplicate guard must list at the scope of the write;
- delete verification must re-read at the scope of the delete.

`SDLClient` sets `S1-Scope` from the per-call `scope` argument, falling back to `s1_scope` in config / `SDL_S1_SCOPE`. Pass `scope=None` to suppress the default and send no header.

## Query rate limiting (CPU leaky bucket)

`/api/query`, `/api/powerQuery`, `/api/timeseriesQuery`, `/api/numericQuery`, and `/api/facetQuery` all share a CPU-second budget per account.

- Each call returns `cpuUsage` (ms) on success: that's how much it cost.
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

Usage Metering datasource calls (`| datasource "metering"` for `tenants` / `reports` / `report_name`) have their own cap: **50 requests/sec with a 100-request burst**, and require the `Metering Reports - View` permission. See `methods.md` → Usage Metering reports.

- **12 concurrent requests** max from the same API key.

### Ingestion (moved to HEC)

Raw-log/event ingestion is no longer part of this skill; use the HEC ingest path. HEC ingest limits are documented with the HEC tooling.

## Retry strategy

The SDLClient retries automatically on:

- HTTP 429
- HTTP 5xx
- HTTP 200 with body `status` starting `error/server/backoff`

It honours `Retry-After` when present and otherwise uses `min(2**attempt, 30)` seconds. For long-running ingest pipelines, prefer the binary truncated exponential backoff loop in `integration_patterns.md`; it is designed to (a) stop on `discardBuffer` and (b) slowly relax wait time after success.

## Audit references

- Query CPU audit: `tag='audit' cpuUsage=*`
- Ingestion failures: `tag='ingestionFailure'`
