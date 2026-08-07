## s1-secops-mcp 1.2.3

Correctness release from the 2026-07-29 defect review. Fixes two bugs that
produced plausible-but-wrong query results, hardens the SDL auth chain and the
HTTP retry paths, corrects the HEC `/event` content type so per-event
timestamps are honored, and adds a regression suite. Tool count is unchanged at
26.

Versioning: the `@pmoses-s1/s1-secops-mcp` npm package moves to **1.2.3**
(from 1.2.2, no skipped version). The Docker bundle image moves to **1.2.4**
(from 1.2.3) and pins `S1_MCP_VERSION=1.2.3`, so the image tag stays ahead of
the npm package tag as it has since the split.

### Fixed
- **`powerquery_run` no longer collapses a caller-supplied time window.** The
  old code overwrote BOTH `startTime` and `endTime` with the last-`hours`
  default whenever either was missing, so a call with only `startTime` silently
  ran over the last 24 hours instead of the requested range. Each bound now
  defaults independently. Live A/B (2026-07-29): a startTime-only 7.4-day query
  returned 73,755 events on the fixed server vs 12,911 (== the 24h control) on
  the old one, against a pinned truth of 73,743.
- **`powerquery_run` now reports `matchCount`.** It was read from the top level
  of the LRQ response and came back `null` on every call; it lives inside the
  `data` block on current engines. The 0-rows-vs-0-matches triage works again.
- **SDL auth chain falls through on 401/403.** `lib/sdl.js` picked the first
  configured key and treated an auth failure as fatal, so a tenant with the
  config keys set but no dedicated log-read key would 403 forever on
  `powerquery_schema_discover` even though the console JWT later in the chain
  would work. It now advances to the next candidate key on 401/403 and raises
  only when the chain is exhausted. Live-verified: config-write key 403s on
  View Logs, chain advances to the console JWT, query succeeds.
- **HEC `/event` ingestion uses `application/json`.** The wrapper sent
  `text/plain` for both endpoints; on `/event` that made HEC treat the JSON
  envelope as opaque text and ignore per-event `time`, so a backdated event
  indexed at receive time. `/event` now sends `application/json` (per-event
  `time` is honored; absent, HEC defaults to ingest time). Live-verified: a
  backdated envelope indexed at exactly the requested epoch.

### Changed
- **Write requests no longer auto-retry on 5xx.** `doFetch` restricted 429/5xx
  retry to idempotent methods (GET/HEAD); a 5xx received after a mutating POST
  committed would otherwise re-POST and double-write (duplicate rules, notes,
  ingestion). Read-only POSTs (GraphQL queries, Purple AI launches, UAM list)
  opt back in via `allowRetry`. HEC raw ingest no longer retries 5xx (no
  idempotency key); UAM ingest still retries because `metadata.uid` dedupes.
- **`Retry-After` parsing hardened** across all HTTP helpers: an HTTP-date value
  no longer collapses to `sleep(NaN)` (an immediate hammering retry); waits are
  validated and capped at 30s.
- **`uam_add_note` returns the correct note.** It assumed the API appends the
  new note last; it now matches by text and tiebreaks on newest `createdAt`.
- **`uam_post_alert` schema help corrected** to require `class_uid 99602001`
  (the S1 Security Alert extension class). The generic OCSF `2002` is silently
  dropped by the stitcher even though HEC returns HTTP 202. Live-verified end to
  end via the ingest integration test.
- **`ha_export_workflow` no longer implies it returns the archive.** It returns
  metadata only; the misleading "full ZIP in buffer" note is gone.
- **`powerquery_schema_discover` escapes single quotes** in the data-source name
  before building the V1 filter, so a legitimately quoted source name no longer
  breaks (or alters) the filter.

### Tests
- New `tests/regressions-2026-07-29.test.mjs` (mocked fetch, no network):
  independent time-bound defaults, `matchCount` extraction, SDL 401/403
  fall-through, HEC per-endpoint content type, and write-vs-read retry
  semantics. Full unit suite is green (the one live integration test,
  `test_uam_ingest.mjs`, requires tenant credentials).
