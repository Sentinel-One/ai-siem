# Common query parameters

Most list endpoints share these. See per-endpoint docs for additional filters.

- `skip` — pagination offset (0-1000). For >1000 items, use `cursor` instead.
- `limit` — page size (1-1000, default 10).
- `cursor` — opaque pagination token returned by prior response. Prefer this for deep pagination.
- `countOnly` — if true, returns only the count.
- `skipCount` — if true, skips count calc (faster).
- `sortBy` — field to sort by (endpoint-specific enum).
- `sortOrder` — asc or desc.
- `ids` — filter by list of IDs (max 5000 typically).

## Pagination pattern

Use `cursor` for deep pagination. Each response includes a `pagination.nextCursor`; pass it back as `cursor` until it's empty/null.
