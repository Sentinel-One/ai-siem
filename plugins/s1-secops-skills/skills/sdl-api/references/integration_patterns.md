# Ingestion patterns (moved)

Direct SDL ingestion (`uploadLogs`, `addEvents`) has been removed from this skill. Ingest raw logs/events via the **event collector** on the ingest host (`/services/collector/raw` and `/event`, with a named `parser`), authenticated with an SDL Log Write Key in `S1_HEC_TOKEN`. UAM alert creation lives in `mgmt-console-api` (`uam_*`) and keeps using the console API token. This skill covers queries and configuration files only.

## `addEvents` behaviour (for flows that still call it)

Hyperautomation flows still post to `POST {console}/sdl/api/addEvents` with `Authorization: Bearer <console token>`. Measured live 2026-10-09:

| Input | Result |
|---|---|
| `S1-Scope: <accountId>:<siteId>` | events carry `site.id` |
| `S1-Scope: <accountId>` | no `site.id` (account-only data) |
| `ts` back-dated 3 h | accepted and stored |
| no `ts` | not stored; the 200 response carries a `warnings` entry ("timestamp ... far in the past, or beyond this account's retention period") |
| nested object in `attrs` | stored as one JSON string, not as dotted fields; send flat dotted keys |

Account and site sit at session level on `addEvents` data, so verify placement with PowerQuery `| group n=count() by account.id, site.id`, not V1 attributes or LRQ LOG `values` (see `auth_and_limits.md`).
