# UQL `| datasource` adapter reference

Lookup tables for the adapter surface. The rules that change what you write are in `SKILL.md` under
**UQL adapter queries**; this file is the detail you check while authoring, not a substitute for
reading that section.

Everything here was executed against a live tenant unless marked otherwise. Behaviour is moving:
pushdown support is actively being extended, so re-test rather than trusting a table that has aged.

## Adapters

`alerts`, `assets`, `vulnerabilities`, `misconfigurations`, `metering`, `sdl-retention`,
`alert_aggregated_snapshots`, plus external ones such as `baseline_hunting`.

Subset selectors are adapter-specific:

| Adapter | Selector |
|---|---|
| `assets` | `from 'workstation, server'`, and `type 'server'` |
| `metering` | `from 'input_bytes'` |
| `alerts` | neither |

## `where (...)` operator support, per adapter

Allowed operators are declared per adapter, so the same clause can be valid on one and rejected on
another. The rejection reads `'<clause>' is not a valid event filter`. When rejected, drop the clause
from `where` and handle it after the pipe.

| Clause | `alerts` | `vulnerabilities` |
|---|---|---|
| `status in ('NEW','IN_PROGRESS')` | works | works |
| `severity = 'CRITICAL'` | works | works |
| `analystVerdict != 'UNDEFINED'` | works | not tested |
| `alertNoteExists = true` | works | `cveExploitedInTheWild == true` works |
| `assigneeUserId = *` | works | not tested |
| `!(assigneeUserId = *)` | works | not tested |
| `createdAt != null` | **rejected** | `detectedAt != null` works |
| `mitreTactics != null` | **rejected** | not tested |

## Pushdown, the documented floor

PowerQuery pushdown relays commands to the adapter up to the first `group`, or the first command
that cannot be pushed. Adapters must minimally support:

- `filter` with `and, not, =, >, <, in`
- `sort`, `limit`, `columns`
- `group` with `count, sum, min, max` and at most 2 group keys
- `lookup` is never pushed down

One tenant's `alerts` adapter exceeded this comfortably: 5 group keys, plus `percent_of_total` and
`max_by`. Treat the list as a floor and test the specific thing you need.

## Aggregations that work

- `count(<predicate>)`, a conditional count: `count(severity == 'CRITICAL')`,
  `count(analystVerdict contains 'TRUE_POSITIVE')`. Only `count_if` and `sum(if(...))` fail.
- `sum(<ternary>)`.
- `percent_of_total(sum(count))`, `max_by(field, weight)`, `min`, `max`, `avg`.
- Exact distinct by chaining groups: `| group n = count() by assetName | group total = count()`.
  Preferred over `estimate_distinct`, which was observed returning 14,196 against a true 14,043.

## Nulls

- Nulls render as `---`, not blank.
- `| filter field = *` correctly excludes them **before** a group.
- After a `count_by`, the `---` is a literal string and survives `= *`. Filter on the correct side
  of the pipe.
- `field == null` returns HTTP 500. `field != null` is valid in PowerQuery but is often rejected
  inside `where (...)`.
- `!(field = *)`, with the parentheses, is the absence idiom. Bare `!field` matches every row.

## ActivityFeed alert activity types

| Type | Meaning |
|---|---|
| 16000 | New alert created |
| 16001 | Alert status changed |
| 16002 | Alert verdict changed |
| 16003 | Alert severity changed |
| 16004 | Alert assignee changed |
| 16005 | Mitigation action executed |
| 16007 | Note added |

## Multi-hop sankey

`union` must be the query's **first** command; mid-pipeline `| union` returns 400. One grouping per
hop, each aliasing its pair to `source` / `target`:

```text
| union
( | datasource alerts | group c = count() by detectionProduct, severity
  | let source = detectionProduct | let target = severity | columns source, target, c ),
( | datasource alerts | group c = count() by severity, status
  | let source = severity | let target = status | columns source, target, c )
| sort -c | limit 60
```

A grouping subquery inside a union is expensive. A 3-stage funnel built this way timed out and had
to be dropped, so keep the hop count low and the group keys narrow.

## Leads, not facts

Recorded because they cost time once, but not isolated to a single cause. Do not repeat them as
established behaviour.

- **Row cap on grouped adapter queries.** `| datasource alerts | group count()` was reported capping
  at 20 rows in 2025 while `count_by status | group sum(count)` returned 1,000. Not reproduced in
  2026. Cross-check a suspiciously round total against a `count_by` version.
- **Facet chips can blank adapter panels.** A facet-backed control on a tab whose panels read a
  `| datasource` adapter may blank them, because the facet is drawn from the event index while the
  panel reads the inventory. An active `OS = *` chip was present when all datasource panels on one
  dashboard showed *No results found*, but a 2-hour time picker on the same dashboard is an equally
  plausible explanation. Clear the chip before concluding the query is wrong.
- **Scope-filtered read after create.** A newly created dashboard may render *No dashboard found,
  unavailable within your scope* even though `sdl_list_files` shows it. Re-check at the scope it was
  created in. Root cause not isolated.
