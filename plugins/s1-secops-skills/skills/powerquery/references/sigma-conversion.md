# Converting Sigma rules (and KQL hunts) to PowerQuery

Use this when converting community or vendor detection content (Sigma YAML, KQL or SPL hunts) into
SentinelOne PowerQuery rule bodies. Convert by hand from the rule's intent, then prove every
converted rule with the detection testing playbook (`sdl-solutions/references/detection-testing.md`).

## Before you convert

- **Check platform coverage first.** A platform rule may already cover the behaviour (playbook step 1).
- **Review automated output line by line.** Generic converters map field names and operators
  mechanically. Check each of these, which change what the rule matches:
  - `startswith` and `endswith` must become `starts_with` and `ends_with`, not `contains`, which
    widens the match;
  - a negation must be written `!( ... )`: a bare `not` before a field returns no rows and no error;
  - third-party log sources need their own field names, checked on the tenant (playbook section 14),
    because converter field maps usually cover EDR fields only.

## Value matching

| Sigma | PowerQuery | Why |
| --- | --- | --- |
| Plain value or value list | `f in:anycase ('a', 'b')` | `=` and `in` are case-sensitive; Sigma is not |
| `\|contains` | `f contains 'x'` | Case-insensitive |
| `\|startswith` / `\|endswith` | `f starts_with 'x'` / `f ends_with 'x'` | Not `contains`, which widens the match |
| Value with inner wildcards | `f matches '^...$'` | `matches` is an unanchored search; anchor it |
| `\|re` | `f matches:matchcase '...'` | Sigma regex is case-sensitive unless it sets the `i` flag |
| `\|cidr` | `net_ipsubnet(f, '10.0.0.0/8')` | There is no `net_incidr` |
| `\|exists: true` / `f: null` | `f = *` / `!(f = *)` | `f == null` fails |
| `not`, `1 of ... and not` | `!( ... )` | `not f contains 'x'` returns 0 rows with no error |
| Numeric `\|gt`, `\|lt` | `number(f) > n` | Columns can be string-typed |
| Numeric value list | `f in (4624, 4625)` | Numbers are not quoted |

Double every backslash inside a string literal or regex (`ends_with '\\svchost.exe'`).

## Scheduled rule body

- A single-event rule becomes the filter plus `| group hits = count() by <entity>`: one alert per
  host, address or identity per run, with `entityMappings` on the entity columns.
- `event_count`: `| group event_count = count() by bucket = timebucket('<timespan>'), <keys> | filter event_count >= N`.
- `value_count`: two chained groups for an exact count:
  `| group per_value = count() by bucket = timebucket('<timespan>'), <field>, <keys> | group value_count = count() by bucket, <keys> | filter value_count >= N`.
  `estimate_distinct` is approximate, so a threshold on it can miss or misfire at the boundary.
- Timing for correlations: `runIntervalMinutes = max(5, min(timespan, 60))` and
  `lookbackWindowMinutes = 2 x timespan + 5` (at least the interval), so every bucket is read whole
  by at least one run. Keep lookback divided by interval at or under 96.
- Scheduled bodies accept only simple aggregates inside `group` (`count()`, not `count_distinct`).
  Restrictions apply to the part before the first `| group`: see `references/detection-rules.md`.

## Log source anchors

- **Endpoint** (`process_creation`, `file_event`, `registry_*`, `dns_query`, `network_connection`):
  `dataSource.name='SentinelOne'`. `file_event` reads `File Creation`, `File Modification` and
  `File Rename` (not `File Deletion`). `registry_set` and `registry_event` read
  `Registry Value Create` and `Registry Value Modified`. `dns_query` reads `event.dns.request` with
  `event.category = 'dns'`. Field names: `references/fields-and-schema.md`.
- **Third-party sources:** `tag != 'logVolume' !(dataSource.name in ('alert', 'indicator', 'ActivityFeed'))`,
  so metering rows and SentinelOne's own alert, indicator and activity records (which carry the same
  IOC strings) do not match. Pin to one `dataSource.name` once the source is known.
- **Web proxy and web server:** also require a URL field and exclude
  `class_uid in (3001, 3002, 3003, 3004, 3005, 3006, 6003)`: sign-in, account and API activity
  records carry `http_request.user_agent` too.
- **DNS names:** accept an optional trailing dot on exact and suffix matches (`\\.?$`).

## KQL and SPL hunts

The same rules apply: map each comparison to its exact PowerQuery operator (`==` is
case-sensitive, KQL `=~` and SPL default matching are not, so use `in:anycase`), rewrite `has` /
`contains` / `startswith` with the matching PowerQuery operator, and rebuild `summarize` /
`stats ... by` as `| group ... by`.
