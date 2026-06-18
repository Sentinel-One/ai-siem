# Functions reference

All built-in functions you can use in PowerQuery expressions. Read when you need a function and can't remember the name or signature.

## Table of contents

1. Numeric
2. String (and method chaining)
3. `format()` — printf-style strings
4. JSON
5. Network and URL
6. Aggregate (across groups) vs. running / overall (across rows)
7. Array (functional operations, `func(x) -> expr` lambdas)
8. Geolocation
9. Timestamp / time

---

## 1. Numeric

`abs(x)`, `ceiling(x)`, `floor(x)`, `min(x, y)`, `max(x, y)`, `sqrt(x)`, `exp(x)`, `ln(x)`, `log(x)`, `log(x, y)`, `pow(x, y)`.

These are element-wise — don't confuse with the `min()` / `max()` aggregation functions used inside `group`. `min(x, y)` with two args is the function; `min(x)` inside `group` is the aggregate.

---

## 2. String

| Function | What it does |
|---|---|
| `len(x)` | Characters in `x` |
| `lower(x)`, `upper(x)` | Case conversion |
| `ltrim(x)`, `ltrim(x, y)` | Remove leading whitespace, or any chars in `y` |
| `rtrim(x)`, `rtrim(x, y)` | Same, trailing |
| `trim(x)`, `trim(x, y)` | Both sides |
| `substr(x, y)` | Drop first `y` chars |
| `substr(x, y, z)` | `z` chars starting at `y` |
| `isempty(x)` | True if null or `""` |
| `isblank(x)` | True if null, `""`, or only whitespace |
| `bool(x)` | Coerce to boolean. `0`, `null`, `""` → false |
| `string(x)` | Stringify (useful for large numbers) |
| `number(x)` | Parse to number. Null / missing → 0; unparseable → NaN |
| `pad_version(x)` | Zero-pad each dotted segment to 5 digits — enables lexicographic version sort |
| `replace(x, y, z)` | Regex replace in `x`. `y` is a regex (case-insensitive). Use `$1` / `$2` for capture references, `\$` for a literal `$` |

> **String-function gotchas (tenant-validated 2026-06-16):** the substring function is `substr`, not `substring` (`substring(...)` returns `400 Unknown function 'substring'`). Because `replace`'s pattern is a regex, a lone bracket errors: `replace(x, '[', '')` returns `error parsing regexp: missing closing ]`. To strip literal `[` / `]` without escaping, use the character class `[][]` (a `]` placed first in a class is literal), e.g. `replace(x, '[][]', '')`.

### Method chaining

Strings support `.method()` chaining: `len(x)` → `x.len()`, `substr(x, y, z)` → `x.substr(y, z)`. Drop the first (string) argument.

```
| limit 1
| columns s = "three blind mice"
| columns mice_len = s.substr(12).len()
```

---

## 3. `format()`

Printf-style; up to 50 values.

```
| let line = format("%,d events for %s (%.2f%%)", ct, endpoint, ratio * 100)
```

Specifiers:

| Spec | Type | Notes |
|---|---|---|
| `%d` | int (rounded from float) | No precision |
| `%f` | float | Default 6-digit precision |
| `%s` | string | Only supports `-` flag |
| `%%` | literal `%` | |

Flags (between `%` and the letter): `-` left-justify, `+` force sign, ` ` (space) space before positive, `0` zero-pad, `,` thousands separator (digits only), `(` parenthesize negatives.

`format()` is slow — use it after a `group` or `limit` so you're only formatting tens of rows, not millions.

---

## 4. JSON

`json_object_value(obj, "field")` — parse a JSON string, return the named field's value. Returns a primitive or an array of strings.

```
| columns obj = '{"users":[{"name":"A"},{"name":"B"}]}'
| let users = json_object_value(obj, "users")
| let first_user = array_get(users, 0)
| let first_name = json_object_value(first_user, "name")
```

---

## 5. Network and URL

| Function | Meaning |
|---|---|
| `net_ip(x)` | Valid IPv4 or IPv6 |
| `net_ipv4(x)`, `net_ipv6(x)` | Specific family |
| `net_ipsubnet(x, cidr)` | `x` is within CIDR (e.g., `net_ipsubnet("1.2.3.4", "1.0.0.0/8")`) |
| `net_private(x)` | IPv4 or IPv6 private |
| `net_rfc1918(x)` | IPv4 private (10/8, 172.16/12, 192.168/16, 127/8) |
| `net_rfc4193(x)` | IPv6 unique-local |

URL parsing (all expect a string):

`net_url_scheme`, `net_url_netloc`, `net_url_subdomain`, `net_url_domain`, `net_url_tld`, `net_url_port`, `net_url_path`, `net_url_query`, `net_url_fragment`, `net_url_userinfo`, `net_url_parts` (returns an array in order: protocol, netloc, subdomain, registered domain, TLD, port, path, query, fragment, userinfo).

---

## 6. Aggregation vs. running / overall

Two distinct concepts:

### Aggregate (inside `group`)

See [commands-reference §4](commands-reference.md#4-group) for the full list. These collapse groups of rows into one row.

**Confirmed working** (tested live): `count()`, `sum(x)`, `avg(x)`, `stddev(x)`, `min(x)`, `max(x)`, `any(x)`, `estimate_distinct(x)`, `median(x)`, `p10(x)` / `p50(x)` / `p90(x)` / `p95(x)` / `p99(x)` / `p999(x)`, `pct(N, x)`, `array_agg(x[, N])`, `array_agg_distinct(x[, N])`, `oldest(ts)`, `newest(ts)`, `min_by(x, ord)`, `max_by(x, ord)`.

`avg(x)` is the group mean and `stddev(x)` is the sample standard deviation; percentiles support `p10/p50/p90/p95/p99/p999` and the general `pct(N, x)`. Tenant-validated.

**Avoid** on general tenants (return 500 error on this deployment even though docs list them):
- `percentile(x, N)` — use `p50` / `p95` / `p99` instead.
- `first(x)` / `last(x)` — use `min_by(x, timestamp)` / `max_by(x, timestamp)`. These are more explicit and always work.

### Row-level / overall (no `group` needed)

These operate over the already-computed result set and add a value per row.

| Function | Meaning |
|---|---|
| `running_sum(expr)` | Cumulative sum up through this row |
| `running_count()` | 1, 2, 3, … |
| `overall_sum(expr)`, `overall_count()`, `overall_min`, `overall_max`, `overall_avg` (also `overall_mean` / `overall_average`) | Global over the whole result |
| `percent_of_total(expr)` | `expr` as % of its overall sum |
| `running_percent(expr)` | Cumulative percent |

Useful for Pareto-style "top contributors" reports:

```
| group ct = count() by endpoint.name
| sort -ct
| let share_pct = percent_of_total(ct), running_share = running_percent(ct)
```

---

## 7. Array (beta)

Array functions are only in PowerQueries (not alerts). Arrays cap at 8 MB. Create with `array(…)` (up to 50 values), `array_from_json(…)` (JSON capped at 1 MB), or — much more commonly — via `array_agg()` / `array_agg_distinct()` inside `group`.

### Creation / conversion

`array(x, y, z, …)`, `array_from_json(jsonStr)`, `array_to_json(arr)`, `extract_matches(regex[, max])`, `extract_matches_matchcase(regex[, max])`, `split(pattern[, max])`, `split_matchcase(pattern[, max])`.

`extract_matches` returns all regex matches as an array. If the regex has groups, it returns the first group's content.

### Operations (chainable)

| Function | Meaning |
|---|---|
| `concat(arr)` | Append elements |
| `distinct()` | Unique (numbers and strings are distinct — `5 != "5"`) |
| `expand()` | Explode: one row per element |
| `filter(func)` | Keep elements where lambda returns truthy |
| `intersect(arr)` | Elements present in both |
| `map(func)` | Transform each element |
| `set(i, v)` | Replace at index (negative from end; out-of-bounds is a no-op) |
| `slice(from[, to])` | Subrange; negatives count from end |
| `sort()`, `sort_desc()` | Sort (UTF-8 bytewise — case-sensitive) |
| `zip(arr, func)` | Element-wise function of two arrays |

### Array-to-primitive

`contains(value)`, `get(i)`, `len()`, `match_any(func)`, `match_all(func)`, `max()`, `mean()`, `median()`, `min()`, `reduce(init, func)`, `sum()`, `to_string([delim])`.

### Lambda syntax

`func(args) -> expression`. No nesting.

```
tgt.file.size = *
| group sizes = array_agg(tgt.file.size) by endpoint.name
| let big_files = sizes.filter(func(x) -> x > 1_000_000)
| let avg_big = big_files.mean()
```

---

## 8. Geolocation

| Function | Meaning |
|---|---|
| `geo_ip_city(ip[, locale])` | City name |
| `geo_ip_state(ip[, locale])` | State/province |
| `geo_ip_state_iso(ip)` | ISO 3166-2 code |
| `geo_ip_country(ip[, locale])` | Country name |
| `geo_ip_country_iso(ip)` | ISO 3166-1 code |
| `geo_ip_continent(ip[, locale])` | Continent name |
| `geo_ip_continent_code(ip)` | AF / AS / EU / NA / SA / OC / AN |
| `geo_ip_location(ip)` | "lat,lon" string |
| `geo_is_point("lat,lon")` | Valid point |
| `geo_distance(p1, p2[, "kilometer" | "mile"])` | Distance |
| `geo_point_within_polygon("lat,lon", wkt)` | Polygon membership |

Locales supported: `de en es fr ja pt-BR ru zh-CN`.

---

## 9. Timestamp / time

Timestamps are stored as nanoseconds since epoch. Any numeric field named `timestamp` or ending in `.timestamp` renders as ISO datetime in results.

### Conversion

| Function | What it does |
|---|---|
| `simpledateformat(ns)` | ns → GMT ISO8601 |
| `simpledateformat(ns, pattern)` | With Java `SimpleDateFormat` pattern |
| `simpledateformat(ns, pattern, tz)` | With timezone (e.g., `"GMT+8"`) |
| `simpledateparse(str, pattern)` | String → ns |
| `strftime(ns)` | ns → GMT ISO8601 |
| `strftime(ns, pattern)` | With strftime pattern |
| `strftime(ns, pattern, tz)` | With timezone |
| `strptime(str, pattern)` | String → ns (strftime pattern) |

### Time-range functions (inside a single query)

| Function | Meaning |
|---|---|
| `timebucket([ts,] unit)` | Truncate to bucket start. Units: `s m h d w`, words, `auto`, or integer 1-500 = buckets across query span |
| `querystart([unit])` | Start of query window (ns by default) |
| `queryend([unit])` | End of query window |
| `queryspan([unit])` | Length of query window |

```
// "events per minute" rate
indicator.category = *
| group rate = count() / queryspan('minutes') by endpoint.name
| sort -rate
```

### strftime patterns (abbreviated)

`%Y` full year, `%y` 2-digit year, `%m` month, `%d` day, `%H` 24-hr hour, `%M` minute, `%S` second, `%z` UTC offset, `%a` short weekday, `%B` full month.

### Java SimpleDateFormat patterns

`yyyy` year, `MM` month, `dd` day, `HH` 24-hr, `mm` minute, `ss` second, `SSS` millis, `z` GMT zone name, `Z` RFC 822 zone, `X` ISO 8601 zone, `E` day name, `D` day of year. Literals inside single quotes (`'T'`, `'W'`).
