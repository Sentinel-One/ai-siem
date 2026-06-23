# Built-in SDL Parsers

Before writing a parser by hand, check this catalog. If one of these matches the input, just reference it by name at HEC ingest (`parser: <name>` header) — no authoring required. If you need the same behavior plus a couple of extra tags, write a trivial alias parser:

```js
{
  aliasTo: "json",
  // (aliasTo is mutually exclusive with everything else — to add tags,
  //  instead author a minimal parser that duplicates the built-in and
  //  adds top-level `attributes: { ... }`. See section 18.)
}
```

## Table

| Parser name | Input shape |
|---|---|
| `accessLog` | Extended-Apache / NCSA web access logs |
| `cloudfront` | AWS CloudFront distribution access logs |
| `json` | One JSON object per line, camelCase flattening |
| `dottedJson` | One JSON object per line, dotted-notation flattening |
| `dottedEscapedJson` | Dotted JSON with one backslash-escape layer stripped |
| `elb-access` | AWS Classic ELB access logs |
| `heroku-logplex` | Heroku logplex syslog-framed lines |
| `keyValue` | Freeform `key=value` or `key="value"` pairs |
| `leveldbLog` | LevelDB internal LOG file |
| `mysqlGeneralQueryLog` | MySQL general query log |
| `mysqlSlowQueryLog` | MySQL slow query log (multi-line) |
| `postgresLog` | PostgreSQL / RDS Postgres logs |
| `redshift` | Amazon Redshift connection/activity logs |
| `s3_bucket_access` | AWS S3 server access logs |
| `spot_instance_data` | AWS Spot Instance data feeds |
| `systemLog` | Classic `<ts> <host> <process>[pid]: <text>` syslog |

## Notes per parser

- **`accessLog`** — five ordered halting formats covering combined, common, and invalid-request shapes. Breaks the request line apart with `{parse=uri}`. Tags `dataset="accesslog"`.
- **`cloudfront`** — single format with 23 positional fields and a dedicated tab-tolerant timestamp pattern.
- **`json` / `dottedJson`** — the flattening differs: `json` becomes `fooBar`, `dottedJson` becomes `foo.bar`. Choose based on your team's query preference. Both uncomment `discardAttributes: ["message"]` to save storage.
- **`dottedEscapedJson`** — same as `dottedJson` but strips one layer of `\\` escapes first. Useful when JSON was double-encoded upstream.
- **`elb-access`** — two formats; the first tolerates a leading protocol token seen in some deployments.
- **`heroku-logplex`** — parses syslog envelope plus web/app/router variants. `dataset="herokulog"`.
- **`keyValue`** — optional bracketed timestamp, then a repeating catch-all. `dataset="keyValue"`.
- **`leveldbLog`** — general line split plus specialized fragments for compaction/generation metrics.
- **`mysqlGeneralQueryLog` / `mysqlSlowQueryLog`** — both set `intermittentTimestamps: true`; slow-query adds `lineGroupers` to reassemble multi-line records.
- **`postgresLog`** — two line groupers + many ordered halting formats for statement / statement_log / duration / connection / disconnection / statistics. UTC-targeted; other TZ needs Support involvement.
- **`redshift`** — line grouper + two formats (connectionLog, activityLog).
- **`s3_bucket_access`** — integration-guide style article; realized as a Marketplace app.
- **`spot_instance_data`** — single format; UTC timestamps.
- **`systemLog`** — accepts both classic syslog (`Feb 3 03:47:01`) and ISO-8601 with offset. Two halting formats (with/without PID).

## Decision hints

- Generic JSON from a collector → start with `json` or `dottedJson`. If the raw message is quoted-inside-quoted, go `dottedEscapedJson`.
- Any vendor security appliance that emits syslog-framed lines → **don't** start from scratch; check if the body is JSON or CEF/LEEF or key=value, then pick the right building block (alias + attrs, or a custom parser around `{parse=json}` etc.).
- Web logs → `accessLog` first; only fork if you have a non-standard extra column.
- Unless the user specifically needs fields the built-in omits, aliasing is the cheapest path.

## Example: alias with extra attributes

`aliasTo` can't be combined with `attributes`, so to alias "json" and add tenant tagging, duplicate the minimal body:

```js
{
  attributes: { dataset: "json", vendor: "Acme" },
  formats: [ { format: "$json{parse=json}$", repeat: true, discardAttributes: ["message"] } ]
}
```
