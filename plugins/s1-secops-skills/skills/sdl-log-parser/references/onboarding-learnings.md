# Onboarding learnings

Reference detail for the onboarding-learnings pointer in `SKILL.md`. Tenant-validated learnings captured while onboarding data sources through the `sdl-solutions` playbook.

## Onboarding learnings (tenant-validated 2026-06-13, <console>)

These came out of onboarding Cisco Meraki via the `sdl-solutions` onboarding playbook.

- **JSON-per-line flatten needs a dotted-prefix capture.** `format: "$unmapped.=json{parse=dottedJson}$"`
  flattens the body into `unmapped.*` queryable fields. A non-prefix capture name like
  `$json{parse=json}$` captures the raw JSON string and emits NO subfields, so every field reads
  null after deploy and only the parser-root `attributes` (e.g. `dataSource.name`) apply. This is
  already shown in `examples/02-json-with-envelope.json`; reach for it first for any JSON source.
- **`mappings` requires `version: 1` and `transformations`.** The error
  `Got unsupported event mapper version -1` on `putFile` means the `mappings` block is missing
  `version`. Ops go inside `transformations: [...]`, each as `{ <op>: {...} }`.
- **Parsers are account-level.** Deploy at account scope even when the data ingests at a site.
  There is no site-scoped `/logParsers/` file; the sourcetype label binds events to the parser.
- **Activation latency is 3 to 5 minutes per deploy** on this tenant, not seconds. Batch parser
  edits and wait out the window before validating, rather than iterating one field at a time.
- **A `parser=<name>` label with no `/logParsers/<name>` file and no `dataSource.name`** means the
  events were tagged with a sourcetype but never transformed (e.g. a marketplace `*-latest` label
  with no editable file). Creating the parser at that exact path normalises the live stream. The
  initial `sdl_get_file` 404 is a "create me", not an error.
- **Network-source enrichment keys on IP.** Build an IP-keyed endpoint lookup
  (`datasource assets from 'surface/endpoint'`, keyed on `agentLastReportedIp`) and join in the
  `computeFields` rewrite `by device_ip = unmapped.src_ip` using the pre-rename `unmapped.*` field,
  since the rewrite runs before `mappings` renames.
