## s1-secops-skills plugin 1.3.13, image 1.5.3

> **Draft for review.** Not yet tagged or published.

Image **1.5.3** on `docker.io/sentinelone/secops-mcps` (linux/amd64, linux/arm64) with
`s1-secops-mcp` 1.5.3. The VirusTotal and purple-mcp forks are unchanged. Closes
[issue #111](https://github.com/Sentinel-One/ai-siem/issues/111).

### Upgrade

Pull the image, point your MCP entries or launcher at `:1.5.3`, restart, and install plugin
1.3.13. No other configuration changes.

```bash
docker pull sentinelone/secops-mcps:1.5.3
docker run --rm sentinelone/secops-mcps:1.5.3 versions
```

### One token, every account and site

A single global or multi-account token now works across every account and site it can reach.
Name the account or site in your prompt and each call is limited to it; leave it out and the
call covers everything the token can see.

| Tool | Scope with |
|---|---|
| `powerquery_run`, `powerquery_enumerate_sources`, `powerquery_schema_discover` | `scope: "<accountId>"` or `"<accountId>:<siteId>"` |
| `uam_list_alerts` | `scopeIds`, with `scopeType: "SITE"` for a site |
| `ha_list_workflows`, `ha_export_workflow`, `ha_delete_workflow` | `accountIds` or `siteIds` |
| `uam_available_actions` and the UAM write tools | Nothing: they use the alert's own account |

PowerQuery results report the scope they ran with in `scopeApplied`. Joins, unions, inventory
datasources and lookup tables are scoped too. The one exception is `| datasource alerts`, which
has no site column; use `uam_list_alerts` for site-level alerts. If the token can't reach the
account you name, you get a clear error, never another account's data.

### Also in this release

- `ha_list_workflows` finds a workflow by name with `nameContains`.
- `ha_delete_workflow` deletes active workflows in one step.
- `uam_list_alerts` shows each alert's account and site.
- `powerquery_schema_discover` works on a global token without a scope.
- `sdl_create_dashboard` accepts the dashboard as an object or a JSON string.

### Plugin 1.3.13

The skills now document SentinelOne API behaviour verified on live consoles, so Claude gets these
right first time:

- **Detections:** detection library settings and paging, label filters, inheritance, rule
  activation, and why rules only fire on data that arrives after they are active.
- **Alerts:** name filters, sorting, AI Investigation availability, and linking ingested events to
  real endpoints.
- **Hyperautomation:** finding, running, deactivating and deleting workflows, response triggers,
  connections, and features that vary by console.
- **Data ingest:** event collector credentials, checking where data landed, `addEvents`, and
  per-scope lookup tables.
- **PowerQuery rules:** scheduled-rule availability, deduplication settings, inventory site
  columns, and correlation behaviour.

### Testing

All unit, skill and eval suites pass. `tools/live_learnings_check.mjs` is a new host-side script
that re-verifies the documented API behaviour against a console of your choice.

### Security

No dependency or base image changes. <!-- TODO after build: Docker Scout result for both architectures. -->

### Rollback

Pin `:1.5.2`.
