## s1-secops-skills 1.3.10, image 1.4.9

Docker bundle image **1.4.9**, published to **`docker.io/sentinelone/secops-mcps`**. It
bundles `s1-secops-mcp` 1.3.10. The `purple-mcp` and `virustotal-mcp` pins are unchanged
from 1.4.8. Multi-arch: `linux/amd64`, `linux/arm64`.

## Action required

Change the tag in all three MCP entries in `claude_desktop_config.json` from `1.4.8` to `1.4.9`:

```bash
docker pull sentinelone/secops-mcps:1.4.9
```

`1.4.8` stays published, so you can roll back to it.

## What changed

- **Ingest-metering rows are excluded by default.** Every ingest writes receive-time
  `tag='logVolume'` accounting rows under the source's own `dataSource.name`.
  - `powerquery_run`, `pq.run_pq()` and schema discovery now drop them unless asked
    not to.
  - The shipped sdl-solutions templates now include `tag != 'logVolume'`: 42 dashboard
    and detection queries, plus the ingest-health baseline builder and watchdog, and the
    UEBA baseline and refresh.
  - Measured effect: an ingest-health panel that flagged 14 of 14 sources for events
    missing `dataSource.category` now flags 0. Every one of those flags came from
    metering rows.
- **`powerquery_schema_discover`** no longer returns metering fields (`metric`, `path1`,
  `tag`, `value`) as a source's schema.
- **`sdl_create_dashboard`** catches a tab labelled `name` instead of `tabName` and says
  which key to use. The 60-column grid is documented.
- **`sdl_save_dashboard_layout`** is documented as position-only. It now refuses a
  payload with a different panel count, and warns when panel content changes would be
  dropped.
- **Docs:**
  - `powerquery` gains pitfalls for counting field presence (`count(field != null)`;
    `count(field=*)` returns 400) and for metering rows.
  - The HEC back-dated "shadow copy" note is replaced. Those rows are ingest metering;
    no events were duplicated (`sdl-api/references/hec-backdated-ingest.md`).
