## s1-secops-skills plugin 1.3.11, image 1.4.10

Docker bundle image **1.4.10**, published to **`docker.io/sentinelone/secops-mcps`** (linux/amd64
and linux/arm64). It bundles `s1-secops-mcp` 1.4.0, the VirusTotal fork at `0305f3d` and the
purple-mcp fork at `1390b8c`.

### Upgrade

Change the tag in all three MCP entries in `claude_desktop_config.json` from `1.4.9` to `1.4.10`:

```bash
docker pull sentinelone/secops-mcps:1.4.10
docker run --rm sentinelone/secops-mcps:1.4.10 versions
```

Install or update the plugin to 1.3.11.

Image tag `1.4.0` is an older image from an earlier release. MCP 1.4.0 ships inside image 1.4.10;
do not pull `:1.4.0` expecting it.

### What is new

Everything below was measured on a live S-26.3.4 tenant on 2026-10-05.

- **Custom rules with MITRE mapping** (new sdl-solutions solution). STAR rules cannot carry MITRE
  ATT&CK and their alerts reach UAM with none. The solution renders a rule spec into a Hyperautomation
  watchdog that posts the alert with `attacks[]` on `finding_info.related_events[]`, so
  `mitreTactics` / `mitreTechniques` are populated. Tested end to end.
- **Query slicing** (new sdl-solutions solution). Long-window PowerQueries run as parallel time
  slices through the LRQ API and merge client-side: a 30-day aggregate in about 5 s instead of
  21 to 40 s, identical totals. Zero-dependency runner `sdl-solutions/scripts/lrq_sliced.py`.
- **Measured LRQ limits.** One token sustains about 30 calls/s; only launches are throttled, from
  about 35 calls/s. The "3 requests/s per user" guidance and the two-token round-robin are retired.
- **`powerquery_run` `edrStrict`** (MCP 1.4.0) and `pq.run_pq(edr_strict=True)`: a mistyped EDR
  field fails with HTTP 400 instead of returning 0 rows.
- **Long windows are a cost, not a wall.** The documented "15 to 30 days does not complete" row was
  inferred, never measured. A broad count over 15, 30 and 90 days completed in 3 to 12 s as 15
  slices and 5 to 18 s as one query; the powerquery, sdl-dashboard and query-slicing references now
  say so.
- **`sdl_client.power_query(recurring=True)`** for repeated queries.
- **Corrections:** correlation `entitiesAndFields` are entity groups (OR within, AND across); the
  previously documented positional shape never fired. The generic HA watchdog template referenced
  action names that no longer existed. Activities live in `dataSource.name='ActivityFeed'`; 4114
  links alerts to threats. Weekly alert snapshots and INFORMATIONAL alerts are hidden unless
  filtered for explicitly.

### Security

- Debian security updates are applied in the image (`libpcre2-8-0`, CVE-2026-103111, HIGH).
- VirusTotal fork: `fast-uri` 3.1.8 (CVE-2026-86472), `ip-address` 10.7.1 (CVE-2026-101911,
  CVE-2026-101912).
- purple-mcp fork: lock refreshed past the authlib, pyjwt, fastmcp, anyio, aiohttp, cryptography,
  urllib3, starlette and python-multipart advisories.
- Trivy: no fixable HIGH or CRITICAL findings. Smoke test passes on both architectures.

### Rollback

Pin `:1.4.9` (immutable) and the previous plugin.
