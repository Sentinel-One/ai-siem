# parsers/

Log parsing configurations for the Singularity Platform, mapped to OCSF.

```
parsers/
├── community/     # community-contributed parsers
└── sentinelone/   # official marketplace parsers (marketplace-<source>-latest)
```

Each parser is its own directory containing the parser definition (`*.conf`)
and a `metadata.yaml`. Start new parsers from
[`sentinelone/PARSER_TEMPLATE.conf`](sentinelone/PARSER_TEMPLATE.conf) and add
sanitized sample logs under `tests/fixtures/`.

**Naming:** `<vendor>_<product>-latest/` for the current version, or
`<vendor>_<product>-vX.Y/` when you need to keep multiple versions side by side.

**Required `metadata.yaml` fields:** `datasource_vendor`, `dataSource`,
`format` (gron | json | xml | raw | syslog), `ingestion_method`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full process.
