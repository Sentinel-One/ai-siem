# Validation Workflow: Testing a Parser End to End

There is **no dedicated `testParser` REST endpoint** on the SDL tenant. The in-console `Test Parser` button at `/logImportTester` runs the parser client-side in JavaScript. To validate end-to-end you must deploy the parser, ingest a sample through it, and query the result back. This doc is the recipe for the synthetic-ingest path; when the source is already live, validate on the live stream instead (see "Validation (mandatory)" in SKILL.md).

## Prerequisites

- The `s1-secops-mcp` MCP server is connected (`sdl_get_file`, `sdl_put_file`, `sdl_delete_file`, `hec_ingest`, `powerquery_run`, `powerquery_schema_discover`). It runs on the user's machine and reads credentials from environment variables or the OS keychain; `hec_ingest` needs `S1_HEC_INGEST_URL` and the SDL Log Write Key in `S1_HEC_TOKEN`. The `sdl-api` skill's Python client can do the same from the user's host only; it cannot reach the tenant from the Cowork sandbox.
- You have a draft parser JSON and a sample log file.

## Full loop (MCP tool calls)

```text
1. Deploy
   sdl_get_file  {path: "/logParsers/<name>"}
     -> if it exists, note version; bump metadata.version in the draft
   sdl_put_file  {path: "/logParsers/<name>", content: <draft parser>, expectedVersion: <version>}
     -> omit expectedVersion only when the file does not exist yet

2. Ingest a sample
   Embed a unique nonce IN the payload (for example append " claude_test=<12 hex chars>" to
   each line). The `server-host` upload header is unreliable for isolation: SDL sometimes
   overrides it, and a `host` field parsed from the log wins over it.
   hec_ingest    {logContent: <sample with nonce>, parser: "<name>", endpoint: "raw"}
     -> the Log Write Key fixes the destination account or site; no scope argument applies

3. Query back (wait ~8 s first so the events are searchable)
   powerquery_run {query: "* contains '<nonce>' | columns message, timestamp, src, dst, spt, dpt, proto, act",
                   hours: 1}
```

## What success looks like

- `sdl_put_file` returns success with the new version.
- `hec_ingest` returns `{"text": "Success", "code": 0}`.
- `powerquery_run` returns at least one row per line in the sample, and every expected field is present (not null) for at least the lines where it should be.

A duplicate-`Nonce` response (`status: "success", message: "ignoring request, due to duplicate nonce..."`) means the ingest was deduped, advance to a fresh nonce on iteration.

## Common failure modes

| Symptom | Likely cause |
|---|---|
| `sdl_put_file` → `error/client/badParam` | JSON syntax error. Run the body through a JSON5-tolerant validator; watch for unmatched braces or trailing commas inside format strings. |
| HEC ingest → `error/client/badParam` with "unknown parser" | Wrong `parser:` header name, or putFile hadn't replicated yet (retry after a few seconds). |
| `powerquery_run` returns rows but expected fields are null | Line format didn't match. Check: regex escaping (`\\d` not `\d`), delimiter mismatches, `halt: true` on an earlier format eating the line, `message`-as-field-name mistake. |
| `powerquery_run` returns zero rows | The nonce filter does not match, or the window is too short. Widen to a few hours. **Also check event time:** if the parser sets event time from a field in the log (a `timestamp` rewrite off `createdDateTime`/`activityDateTime`/etc.), events are stamped at the log's own time, not ingest time, so a log a few hours old falls outside a `10m`/`1h` window seconds after you ingest it. Widen the window to `hours: 24` or `168` (or filter by a `claude_test=<nonce>` field instead of time). |
| Field X populated sometimes, null others | The format works for some variants and not others. Add a fragment format for the other shape, or widen the regex. |
| Re-ingested event still shows the OLD shape on a LIVE source | Parser propagation is ~3-5 min; a continuously-ingesting source keeps producing events parsed by the PREVIOUS version during that window, and SDL does not re-parse historical events. A "still broken" event is usually pre-propagation, not a parser bug. Confirm with the version canary below before concluding anything. |
| `\| columns unmapped.x[0].y` → "Unable to parse the entire query" | You can't type a `[N]` array-index field name in a raw PowerQuery `columns`/`filter` clause (backticks and quotes don't help). The field exists; read it via `powerquery_schema_discover` or the Event Search field picker instead. |

## Version canary: confirm WHICH parser version parsed an event

Parser propagation is ~3-5 min on the tenant, and on a live source events keep flowing through the old version during that window. Make "which version produced this event" observable:

1. Bump `metadata.version` on every deploy (semver).
2. After deploying, poll until the new version appears in the live stream, with `powerquery_run`:

   ```json
   { "query": "dataSource.name='Microsoft Entra ID' | group c=count() by metadata.version", "hours": 1 }
   ```

3. When validating a specific re-ingested sample, check `metadata.version` on that event, if it still shows the prior version, you're looking at a pre-propagation event; wait and re-ingest, don't "fix" a non-bug.

## Validating array (`[N]`) and bracketed fields

`gron`/`dottedJson` expand arrays into `[N]`-indexed attributes (e.g. `unmapped.targetResources[0].modifiedProperties[0].newValue`). A PowerQuery `columns`/`filter` clause **cannot type the `[`**, so use `powerquery_schema_discover` to see the full event JSON including every `[N]` key and confirm where values landed (and that envelope noise was dropped, that `rename_tree` moved a subtree, etc.):

```json
{ "dataSourceName": "Microsoft Entra ID", "maxEvents": 30, "startTime": "24h" }
```

`powerquery_run` with `queryType: "LOG"` and `query: "dataSource.name='Microsoft Entra ID'"` returns the same full attribute sets for a larger sample (add `outputFile` to keep them on disk). Both exclude SDL `logVolume` metering rows. This is the most reliable way to verify array-heavy parsers, since the values are unreachable via a normal `columns` projection.

## Isolating which format matched

Add a per-format constant attribute so the query can tell you which branch fired:

```js
formats: [
  { id: "tcp", attributes: { _matched: "tcp" }, format: "... proto=TCP ...", halt: true },
  { id: "udp", attributes: { _matched: "udp" }, format: "... proto=UDP ...", halt: true }
]
```

Then query `| columns _matched, ...` to see which format each line hit. Remove the `_matched` tags once the parser stabilizes.

## Cleanup

If you deployed under a throwaway name for a source that is not live yet:

```text
Throwaway test, delete:
  sdl_get_file    {path: "/logParsers/<throwaway>"}            -> note version
  sdl_delete_file {path: "/logParsers/<throwaway>", expectedVersion: <version>}

Keep and rename:
  sdl_get_file    {path: "/logParsers/<throwaway>"}            -> content, version
  sdl_put_file    {path: "/logParsers/<canonical>", content: <content>}
  sdl_delete_file {path: "/logParsers/<throwaway>", expectedVersion: <version>}
```

Ask the user before promoting a throwaway parser to a canonical name; it's their tenant.

## Synthesizing samples when the catalog parser ships without a `samples/` dir

The vast majority of catalog parsers in `Sentinel-One/ai-siem` (none of marketplace, very few of community) ship without a `samples/` directory. When you copy a catalog parser as a starting point and want to validate, you have to synthesize a sample yourself. Approach:

1. **Read the parser's `format` strings.** Reverse-engineer the shape: look for literal anchors (`THREAT,`, `[ALERT]`, `<14>`), positional commas/pipes, and field names that hint at vendor docs.
2. **Grep the vendor's public docs** for sample lines that match. Most vendors publish at least one example log line per event subtype.
3. **Generate one sample per format.** If the parser has 5 formats with different `id`s, your sample file should have 5 lines so each format gets exercised.
4. **Run the validation loop** above. If a format never matches, your synthesized sample for that format is wrong; iterate.

Synthesizing samples is also the right move when the user is preparing a parser for a source they don't yet have flowing in production, validate end-to-end first, then turn it on at the source.

## Pre-flight check: 4 mandatory attributes and OCSF field names

Before deploying, run a two-step pre-flight on every parser you're about to ship. It is local Python with no network calls, so it runs anywhere, including the Cowork sandbox:

```python
import os, pathlib
import json5  # tolerant of // comments and unquoted keys
parser_body = pathlib.Path("draft_parser.json").read_text()
parser = json5.loads(parser_body)

# 1. The 4 mandatory attributes.
#    metadata.version may also be set inside mappings via a `constant` op,
#    so accept either location.
attrs = parser.get("attributes", {})
assert attrs.get("dataSource.category") == "security", \
    "dataSource.category must be hardcoded to 'security'"
assert attrs.get("dataSource.name"),   "dataSource.name is required"
assert attrs.get("dataSource.vendor"), "dataSource.vendor is required"

def _has_mappings_constant(parser, field):
    for entry in parser.get("mappings", {}).get("mappings", []):
        for t in entry.get("transformations", []):
            if "constant" in t and t["constant"].get("field") == field:
                return True
    return False
assert attrs.get("metadata.version") or _has_mappings_constant(parser, "metadata.version"), \
    "metadata.version is required (parser-root attributes or mappings.constant)"

# 2. Every OCSF field name should be discoverable in ocsf-schema-documentation.md.
#    Grep the schema doc for each emitted field name.
import re, pathlib
_skill_root = os.environ.get("SKILL_DIR", os.path.dirname(os.path.abspath(__file__)))
schema_doc = pathlib.Path(_skill_root, "references", "ocsf-schema-documentation.md").read_text()
emitted_fields = set()
def collect(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("to", "field", "output") and isinstance(v, str):
                emitted_fields.add(v)
            collect(v)
    elif isinstance(obj, list):
        for x in obj: collect(x)
collect(parser.get("mappings", {}))
unknown = [f for f in emitted_fields if f and "." in f and f not in schema_doc]
if unknown:
    print(f"WARN: fields not found in OCSF schema doc: {unknown}")
```

Both checks catch >80% of "ingested but unusable downstream" failures before they reach the tenant.
