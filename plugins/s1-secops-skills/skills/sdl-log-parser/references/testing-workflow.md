# Validation Workflow — Using `sdl-api` to Test a Parser

There is **no dedicated `testParser` REST endpoint** on the SDL tenant. The in-console `Test Parser` button at `/logImportTester` runs the parser client-side in JavaScript. To validate end-to-end you must deploy the parser, ingest a sample through it, and query the result back. This doc is the recipe.

## Prerequisites

- `sdl-api` skill is installed.
- `credentials.json` is dropped directly into your Cowork project folder and contains at minimum `SDL_CONFIG_WRITE_KEY` and `SDL_LOG_READ_KEY` plus a HEC ingest token, or `S1_CONSOLE_API_TOKEN` (the same management-console JWT; legacy `SDL_CONSOLE_API_TOKEN` is also accepted). The plugin's SessionStart hook auto-discovers it at session start.

- You have a draft parser JSON and a sample log file.

## Full loop

```python
import sys, os, time, uuid, json, pathlib
_sdl_scripts = os.environ.get("SDL_API_SCRIPTS") or os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sdl-api", "scripts")
)
sys.path.insert(0, _sdl_scripts)
from sdl_client import SDLClient

c = SDLClient()

PARSER_NAME = "claude_test_fortigate_cef"    # claude_test_ prefix so cleanup is a one-liner
parser_body = pathlib.Path("draft_parser.json").read_text()
sample      = pathlib.Path("sample.log").read_text()

# --- 1. Deploy ------------------------------------------------------------
#    Use expected_version=0 on first deploy to refuse overwriting a parser
#    that already exists; drop expected_version on iterative edits.
try:
    existing = c.get_file(f"/logParsers/{PARSER_NAME}")
    version  = existing["version"]
except Exception:
    version = None

put_kwargs = {"content": parser_body}
if version is not None:
    put_kwargs["expected_version"] = version
c.put_file(f"/logParsers/{PARSER_NAME}", **put_kwargs)

# --- 2. Ingest a sample --------------------------------------------------
#    A unique host tag per run lets you isolate this test's events from
#    every other thing flowing through the tenant.
host_tag = f"parser-test-{uuid.uuid4().hex[:8]}"
nonce    = str(uuid.uuid4())
# HEC ingest applies the named parser before the data lands (replaces the removed uploadLogs).
hec_ingest(
    content=sample,
    parser=PARSER_NAME,
    server_host=host_tag,
    logfile="parser_validation.log",
)

# --- 3. Query back -------------------------------------------------------
#    Sleep long enough that the event is durable and searchable.
time.sleep(8)

EXPECTED = ["timestamp", "src", "dst", "spt", "dpt", "proto", "act"]
pq = f"host='{host_tag}' | columns " + ", ".join(["message"] + EXPECTED)
res = c.power_query(query=pq, start_time="10m")
print(json.dumps(res, indent=2))
```

## What success looks like

- `put_file` → `{"status": "success", ...}`.
- HEC ingest → `{"status": "success", ...}` (a `bytesCharged` number appearing is normal).
- `power_query` returns at least one row per line in the sample, and every expected field is present (not null) for at least the lines where it should be.

A duplicate-`Nonce` response (`status: "success", message: "ignoring request, due to duplicate nonce..."`) means the ingest was deduped — advance to a fresh nonce on iteration.

## Common failure modes

| Symptom | Likely cause |
|---|---|
| `put_file` → `error/client/badParam` | JSON syntax error. Run the body through a JSON5-tolerant validator; watch for unmatched braces or trailing commas inside format strings. |
| HEC ingest → `error/client/badParam` with "unknown parser" | Wrong `parser:` header name, or putFile hadn't replicated yet (retry after a few seconds). |
| `power_query` returns rows but expected fields are null | Line format didn't match. Check: regex escaping (`\\d` not `\d`), delimiter mismatches, `halt: true` on an earlier format eating the line, `message`-as-field-name mistake. |
| `power_query` returns zero rows | `host_tag` isn't set (upload header `server-host` missing) or too short a `start_time` window. Widen to 30m. **Also check event time:** if the parser sets event time from a field in the log (a `timestamp` rewrite off `createdDateTime`/`activityDateTime`/etc.), events are stamped at the log's own time, not ingest time — so a log a few hours old falls outside a `10m`/`1h` window seconds after you ingest it. Widen `start_time` to `24h`/`7d` (or filter by a `claude_test=<nonce>` field instead of time). |
| Field X populated sometimes, null others | The format works for some variants and not others. Add a fragment format for the other shape, or widen the regex. |
| Re-ingested event still shows the OLD shape on a LIVE source | Parser propagation is ~3-5 min; a continuously-ingesting source keeps producing events parsed by the PREVIOUS version during that window, and SDL does not re-parse historical events. A "still broken" event is usually pre-propagation, not a parser bug. Confirm with the version canary below before concluding anything. |
| `| columns unmapped.x[0].y` → "Unable to parse the entire query" | You can't type a `[N]` array-index field name in a raw PowerQuery `columns`/`filter` clause (backticks and quotes don't help). The field exists; read it via `powerquery_schema_discover` or the Event Search field picker instead. |

## Version canary: confirm WHICH parser version parsed an event

Parser propagation is ~3-5 min on the tenant, and on a live source events keep flowing through the old version during that window. Make "which version produced this event" observable:

1. Bump `metadata.version` on every deploy (semver).
2. After deploying, poll until the new version appears in the live stream:

   ```python
   c.power_query(query="dataSource.name='Microsoft Entra ID' | group c=count() by metadata.version",
                 start_time="30m")
   ```

3. When validating a specific re-ingested sample, check `metadata.version` on that event — if it still shows the prior version, you're looking at a pre-propagation event; wait and re-ingest, don't "fix" a non-bug.

## Validating array (`[N]`) and bracketed fields

`gron`/`dottedJson` expand arrays into `[N]`-indexed attributes (e.g. `unmapped.targetResources[0].modifiedProperties[0].newValue`). A raw `power_query` `columns`/`filter` clause **cannot type the `[`**, so use `powerquery_schema_discover` (V1 query endpoint) to see the full event JSON including every `[N]` key and confirm where values landed (and that envelope noise was dropped, that `rename_tree` moved a subtree, etc.):

```python
# returns confirmedFields (all attribute names) + allSampleAttributes (full per-event JSON)
discover(dataSourceName="Microsoft Entra ID", maxEvents=30, startTime="24h")
```

Caveat: for a source that also emits SDL metering, the sample mixes real events with `logVolume`/`logBytes` rows — read past those. This is the most reliable way to verify array-heavy parsers, since the values are unreachable via a normal `columns` projection.

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

```python
# Throwaway test: delete
c.put_file(f"/logParsers/{PARSER_NAME}", delete=True)

# Keep and rename
content = c.get_file(f"/logParsers/{PARSER_NAME}")["content"]
c.put_file("/logParsers/FortiGate_CEF", content=content)
c.put_file(f"/logParsers/{PARSER_NAME}", delete=True)
```

Ask the user before promoting a `claude_test_` parser to a canonical name — it's their tenant.

## Synthesizing samples when the catalog parser ships without a `samples/` dir

The vast majority of catalog parsers in `Sentinel-One/ai-siem` (none of marketplace, very few of community) ship without a `samples/` directory. When you copy a catalog parser as a starting point and want to validate, you have to synthesize a sample yourself. Approach:

1. **Read the parser's `format` strings.** Reverse-engineer the shape: look for literal anchors (`THREAT,`, `[ALERT]`, `<14>`), positional commas/pipes, and field names that hint at vendor docs.
2. **Grep the vendor's public docs** for sample lines that match. Most vendors publish at least one example log line per event subtype.
3. **Generate one sample per format.** If the parser has 5 formats with different `id`s, your sample file should have 5 lines so each format gets exercised.
4. **Run the validation loop** above. If a format never matches, your synthesized sample for that format is wrong; iterate.

Synthesizing samples is also the right move when the user is preparing a parser for a source they don't yet have flowing in production — validate end-to-end first, then turn it on at the source.

## Pre-flight check: 4 mandatory attributes and OCSF field names

Before deploying, run a two-step pre-flight on every parser you're about to ship:

```python
import json5  # tolerant of // comments and unquoted keys
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
