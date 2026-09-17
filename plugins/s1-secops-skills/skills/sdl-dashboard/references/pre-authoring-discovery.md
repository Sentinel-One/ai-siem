# Pre-authoring discovery

Moved out of `SKILL.md` to keep it under the 500-line authoring limit. The content is unchanged.

## Pre-authoring discovery

Different tenants connect different data sources, and even the same tenant drifts between sessions as parsers are updated. Authoring a panel from a remembered schema is the single most common cause of empty-or-misleading dashboards.

### 1. Enumerate connected data sources every session

```text
| group UniqueDataSourceNames = array_agg_distinct(dataSource.name)
| limit 1000
```

If the source the dashboard is meant to cover does not appear, the dashboard cannot work. Stop and surface this to the user. Do not silently switch to a different source.

### 2. PowerQuery cannot discover a source's schema by itself

`| limit N` against a parser-emitted source returns only `timestamp + message`. PowerQuery has no `| columns *` or wildcard projection. Use the V1 query endpoint (`/api/query`, returns full event JSON) via the SDL client. Force-clear the scoped keys so auth falls through to the console JWT (which has `query` permission):

```python
from sdl_client import SDLClient
c = SDLClient()

res = c.query(filter=f"dataSource.name=='{source}'", max_count=50, start_time="7d")
attrs = sorted({k for m in res["matches"] for k in (m.get("attributes") or {}).keys()})
```

Persist `attrs` to a per-session JSON and reference it during panel authoring. Do this for every source the dashboard will query.

**SDL operations via s1-secops-mcp tools.**

All SDL operations should use the s1-secops-mcp MCP tools, which run locally and bypass the sandbox proxy:

| Operation | s1-secops-mcp tool |
|---|---|
| PowerQuery (enumeration, hunts, panel queries) | `mcp__s1-secops-mcp__powerquery_run` |
| V1 `query` (full event JSON for schema discovery) | `mcp__s1-secops-mcp__powerquery_schema_discover` |
| `put_file` / `get_file` / `list_files` (dashboard deploy) | `mcp__s1-secops-mcp__sdl_put_file`, `mcp__s1-secops-mcp__sdl_get_file`, `mcp__s1-secops-mcp__sdl_list_files` |

These tools run on your local machine and make direct HTTPS calls to the console host
without sandbox proxy interference. No fallback or workaround needed.

### 3. A field visible in `raw_data` may NOT be queryable

Parsers vary in what they extract to top-level OCSF / `unmapped.*` columns. A field plainly visible inside the `raw_data` JSON envelope may not exist as a queryable structured column. Always probe a single sample event with the V1 query to confirm a field is queryable before authoring a panel around it. Both the schema dump and a raw event are ground truth, neither alone is sufficient.

If a field is only present in `raw_data`, it can still be filtered via a full-text predicate but **cannot be grouped or aggregated** efficiently. See **Full-text predicate cost** below.

### 4. Identify the discriminator before counting

A single `event.type` value frequently bundles multiple distinct event kinds (delivery-time vs click-time, scheduled vs on-demand, inbound vs outbound, policy-event vs detection-event). The discriminator field, often named `creationMethod`, `messageType`, `triggerType`, `disposition`, etc., may or may not be promoted to the top level. Run an exploration query before authoring count panels:

```text
dataSource.name='<source>' event.type='<type>'
| group hits=count() by <candidate-discriminator>
| sort -hits
| limit 50
```

If the same `event.type` row repeats with different discriminator values, that secondary field is part of the partition key. Panels must filter on both, or split into separate sections per population. Counting "events of type X" without splitting by discriminator gives a number that conflates two semantically different things, which is the highest-cost class of dashboard bug because it looks correct.

### 4b. Null-check every grouping column before including it in a table panel

Before including any field as a grouping column in a table panel, confirm it is non-null for that specific `event.type`. A column that is null for all rows produces an empty column in the rendered table with no error. The check is one query:

```text
dataSource.name='<source>' event.type='<type>' <field>=*
| group count=count()
| limit 1
```

If this returns 0, that field is null for that event type. Remove it from the panel or replace with the correct field. **This check is mandatory for every column in every table panel, not just fields you suspect might be missing.**

Common trap: `src_endpoint.svc_name` (service name), `src_endpoint.ip`, and `app_name` may be populated for `traffic` events but null for `vpn` or `app-ctrl` events from the same source. Schema discovery on `traffic` events does not transfer to other event types.

### 5. `event.type` is not always the right partition key

Some sources emit multiple log subtypes under the same `event.type` (header logs vs body logs, policy events vs detection events). Run the same exploration query above with `event.type` PLUS a secondary discriminator before assuming `event.type` partitions the source cleanly.

---

## Field semantics: verify before grouping

Two patterns cause panels to look broken silently:

**Subject vs target in Windows logon events.** For event 4624 on a domain controller, `subjectUserName` is almost always the machine account or `-`. The account that actually logged on is in `targetUserName`. A panel that groups by `subjectUserName` renders mostly empty rows.

**Same field name, different semantic per event ID.** `targetUserName` in 4624 is the human account; in 4771 (Kerberos pre-auth failure) it includes machine accounts (`host123$`). 4625 and 4740 may use `subjectUserName` depending on the failure path.

Always sample 3-5 events per event ID before authoring a grouping query:

```python
res = c.query(
    filter=f"dataSource.name=='<source>' <event-id-filter> <host-filter>",
    max_count=5, start_time="1h",
)
for m in res.get("matches") or []:
    attrs = m.get("attributes", {})
    for k in sorted(attrs.keys()):
        if any(s in k.lower() for s in ("user","subject","target","domain","logonid")):
            print(f"  {k} = {str(attrs[k])[:80]}")
```

This is the same V1-query schema-discovery pattern from the `sdl-api` skill, apply it per-event-ID, not just per-source.

---
