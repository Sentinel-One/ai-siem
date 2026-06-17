# SDL Automatic Lookups

> **Supported from:** February 11, 2025, in all Management versions.
> **Required SKU:** Singularity Platform, Singularity Data Lake License.
> **Permission:** View or Manage on **SDL Configuration Files** to view/edit lookup tables and automatic lookups. Automatic lookups then apply to *all* users' searches and PowerQueries.

Automatic lookups enrich search results and PowerQueries with contextual values from lookup tables, with no `| lookup` command required in the query. You define filters that decide which events get enriched, plus a key-to-column mapping. The injected values are also available as **searchable fields**, so you can filter on them directly.

This is the always-on, tenant-wide counterpart to the per-query `| lookup` command (see `commands-reference.md` section 8). Use automatic lookups when every analyst should see the enrichment without typing anything; use `| lookup` when you want enrichment scoped to a single query.

---

## The `/automaticLookups` configuration file

- Your console has **one** automatic-lookups config file.
- It must be named `automaticLookups`, with no leading folder and no trailing extension (path is exactly `/automaticLookups`).
- It defines one or more `lookupSpecs`. Each spec references a lookup table stored under `/datatables/<name>`.

### Schema

```json
{
  "schemaVersion": "0",
  "lookupSpecs": [
    {
      "name": "<display name>",
      "lookupTable": "<lookup table filename, e.g. sid_username.csv>",
      "match": "<filter that events must match to be enriched>",
      "keys": {
        "<event field>": "<lookup-table column>"
      },
      "values": {
        "<lookup-table column>": "<output event field name>"
      }
    }
  ]
}
```

### Field semantics (the two mappings are mirror images, read them carefully)

| Field | Meaning |
|---|---|
| `name` | Display name for the spec. |
| `lookupTable` | Filename of the lookup table under `/datatables/`. Include the extension if the file has one (e.g. `sid_username.csv`). |
| `match` | Filter expression. Only matching events are enriched (e.g. `dataSource.name='Windows Event Logs'`). |
| `keys` | **key = event field name, value = lookup-table column.** All mapped event values must match the lookup-table key column for enrichment to apply. |
| `values` | **key = lookup-table column, value = output event field name.** If the output field name matches an existing event field, the lookup value **overwrites** it. Use new names to avoid clobbering native fields. |

---

## Hard rules confirmed on-tenant

These were verified live while building the Windows Event Logs SID enrichment (usea1-purple, 2026-06-01):

1. **Output value field names must be globally unique across ALL `lookupSpecs`.** Two specs writing the same output field (even when keyed on different event fields) returns:

   ```
   HTTP 400: Syntax error at position -1: Output value fields are not unique
   ```

   Consequence: you cannot register both `subjectUserSid` and `description.securityId` as separate specs that both write `sid_username`. Pick one key field per output, or give each spec its own distinct output field names.

2. **Append, never blind-overwrite.** The file is shared tenant-wide and usually already has specs. Read it first (`sdl_get_file '/automaticLookups'`), add your spec to the existing `lookupSpecs` array, then write back with the returned version as `expectedVersion` for optimistic locking.

3. **`schemaVersion` is a string on a live tenant.** The published doc shows `"schemaVersion": 0` (numeric); the live config file held `"schemaVersion": "0"` (string) and accepted the string on write. Match whatever the existing file uses.

4. **Output fields overwrite on name collision.** If a `values` output name equals an existing event field, the lookup value replaces the native value. Namespace your outputs (e.g. `sid_username`, `sid_domain`) when you want enrichment *alongside* the native fields rather than on top of them.

### Size limits (combined across all lookup tables referenced by automatic lookups)

- Combined size must not exceed **5 MB**.
- Combined total must not exceed **100 rows**.
- Combined total of columns referenced by `values` must not exceed **50 columns**.

### Automatic lookups do NOT apply to

- Queries in dashboards.
- Trigger expressions in alerts.
- PowerQueries in log parsers.

(For those three contexts, use an explicit `| lookup` instead.)

### Cross-lookup referencing

When multiple specs can apply to the same event, values produced by one `lookupSpecs` entry **cannot** be used as `keys` by a later entry.

---

## Worked example: Windows Event Logs SID to username

Goal: resolve a Windows Security Identifier (SID) to the account name across all Windows Event Logs events, so analysts can read or search by resolved identity.

**Source field locations (on `dataSource.name='Windows Event Logs'`, vendor SentinelOne):**

| Field | Example | Notes |
|---|---|---|
| `winEventLog.data.event.eventData.subjectUserSid` | `S-1-5-18` | Structured subject SID. Authoritative, present where the event schema carries it. |
| `winEventLog.data.event.eventData.subjectUserName` | `THIB-DC01$` | Structured subject account name. |
| `winEventLog.data.event.eventData.subjectDomainName` | `LETIBE` | Structured subject domain. |
| `winEventLog.description.securityId` | `S-1-5-18` | Parsed from the human-readable description. Broader coverage but only the first ("Subject") Security ID. |
| `winEventLog.description.userid` | `THIB-DC01$` | Parsed account name. |
| `winEventLog.description.accountDomain` | `LETIBE` | Parsed domain. |

Note: the OCSF-mapped sibling source `dataSource.name='Windows Event Log'` (singular) does **not** carry the raw `S-...` SID; its `account.id` is a numeric value. Use the plural `Windows Event Logs` source for SID work.

**Lookup table** at `/datatables/sid_username.csv` (one row per SID; well-known SIDs resolved to canonical names because they are reused on every host and are not 1:1 with a machine account):

```csv
sid,username,domain,account_type
S-1-0-0,NULL SID,,well-known
S-1-5-18,SYSTEM,NT AUTHORITY,well-known
S-1-5-19,LOCAL SERVICE,NT AUTHORITY,well-known
S-1-5-20,NETWORK SERVICE,NT AUTHORITY,well-known
S-1-5-21-2462337904-732002373-3379971585-1108,victim,LETIBE,user
S-1-5-21-3186755526-1278685290-640695292-1109,jeanluc,STARFLEET,user
...
```

**The spec added to `/automaticLookups`:**

```json
{
  "name": "WEL SID to Username",
  "lookupTable": "sid_username.csv",
  "match": "dataSource.name='Windows Event Logs'",
  "keys": {
    "winEventLog.data.event.eventData.subjectUserSid": "sid"
  },
  "values": {
    "username": "sid_username",
    "domain": "sid_domain",
    "account_type": "sid_account_type"
  }
}
```

After deploy, any matching event gains the searchable fields `sid_username`, `sid_domain`, `sid_account_type`. Verification confirmed `S-1-5-18` rows whose native name is a machine account (`THIB-DC01$`) correctly resolve to canonical `SYSTEM` / `NT AUTHORITY`, while domain SIDs resolve to real users (`victim`, `jeanluc`).

---

## Using the lookup table in PowerQuery (three verified patterns)

**1. Automatic lookup, no command.** The injected fields appear for free. Keep a presence check on the keyed field or most rows are null:

```
dataSource.name='Windows Event Logs' winEventLog.data.event.eventData.subjectUserSid=*
| columns sid=winEventLog.data.event.eventData.subjectUserSid,
          native_user=winEventLog.data.event.eventData.subjectUserName,
          sid_username, sid_domain, sid_account_type
| limit 50
```

**2. Explicit `lookup` against the CSV.** Table name keeps the `.csv`; the `by` direction is `lookupTableColumn = eventField`:

```
dataSource.name='Windows Event Logs' winEventLog.data.event.eventData.subjectUserSid=*
| lookup username, domain, account_type from sid_username.csv by sid = winEventLog.data.event.eventData.subjectUserSid
| columns sid=winEventLog.data.event.eventData.subjectUserSid, username, domain, account_type
| limit 50
```

**3. `lookup` after `group` (best practice, resolves once per SID):**

```
dataSource.name='Windows Event Logs' winEventLog.data.event.eventData.subjectUserSid=*
| group cnt=count() by sid=winEventLog.data.event.eventData.subjectUserSid
| lookup username, domain, account_type from sid_username.csv by sid = sid
| columns sid, username, domain, account_type, cnt
| sort -cnt
```

### `lookup` / `dataset` gotchas confirmed on-tenant

- **`from <table>` uses the literal filename.** If the file is `sid_username.csv`, write `from sid_username.csv` (keep the extension). A bare name without the extension can miss the file.
- **`by` direction is `lookupColumn = eventField`.** Left of the `=` is the lookup-table key column, right is the event field or expression.
- **`dataset 'config://datatables/<name>'` returned 0 rows** for a freshly written CSV on the tested tenant, both with and without the `.csv` suffix. Prefer `| lookup` to read or enrich a table. If you must use `dataset` to dump a table, confirm it returns rows before relying on it.
- **Defer `lookup` until after `group`** so the join runs once per group row instead of once per raw event. Do not use a dynamic `lookup` inside an alert body.

---

## Deploying via the SDL API

```
1. sdl_get_file '/automaticLookups'                  -> capture current `version`
2. sdl_put_file '/datatables/<name>.csv'             -> new lookup table (omit expectedVersion when creating)
3. sdl_put_file '/automaticLookups'                  -> pass expectedVersion = version from step 1
4. Run a PQ projecting the new output fields         -> confirm enrichment is live
```

If step 3 fails with `Output value fields are not unique`, two specs are writing the same output field name. Rename the outputs or consolidate to a single spec.
