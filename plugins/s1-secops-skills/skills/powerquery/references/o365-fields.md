# Microsoft 365 (O365) audit fields

Where the data actually lives on an M365 / Exchange / Teams / SharePoint audit source, and how to discover the exact field paths on **the tenant you're querying** rather than assuming them. Static schema tables are a trap on M365 sources because parsers, mappings, and `unmapped.*` populations drift across tenants and across parser versions.

## Rule zero: discover before you filter

**Never hardcode an M365 field path.** Run schema discovery first, every time, on the tenant you're about to query. The right helpers already exist:

- `sentinelone-mgmt-console-api/scripts/inspect_source.py` enumerates fields for a given `dataSource.name`, classifies them into role buckets (principal user, principal host, principal IP, action, etc.), and returns `(prim_key, action_key)`. Use it before writing any filter against a source you haven't queried recently.
- For an ad-hoc check inside a query, `dataSource.name='<m365_source>' | limit 1 | columns *` shows every parsed field on one event. `| group ct=count() by <candidate_field> | sort -ct | limit 20` confirms which fields actually carry data on this tenant.

Treat the names below as conceptual placeholders. Discover the real ones each time.

## The hybrid field shape

M365 audit events arrive as a hybrid: a thin layer of OCSF-normalized scalars on top of a raw JSON `message` blob. Three observable consequences shape every M365 query:

1. The OCSF normalized fields are sparsely populated. The path you'd reach for first (the OCSF principal-user path, the OCSF source-IP path, etc.) is often empty even though the data exists, just under a different name.
2. Parser-emitted fields land in the `unmapped.*` namespace alongside the normalized ones. The actual field name inside `unmapped.*` mirrors the upstream M365 audit JSON key (case-sensitive). Discover it; do not assume it.
3. Several rich fields (recipient list, subject, attachment metadata, DLP rule details, parent folder) are **not** parsed into queryable scalars at all. They live inside the JSON `message` blob and require either a value-anywhere search (`* contains`) or post-processing in Python.

## Discovery recipe (run this first)

```
// 1. Confirm the source string and event volume on this tenant.
| group ct=count() by dataSource.name | sort -ct | limit 50

// 2. Pick one event from the source and dump every field.
dataSource.name='<m365_source>' | limit 1 | columns *

// 3. For a candidate principal-user field, confirm it's populated.
dataSource.name='<m365_source>'
| group ct=count() by <candidate_field>
| sort -ct | limit 20
```

If `<candidate_field>` returns mostly nulls or "Unknown", it's not the right field on this tenant. Try the corresponding `unmapped.*` form. If neither is populated, the field is inside the JSON `message` blob and is not queryable as a scalar; switch strategy (see "Fields inside the JSON blob" below).

## OCSF ↔ `unmapped.*` duality

A common pattern, **not a contract**: many M365 fields exist in both an OCSF-normalized form (often empty) and an `unmapped.*` form (often populated, mirroring the upstream audit JSON key). When in doubt, write the filter against both with `OR`, then narrow once discovery confirms which is real on this tenant:

```
dataSource.name='<m365_source>'
(<ocsf_user_field> contains:anycase 'user@example.com'
 OR <unmapped_user_field> contains:anycase 'user@example.com')
| limit 50
```

After one discovery pass, replace the disjunction with whichever form actually carries the data. The first-pass `OR` exists to avoid silent false-empty results before discovery.

## Fields inside the JSON `message` blob

Some M365 fields have no scalar form at all on most tenants. They are inside the JSON-encoded `message` field and cannot be filtered or grouped without parsing. Conceptually these include the recipient list, subject line, internet message id, attachment metadata, parent folder path, and DLP rule details. **Confirm by inspection** which fields are blob-only on the tenant you're querying. Some parsers do extract a subset.

Two strategies for hunting on blob-only fields:

1. **Value-anywhere search at the initial filter:** `* contains 'value'` indexes across all parsed scalars and is dramatically faster than `message contains`. It will surface the value if the tenant's parser exposes it as a scalar anywhere; if it doesn't, the search still works but degrades to a substring scan.
2. **Pull then post-process:** narrow with predicates that hit indexed fields (event type, sender, time slice), pull the candidate rows, and parse the JSON blob in Python to evaluate the blob-only condition. Use this when the predicate is a negation or a nested-array test that PQ cannot express inline.

## Send-style operations

Outbound mail on M365 spans several operation values across workloads. The set is not fixed across parser versions; discover the actual operation strings on this tenant, then filter on the discovered set:

```
dataSource.name='<m365_source>'
| group ct=count() by <operation_field>
| sort -ct | limit 50
```

Conceptually you'll typically see at minimum: a per-user mailbox send, a delegated-mailbox send (acting as another mailbox), an on-behalf send, and a Teams chat send. The operation strings vary; the right filter is built from the discovery output, not from a static list.

## RecordType is numeric

M365 audit records carry an integer category code. The exact integer-to-category mapping is documented by Microsoft and is stable across tenants; the field name carrying it on the SDL side is the variable part. Discover the field name once, then use the integer for cheap pre-filters:

```
// discover the field name carrying the M365 RecordType integer
dataSource.name='<m365_source>' | limit 1 | columns *

// once known, pre-filter coarse categories cheaply
dataSource.name='<m365_source>' <recordtype_field> = 2     // Exchange item
```

If a human-readable category column is needed, build a small lookup table (`savelookup`) keyed on the discovered field name. Don't hand-inline the integer-to-string map into every query.

## Service-tier IP filter for "top client IPs"

Client IP fields on M365 audit events are dominated by Microsoft service-tier traffic. Any "top external IPs" or "unique source IPs" analysis without a service-tier exclusion produces a meaningless ranking. The exact prefix set drifts and varies by tenant geography; **build the exclusion list from this tenant's data**, not from a hardcoded list:

```
// 1. Pull the top client IPs without filtering.
dataSource.name='<m365_source>'
| group ct=count() by <client_ip_field>
| sort -ct | limit 100

// 2. Inspect the result and identify the prefixes that dominate.
//    They will be Microsoft service ranges; the specific prefixes
//    differ across tenants.

// 3. Encode the discovered prefixes as a regex exclusion.
dataSource.name='<m365_source>'
| filter !(<client_ip_field> matches '^(<prefix1>|<prefix2>|<prefix3>)')
| group ct=count() by <client_ip_field>
| sort -ct | limit 100
```

If the analysis runs frequently, persist the discovered exclusion list as a `savelookup` and reference it via `| lookup` rather than embedding the regex into every query. Refresh the lookup periodically; the prefix set drifts.

## Investigation-noise separator

Searching SDL for an identity string returns two interleaved record sets:

1. Real-world events from parsed sources, identifiable by `dataSource.name` being set.
2. SDL platform-internal audit logs of analysts who previously searched for that string. These have no `dataSource.name` and carry platform-audit fields (the exact field names are themselves discoverable; see below).

Always partition the result set on `dataSource.name` presence and report the two as separate quantities. The SDL audit trail of prior investigations is itself a finding (it tells you the subject has been investigated before), but it is not subject activity:

```
* contains 'user@example.com'
| let category = (dataSource.name = *) ? 'subject_activity' : 'investigation_noise'
| group ct=count() by category
```

To inspect what the investigation-noise records actually look like on this tenant, drill in:

```
* contains 'user@example.com'
| filter !(dataSource.name = *)
| limit 5 | columns *
```

## Pattern: "user appears in data but never as actor"

When a user's email shows up frequently under `* contains '<email>'` but returns zero rows when filtered as actor, three interpretations are possible: the mailbox isn't ingested (coverage gap), the entity is external (only appears as a recipient or in message content), or the active UPN differs from the address you're searching for. Run both queries; if the first returns rows and the second returns zero, frame the result as one of those three, not as "no activity".

```
// Does the address appear anywhere?
* contains 'user@example.com'
| group ct=count() by event.type
| sort -ct | limit 20

// Does the address appear as actor on send-style operations?
// Use the actor field + operation field discovered for this tenant.
dataSource.name='<m365_source>'
<operation_field> in (<discovered_send_operations>)
(<ocsf_user_field> contains:anycase 'user@example.com'
 OR <unmapped_user_field> contains:anycase 'user@example.com')
| group ct=count() by <operation_field>
```
