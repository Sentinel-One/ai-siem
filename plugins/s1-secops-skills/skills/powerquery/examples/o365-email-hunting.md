# O365 / M365 email hunting recipes

Workflow patterns for the most common Microsoft 365 audit hunts: finding senders, tracing recipients, identifying outbound external mail, correlating DLP, and resolving identity-attribution gaps. **Every recipe leads with schema discovery**, not assumed field paths. See `references/o365-fields.md` for the why.

## Recipe 0: discovery (always run this first)

Before any M365 hunt, confirm the source string, the actor / operation field names, and the populated values on this tenant.

```
// Confirm the source name.
| group ct=count() by dataSource.name | sort -ct | limit 50

// Inspect one event end-to-end.
dataSource.name='<m365_source>' | limit 1 | columns *

// Confirm the actor and operation fields are populated and which form
// (OCSF or unmapped.*) carries the data on this tenant.
dataSource.name='<m365_source>'
| group ct=count() by <candidate_actor_field>, <candidate_operation_field>
| sort -ct | limit 30
```

The `<candidate_*_field>` placeholders below should be replaced with the field names that the discovery step confirmed are populated. The mgmt-console-api skill's `inspect_source.py` automates this and returns the right keys; use it when scripting.

## Recipe 1: "did user X send any mail in the last N days"

This is the single most common M365 hunt, and the answer is rarely "yes/no" by itself; it's usually a count by operation type plus a rough cadence. The trap to avoid: assuming the user is a sender. If the address only appears as a recipient or in inbound mail content, the hunt should report a coverage gap rather than "no activity".

```
// Step A: does the address appear anywhere on this source?
dataSource.name='<m365_source>' * contains 'user@example.com'
| group ct=count() by <operation_field>
| sort -ct | limit 30

// Step B: does the address appear as actor on send-style operations?
dataSource.name='<m365_source>'
<operation_field> in (<discovered_send_operations>)
(<ocsf_actor_field> contains:anycase 'user@example.com'
 OR <unmapped_actor_field> contains:anycase 'user@example.com')
| group ct=count() by <operation_field>
| sort -ct
```

Reading the result:

- Both queries return rows: the user is a sender; proceed to recipe 2 or 3.
- Step A returns rows, step B returns zero: the address is in the data but never as actor. Three interpretations: mailbox not ingested (coverage gap), external entity, or alias mismatch. State which is most likely; do not report "no activity".
- Both return zero: the address is not in this source's window. Widen the window or confirm the source is the right one.

## Recipe 2: per-day cadence for a specific sender

Used to spot bursts, off-hours activity, or sudden drops.

```
dataSource.name='<m365_source>'
<operation_field> in (<discovered_send_operations>)
(<ocsf_actor_field> contains:anycase 'user@example.com'
 OR <unmapped_actor_field> contains:anycase 'user@example.com')
| group ct=count() by day=timebucket('1d'), <operation_field>
| sort day
```

For longer windows (over 7 days), prefer running this through the LRQ API with daily slices and merging client-side. See `references/lrq-api.md` → "Slicing & parallelism".

## Recipe 3: outbound external mail for a specific sender

The "did user X send mail to anyone outside the org" question. Recipients live inside the JSON `message` blob on most M365 parsers, so this is typically a two-step hunt: filter by sender + send-style operations in PQ, then post-process the recipient list in Python against the org's owned-domain list.

PQ side:

```
dataSource.name='<m365_source>'
<operation_field> in (<discovered_send_operations>)
(<ocsf_actor_field> contains:anycase 'user@example.com'
 OR <unmapped_actor_field> contains:anycase 'user@example.com')
| columns timestamp, <operation_field>, <ocsf_actor_field>, <unmapped_actor_field>, message
| sort -timestamp
| limit 1000
```

Python post-processing pseudocode:

```python
import json, re

# Build the owned-domain list from tenant config; do NOT hardcode.
# Discover via the tenant's accepted-domains list, parser metadata,
# or by sampling internal-only sends and inferring the trailing domain.
owned_domain_pattern = re.compile(
    r"@(" + "|".join(re.escape(d) for d in owned_domains) + r")$",
    re.IGNORECASE,
)

def extract_recipients_from_message(msg):
    if not msg:
        return []
    try:
        j = json.loads(msg)
        item = j.get("Item") or {}
        return [r.get("Address") for r in (item.get("Recipients") or [])
                if isinstance(r, dict) and r.get("Address")]
    except Exception:
        return []  # fall back to a regex extraction if needed

external_rows = []
for row in pq_rows:
    addrs = extract_recipients_from_message(row.get("message", ""))
    external = [a for a in addrs if not owned_domain_pattern.search(a)]
    if external:
        external_rows.append({**row, "external_recipients": external})
```

Three caveats:

1. The owned-domain list is per-tenant; pull it from M365 accepted-domains config or infer it from the data, never hardcode.
2. The recipient JSON path inside the `message` blob (`Item.Recipients[].Address`) reflects upstream M365 audit JSON keys and is consistent across tenants on most parsers; confirm by inspection on the tenant in scope.
3. If the parser on this tenant exposes recipients as a scalar (some do, via an `unmapped.*` flattening), `* contains '@<external_domain>'` in PQ may be enough and the Python step is unnecessary. Discovery decides.

## Recipe 4: top recipient domains for a sender

Useful for relationship-mapping ("who does this user email most"). Same two-step pattern as recipe 3: pull rows, post-process recipient domains.

```python
from collections import Counter

domain_counts = Counter()
for row in pq_rows:
    for addr in extract_recipients_from_message(row.get("message", "")):
        if "@" in addr:
            domain_counts[addr.split("@", 1)[1].lower()] += 1

for domain, count in domain_counts.most_common(20):
    print(f"{count:>6}  {domain}")
```

## Recipe 5: correlate DLP rule matches with sender

When DLP fires on a send, the `message` blob contains policy and rule details. Useful for triaging "which DLP rules is user X tripping repeatedly".

```
dataSource.name='<m365_source>'
<recordtype_field> = 13                       // discover the field name carrying RecordType first
(<ocsf_actor_field> contains:anycase 'user@example.com'
 OR <unmapped_actor_field> contains:anycase 'user@example.com')
| columns timestamp, <ocsf_actor_field>, message
| sort -timestamp
| limit 500
```

Post-process the `message` JSON to walk `PolicyDetails[].Rules[].RuleName`, `Severity`, and `Actions`. Group by rule name client-side. The shape of the DLP record is consistent across tenants on a given parser version; confirm by inspecting one event before scripting against the schema.

## Recipe 6: "is this entity inside or outside the tenant"

When an address shows up as a recipient repeatedly but never as actor, decide whether it's a real coverage gap or an external contact. Indicators:

- The address has the same trailing domain as the tenant's accepted-domains list, but never appears as actor on send-style operations: likely a coverage gap (mailbox not ingested, or the licensed UPN differs).
- The trailing domain is not in the accepted-domains list: external entity. Outbound mail to it is a tenant-to-external pattern; inbound mail from it appears under different actor fields (often the on-prem mail gateway's identity).

Run recipe 1 step A and step B together; the comparison is the answer.

## Recipe 7: investigation-noise separation in identity hunts

When the search predicate is an identity string (email, user id, IP), partition the result set on `dataSource.name` presence to separate real-world events from SDL platform-internal audit records of prior analyst searches. The audit trail is itself a finding, but it must be reported separately.

```
* contains 'user@example.com'
| let category = (dataSource.name = *) ? 'subject_activity' : 'investigation_noise'
| group ct=count(), first_seen=min(timestamp), last_seen=max(timestamp) by category
```

To inspect what the investigation-noise records carry on this tenant:

```
* contains 'user@example.com'
| filter !(dataSource.name = *)
| limit 5 | columns *
```

The exact field names on the platform-audit records are themselves discoverable via `| columns *`; do not assume them.

## Performance notes specific to M365 hunts

1. Always pre-filter on `dataSource.name`. M365 sources can be very high-volume; an initial filter without a source pin pulls in unrelated traffic and pushes the query past timeout.
2. Prefer `<recordtype_field> = N` over `<operation_field> in (long_list)` for coarse category pre-filtering. The numeric form is cheaper.
3. For value-anywhere identity hunts, `* contains 'value'` in the initial filter beats `message contains 'value'` by a wide margin. See `references/pitfalls.md` → "Reaching for `message contains` on a JSON-blob source".
4. Long-window hunts over M365 sources should run via the LRQ API with daily slices, not via interactive PQ. The Purple MCP path will time out on anything over a few days against high-volume M365 sources.
