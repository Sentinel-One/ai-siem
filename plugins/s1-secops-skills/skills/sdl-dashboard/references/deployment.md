# Deploying, validating, and troubleshooting a dashboard

Deployment via the SDL API (udoId and CAS guard, duplicate handling), the pre-deploy parallel load test and verification, the escalation ladder for a hung dashboard, and the full pre-deploy checklist. Referenced from `SKILL.md`.

## Choosing a deployment route

Three routes. Pick by what you need, not by habit.

| Route | Use when | Call |
|---|---|---|
| **`create_dashboard` at a scope** | Creating a new dashboard, any scope. **Preferred.** | `create_dashboard(name, config, scope=...)` / `sdl_create_dashboard` |
| **`create` then `share`** | The calling token sits at account scope but the dashboard belongs to a site | `create_dashboard(...)` then `share_dashboard(id, scopes=[...])` |
| **`put_config_file` by udoId** | Updating an existing dashboard's full config with a CAS guard | `put_config_file(udo_id=..., expected_version=...)` |

`create_dashboard` takes the whole document as one `config` string and is the path the console itself uses. `put_config_file` is the raw config-file layer underneath; only it exposes the numeric version needed for optimistic locking.

## Site-level deployment

**Deployment scope and query scope are separate decisions.** Before deploying to a site, confirm the panels are scoped too: see the **Scope doctrine** section of `SKILL.md`. A site-deployed dashboard whose panels have no `site.id` predicate reports the wrong numbers, and one that filters on `site.name` silently drops `alert` and `asset` records.

### Route A: create in place at the site

```python
from sdl_client import SDLClient

client = SDLClient()
ACCOUNT_ID = "2046190533732727925"
SITE_ID    = "2547662415802335157"
SITE_SCOPE = f"{ACCOUNT_ID}:{SITE_ID}"

created = client.create_dashboard(
    name="Metacortex Site",
    config=json.dumps(dashboard_json),   # panels already filter site.id='<SITE_ID>'
    scope=SITE_SCOPE,
)
dashboard_id = created["id"]             # == the udoId in config_files()
```

### Route B: create at account scope, then share to the site

Use this when the token cannot be scoped to the site. `shareResource` is the **only** SDL operation that takes an explicit scope target; everything else infers scope from the header.

```python
created = client.create_dashboard(name="Metacortex Site", config=body)   # account scope

client.share_dashboard(
    dashboard_id=created["id"],
    scopes=[{"scopeType": "site", "scopeId": SITE_ID, "operation": "ADD"}],
)
```

### Two things that make a successful deploy look like a failure

**Set `isPublic: true` for anything a human will open.** `createDashboardV2` defaults `public` to
false and records `access.owner` as the calling identity. With an API service-account token that
owner is `serviceuser-<uuid>@mgmt-<n>.sentinelone.net`, not a person, so a private dashboard is
readable through the API and **invisible in the console to the operator**. It presents exactly like
a failed deploy. Verified live: the same dashboard at the same scope became visible purely by
recreating it with `public: true`, and every pre-existing dashboard at that site was public.
`shareResource` to a scope does not flip `public`; they are independent.

**Dashboard names reject punctuation, and the only error is `Invalid name`.** Probed live, one
character class at a time:

| Accepted | Rejected |
|---|---|
| letters, digits, space, `-`, `_`, `.`, `/` | `(` `)` `[` `]` `{` `}` `:` `,` `&` `'` `%` `#` |

So `My Dashboard (prod)` fails with no hint about which character was at fault. Normalise the name
before creating.

### Verify at BOTH scopes, not one

Confirming at a single scope proves nothing, because a listing at the wrong scope reports a live dashboard as absent.

```python
at_site    = client.list_dashboards(scope=SITE_SCOPE)
at_account = client.list_dashboards(scope=ACCOUNT_ID)

assert any(d["id"] == dashboard_id for d in at_site), "not visible at the site"
# Route A: expect it ABSENT from the account listing.
# Route B: expect it present in both.
```

Measured on `usea1-purple` 2026-08-17: `configFiles` returned 113 files at account scope and 4 at a site scope, same token and query. A dashboard created at site scope is invisible from account scope and `config_file` on its `udoId` reports it absent. **Every "not found" is scope-relative.**

### Getting the ids

```bash
# account ids
curl -s -H "Authorization: ApiToken $TOKEN" "$CONSOLE/web/api/v2.1/accounts" | jq '.data[].id'
# site ids (the same value used in site.id predicates and shareResource scopeId)
curl -s -H "Authorization: ApiToken $TOKEN" "$CONSOLE/web/api/v2.1/sites?states=active" \
  | jq '.data.sites[] | {id, name}'
```

## Deploying a dashboard via API

Use the `sdl-api` skill to deploy. Dashboard config files live at paths like `/dashboards/my-dashboard-name`.

### 1. Resolve the udoId, then write with a CAS guard

```python
import json
from sdl_client import SDLClient

client = SDLClient()
DASH_NAME = "/dashboards/soc-overview"

# Resolve the name to its udoId. Only /dashboards/ files carry one, and a name
# can resolve to more than one file, so check the count before writing.
matches = [f for f in client.config_files() if f["name"] == DASH_NAME]
if len(matches) > 1:
    raise SystemExit(f"{len(matches)} copies already share that name: {[m['udoId'] for m in matches]}")

body = json.dumps(dashboard_json, indent=2)

if matches:
    cur = client.config_file(udo_id=matches[0]["udoId"])      # None if absent, does not raise
    open(f"/tmp/{DASH_NAME.replace('/','_')}.{cur['version']}.bak.json", "w").write(cur["content"] or "{}")
    res = client.put_config_file(udo_id=cur["udoId"], content=body, expected_version=cur["version"])
else:
    res = client.put_config_file(name=DASH_NAME, content=body)   # first create only

udo_id = res["udoId"]    # record this; every later deploy addresses by udoId
```

The `expected_version` argument is a CAS guard against concurrent writes from the SDL UI or another script.

### 2. Verify deployment by re-fetching (and grep for a canary)

```python
time.sleep(3)  # eventual-consistency window
verify = client.get_file(DASH_PATH)
deployed_content = verify.get("content", "")
assert verify.get("version") != cur_version, "version did not bump"
assert "<canary-string-from-new-section>" in deployed_content, "deploy did not include new content"
```

A `put_file` response of `{"status": "success"}` does not guarantee the new content was written, always re-fetch and grep for a canary string from the change.

### 3. Never update a dashboard by name, address it by udoId

The console's Configuration Files grid displays a dashboard as
`/dashboards/id/6554761743556608/AI Usage`. **That string is not a path.** The number is the
file's `udoId`; the real `name` is `/dashboards/AI Usage`. Writing to the display string returns
`no file exists at path`.

`addConfigFile(name:)` updates in place for `/lookups/`, `/datatables/`, `/logParsers/` and
`/automaticLookups`, but **creates a duplicate** for `/dashboards/`. Create a dashboard by name
once (it has no `udoId` yet), then address it by `udoId` for every update after that. One tenant
reached 152 copies of `/dashboards/AI Usage` and 256 surplus dashboard files this way.
`sdl_put_file` refuses a path-addressed write to an existing dashboard.

Resolve a name to its `udoId` with `sdl_list_files` (`pathPrefix: "/dashboards/"`). See
`sdl-api/references/config-file-graphql.md`.

**Resolving a name can return more than one file, and they need not share a storage form.**
Measured on a live tenant: 16 dashboard names had duplicates, and in 11 of those a single
name-addressed copy (`udoId: null`) sat alongside the `udoId`-addressed ones. Two consequences:

- Never assume a name resolves to exactly one file. Filter the listing, check the match count,
  and stop for a human decision when it is greater than one. Picking the first match silently
  edits an arbitrary copy.
- A name-addressed copy of a dashboard can exist. It is readable and writable by name, so a
  script that only ever addressed dashboards by name may appear to work correctly while
  operating on a file the console user never sees.

Duplicates on this tenant cluster almost entirely on stock template names (`AI Usage` had 152
copies, `EDR Data Collection Analysis` 25), while hand-authored names have none. Each install of
a template dashboard creates a new file, so a shared tenant accumulates copies over time
independently of anything the API does.

### 4. Layout coordinates accumulate

Panels are placed by `layout: {w, h, x, y}`. When appending a new section to an existing dashboard, compute the next `y` as `max(existing_y + existing_h)` across the tab, not by visual estimation. Off-by-a-few errors stack panels on top of each other and the UI will not flag this as an error.

### 5. Test panels in the SDL UI before declaring done

The SDL dashboard render engine has a longer query budget than the PowerQuery MCP. A query that times out in MCP validation may still render in the UI. Conversely, a query that returns from MCP may render slowly in the UI. The final smoke test for every dashboard is: open it in the UI, watch each tab load, confirm no panel spins indefinitely.

After deploying, open in the SDL UI: **Visibility Enhanced → Dashboards** → select the dashboard by name.

---

## Pre-deploy validation

### The browser renderer is a separate execution path

The SDL engine has three query surfaces: the V1 query API, the LRQ async API, and the in-browser dashboard renderer. The renderer has different timeouts, a stricter column-name parser, and a different concurrency model. A query that returns results instantly via the API can still hang the renderer. "All API queries pass" is necessary but not sufficient. The renderer is the only path that matters for dashboards, and it cannot be tested directly except by deploying and opening the page.

The learnings below let you predict and eliminate renderer failures before deploy.

### Parallel load test (run before every `put_file`)

The browser fires all panel queries in parallel on load. Total dashboard load time ≈ slowest single panel + small per-panel render overhead. Always run a parallel load test before deploying a new or significantly modified dashboard:

```python
import concurrent.futures, time

def run_one(panel_query):
    c = SDLClient()
    # auth setup ...
    t0 = time.time()
    try:
        res = c.power_query(query=panel_query, start_time="24h")
        return ("OK", time.time() - t0, res.get("matchingEvents") or 0)
    except Exception as e:
        return ("FAIL", time.time() - t0, str(e)[:200])

queries = [p["query"] for tab in dashboard["tabs"] for p in tab["graphs"]
           if p.get("graphStyle") != "markdown" and p.get("query")]

wall_t0 = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    results = list(pool.map(run_one, queries))
wall_clock = time.time() - wall_t0

print(f"  Total serial:        {sum(r[1] for r in results):.1f}s")
print(f"  Wall-clock parallel: {wall_clock:.1f}s   <- expect this in browser")
print(f"  Slowest single:      {max(r[1] for r in results):.1f}s")
```

**Acceptance thresholds:** slowest single panel ≤ 2s, wall-clock parallel ≤ 5s, zero failures. If the slowest panel exceeds 2s, identify it and rewrite: replace `group` with `top K`, narrow the initial filter, raise the timebucket granularity, or split the dashboard.

### Deploy-and-verify: sleep before re-fetching

`put_config_file` returns synchronously, but the file propagates across replicas with eventual consistency. Re-reading ~100ms after a successful write can report the file as absent. Always wait:

```python
res = c.put_config_file(udo_id=udo_id, content=new_content, expected_version=cur_version)
assert res.get("udoId") == udo_id

import time
time.sleep(3)            # eventual-consistency window

post = c.get_file(DASH_PATH)
assert post.get("version") != cur_version  # version bumped
```

Without the sleep, verification looks like a deploy failure even when the deploy succeeded.

---

## Escalation ladder when a deployed dashboard hangs

1. **Log out and log back in.** The SDL UI caches panel render state in the session. After a `put_file`, the browser can serve a stale render from the prior version even though the underlying config changed. A fresh login clears session state completely. Try this before any config investigation when the query is confirmed to return data.
2. **Hard refresh** (`Ctrl+Shift+R` / `Cmd+Shift+R`). Eliminates cached state from a previous broken version. Resolves ~10% of "still hung" reports.
3. **Check dev-tools network tab.** If panel queries are NOT being fired, the renderer is stuck before any HTTP call. Cause is structural (layout/options/JSON parse), not query performance. If queries ARE firing, record the slowest and move to step 3.
4. **Run the slow panel's query in isolation via the V1 API.** If it returns fast, the issue is renderer-side (column names, `transpose`, panel options). If it is slow, optimise the query.
5. **Reduce panel count by 50%.** If the dashboard now loads, the issue was concurrency or memory in the renderer. Add panels back 25% at a time until a regression isolates the offender.
6. **Diff against a working reference dashboard in the same tenant.** `list_files /dashboards/`, `get_file` on a working dashboard, compare top-level keys, panel `layout` shape, `options` keys, and `graphStyle`-specific fields. Working dashboards in the same tenant are more reliable ground truth than any external documentation, because rendering rules drift between SDL releases.
7. **Roll back.** Always keep a backup of the prior dashboard JSON before `put_file`-ing a new version. Restore via `put_file(expected_version=current)` to unblock analysts while iterating offline.

---

## Pre-deploy checklist

Run this before every `put_file`. Items marked **[scripted]** are checked automatically by `scripts/panel_safety_check.py`.

```text
PRE-AUTHORING
[ ] Live data-source enumeration confirms every dataSource.name used by the dashboard exists
[ ] V1-query schema discovery run for every source; field list saved for the session
[ ] Discriminator field validated for every event.type the dashboard counts
[ ] No panel relies on a field that is only present in raw_data (or, if it does, the panel
    is a number/selective-table that won't time out under full-text)

JSON STRUCTURE (scripted)
[ ] Every panel has explicit x, y, w, h in layout                                  [scripted]
[ ] When appending to existing dashboard, next y = max(existing_y + existing_h)
[ ] No panel uses `transpose <field> on timestamp` where <field> values may contain hyphens
[ ] No `graphStyle: "area"` panel with a `query:` field (must use `plots:`)        [scripted]
[ ] Markdown panels use `markdown:` field, not `content:`                          [scripted]
[ ] No content after `| transpose` (transpose must be terminal)                    [scripted]
[ ] No hyphenated arithmetic (`x-y` without spaces)                                [scripted]

QUERY HYGIENE (scripted)
[ ] All number panels end with `| limit 1`                                         [scripted]
[ ] All table panels end with explicit `| limit N`                                 [scripted]
[ ] All time-series panels use a timebucket appropriate for duration
[ ] min/max(timestamp) columns wrapped in simpledateformat(...) with tz
[ ] Any millisecond-typed time field multiplied by 1000000 before simpledateformat
[ ] Hostname/value-list filters use `field in (...)` not `field matches '(...)'`
[ ] Numeric fields wrapped with number() before arithmetic / sum / avg
[ ] No use of count_if / sum(if(predicate, value, 0)) / mid-pipeline | union (union-first is allowed) / named subqueries [scripted]
[ ] No `\\s` / `\\d` regex escapes inside `matches '...'`                          [scripted]
[ ] No full-text predicate combined with timebucket+transpose                      [scripted]
[ ] Number panels use only {format, precision, suffix} in options

NAMING & SEMANTICS
[ ] Every panel title reads as an SLA-grade claim (no overstated counts)
[ ] Distinct event populations under the same event.type live in separate sections
    each with a markdown header explaining the split
[ ] Panels that may legitimately return 0 have a markdown header explaining the
    SOC-positive interpretation
[ ] 3-5 sample events checked to verify which field carries the user semantic per event ID
[ ] Machine-account filter applied on user-facing panels

PERFORMANCE & LOAD
[ ] Parallel load test passes: wall-clock <= 5s, slowest panel <= 2s, zero failures
[ ] All time-series panels obey the timebucket-vs-duration table

DEPLOYMENT
[ ] Backup of current dashboard JSON saved (for rollback)
[ ] put_file called with expected_version of the current deployed copy
[ ] sleep(3) before re-fetching to verify deploy
[ ] Re-fetched content greps for a canary string from the change
[ ] Existing dashboard addressed by udoId from sdl_list_files, not by name (name-addressed writes are for the first create only)

POST-DEPLOY (MANDATORY)
[ ] scripts/validate_dashboard.py run; per-panel evidence JSON persisted
[ ] Markdown evidence file emitted alongside the JSON
[ ] scripts/render_validation_pdf.py run; PDF report delivered with the dashboard
[ ] PDF Appendix lists every empty-result panel with a SOC-meaningful interpretation
```

---
