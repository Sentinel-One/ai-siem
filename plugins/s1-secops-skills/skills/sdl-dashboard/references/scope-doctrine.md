# Scope doctrine

Moved out of `SKILL.md` to keep it under the 500-line authoring limit. The content is unchanged.

## Scope doctrine: where the dashboard lives vs. what its queries read

**Two independent decisions. Get them both explicitly before authoring a panel.**

1. **Deployment scope**: which scope the dashboard object is filed at (Global, Account, or Site). Set by the `S1-Scope` header on the create call, or by `shareResource` afterwards.
2. **Query scope**: which data the panels read. Set by what you put in the query.

### The rule

**A dashboard deployed at a SITE must scope its panel queries to that site with an explicit `site.id` predicate.** Add `site.id='<siteId>'` to every query panel.

The single exception: the user explicitly asks for account-scoped (or cross-site) queries on a site-deployed dashboard. That is a legitimate ask, for example an MSSP hub dashboard filed in one site but reporting across the account. When it happens, say so in the dashboard `description` so the next reader is not surprised, and pass `--allow-account-scope-queries` to the safety check.

Do not infer the exception from convenience. If the deployment scope is a site and the user has not said otherwise, scope the queries.

### Use `site.id`, never `site.name`

`site.name` is a lossy scoping filter. Measured on `<console>` 2026-08-17 for one site:

| Filter | Events matched |
|---|---|
| `site.id='9876543210987654321'` | 60,410 |
| of those, rows where `site.name` is null | **510** |

Breakdown of the 510 that a `site.name` filter would silently drop: `ActivityFeed` 172, `asset` 111, unattributed source 99, `SentinelOne` 70, `Windows Event Logs` 48, **`alert` 10**.

So `site.name` drops alert and asset records, which is exactly what a SOC dashboard leans on, with no error and no empty panel to hint at it. `site.id` also:

- is the **same identifier** as the `siteId` in the `S1-Scope` header and `shareResource`'s `scopeId`, so one value threads the whole deployment;
- survives a site rename.

`site.name` is fine as a display column or a `group by` key. It is not fine as the scoping predicate.

### Enforcement

`scripts/panel_safety_check.py` implements both halves:

```bash
# Site-deployed dashboard: every query panel must carry site.id='<siteId>'
python3 scripts/panel_safety_check.py dash.json --site-id 9876543210987654321

# Deliberate account-wide queries on a site-deployed dashboard
python3 scripts/panel_safety_check.py dash.json --site-id 9876543210987654321 \
    --allow-account-scope-queries
```

- **S01** fires when a site-targeted dashboard has a query panel with no `site.id` predicate, or one scoped to a *different* site. Suppressed by `--allow-account-scope-queries`.
- **S02** fires when `site.name` is used as a scoping filter without a `site.id` predicate alongside it. **Never suppressed by the account-scope flag**, because the substitution is wrong at any scope.

Markdown tiles, `alerts_table` and `distribution` panels are exempt: they have no PQ to scope.

**Two deploy-time traps that mimic failure** (detail in `references/deployment.md`): `createDashboardV2` defaults `public` to false and owns the object as the API service user, so the dashboard is invisible in the console to a human even at the right scope. Pass `isPublic: true`. And dashboard names reject `( ) [ ] { } : , & ' % #` with only `Invalid name` as the error; letters, digits, space, `-`, `_`, `.` and `/` are accepted.
