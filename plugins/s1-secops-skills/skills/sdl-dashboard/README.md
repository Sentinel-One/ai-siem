# sdl-dashboard (Claude skill)

A Claude skill for designing, authoring, and deploying SentinelOne **Singularity Data Lake (SDL) dashboards**: from a single panel to a full multi-tab SOC dashboard. Covers all panel types, multi-tab layouts, parameters, and full dashboard JSON authoring with community examples.

## Install

Copy this folder into your user skills directory:

```bash
cp -r sdl-dashboard ~/.claude/skills/
```

In Cowork/Claude Code, the path is:

```text
/sessions/<session>/mnt/.claude/skills/sdl-dashboard/
```

Or install the full plugin (recommended) to get all the SentinelOne SecOps skills together.

## Usage

This skill has no Python client of its own: dashboards are authored as JSON and deployed via the `sdl-api` skill's `put_file` method. Use alongside:

- **`sdl-api`**: to deploy the dashboard JSON to your SDL tenant (`put_config_file`, by name on first create, by `udo_id` thereafter)
- **`powerquery`**: to validate and compose the queries inside panels before embedding them

## Example prompts

Keep them short. The skill carries the constraints, so you do not have to. You never need to say
"put the predicate in `where (...)`", "`now()` is nanoseconds", "use chained group not
`estimate_distinct`", or "validate before deploying": those are defaults, listed in SKILL.md under
**Defaults you apply without being asked**. If you find yourself writing one into a prompt, that is a
bug in the skill, not a habit to keep.

**Build**

- Build a SOC leader alert dashboard.
- Add an identity tab to `SOC Leader Alert Operations`, with a product-to-verdict sankey and a tactic-by-severity heatmap.
- Build a vulnerability management dashboard.

**Extend**

- Clone `UQL Query Template Library` and add `misconfigurations` and `metering` patterns.
- Add MTTA and MTTR panels to the SOC dashboard.

**Debug**

- Fix the broken panels on `<dashboard>`.
- This panel is blank but the query returns rows.
- Audit `<dashboard>` for panel titles that overstate what the query measures.

**Query authoring**

- UQL query for open Critical alerts older than 14 days, grouped by owner.
- Exact distinct count of assets with alerts.
- Convert this query to `| datasource alerts`, or tell me why it cannot be converted.

**Discovery first**

- Show me dashboards in this account that already use `| datasource`.
- Which `where (...)` operators does the `alerts` adapter actually accept?

Two worked examples: "Fix the broken panels" already implies diagnosing the XDR scope trap, checking
the visual's column contract and looking for hyphens in transposed values. "Add MTTA and MTTR panels"
already implies checking whether the metrics source has data on this tenant and telling you if it
does not, rather than shipping empty panels.

## What this skill does

- Designs tab structure and panel layout for any dashboard use case (SOC, compliance, network, threat hunting, identity)
- Authors correct JSON for all panel types: `line`, `bar`, `pie`, `table`, `number`, `timeline`, `honeycomb`, `markdown`
- Authors both query surfaces: the event stream, and UQL `| datasource` adapter queries against SentinelOne inventory (alerts, assets, vulnerabilities, misconfigurations, metering)
- Applies query performance rules: `net_rfc1918()`, `| limit 1` on number panels, explicit limits on tables, `timebucket` granularity matched to duration, early filter placement, `estimate_distinct()` for cardinality on the event stream and chained `group` for exact distinct on inventory
- Adds markdown descriptor panels to each tab
- Deploys to SDL via `sdl-api`

## Layout

- `SKILL.md`: instructions Claude reads when the skill triggers.
- `references/panel-type-cheatsheet.md`: JSON schema for every panel type with annotated examples.
- `references/common-queries.md`: ready-to-use PQ queries for security, network, identity, and compliance dashboards.
- `references/community-examples.md`: full dashboard JSON examples from the SentinelOne community.
- `references/lessons-learned.md`: source-agnostic patterns and field requirements from production engagements (PowerQuery feature gaps, full-text cost, naming hygiene, discriminator handling, mandatory validation runner).
- `references/evidence-report-template.md`: required schema for the per-panel JSON, markdown, and PDF the validation runner produces.
- `scripts/panel_safety_check.py`: pre-deploy linter for known-bad panel patterns. Run before every `put_file`.
- `scripts/validate_dashboard.py`: post-deploy panel replay; persists per-panel evidence (sample rows, row count, matchCount, elapsed, errors) and emits a markdown report.
- `scripts/render_validation_pdf.py`: renders the evidence JSON into a leadership-ready PDF with cover, per-tab sections, sample-data tables, and an empty-result appendix.

## Mandatory log-evidence report

Every dashboard delivered with this skill ships with a log-evidence report produced by `scripts/validate_dashboard.py` plus `scripts/render_validation_pdf.py`. The PDF is the leadership deliverable, the markdown stays in version control. See `references/evidence-report-template.md` for the full schema and what a passing dashboard's report looks like.
