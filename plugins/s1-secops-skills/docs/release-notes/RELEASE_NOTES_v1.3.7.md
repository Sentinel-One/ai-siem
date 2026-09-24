## s1-secops-skills 1.3.7

Plugin **1.3.7**. npm `@pmoses-s1/s1-secops-mcp` **1.3.9**. Docker bundle image
**1.3.6**, pinning purple-mcp **v0.7.0** and virustotal-mcp **1.0.21**. Tool count 32.

The three numbers differ on purpose and always have. The image tag versions the
container, not the servers inside it.

**An image tag is now strictly increasing and never republished.** That is the
headline, because it is what decides whether the rest of this release reaches you.

---

## Action required: update your Docker config

Replace the pinned tag and `--pull=missing` with `:latest` and `--pull=always`:

```json
{
  "command": "docker",
  "args": ["run", "-i", "--rm", "--pull=always",
           "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN",
           "-e", "S1_HEC_INGEST_URL", "-e", "S1_HEC_TOKEN",
           "ghcr.io/pmoses-s1/s1-mcps:latest", "s1-secops-mcp"]
}
```

Restart Claude Desktop afterwards.

**Why this matters more than it looks.** `s1-mcps:1.3.3` shipped npm 1.3.3, then
1.3.7, then 1.3.8, and the image version once moved backwards from 1.3.7 to 1.3.3.
With `--pull=missing` against a tag string that never changes, Docker has nothing to
notice, so a machine that pulled in August keeps an August build indefinitely while
the tag still reads "current". At least one field report of a "1.3.6 defect" was a
build from before the fix it was missing.

Check what you are actually running:

```bash
docker image inspect ghcr.io/pmoses-s1/s1-mcps:latest --format '{{.Created}}'
docker run --rm --entrypoint npm ghcr.io/pmoses-s1/s1-mcps:latest ls -g --depth=0
```

Pin to `:1.3.6` instead when you need a reproducible build for a customer demo or a
support investigation. Version tags are immutable and are never republished.

---

## Skills

**soc-investigator gains a fourth mode, SWEEP.** Alert-agnostic. It answers "what MITRE
TTPs are in my logs over window X", which none of SHORT, MEDIUM or LONG could, because all
three start from an alert. Six phases in `references/ttp-sweep.md`: scope confirmation,
source enumeration with platform-noise separation, per-source schema discovery, ATT&CK
extraction from the alert stream, raw-log corroboration per technique, and a simulation and
authorised-scanner suppression pass.

That suppression pass is the point. Breach-and-attack-simulation agents and cloud posture
scanners emit genuine attack telemetry, so without it a sweep reports a fleet-wide intrusion
that is not happening. Suppression requires a named agent, host or principal, never deletes
evidence, and anything surviving it is reported at full weight. SWEEP is a **peer** of the
other three, not a cumulative step, and both `SKILL.md` and `investigation-modes.md` say so,
because an operator who reads it as cumulative waits for alert phases that never run.

**powerquery gains geo-velocity, impossible travel in km/h.** The obvious implementation is
wrong on this engine and fails silently: `| join` zips its two sides roughly one-to-one
rather than producing a cross product, measured as 20 rows from two 20-row sides joined on a
constant key, where a cartesian product would give 400. A pairwise query therefore reports
an arbitrary pair's speed as the maximum, with no error, and that shipped in a real detection
once. The documented query computes first and last position inside a single `group` instead.

Two traps are now documented with it. `timestamp` is nanoseconds, so the hours divisor is
`3600000000000`. Divide by zero returns the **string** `'Infinity'`, which sorts as a string
and defeats every numeric threshold downstream without raising anything, so the ternary guard
is mandatory rather than stylistic. The first-to-last-leg limitation is stated plainly: exact
for two locations, understates for three or more, never overstates, so it is a safe lower
bound for alerting.

**sdl-dashboard gains the UQL `| datasource` surface and the XDR scope trap.** The skill had
no mention of the adapter surface at all. The initial predicate belongs inside `where (...)`,
not `| filter`, which is the single most common failure on that surface.

The XDR trap is promoted into the rendering-pitfalls table with its exact error string, and
given its own section. Selecting XDR injects `preFilter: dataSource.category = 'security'`
into every panel query, which hard-errors `| datasource` panels and silently empties
alert-stream and `| dataset` panels, so a dashboard looks half-broken while every query is
correct. There is no dashboard-JSON field that pins the selector, so the fix is an
instruction in the description. Related: the LRQ API never applies that preFilter, so
API-passing and render-passing are separate gates.

Three corrections where the skill was wrong: `count(<predicate>)` is a working conditional
count and only `count_if` and `sum(if())` fail; `estimate_distinct` is approximate, measured
at 14,196 against a true 14,043, and chained `group` is exact; `transpose` tolerates spaces
and breaks on hyphens.

**Prompts got simpler, which is the real deliverable.** A prompt that has to say "put the
predicate in `where (...)`" or "`now()` is nanoseconds" is a skill defect. Those constraints
now live in a **Defaults you apply without being asked** table in the dashboard SKILL.md, so
"Build a SOC leader dashboard" is a complete instruction. Example prompts are in the skill's
README, with a note that writing a constraint into a prompt means the skill needs fixing.

The soc-investigator description was also widened: it advertised only alert-based entry, so a
plain "find the MITRE TTPs in my logs from last week" would not reliably reach the skill that
now has a mode for exactly that.

---

## Fixed

**`ha_import_workflow` no longer double-wraps.** The `/import` endpoint's body is
`{"data": {...}}` and the tool supplies that envelope itself, so pasting the
skill's documented example produced `{"data":{"data":{...}}}` and a
`422 body.data.name Field required`. The tool now unwraps a wrapped payload when it
is unambiguous and reports that it did. The hyperautomation skill prints both forms,
labelled: **Form A** the raw API body, **Form B** the bare object the tool wants.

**`sdl_list_dashboards` is paginated.** On an MSSP account it returned 442,581
characters across 17,111 lines. New `limit` (default 100, max 1000), `offset` and
`namesOnly`, plus `totalCount`, `hasMore` and `nextOffset` in the response.
`namesOnly` returns `{id, name}` and is about four times smaller, which covers
resolving a name to an id. `sdl_list_files` gets the same, default 500; its `count`
still reports the full post-filter total.

**`ha_export_workflow` accepts a scope.** New `accountIds` / `siteIds`. An unscoped
403 now names scope as a possible cause rather than reading as a missing role.

---

## Known client issue, not fixed by this release

Calling these tools **without passing every parameter** fails with
`expected nonoptional, received undefined` before the request reaches the server:

| Tool | Parameters that must be passed explicitly |
|---|---|
| `ha_list_workflows` | `limit`, `skip`, `sortBy`, `sortOrder` |
| `uam_list_alerts` | `first`, `viewType` |
| `powerquery_run` | `hours`, `maxRows` |
| `powerquery_schema_discover` | `maxEvents`, `startTime` |
| `powerquery_enumerate_sources` | `hours` |
| `sdl_create_dashboard` | `isPublic` |
| `uam_ingest_alert` | `title`, `hostname`, `filename`, `inline` |

This is in the Claude Code host, not the MCP. The package has no dependencies and
does not use zod; those are Zod v4 codes and the error arrives before dispatch. The
host maps a JSON-Schema property carrying `default` to a non-optional field.
Upgrading the MCP will not fix it. **Workaround: pass every parameter.** Reported
upstream. The parameters added in this release deliberately carry no `default`
keyword, so they are unaffected.

---

## Prevention

The previous suite asserted structure with the HTTP layer mocked, and every defect
above sat in what that left uncovered. Four new test classes, 132 tests total:

- **Executable doc examples.** Both JSON blocks in the hyperautomation smoke-test
  section are parsed from the markdown and run through `ha_import_workflow`. A
  documented payload that cannot survive the tool beside it fails the build.
- **Outbound wire shape.** Assert the body sent, not that a call happened.
- **Client-parity schema lint.** Every tool must be callable with only its
  `required` fields, and the set of default-bearing properties is frozen.
- **Response budget.** List tools are driven with MSSP-scale fixtures (1,200
  dashboards, 2,000 config files) and must stay under 200,000 characters.

CI also refuses any image publish where `IMAGE_VERSION` does not strictly increase.
The old check tested that the line changed, which is how the version once moved
backwards; and it allowed republishing a tag that was absent from the registry,
which made "delete and republish different bytes" a supported route. Both are gone.
