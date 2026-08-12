# Per-app sentinel pattern

Reference detail for the per-app sentinel pointer in `SKILL.md`. Use this pattern when one parser handles events from many distinct services or applications, each needing its own OCSF class assignment.

## Per-app sentinel pattern (multi-tenant / multi-service parsers)

Use this pattern when a single parser handles events from many distinct services or applications, each needing its own OCSF class assignment.

### Pattern overview

1. **Extract a discriminator field** (e.g. `app_name` from a raw JSON `app_id` key) using a two-segment capture format.
2. **Create one format-id sentinel per service**: `{ id: "my_app", format: "$_scratch{regex=.*\"app_id\":\"my-app-id\"}$" }`. This sets `my_app='true'` on matching events.
3. **List all sentinel field names in `discardAttributes`** so they don't appear in the output event.
4. **Add one v1 mappings block per sentinel** with the OCSF constants and any drop ops. Because v1 is first-match-wins, drops cannot be factored into a shared block, duplicate them in every block including the catch-all.
5. **End with a `predicate: "true"` catch-all** that applies drops but assigns no class. Place it last or it will consume every event.

### How to add a new service

1. Confirm the new service's discriminator value (e.g. sample a few raw events via PowerQuery).
2. Check whether it already fires an existing sentinel (e.g. a shared type field that already has a sentinel). If yes, no new entry needed.
3. Add the sentinel ID to `discardAttributes`.
4. Add a format entry before the catch-all sentinels.
5. Add a mapping block before `predicate: "true"` with the right OCSF constants and all noise drops.
6. Bump `metadata.version` (minor bump for new service; patch for fixes).
7. Deploy via `sdl_put_file` with the current `expectedVersion` from `sdl_get_file`.
8. Wait ~3 min for propagation, then verify on a short window (5 min): `dataSource.name = 'MySource' | group count=count(), has_class=count(class_uid) by app_name | filter app_name = 'my-new-service'`.

### Periodic audit query

Run this periodically to catch new services that have accumulated in the catch-all:

```text
dataSource.name = 'MySource' app_name = *
| group count=count(), has_class=count(class_uid) by app_name
| filter has_class == 0
| sort -count
```

Any `app_name` with `has_class == 0` and meaningful volume is a candidate for a new sentinel.
