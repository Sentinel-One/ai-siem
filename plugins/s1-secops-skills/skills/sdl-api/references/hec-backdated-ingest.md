# HEC back-dated ingest and the receive-time "shadow" rows

Companion to the HEC section of `sdl-api/SKILL.md`.

## Current finding (re-tested live 2026-10-03)

The extra receive-time rows seen after a back-dated HEC POST are **SDL ingest-metering
rows, not copies of the event**. No event was duplicated.

| Row kind | `tag` | Carries body fields | Timestamp | What it is |
|---|---|---|---|---|
| The event | absent | yes | the `time` you sent | the real, back-dated event |
| Metering | `logVolume` | no; has `metric` (`logBytes` or `logEvents`), `value`, `path1` | receive time | ingest accounting, emitted for every POST, back-dated or not |
| Query audit | `queryOutcome` / `audit` | no `dataSource.name` | when you ran a query or saved a config | logs of your own queries and config writes. Any of them that contain the nonce match a full-text `* contains '<nonce>'` search |

Metering rows carry the URL-supplied `dataSource.name` and `dataSource.vendor`, so an
unfiltered `dataSource.name='X'` count includes them. That is the inflation described in
the 2026-07-29 and 2026-08-09 notes. The rows aren't 1:1 with POSTs or events.

### Evidence

Two probes, both to `POST /services/collector/event?isParsed=true` with
`Content-Type: application/json`:

- **Probe A**, `dataSource.name=ZZ_HEC_SHADOW_PROBE`, run `hs20261003a`: one event back-dated 72h,
  plus one control event with no `time`.
  Result: 2 real events at the expected timestamps, plus 4 `logVolume` rows at receive time
  (a `logBytes` and `logEvents` pair per POST). The **control** got the same metering pair
  as the back-dated event, so the extra rows aren't caused by back-dating.
- **Probe B**, `dataSource.name=ZZ_HEC_SHADOW_PROBE_B`, run `hs20261003b`: one POST of 100
  events, back-dated 72h to 70h.
  Result: exactly 100 real events at the back-dated times, plus 40 `logVolume` rows at
  receive time (20 `logBytes` summing to 12,200 bytes and 20 `logEvents` **summing to 100**,
  the number of events sent). The trailing 1h window showed 0 real events and 40 metering rows.

The `logEvents` total equals the number of events sent, which identifies these rows as
accounting for the ingest. They aren't replicas.

### How to count correctly

```text
dataSource.name='X'
| group unfiltered = count(),
        metering   = count(tag = 'logVolume'),
        real       = count(tag != 'logVolume')
| limit 1
```

- Exclude metering in any count or schema sample: `dataSource.name='X' tag != 'logVolume'`.
  Rows with no `tag` are kept, which the probe confirmed (Netskope: 45 rows, 14 metering, 31 kept).
- Don't validate an empty-live-window detection (SILENT, anti-join watchdog) with an
  unfiltered count. Exclude `logVolume` first, or the metering rows from the back-dated POST
  make the source look live.
- A full-text nonce search also matches `queryOutcome` / `audit` rows created by your own
  queries and config writes. Anchor on `dataSource.name` or a body field instead.

