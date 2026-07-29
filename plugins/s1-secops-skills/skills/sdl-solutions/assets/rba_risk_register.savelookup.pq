// OPTIONAL: persisted decayed risk register.
// A machine-maintained running per-object risk score with time decay. It COMPLEMENTS the dynamic
// windowed score (the incident rules) and does NOT replace them: use it for long-horizon entity
// risk, trend lines, and cheap executive/leaderboard views that survive the 24h/7d windows and even
// raw-event retention expiry. Deploy as a DAILY scheduled Hyperautomation flow (reuse the
// rba_collector.workflow.template.json shape: a single sync PowerQuery action bound to the
// 'SentinelOne SDL' Bearer connection running this body).
//
// Rewritten 2026-07-29. The previous body started from the last-24h risk events and pulled the
// prior register in via `| lookup`, so any entity with NO activity in the window was absent from
// the output row set and the savelookup overwrite DROPPED it instead of decaying it. This body
// starts from the UNION of two row sets, so quiet entities persist and decay toward zero:
//   subquery A: today's per-entity aggregate from the risk index (last 24h).
//   subquery B: the prior register itself, read back via `| dataset 'config://datatables/...'`,
//               with the decay multiplier already applied and tactics_today zeroed.
// then re-groups by the entity key: risk_score_total = decayed_prev + today.
// `union` is only valid as the FIRST command of a PowerQuery; a mid-pipeline `| union (subquery)`
// returns HTTP 400 (live-verified 2026-07-29). The union-first skeleton of this body (two
// subqueries -> group by key -> sort/limit) was validated read-only against dataSource.name='alert'
// on 2026-07-29; the `| dataset` read of the register inside a union subquery and the savelookup
// overwrite are PENDING: validate on demo tenant (they depend on a deployed register table and a
// write, neither of which the read-only validation covered).
//
// Tokens: {{PREFIX}} (register name), {{DECAY}} (0.9 ~= one-week half-life; lower = shorter memory).
// Cadence must match the window: this body sums the last 24h, so run it once per day.
// The `risk_score_total >= 0.5` prune stops fully-decayed entities from accumulating forever;
// tune the floor to taste (it only drops entities whose score has decayed to noise).
//
// Bootstrap: on the very first run the register does not exist yet, so the `| dataset` subquery
// has nothing to read (and may error on a non-existent table). Seed it once by running ONLY
// subquery A's body followed by `| limit 100000 | savelookup '{{PREFIX}}RiskRegister'` (writes
// today's scores as the initial register), then switch to the full union body below.
//
// Read it back for a persistent leaderboard with:  <name> from {{PREFIX}}RiskRegister ... (dashboard
// panel or | lookup), or query the savelookup like any datatable.

| union
  (dataSource.name='risk' risk_object=*
   | group part_score = sum(number(risk_score)), tactics_today = estimate_distinct(mitre_tactic), last_seen = newest(timestamp) by risk_object, risk_object_type
   | columns factor_key = risk_object, risk_object_type, part_score, tactics_today, last_seen),
  (| dataset 'config://datatables/{{PREFIX}}RiskRegister'
   | let decayed = number(risk_score_total) * {{DECAY}}
   | let zero_tactics = 0
   | columns factor_key, risk_object_type, part_score = decayed, tactics_today = zero_tactics, last_seen)
| group risk_score_total = sum(part_score), tactics_today = max(tactics_today), last_seen = max(last_seen) by factor_key, risk_object_type
| filter risk_score_total >= 0.5
| limit 100000
| savelookup '{{PREFIX}}RiskRegister'
