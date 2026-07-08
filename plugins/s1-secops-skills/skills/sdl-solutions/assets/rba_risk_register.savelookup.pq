// OPTIONAL: persisted decayed risk register.
// A machine-maintained running per-object risk score with time decay. It COMPLEMENTS the dynamic
// windowed score (the incident rules) and does NOT replace them: use it for long-horizon entity
// risk, trend lines, and cheap executive/leaderboard views that survive the 24h/7d windows and even
// raw-event retention expiry. Deploy as a DAILY scheduled Hyperautomation flow (reuse the
// rba_collector.workflow.template.json shape: a single sync PowerQuery action bound to the
// 'SentinelOne SDL' Bearer connection running this body). The query reads its OWN prior output and
// applies decay, so risk persists without growing unbounded.
//
// Tokens: {{PREFIX}} (register name), {{DECAY}} (0.9 ~= one-week half-life; lower = shorter memory).
// Cadence must match the window: this body sums the last 24h, so run it once per day.
//
// Bootstrap: on the very first run the register does not exist yet and the `lookup` returns null
// (prev -> 0). If your tenant errors on a lookup against a non-existent table, seed it once by running
// this body with the `| lookup ... | let ... ` lines removed (writes today's scores as the initial
// register), then switch to the full decayed body below.
//
// Read it back for a persistent leaderboard with:  <name> from {{PREFIX}}RiskRegister ... (dashboard
// panel or | lookup), or query the savelookup like any datatable.

dataSource.name='risk' risk_object=*
| group today=sum(number(risk_score)), tactics_today=estimate_distinct(mitre_tactic), last_seen=newest(timestamp) by risk_object, risk_object_type
| lookup prev=risk_score_total from {{PREFIX}}RiskRegister by factor_key =:anycase risk_object
| let risk_score_total = (prev ? number(prev) : 0) * {{DECAY}} + today
| columns factor_key=risk_object, risk_object_type, risk_score_total, tactics_today, last_seen
| limit 100000
| savelookup '{{PREFIX}}RiskRegister'
