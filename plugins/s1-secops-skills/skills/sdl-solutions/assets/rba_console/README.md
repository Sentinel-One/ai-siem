# RBA demo console (optional)

A local, browser-based console for demoing Risk-Based Alerting. Zero dependencies beyond the
Python 3 that ships with macOS. It reads your SentinelOne credentials from the environment or the
OS keychain at runtime (nothing hard-coded, no config file) and proxies SDL calls, so the browser never holds a token and CORS
is not an issue.

## Files

- `server.py` - zero-dependency proxy + static server (stdlib `http.server`, ~90 lines).
- `index.html` - single-page 4-tab UI: Talk track, Deployed artefacts, Live risk, Risk factor editor.

## Run

```bash
cd rba_console
python3 server.py
# then open http://localhost:8787  (use the localhost URL, NOT file://, file:// has no proxy)
```

Ctrl-C to stop. Override the port with `RBA_PORT=9000 python3 server.py`.

## Credentials

`server.py` reads `S1_CONSOLE_URL` and `S1_CONSOLE_API_TOKEN` at runtime from the environment,
else the OS keychain (service `sentinelone-mcp`, account `<S1_PROFILE>:<NAME>`, the items
`s1-secops-mcp setup` writes). It reads no config file. To target a different tenant, store that
tenant under its own profile and start the server with `S1_PROFILE=<name>`; on Windows the
keychain read needs the Python `keyring` package. The proxy exposes three POST/JSON endpoints: `/api/powerQuery {query,startTime}`,
`/api/getFile {path}`, `/api/putFile {path,content}`.

## Tabs

- Talk track - the demo script, on screen.
- Deployed artefacts - what each RBA artefact is and does.
- Live risk - 24h leaderboard + count tiles, live from `dataSource.name='risk'`.
- Risk factor editor - read / edit / save `{{PREFIX}}RiskFactors.csv` in the Data Lake, with a live
  "projected impact" panel (Sigma base_score x current multiplier vs the fire threshold). This is the
  same table the collector joins on every run, so edits take effect on the next collector cycle.

## Template tokens (render before shipping to a customer)

`{{ACCOUNT_NAME}}`, `{{ACCOUNT_ID}}`, `{{PREFIX}}`, and the four `{{RULE_*_ID}}` values shown in the
Deployed artefacts tab (`{{RULE_USER_CUM_ID}}`, `{{RULE_HOST_CUM_ID}}`, `{{RULE_USER_TAC_ID}}`,
`{{RULE_HOST_TAC_ID}}`). The factor-table path is `/datatables/{{PREFIX}}RiskFactors.csv`. The demo
object base-score sums in the "projected impact" panel (`BASE` in index.html) are illustrative, adjust
to the seeded scenario.
