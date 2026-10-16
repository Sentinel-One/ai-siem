# Account and site licences

How to set an account's and a site's SKUs, add-ons and licence settings through the Mgmt API.
Measured with a global-scope token, October 2026.

## Order: account first, then site

1. `PUT /web/api/v2.1/accounts/{id}` with `data.licenses.{bundles, modules, settings}`.
2. `PUT /web/api/v2.1/sites/{id}` with `data.licenses.{bundles, modules}`.

A site can only be given a bundle or add-on that its account already holds, so set the account
first.

- `PUT /sites` does not take `licenses.settings`: it returns `400 "Unknown field"`. Site licence
  settings follow the account.
- The account `PUT` needs a global-scope token. An account-scoped token gets
  `403 "Action limited to global users"`.

## Bundles and counts

- Bundles: `complete`, `hyperautomation`, `singularity_credits`, `singularity_data_lake`.
- Surface counts use `-1` for Unlimited.
- A site holds one endpoint suite only (core, control or complete).
- A new account starts with Total Agents 5 and Action Packs 1. Set these on the account as well:
  copying the site SKUs alone does not raise them.

## Console label to API module name

| Console label | Module name |
|---|---|
| Purple AI Foundations | `purple_ai` |
| Purple AI SOC Analyst | `purple_ai_soc_analyst` |
| Purple AI Agentic Investigations | `purple_ai_agentic_investigations` |
| Remote Script Orchestration | `rso` |
| RemoteOps Forensics | `remote_ops_forensics` |
| Network Discovery | `ranger` |
| Unprotected Endpoints Discovery | `rogues` |
| Vulnerability Management | `vulnerability_management` |
| Threat Intelligence | `threat_intel` |
| Data Ingest Retention 30 days | `xdr_30d_retention` |
| Long Range Retention 1 year | `xdr_extended_365d_retention` |

With the account setting `account_level_ranger = Account`, `ranger` and `rogues` live on the
account only and are not set per site.

## Provisioning many consoles or accounts

Configure one golden account by hand, then audit each target account and site against it before
deploying anything. Stop the deploy on any gap and report it; do not continue with a partial
licence set, because features that depend on a missing module fail later and less visibly.
