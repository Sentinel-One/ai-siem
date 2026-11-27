# Cloudflare Hyperautomation Workflows

This folder contains SentinelOne × Cloudflare co-developed Hyperautomation workflows that extend endpoint threat intelligence to Cloudflare's WAF, Zero Trust, and Email Security services.

## Structure Notes

- **Action folders** follow the standard pattern used elsewhere in `workflows/community/`.
- **General guides** have been moved to `general-guides/` because they apply to Hyperautomation usage in general.
- **Detailed workflow documentation** from the original `/docs` folder is preserved ("grandfathered") inside each action's `docs/` subfolder due to its high quality and extensive screenshots.

## Available Workflows

### 1. Automated WAF Policy Enforcement based on Risk Score
See [`Automated WAF Policy Enforcement based on Risk Score/readme.md`](./Automated%20WAF%20Policy%20Enforcement%20based%20on%20Risk%20Score/readme.md)

Detailed original guide: [`workflow-automated-waf-policy-risk.md`](./Automated%20WAF%20Policy%20Enforcement%20based%20on%20Risk%20Score/workflow-automated-waf-policy-risk.md)

### 2. Revoke Zero Trust Access on High IoC
See [`Revoke Zero Trust Access on High IoC/readme.md`](./Revoke%20Zero%20Trust%20Access%20on%20High%20IoC/readme.md)

Detailed original guide: [`workflow-revoke-zta-on-high-ioc.md`](./Revoke%20Zero%20Trust%20Access%20on%20High%20IoC/workflow-revoke-zta-on-high-ioc.md)

## General Hyperautomation Guides (applicable beyond Cloudflare)
- [Importing the Workflows](../../docs-guides/importing-the-workflows.md)
- [Setting up Hyperautomation Integrations](../../docs-guides/setting-up-hyperautomation-integrations.md)
