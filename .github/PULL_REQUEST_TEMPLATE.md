## Summary

<!-- What does this change and why? -->

## Component type

- [ ] Parser
- [ ] Dashboard
- [ ] Detection
- [ ] Workflow
- [ ] Pipeline / monitor / tooling
- [ ] Docs / repo hygiene

## Checklist

- [ ] Follows the `vendor-usecase-vX.Y` naming convention and directory layout
- [ ] Includes a complete `metadata.yaml` (`.yaml`, not `.yml`)
- [ ] Parsers: sample logs added under `tests/fixtures/`
- [ ] No real credentials, tenant hostnames or IDs (account, site, alert), customer data or internal hostnames. Use placeholders such as `your-console.sentinelone.net`
- [ ] Write-capable components (anything that creates, changes or deletes tenant objects, takes response actions, or ingests data) are called out in the description, and default to read-only or disabled where possible
- [ ] Dependencies, GitHub Actions and images are pinned (commit SHA, image digest or exact version), not floating tags
- [ ] Linked the tracking or review ticket, if one exists (issue number or ticket reference): 
- [ ] `CHANGELOG.md` updated under **Unreleased** (if user-visible)

## How was this tested?

<!-- e.g. imported into a tenant and validated against sample data -->
