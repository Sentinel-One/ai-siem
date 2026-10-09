# Security Policy

## Supported Versions

AI-SIEM is a content library (parsers, dashboards, detections, workflows and
helper scripts), released continuously from `main`. Only the latest release
and the current `main` branch receive fixes. Older tagged releases are not
patched; update to the latest release instead.

## Reporting a Vulnerability

**Please do not open a public issue, pull request or discussion for a
security problem.**

Report privately using the *Report a vulnerability* button on the repository's
**Security** tab. If that button is not available, email **security@sentinelone.com**. Include in your private report:

- the affected file(s) or component and the commit or release you tested
- what the issue is and how it could be abused
- steps to reproduce, or a proof of concept if you have one

What to expect:

| Step | Target |
| ---- | ------ |
| Acknowledgement of your report | within 5 business days |
| Initial assessment and severity | within 10 business days |
| Status updates | at least every 14 days until resolved |

If the report is accepted, we will work on a fix, credit you in the release
notes if you wish, and coordinate disclosure with you. If it is declined (for
example, it is out of scope or not reproducible), we will explain why.

## Scope

In scope: anything shipped in this repository, including the Python monitors
in `monitors/`, the MCP server and plugin code, CI configuration, and
parser, dashboard, detection and workflow content that could cause unsafe
behaviour when imported (for example, injection through crafted log fields or
overly permissive response actions).

Out of scope: vulnerabilities in third-party products that this content
parses or integrates with (report those to the vendor), and findings that
require an already-compromised tenant or console.

## Exposed Credentials

Never commit real API keys, tokens, passwords or tenant identifiers. Use
obvious placeholders (`<API_TOKEN>`, `example.com`) in templates and sample
logs. Pull requests are scanned for verified secrets. If you find a live
credential in the repository or its history, report it as above and rotate
it immediately; removing it from the latest commit is not enough.
