# Okta Hyperautomation Workflows

## Overview

Okta Shared Signals Framework (SSF) is an [OpenID Foundation standard](https://openid.net/wg/sharedsignals/) integrated into Okta Identity Engine that enables real-time security event sharing between Okta and third-party apps. It allows Okta to receive or transmit security signals (like user risk changes, session revocation, or device non-compliance) to instantly trigger automated policy actions, such as forcing reauthentication. 

#### Key Aspects of Okta SSF:

- **Real-Time Security**: Unlike polling, SSF acts instantly when security events occur, supporting zero-trust architectures.
- **Key Profiles**: SSF primarily uses Continuous Access Evaluation Profile (CAEP) for session/token events and Risk Incident Sharing and Coordination (RISC) for account-level threats.
- **Automated Responses**: If a security app detects a threat (e.g., malware or impossible travel), it signals Okta, which can immediately revoke access.
- **Supported Events**: Common events include "Session Revoked" and "Credential Change".
- **Integration**: Used alongside Identity Threat Protection with Okta AI to strengthen security posture.

The workflows provided in this library connect Okta and the SentinelOne Singularity platform using SSF through Hyperautomation. 

## Next Steps

Before continuing with these workflows, please review the following documentation:

- [Import the Workflows](./docs/importing-the-workflows.md)
- [Configure Hyperautomation Integrations](./docs/setting-up-hyperautomation-integrations.md)
- [Configure SSF for Okta](./docs/configure-okta-ssf.md)

## Available Workflows

The following workflows are available:

- [Okta - Send Device Risk Change Event via SSF](./docs/send-device-risk-change-event-via-ssf.md)
