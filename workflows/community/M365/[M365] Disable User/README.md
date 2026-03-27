# [M365] Disable User

**Version**: 1.0.0  
**Last Updated**: 2026-03-27

## Purpose
Automatically disables a Microsoft 365 user account when triggered by a high-severity alert. This serves as a rapid containment action to prevent further lateral movement or data access by a potentially compromised account.

## Trigger
- **Type**: Alert (SentinelOne AI SIEM or Singularity XDR)
- **Conditions**: High severity alert involving user compromise indicators

## Integration Dependencies
- Microsoft Graph API (Users.ReadWrite.All permission)
- SentinelOne HyperAutomation

## Detailed Workflow Diagram (JSON-aligned)

```mermaid
flowchart TD
    Start[Trigger: Alert Received] --> ExtractUPN["Extract userPrincipalName from alert payload"]
    ExtractUPN --> Validate{"Validate UPN exists?"}
    Validate -->|No| ErrorNote["Add error note: Missing UPN"]
    Validate -->|Yes| DisableCall["Microsoft Graph: PATCH /users/{id} - accountEnabled: false"]
    DisableCall --> Revoke["Microsoft Graph: POST /users/{id}/revokeSignInSessions"]
    Revoke --> SuccessCheck{"Success?"}
    SuccessCheck -->|Yes| UpdateNote["Update alert with success details + timestamp"]
    SuccessCheck -->|No| ErrorPath["Update alert with failure reason + error code"]
    UpdateNote --> End[Workflow Complete]
    ErrorPath --> End
    ErrorNote --> End
```

## Execution Steps (Directly from JSON)

1. Parse userPrincipalName or userId from incoming alert payload.
2. Call Microsoft Graph PATCH /users/{id} to set accountEnabled: false.
3. Call Microsoft Graph POST /users/{id}/revokeSignInSessions.
4. Update the original alert note with success/failure details and timestamp.
