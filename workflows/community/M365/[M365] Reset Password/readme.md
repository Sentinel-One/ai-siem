# [M365] Reset Password

**Version**: 1.0.0  
**Last Updated**: 2026-03-27

## Purpose
Forces a password reset on a Microsoft 365 user account to invalidate stolen or compromised credentials.

## Trigger
- **Type**: Alert
- **Conditions**: Credential compromise indicators (e.g., password spray, unusual sign-ins)

## Integration Dependencies
- Microsoft Graph API (UserAuthenticationMethod.ReadWrite.All)
- SentinelOne HyperAutomation

## Workflow Diagram

```mermaid
flowchart TD
    A[Alert Trigger] --> B{Extract UPN}
    B --> C[Force Password Reset]
    C --> D[Notify User via Alternate Contact]
    D --> E[Add Reset Details to Alert]
    E --> F[Workflow Complete]
```

## Execution Steps

1. Extract user principal name.
2. Force password reset via Graph API.
3. Optionally notify user and log the action.
