# add_ip_to_fortigate_blocklist

**Version**: 1.0.0  
**Last Updated**: 2026-04-04

## Purpose
Adds a provided IP address to the FortiGate firewall blocklist. The workflow first checks if an address object for that IP already exists. If it does not, it creates a new /32 host address object named `blocked_{IP}` with an appropriate comment. This is commonly used as a containment action for IOCs or malicious IPs identified by SentinelOne.

## Trigger
- **Type**: Manual (with dynamic input for the IP to block)
- **Conditions**: None (manual execution)

## Integration Dependencies
- FortiGate Firewall REST API (v2) – requires authenticated connection with permissions to read/write `firewall/address` objects
- SentinelOne HyperAutomation

## Detailed Workflow Diagram (JSON-aligned)

```mermaid
flowchart TD
    Start[Manual Trigger] --> InputIP["Input: ipToBlock (required)"]
    InputIP --> ResetList["Reset member list variable to []"]
    ResetList --> GetObject["HTTP GET /api/v2/cmdb/firewall/address?filter=name=@{{ipToBlock}}"]
    GetObject --> ParseJSON["Parse JSON response"]
    ParseJSON --> Flatten["Flatten results array"]
    Flatten --> ObjectExists{"Does object already exist?"}
    ObjectExists -->|Yes| ExtractName["Extract existing object name"]
    ObjectExists -->|No| CreateObject["HTTP POST /api/v2/cmdb/firewall/address\n{name: blocked_{{ipToBlock}}}, subnet: {{ipToBlock}}/32"]
    CreateObject --> ParseCreate["Parse create response"]
    ParseCreate --> SuccessCheck{"Status == success and code 200?"}
    SuccessCheck -->|Yes| UpdateNote["Update alert / log success with object details"]
    SuccessCheck -->|No| ErrorPath["Update with failure reason + status code"]
    ExtractName --> UpdateNote
    UpdateNote --> End[Workflow Complete]
    ErrorPath --> End
```
