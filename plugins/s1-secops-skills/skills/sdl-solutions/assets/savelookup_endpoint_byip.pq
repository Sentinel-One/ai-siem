// IP-keyed endpoint enrichment table for NETWORK sources (firewall, proxy, DNS).
// device_ip is FIRST so the parser join works: `| lookup ... from <table> by device_ip = unmapped.<client_ip>`.
// Keyed on agentLastReportedIp. Empty riskFactors ("[]") is converted to null.
// Reuse ONE generic table (e.g. assetEndpointByIp) across all network sources; do not rebuild per source.
// Run through the powerquery LRQ runner. Persists as {{ENDPOINT_TABLE}}.
// Asset-binding keys for STAR-rule alerts (project these in the detection | columns and entityMappings):
//   device_assetid  = the unified asset id (the `id` from datasource assets). UNIVERSAL reconciliation key.
//   device_agentid  = the numeric console agent id (agentId). NOT agentUuid and NOT a uuid.
| datasource assets from 'surface/endpoint'
| filter name = *
| filter agentLastReportedIp = *
| columns device_ip=agentLastReportedIp, device_host=name, device_assetid=id, device_os=os,
          device_agentid=agentId, device_agentuuid=agentUuid, device_lastuser=agentLastLoggedInUser,
          device_site=s1SiteName, device_criticality=assetCriticality, _rf=riskFactors
| let device_riskfactors = (_rf == '[]' ? null : _rf)
| columns device_ip, device_host, device_assetid, device_os, device_agentid, device_agentuuid,
          device_lastuser, device_site, device_criticality, device_riskfactors
| limit 2000
| savelookup '{{ENDPOINT_TABLE}}'
