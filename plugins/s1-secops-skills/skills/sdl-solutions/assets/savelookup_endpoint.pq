// Endpoint enrichment table for the asset-enrichment solution.
// Keyed on hostname. Empty riskFactors ("[]") is converted to null.
// Run through the powerquery LRQ runner. Persists as {{ENDPOINT_TABLE}}.
// Asset-binding keys for STAR-rule alerts (stamp one into device.uid in the parser, plus a class_uid):
//   device_assetid  = the unified asset id (the `id` from datasource assets). This is the UNIVERSAL
//                     reconciliation key, the same id space resolves device / identity / cloud assets.
//   device_agentid  = the numeric console agent id (agentId), an endpoint alias that also resolves in
//                     device.uid. NOT agentUuid and NOT a uuid (a uuid does not bind the Target Asset).
| datasource assets from 'surface/endpoint'
| filter name = *
| filter agentUuid = *
| columns hostname=name, device_assetid=id, device_os=os, device_ip=agentLastReportedIp,
          device_agentid=agentId, device_agentuuid=agentUuid, device_lastuser=agentLastLoggedInUser,
          device_site=s1SiteName, device_criticality=assetCriticality, _rf=riskFactors
| let device_riskfactors = (_rf == '[]' ? null : _rf)
| columns hostname, device_assetid, device_os, device_ip, device_agentid, device_agentuuid,
          device_lastuser, device_site, device_criticality, device_riskfactors
| limit 2000
| savelookup '{{ENDPOINT_TABLE}}'
