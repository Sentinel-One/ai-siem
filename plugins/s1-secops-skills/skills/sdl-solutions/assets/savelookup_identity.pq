// Identity enrichment table for the asset-enrichment solution.
// Keyed on {{USERNAME_KEY}} (samAccountName or principalName).
// Empty riskFactors ("[]") is converted to null so enrichment never writes an empty field.
// Run through the powerquery LRQ runner. Persists as {{IDENTITY_TABLE}}.
// user_assetid = the unified asset id (the `id` from datasource assets). Stamp it into user.uid
//   in the parser (plus an Identity class_uid such as 3002) to bind this user as the alert's
//   Target Asset on an events-type STAR rule. An objectSid / objectGuid / RANGER id only TYPES the
//   asset as "AD User"; only the unified asset id resolves the specific named identity.
// The `| sort username` before the limit makes the kept subset DETERMINISTIC on directories
// larger than the cap. Raise the `| limit` to cover the full directory; 1000 is a template
// default, not a platform cap (lookup tables allow up to 150 MB).
| datasource assets from 'surface/identity'
| filter resourceType = 'AD User'
| filter objectSid = *
| columns username={{USERNAME_KEY}}, user_assetid=id, user_principal=principalName, user_sid=objectSid,
          user_domain=domain, user_dn=distinguishedName, user_groups=memberOf,
          user_privileged=privileged, user_criticality=assetCriticality, _rf=riskFactors
| let user_riskfactors = (_rf == '[]' ? null : _rf)
| columns username, user_assetid, user_principal, user_sid, user_domain, user_dn, user_groups,
          user_privileged, user_criticality, user_riskfactors
| sort username
| limit 1000
| savelookup '{{IDENTITY_TABLE}}'
