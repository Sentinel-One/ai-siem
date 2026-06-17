# Hashes

1 endpoints.

## `GET /web/api/v2.1/hashes/{hash}/verdict`
**Hash Reputation verdict**
`operationId`: `_web_api_hashes_{hash}_verdict_get`

[DEPRECATED] Get the verdict of the of a hash, given the required SHA1.
A hash, either malicious or non-malicious, means it has been marked as such by the Reputation's sources.	
An unknown answer is given for hashes that are not yet known by Reputation.

Required permissions: `Blacklist.view`

Parameters:
- `hash` [path, string] **required** — Hash

Responses: 200 Verdict of the hash known to the management, 401 Unauthorized access - please sign in and retry.
