# licenses

1 endpoints.

## `PUT /web/api/v2.1/licenses/update-sites-modules`
**Update sites add-ons**
`operationId`: `_web_api_licenses_update-sites-modules_put`

Change the add-ons of the sites by a given filter

Required permissions: `Sites.edit`

Parameters:
- `body` [body, licenses.schemas_SiteBulkModulesSchema] — 

Responses: 200 Success, 400 Invalid user input received. See error details for further i, 401 Unauthorized access - please sign in and retry.
