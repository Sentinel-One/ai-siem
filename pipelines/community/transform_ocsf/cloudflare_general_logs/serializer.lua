-- Cloudflare General Logs to OCSF HTTP Activity transformation
-- Class: HTTP Activity (4002), Category: Network Activity (4)

local CLASS_UID = 4002
local CATEGORY_UID = 4

-- Nested field access
function getNestedField(obj, path)
    if obj == nil or path == nil or path == '' then return nil end
    local current = obj
    for key in string.gmatch(path, '[^.]+') do
        if current == nil or current[key] == nil then return nil end
        current = current[key]
    end
    return current
end

function setNestedField(obj, path, value)
    if value == nil or path == nil or path == '' then return end
    local keys = {}
    for key in string.gmatch(path, '[^.]+') do table.insert(keys, key) end
    if #keys == 0 then return end
    local current = obj
    for i = 1, #keys - 1 do
        if current[keys[i]] == nil then current[keys[i]] = {} end
        current = current[keys[i]]
    end
    current[keys[#keys]] = value
end

-- Safe value access with default
function getValue(tbl, key, default)
    local value = tbl[key]
    return value ~= nil and value or default
end

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Get severity ID from error codes or event category
local function getSeverityId(errorCode, eventCategory)
    if errorCode then
        -- Map common error patterns to severity
        if string.match(errorCode, "AccessDenied") or string.match(errorCode, "Unauthorized") then
            return 4 -- High
        elseif string.match(errorCode, "InvalidRequest") or string.match(errorCode, "BadRequest") then
            return 3 -- Medium
        else
            return 2 -- Low
        end
    end
    
    if eventCategory then
        if eventCategory == "Management" then
            return 1 -- Informational
        elseif eventCategory == "Data" then
            return 2 -- Low
        end
    end
    
    return 0 -- Unknown
end

-- Parse ISO timestamp to milliseconds
local function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then
        return os.time() * 1000
    end
    
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        return os.time({
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        }) * 1000
    end
    
    return os.time() * 1000
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct field mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc.uid"},
    
    -- Nested field mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.session.issuer"},
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.resource"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "dst_endpoint.availability_zone"},
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "http_response.headers.access_key_id"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "http_response.headers.expiration"},
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "http_response.headers.x_amz_id_2"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "CloudFlare"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Cloudflare"},
}

function processEvent(event)
    if type(event) ~= "table" then return nil end

    local result = {}
    local mappedPaths = {}

    -- Apply field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getNestedField(event, mapping.source)
            if value ~= nil and value ~= "" then 
                setNestedField(result, mapping.target, value) 
            end
            mappedPaths[mapping.source] = true
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end

    -- Set activity details
    local eventCategory = getValue(event, "eventCategory", "")
    local activityId = 99 -- Other
    local activityName = "HTTP Request"
    
    if eventCategory == "Management" then
        activityId = 1 -- Create
        activityName = "Management Request"
    elseif eventCategory == "Data" then
        activityId = 2 -- Read
        activityName = "Data Access Request"
    end
    
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId

    -- Set severity based on error code and category
    result.severity_id = getSeverityId(event.errorCode, event.eventCategory)

    -- Parse timestamp
    result.time = parseTimestamp(event.eventTime)

    -- Set HTTP response code if error present
    if event.errorCode then
        if event.errorCode == "AccessDenied" then
            result.status_id = 2 -- Failure
            setNestedField(result, "http_response.code", 403)
            setNestedField(result, "http_response.message", "Forbidden")
        elseif event.errorCode == "InvalidRequest" then
            result.status_id = 2 -- Failure
            setNestedField(result, "http_response.code", 400)
            setNestedField(result, "http_response.message", "Bad Request")
        else
            result.status_id = 2 -- Failure
            setNestedField(result, "http_response.code", 500)
            setNestedField(result, "http_response.message", "Internal Server Error")
        end
    else
        result.status_id = 1 -- Success
        setNestedField(result, "http_response.code", 200)
        setNestedField(result, "http_response.message", "OK")
    end

    -- Mark mapped paths for unmapped collection
    mappedPaths["eventCategory"] = true
    mappedPaths["eventTime"] = true
    mappedPaths["errorCode"] = true

    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)

    -- Create observables for enrichment
    local observables = {}
    if event.sourceIPAddress then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "src_endpoint.ip",
            value = event.sourceIPAddress
        })
    end
    if getNestedField(event, "userIdentity.principalId") then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.uid", 
            value = getNestedField(event, "userIdentity.principalId")
        })
    end
    if #observables > 0 then
        result.observables = observables
    end

    return result
end