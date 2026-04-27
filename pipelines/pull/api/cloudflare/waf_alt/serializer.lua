-- Cloudflare WAF to OCSF HTTP Activity transformation
-- OCSF Class: HTTP Activity (4002)

local CLASS_UID = 4002
local CATEGORY_UID = 4

-- Nested field access (production-proven from Observo scripts)
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

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Get severity ID based on error conditions
local function getSeverityId(event)
    -- Check for error conditions
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        return 4 -- High severity for errors
    end
    
    -- Check event category for security events
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory == "Management" then
        return 2 -- Low for management events
    elseif eventCategory == "Data" then
        return 3 -- Medium for data events
    end
    
    return 1 -- Informational as default
end

-- Map activity based on event patterns
local function getActivityInfo(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 3, "HTTP Response Error" -- activity_id 3 for errors
    end
    
    -- Check for specific request patterns
    local bucketName = getNestedField(event, 'requestParameters.bucketName')
    local instanceId = getNestedField(event, 'requestParameters.instanceId')
    
    if bucketName then
        return 2, "HTTP Response" -- activity_id 2 for S3 operations
    elseif instanceId then
        return 2, "HTTP Response" -- activity_id 2 for EC2 operations
    end
    
    return 1, "HTTP Request" -- activity_id 1 as default
end

-- Field mappings configuration
local fieldMappings = {
    -- Basic event fields
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    
    -- Source endpoint
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    
    -- HTTP request fields
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    
    -- Actor/User information
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Network details
    {type = "direct", source = "vpcEndpointId", target = "dst_endpoint.vpc_uid"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.resource"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "http_response.header.access_key_id"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "http_response.header.expiration"},
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "http_response.header.x_amz_id_2"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "Cloudflare WAF"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Cloudflare"},
}

function processEvent(event)
    if type(event) ~= "table" then return nil end

    local result = {}
    local mappedPaths = {}

    -- Process field mappings
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

    -- Set activity information
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Handle time field - convert ISO timestamp to milliseconds
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime and type(eventTime) == "string" then
        -- Parse ISO 8601 timestamp: 2023-01-01T12:00:00Z
        local yr, mo, dy, hr, mn, sc = eventTime:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        if yr then
            local timestamp = os.time({
                year = tonumber(yr),
                month = tonumber(mo),
                day = tonumber(dy),
                hour = tonumber(hr),
                min = tonumber(mn),
                sec = tonumber(sc),
                isdst = false
            })
            result.time = timestamp * 1000
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end

    -- Set HTTP status based on error conditions
    if getNestedField(event, 'errorCode') then
        result.status_id = 2 -- Failure
        result.status = "Failure"
        -- Map common AWS error codes to HTTP status codes
        local errorCode = getNestedField(event, 'errorCode')
        if errorCode == "AccessDenied" then
            setNestedField(result, "http_response.code", 403)
        elseif errorCode == "NoSuchBucket" or errorCode == "NoSuchKey" then
            setNestedField(result, "http_response.code", 404)
        elseif errorCode == "InvalidRequest" then
            setNestedField(result, "http_response.code", 400)
        else
            setNestedField(result, "http_response.code", 500)
        end
    else
        result.status_id = 1 -- Success
        result.status = "Success"
        setNestedField(result, "http_response.code", 200)
    end

    -- Create observables for security analysis
    local observables = {}
    local sourceIP = getNestedField(event, 'sourceIPAddress')
    if sourceIP then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = sourceIP
        })
    end
    
    local userAgent = getNestedField(event, 'userAgent')
    if userAgent then
        table.insert(observables, {
            type_id = 6,
            type = "User Agent",
            name = "http_request.user_agent",
            value = userAgent
        })
    end
    
    local principalId = getNestedField(event, 'userIdentity.principalId')
    if principalId then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.uid",
            value = principalId
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end

    -- Mark mapped paths for unmapped field collection
    local additionalMappedPaths = {
        "eventTime", "eventCategory", "userIdentity", "requestParameters",
        "responseElements", "additionalEventData", "tlsDetails", "resources"
    }
    for _, path in ipairs(additionalMappedPaths) do
        mappedPaths[path] = true
    end

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    return result
end