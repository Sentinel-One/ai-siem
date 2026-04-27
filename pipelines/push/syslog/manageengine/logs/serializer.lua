-- ManageEngine General Logs to OCSF Network Activity transformation
-- Class: Network Activity (4001), Category: Network Activity (4)

-- Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Helper functions for nested field access
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

function getValue(tbl, key, default)
    local value = tbl[key]
    return value ~= nil and value or default
end

function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Severity mapping based on error codes and event categories
function getSeverityId(errorCode, errorMessage, eventCategory)
    if errorCode then
        -- Error codes indicate issues
        if string.match(errorCode, "AccessDenied") or string.match(errorCode, "Forbidden") then
            return 4 -- High
        elseif string.match(errorCode, "Unauthorized") then
            return 3 -- Medium
        else
            return 2 -- Low
        end
    end
    if errorMessage then
        return 2 -- Low for any error message
    end
    if eventCategory and string.match(eventCategory, "Data") then
        return 3 -- Medium for data events
    end
    return 1 -- Informational for normal activity
end

-- Parse ISO timestamp to milliseconds since epoch
function parseTimestamp(timestamp)
    if not timestamp then return nil end
    local yr, mo, dy, hr, mn, sc = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
    return nil
end

-- Field mappings for ManageEngine logs to OCSF Network Activity
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "eventID", target = "metadata.event_code"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- Request parameters mappings
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "cloud.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.uid"},
    
    -- Resource mappings
    {type = "direct", source = "resources.accountId", target = "cloud.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "api.response.data.access_key_id"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "api.response.data.expiration"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "api.request.uid"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"}
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
    
    -- Set required OCSF fields with defaults
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = "Network Activity"
    result.category_name = "Network Activity"
    
    -- Determine activity based on event category or API call
    local eventCategory = getNestedField(event, "eventCategory")
    local eventName = getNestedField(event, "eventName")
    local activityId = 99 -- Other
    local activityName = "Unknown Activity"
    
    if eventCategory then
        if eventCategory == "Data" then
            activityId = 6 -- Traffic
            activityName = "Data Access"
        elseif eventCategory == "Management" then
            activityId = 1 -- Create
            activityName = "Management Activity"
        end
    end
    
    if eventName then
        activityName = eventName
    end
    
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity based on error conditions
    local errorCode = getNestedField(event, "errorCode")
    local errorMessage = getNestedField(event, "errorMessage")
    result.severity_id = getSeverityId(errorCode, errorMessage, eventCategory)
    
    -- Handle error details
    if errorCode then
        setNestedField(result, "status_detail", errorCode)
        setNestedField(result, "status_id", 2) -- Failure
    else
        setNestedField(result, "status_id", 1) -- Success
    end
    
    if errorMessage then
        setNestedField(result, "status_detail", errorMessage)
    end
    
    -- Parse timestamp
    local eventTime = getNestedField(event, "eventTime")
    if eventTime then
        local timestamp = parseTimestamp(eventTime)
        if timestamp then
            result.time = timestamp
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end
    
    -- Set metadata
    setNestedField(result, "metadata.product.name", "ManageEngine")
    setNestedField(result, "metadata.product.vendor_name", "ManageEngine")
    setNestedField(result, "metadata.version", getNestedField(event, "eventVersion") or "1.0")
    
    -- Set protocol name if TLS details are present
    if getNestedField(event, "tlsDetails.tlsVersion") then
        result.protocol_name = "HTTPS"
    end
    
    -- Mark mapped fields to avoid duplicating in unmapped
    local allMappedPaths = {
        eventTime = true,
        eventCategory = true,
        eventName = true,
        errorCode = true,
        errorMessage = true,
        eventVersion = true
    }
    for k, _ in pairs(mappedPaths) do
        allMappedPaths[k] = true
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, allMappedPaths, result)
    
    return result
end