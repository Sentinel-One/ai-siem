-- Constants for OCSF Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Get severity ID based on error codes and event patterns
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    -- Critical: Authentication/authorization failures
    if errorCode and (string.find(errorCode, "AccessDenied") or 
                     string.find(errorCode, "Forbidden") or 
                     string.find(errorCode, "Unauthorized")) then
        return 5  -- Critical
    end
    
    -- High: Error conditions
    if errorCode or errorMessage then
        return 4  -- High
    end
    
    -- Low: Normal activity
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory == "Data" then
        return 2  -- Low
    end
    
    return 1  -- Informational (default for most network activity)
end

-- Get activity ID and name based on event patterns
local function getActivityInfo(event)
    local eventCategory = getNestedField(event, 'eventCategory')
    local errorCode = getNestedField(event, 'errorCode')
    local userAgent = getNestedField(event, 'userAgent')
    local requestParams = getNestedField(event, 'requestParameters')
    
    -- Network access with errors
    if errorCode then
        return 5, "Network Access Denied"  -- Access denied
    end
    
    -- Data events (S3, etc.)
    if eventCategory == "Data" then
        return 2, "Network Data Transfer"  -- Data access
    end
    
    -- API calls
    if userAgent or requestParams then
        return 1, "Network API Call"  -- Network traffic
    end
    
    return 99, "Network Activity"  -- Other/Unknown
end

-- Field mappings for Network Activity
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    
    -- Network endpoints
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- Event details
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "metadata.product.feature.name"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- Actor/User information
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.uid"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_detail"},
    {type = "direct", source = "errorMessage", target = "status"},
    
    -- TLS details for network security
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Additional metadata
    {type = "direct", source = "vpcEndpointId", target = "connection_info.boundary"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account_uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
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
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if value == nil and mapping.source2 then 
                value = getNestedField(event, mapping.source2) 
            end
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity information
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set time from eventTime (AWS CloudTrail format)
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime and type(eventTime) == "string" then
        -- Parse ISO 8601 timestamp: 2023-12-01T10:30:00Z
        local year, month, day, hour, min, sec = eventTime:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        if year then
            local timestamp = os.time({
                year = tonumber(year),
                month = tonumber(month),
                day = tonumber(day),
                hour = tonumber(hour),
                min = tonumber(min),
                sec = tonumber(sec),
                isdst = false
            })
            result.time = timestamp * 1000  -- Convert to milliseconds
        else
            result.time = os.time() * 1000  -- Fallback to current time
        end
    else
        result.time = os.time() * 1000
    end
    
    -- Set status_id based on error presence
    if getNestedField(event, 'errorCode') then
        result.status_id = 2  -- Failure
    else
        result.status_id = 1  -- Success
    end
    
    -- Set product metadata
    setNestedField(result, "metadata.product.name", "SingularityIdentity")
    setNestedField(result, "metadata.product.vendor_name", "SentinelOne")
    
    -- Add protocol information if available
    if getNestedField(event, 'tlsDetails.tlsVersion') then
        result.protocol_name = "HTTPS"
    else
        result.protocol_name = "HTTP"  -- Default assumption for API calls
    end
    
    -- Create observables for network analysis
    local observables = {}
    local srcIp = getNestedField(event, 'sourceIPAddress')
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local userName = getNestedField(result, 'actor.user.name')
    if userName then
        table.insert(observables, {
            type_id = 4,
            type = "User Name", 
            name = "actor.user.name",
            value = userName
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end