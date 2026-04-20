-- F5 Networks logs transformation to OCSF Network Activity (4001)
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

-- Determine severity based on error conditions and event context
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    local eventCategory = getNestedField(event, 'eventCategory')
    
    -- High severity for authentication/access errors
    if errorCode and (string.find(errorCode:lower(), 'denied') or 
                     string.find(errorCode:lower(), 'unauthorized') or
                     string.find(errorCode:lower(), 'forbidden')) then
        return 4
    end
    
    -- Medium severity for other errors
    if errorCode or errorMessage then
        return 3
    end
    
    -- Low severity for data events, informational for management events
    if eventCategory then
        if eventCategory:lower() == 'data' then
            return 2
        elseif eventCategory:lower() == 'management' then
            return 1
        end
    end
    
    return 1 -- Default to informational
end

-- Convert ISO timestamp to milliseconds since epoch
local function parseEventTime(timeStr)
    if not timeStr then return nil end
    
    -- Parse ISO 8601 format: 2023-01-01T12:00:00Z or 2023-01-01T12:00:00.123Z
    local pattern = "(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)"
    local year, month, day, hour, min, sec = timeStr:match(pattern)
    
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
        return timestamp * 1000
    end
    
    return nil
end

-- Get activity name based on event context
local function getActivityName(event)
    local eventCategory = getNestedField(event, 'eventCategory') or ""
    local errorCode = getNestedField(event, 'errorCode')
    local bucketName = getNestedField(event, 'requestParameters.bucketName')
    local instanceId = getNestedField(event, 'requestParameters.instanceId')
    
    if errorCode then
        return "Network Error - " .. errorCode
    elseif bucketName then
        return "S3 Network Access"
    elseif instanceId then
        return "EC2 Network Activity"
    elseif eventCategory and eventCategory ~= "" then
        return "Network " .. eventCategory:gsub("^%l", string.upper)
    else
        return "Network Communication"
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    
    -- Network endpoint mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- Message and metadata
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "metadata.product.name"},
    {type = "computed", target = "metadata.product.vendor_name", value = "F5 Networks"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    
    -- TLS details as connection info
    {type = "direct", source = "tlsDetails.tlsVersion", target = "connection_info.protocol_ver"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "connection_info.cipher_suite"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- User identity information
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    
    -- AWS specific fields
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resource.uid"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    {type = "direct", source = "requestParameters.bucketName", target = "resource.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "resource.uid"},
    
    -- Additional event data
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
}

function processEvent(event)
    -- Input validation
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
    
    -- Set time from eventTime
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        local timeMs = parseEventTime(eventTime)
        if timeMs then
            result.time = timeMs
        end
        mappedPaths['eventTime'] = true
    end
    
    -- Set default time if not parsed
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set activity based on event context
    local activityId = 99 -- Other/Unknown
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        activityId = 2 -- Deny/Block
    else
        activityId = 1 -- Allow/Accept
    end
    
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.activity_name = getActivityName(event)
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set status_id based on error presence
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        result.status_id = 0 -- Failure
    else
        result.status_id = 1 -- Success
    end
    
    -- Set protocol name if TLS version exists
    if getNestedField(event, 'tlsDetails.tlsVersion') then
        result.protocol_name = "HTTPS/TLS"
    end
    
    -- Create observables for key network indicators
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
            name = "metadata.product.name", 
            value = userAgent
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths
    mappedPaths['errorCode'] = true
    mappedPaths['errorMessage'] = true
    mappedPaths['eventCategory'] = true
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end