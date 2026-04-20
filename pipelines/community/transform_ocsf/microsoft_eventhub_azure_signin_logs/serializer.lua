-- Constants for OCSF Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Convert ISO timestamp to milliseconds
local function parseTimestamp(timestamp)
    if not timestamp or type(timestamp) ~= "string" then
        return os.time() * 1000
    end
    
    -- Parse ISO 8601 format: 2023-12-07T15:30:45.123Z
    local year, month, day, hour, min, sec = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if year then
        local timeTable = {
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }
        return os.time(timeTable) * 1000
    end
    
    return os.time() * 1000
end

-- Determine severity based on event characteristics
local function getSeverityId(event)
    -- Check for error conditions first
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 4 -- High severity for errors
    end
    
    -- Check event category for severity indicators
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        if eventCategory == "Management" then
            return 3 -- Medium severity for management events
        elseif eventCategory == "Data" then
            return 2 -- Low severity for data events
        end
    end
    
    -- Default to informational
    return 1
end

-- Determine activity based on event characteristics
local function getActivityInfo(event)
    local errorCode = getNestedField(event, 'errorCode')
    local eventCategory = getNestedField(event, 'eventCategory')
    
    if errorCode then
        return 5, "Connection Failed" -- Connection failure activity
    elseif eventCategory == "Management" then
        return 2, "Connection Established" -- Management connection
    elseif eventCategory == "Data" then
        return 1, "Connection Started" -- Data connection
    else
        return 99, "Other" -- Unknown activity
    end
end

-- Field mappings for AWS CloudTrail to OCSF Network Activity
local fieldMappings = {
    -- Basic event information
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "metadata.product.feature.name"},
    {type = "direct", source = "recipientAccountId", target = "metadata.product.uid"},
    
    -- Network endpoints
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- User information mapped to connection context
    {type = "priority", source1 = "userIdentity.userName", source2 = "userIdentity.principalId", target = "connection_info.uid"},
    {type = "direct", source = "userIdentity.type", target = "connection_info.protocol_name"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "connection_info.session_uid"},
    
    -- TLS/Security information
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Request/Response context
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.name"},
    {type = "direct", source = "vpcEndpointId", target = "dst_endpoint.uid"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Additional metadata
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "apiVersion", target = "api.version"}
}

-- Main processing function
function processEvent(event)
    if type(event) ~= "table" then return nil end

    local result = {}
    local mappedPaths = {}

    -- Process field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getNestedField(event, mapping.source)
            if value ~= nil then 
                setNestedField(result, mapping.target, value) 
            end
            mappedPaths[mapping.source] = true
            
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if value == nil and mapping.source2 then 
                value = getNestedField(event, mapping.source2) 
            end
            if value ~= nil then 
                setNestedField(result, mapping.target, value) 
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end

    -- Set OCSF required fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = CLASS_NAME
    result.category_name = CATEGORY_NAME
    
    -- Set activity and type information
    local activity_id, activity_name = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    result.time = parseTimestamp(eventTime)
    
    -- Set metadata
    if not result.metadata then result.metadata = {} end
    if not result.metadata.product then result.metadata.product = {} end
    result.metadata.product.name = "AWS CloudTrail"
    result.metadata.product.vendor_name = "Amazon Web Services"
    
    -- Set status based on error conditions
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        result.status = "Failure"
        result.status_id = 2 -- Failure
    else
        result.status = "Success"
        result.status_id = 1 -- Success
    end
    
    -- Add observables for enrichment
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
    
    local userPrincipal = getNestedField(event, 'userIdentity.principalId')
    if userPrincipal then
        table.insert(observables, {
            type_id = 4,
            type = "User Name", 
            name = "connection_info.uid",
            value = userPrincipal
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    return result
end