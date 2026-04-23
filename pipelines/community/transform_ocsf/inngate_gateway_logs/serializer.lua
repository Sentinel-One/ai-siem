-- InnGate Gateway Logs to OCSF Network Activity transformation
-- Class: Network Activity (4001), Category: Network Activity (4)

-- Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

-- Helper functions
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

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    local year, month, day, hour, min, sec = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if year then
        return os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }) * 1000
    end
    return nil
end

-- Determine activity based on event category or error conditions
function getActivityInfo(event)
    local activity_id = 99 -- Other
    local activity_name = "Unknown Network Activity"
    
    local eventCategory = getNestedField(event, 'eventCategory')
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        activity_id = 5 -- Network Access Denied or similar
        activity_name = "Network Access Error"
    elseif eventCategory then
        if eventCategory:lower():find("data") then
            activity_id = 6 -- Network Traffic
            activity_name = "Data Transfer"
        elseif eventCategory:lower():find("management") then
            activity_id = 1 -- Network Connect
            activity_name = "Management Activity"
        else
            activity_id = 6 -- Network Traffic
            activity_name = "Network Traffic"
        end
    end
    
    return activity_id, activity_name
end

-- Determine severity based on error conditions and event type
function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        if errorCode and (errorCode:find("Access") or errorCode:find("Denied") or errorCode:find("Forbidden")) then
            return 4 -- High
        else
            return 3 -- Medium
        end
    end
    
    return 1 -- Informational for normal network activity
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "eventID", target = "metadata.event_code"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "metadata.product.feature.name"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "vpcEndpointId", target = "connection_info.boundary"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- Host/destination mappings
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.hostname"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.user.name"},
    
    -- Error mappings
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- TLS information
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- Resources
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.name", value = "InnGate Gateway"},
    {type = "computed", target = "metadata.product.vendor_name", value = "InnGate"},
    {type = "computed", target = "type_name", value = "Network Activity: Unknown"},
}

-- Main processing function
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
            if value == nil or value == "" then
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
    local activity_id, activity_name = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    
    -- Compute type_uid
    result.type_uid = CLASS_UID * 100 + activity_id

    -- Set severity
    result.severity_id = getSeverityId(event)

    -- Parse timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        local timeMs = parseTimestamp(eventTime)
        if timeMs then
            result.time = timeMs
        else
            result.time = os.time() * 1000
        end
        mappedPaths['eventTime'] = true
    else
        result.time = os.time() * 1000
    end

    -- Set status based on error conditions
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        result.status = "Failure"
        result.status_id = 2 -- Failure
    else
        result.status = "Success"
        result.status_id = 1 -- Success
    end

    -- Set protocol name if we can infer it
    local tlsVersion = getNestedField(event, 'tlsDetails.tlsVersion')
    if tlsVersion then
        result.protocol_name = "HTTPS"
    else
        result.protocol_name = "HTTP"
    end

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    -- Set raw_data if message exists
    if result.message then
        result.raw_data = result.message
    end

    return result
end