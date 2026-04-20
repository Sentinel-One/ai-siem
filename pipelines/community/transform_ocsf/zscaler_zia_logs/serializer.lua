-- Production helper functions (copy these verbatim)
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

-- Constants for OCSF Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Field mappings configuration
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Network endpoints
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- User/Actor information
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    
    -- AWS specific fields
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "connection_info.boundary"},
    
    -- Request/Response data
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.bucketName", target = "resources.name"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    
    -- Error handling
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- TLS information
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Message and metadata
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
}

-- Determine activity ID based on event category
local function getActivityId(eventCategory)
    if eventCategory == nil then return 99 end -- Other
    
    local activityMap = {
        ["Data"] = 1,      -- Access
        ["Management"] = 2, -- Create/Update/Delete
        ["Insight"] = 3,   -- Read
    }
    
    return activityMap[eventCategory] or 99 -- Other
end

-- Determine severity based on error conditions
local function getSeverityId(event)
    local errorCode = getNestedField(event, "errorCode")
    local errorMessage = getNestedField(event, "errorMessage")
    
    if errorCode or errorMessage then
        return 4 -- High - indicates an error occurred
    end
    
    local eventCategory = getNestedField(event, "eventCategory")
    if eventCategory == "Management" then
        return 3 -- Medium - management operations are significant
    end
    
    return 1 -- Informational - normal operations
end

-- Parse ISO timestamp to milliseconds since epoch
local function parseEventTime(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    
    local year, month, day, hour, min, sec = timeStr:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
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

-- Get activity name based on event category
local function getActivityName(event)
    local eventCategory = getNestedField(event, "eventCategory")
    local errorCode = getNestedField(event, "errorCode")
    
    if errorCode then
        return "Network Error"
    elseif eventCategory == "Data" then
        return "Data Access"
    elseif eventCategory == "Management" then
        return "Management Operation"
    elseif eventCategory == "Insight" then
        return "Insight Query"
    else
        return "Network Activity"
    end
end

-- Main entry point
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Apply field mappings
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
    
    -- Set activity_id and compute type_uid
    local activityId = getActivityId(getNestedField(event, "eventCategory"))
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set activity name
    result.activity_name = getActivityName(event)
    
    -- Parse and set time
    local eventTime = getNestedField(event, "eventTime")
    if eventTime then
        result.time = parseEventTime(eventTime)
        mappedPaths["eventTime"] = true
    end
    
    -- Default time if parsing failed
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set metadata
    setNestedField(result, "metadata.product.name", "Zscaler ZIA")
    setNestedField(result, "metadata.product.vendor_name", "Zscaler")
    
    -- Set status based on error conditions
    local errorCode = getNestedField(event, "errorCode")
    if errorCode then
        result.status = "Failure"
        result.status_id = 2 -- Failure
    else
        result.status = "Success"
        result.status_id = 1 -- Success
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end