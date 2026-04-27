-- Constants
local CLASS_UID = 4001
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

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
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
    return nil
end

-- Map severity from error codes or event categories
function getSeverityId(errorCode, errorMessage, eventCategory)
    -- If there's an error, it's at least medium severity
    if errorCode and errorCode ~= "" then
        return 3 -- Medium
    end
    if errorMessage and errorMessage ~= "" then
        return 3 -- Medium
    end
    -- Default to informational for network activity
    return 1
end

-- Determine activity based on event context
function getActivityId(eventCategory, errorCode, userAgent)
    -- If there's an error, classify as failed connection
    if errorCode and errorCode ~= "" then
        return 3 -- Connection Failed
    end
    -- Check for specific network activities
    if userAgent and string.find(userAgent, "aws") then
        return 1 -- Network Connection
    end
    -- Default to generic network activity
    return 99 -- Other
end

-- Field mappings for FortiManager logs
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "userAgent", target = "metadata.product.name"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "awsRegion", target = "metadata.region"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "vpcEndpointId", target = "connection_info.boundary"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Fortinet"},
    
    -- Priority mappings (use first available field)
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "priority", source1 = "userIdentity.accessKeyId", source2 = "userIdentity.principalId", target = "actor.user.uid"},
}

function processEvent(event)
    -- Validate input
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

    -- Set OCSF required fields with context-aware values
    local errorCode = getNestedField(event, "errorCode")
    local errorMessage = getNestedField(event, "errorMessage")
    local eventCategory = getNestedField(event, "eventCategory")
    local userAgent = getNestedField(event, "userAgent")
    
    -- Activity ID based on context
    local activityId = getActivityId(eventCategory, errorCode, userAgent)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Severity based on error presence
    result.severity_id = getSeverityId(errorCode, errorMessage, eventCategory)
    
    -- Activity name
    if errorCode then
        result.activity_name = "Network Connection Failed"
    elseif eventCategory then
        result.activity_name = "Network " .. eventCategory
    else
        result.activity_name = "Network Activity"
    end
    
    -- Status based on error
    if errorCode then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end

    -- Parse timestamp
    local eventTime = getNestedField(event, "eventTime")
    if eventTime then
        local timeMs = parseTimestamp(eventTime)
        if timeMs then
            result.time = timeMs
        end
    end
    -- Fallback to current time if parsing failed
    if not result.time then
        result.time = os.time() * 1000
    end

    -- Set raw_data to preserve original event structure
    result.raw_data = event.message or ""

    -- Add observables for IP addresses and user identities
    local observables = {}
    local sourceIP = getNestedField(event, "sourceIPAddress")
    if sourceIP then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = sourceIP
        })
    end
    
    local userName = getNestedField(result, "actor.user.name")
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

    -- Mark additional mapped paths for unmapped collection
    mappedPaths["errorCode"] = true
    mappedPaths["eventTime"] = true
    mappedPaths["eventCategory"] = true
    mappedPaths["eventID"] = true
    mappedPaths["eventVersion"] = true
    mappedPaths["recipientAccountId"] = true
    mappedPaths["apiVersion"] = true
    mappedPaths["userIdentity"] = true
    mappedPaths["requestParameters"] = true
    mappedPaths["responseElements"] = true
    mappedPaths["additionalEventData"] = true
    mappedPaths["tlsDetails"] = true
    mappedPaths["resources"] = true

    -- Collect unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    return result
end