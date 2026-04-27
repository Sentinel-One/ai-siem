-- Constants for Network Activity class
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

-- Convert timestamp to milliseconds since epoch
function parseTimestamp(timestamp)
    if not timestamp then return nil end
    
    -- Handle ISO timestamp format
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
    
    -- Handle other timestamp formats as needed
    return nil
end

-- Map severity based on result or reason
function getSeverityId(result, reason)
    if not result then return 0 end
    
    local resultLower = string.lower(tostring(result))
    
    -- Map common Cisco authentication/network results to severity
    if resultLower:find("success") or resultLower:find("allow") or resultLower:find("permit") then
        return 1 -- Informational
    elseif resultLower:find("fail") or resultLower:find("deny") or resultLower:find("block") then
        return 3 -- Medium
    elseif resultLower:find("error") or resultLower:find("critical") then
        return 4 -- High
    else
        return 0 -- Unknown
    end
end

-- Determine activity based on event type and result
function getActivityInfo(eventType, result)
    local activityId = 99 -- Other by default
    local activityName = "Other Network Activity"
    
    if eventType then
        local eventTypeLower = string.lower(tostring(eventType))
        
        if eventTypeLower:find("auth") or eventTypeLower:find("login") then
            activityId = 1 -- Connect
            activityName = "Network Connection"
        elseif eventTypeLower:find("disconnect") or eventTypeLower:find("logout") then
            activityId = 2 -- Disconnect
            activityName = "Network Disconnect"
        elseif eventTypeLower:find("deny") or eventTypeLower:find("block") then
            activityId = 5 -- Deny
            activityName = "Network Deny"
        elseif eventTypeLower:find("allow") or eventTypeLower:find("permit") then
            activityId = 1 -- Connect/Allow
            activityName = "Network Allow"
        end
    end
    
    return activityId, activityName
end

-- Field mappings for Cisco network logs
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "txid", target = "metadata.correlation_uid"},
    {type = "direct", source = "user.name", target = "actor.user.name"},
    {type = "direct", source = "username", target = "actor.user.name"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    {type = "direct", source = "user.groups", target = "actor.user.groups"},
    {type = "direct", source = "user.type_id", target = "actor.user.type_id"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    {type = "direct", source = "host", target = "src_endpoint.hostname"},
    {type = "direct", source = "application.name", target = "metadata.product.name"},
    {type = "direct", source = "dataSource.vendor", target = "metadata.product.vendor_name"},
    {type = "direct", source = "dataSource.name", target = "metadata.product.name"},
    {type = "direct", source = "OCSF_version", target = "metadata.version"},
    {type = "direct", source = "observables", target = "observables"},
    {type = "direct", source = "result", target = "status_detail"},
    {type = "direct", source = "reason", target = "status_detail"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Priority mappings (use first available)
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "priority", source1 = "access_device.hostname", source2 = "host", target = "src_endpoint.hostname"},
    {type = "priority", source1 = "application.name", source2 = "dataSource.name", target = "metadata.product.name"}
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
    local activityId, activityName = getActivityInfo(getNestedField(event, "event.type"), getNestedField(event, "result"))
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId

    -- Set severity
    result.severity_id = getSeverityId(getNestedField(event, "result"), getNestedField(event, "reason"))

    -- Parse timestamp
    local timestamp = getNestedField(event, "isotimestamp") or getNestedField(event, "timestamp")
    local parsedTime = parseTimestamp(timestamp)
    result.time = parsedTime or (os.time() * 1000)
    mappedPaths["isotimestamp"] = true
    mappedPaths["timestamp"] = true

    -- Set status based on result
    local resultValue = getNestedField(event, "result")
    if resultValue then
        result.status = tostring(resultValue)
        local resultLower = string.lower(tostring(resultValue))
        if resultLower:find("success") or resultLower:find("allow") then
            result.status_id = 1 -- Success
        elseif resultLower:find("fail") or resultLower:find("deny") then
            result.status_id = 2 -- Failure
        else
            result.status_id = 99 -- Other
        end
    else
        result.status_id = 0 -- Unknown
    end

    -- Set metadata defaults if not already set
    if not getNestedField(result, "metadata.product.vendor_name") then
        setNestedField(result, "metadata.product.vendor_name", "Cisco")
    end

    -- Create observables from key network fields
    local observables = getNestedField(result, "observables") or {}
    
    local srcIp = getNestedField(result, "src_endpoint.ip")
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local dstIp = getNestedField(result, "dst_endpoint.ip")
    if dstIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "dst_endpoint.ip",
            value = dstIp
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

    -- Mark additional fields as mapped
    mappedPaths["result"] = true
    mappedPaths["reason"] = true
    mappedPaths["event.type"] = true
    mappedPaths["class_uid"] = true
    mappedPaths["category_uid"] = true
    mappedPaths["activity_id"] = true
    mappedPaths["type_uid"] = true
    mappedPaths["class_name"] = true
    mappedPaths["category_name"] = true
    mappedPaths["activity_name"] = true
    mappedPaths["type_name"] = true

    -- Collect unmapped fields
    copyUnmappedFields(event, mappedPaths, result)

    return result
end