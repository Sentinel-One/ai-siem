-- Constants for OCSF Network Activity class
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

-- Safe value access with default
function getValue(tbl, key, default)
    if type(tbl) ~= "table" then return default end
    local value = tbl[key]
    return value ~= nil and value or default
end

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    if type(event) ~= "table" then return end
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
    if type(timeStr) ~= "string" then return nil end
    -- Handle ISO format YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)[T ](%d+):(%d+):(%d+)")
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

-- Get severity ID based on result or reason
function getSeverityId(result, reason)
    if type(result) == "string" then
        local lowerResult = result:lower()
        if lowerResult:find("success") or lowerResult:find("allow") then
            return 1  -- Informational
        elseif lowerResult:find("fail") or lowerResult:find("deny") or lowerResult:find("block") then
            return 3  -- Medium
        elseif lowerResult:find("error") then
            return 4  -- High
        end
    end
    
    if type(reason) == "string" then
        local lowerReason = reason:lower()
        if lowerReason:find("authentication") or lowerReason:find("authorization") then
            return 3  -- Medium
        elseif lowerReason:find("timeout") or lowerReason:find("connection") then
            return 2  -- Low
        end
    end
    
    return 0  -- Unknown
end

-- Get activity ID based on event type and result
function getActivityId(eventType, result)
    if type(eventType) == "string" then
        local lowerType = eventType:lower()
        if lowerType:find("connect") or lowerType:find("session") then
            return 1  -- Open
        elseif lowerType:find("disconnect") or lowerType:find("close") then
            return 2  -- Close
        elseif lowerType:find("auth") then
            return 5  -- Authorize
        end
    end
    
    -- Default based on result
    if type(result) == "string" then
        local lowerResult = result:lower()
        if lowerResult:find("success") or lowerResult:find("allow") then
            return 1  -- Open/Allow
        elseif lowerResult:find("deny") or lowerResult:find("block") then
            return 3  -- Deny
        end
    end
    
    return 99  -- Other
end

-- Get activity name based on activity ID
function getActivityName(activityId, eventType, result)
    local activityNames = {
        [1] = "Open",
        [2] = "Close",
        [3] = "Deny",
        [4] = "Reject",
        [5] = "Authorize",
        [99] = "Other"
    }
    
    local name = activityNames[activityId] or "Other"
    
    -- Add context if available
    if type(eventType) == "string" and eventType ~= "" then
        return name .. " - " .. eventType
    elseif type(result) == "string" and result ~= "" then
        return name .. " - " .. result
    end
    
    return name
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    {type = "direct", source = "user.name", target = "actor.user.name"},
    {type = "direct", source = "username", target = "actor.user.name"},
    {type = "direct", source = "application.name", target = "app.name"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "txid", target = "metadata.correlation_uid"},
    {type = "direct", source = "result", target = "status"},
    {type = "direct", source = "reason", target = "status_detail"},
    
    -- Priority mappings (try first source, fallback to second)
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "priority", source1 = "access_device.hostname", source2 = "host", target = "src_endpoint.hostname"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "ISA 3000"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Cisco"},
    {type = "computed", target = "metadata.version", value = "1.0.0"}
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
    
    -- Set timestamp - try isotimestamp first, then timestamp
    local eventTime = getNestedField(event, 'isotimestamp') or getNestedField(event, 'timestamp')
    if eventTime then
        local parsedTime = parseTimestamp(eventTime)
        if parsedTime then
            result.time = parsedTime
        end
    end
    if not result.time then
        result.time = os.time() * 1000  -- Current time as fallback
    end
    mappedPaths['isotimestamp'] = true
    mappedPaths['timestamp'] = true
    
    -- Set activity_id based on event type and result
    local eventType = getNestedField(event, 'event.type')
    local eventResult = getNestedField(event, 'result')
    local activityId = getActivityId(eventType, eventResult)
    result.activity_id = activityId
    mappedPaths['event.type'] = true
    mappedPaths['result'] = true
    
    -- Set type_uid
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set activity_name
    result.activity_name = getActivityName(activityId, eventType, eventResult)
    
    -- Set severity_id
    local reason = getNestedField(event, 'reason')
    result.severity_id = getSeverityId(eventResult, reason)
    mappedPaths['reason'] = true
    
    -- Set status_id based on result
    if eventResult then
        local lowerResult = eventResult:lower()
        if lowerResult:find("success") or lowerResult:find("allow") then
            result.status_id = 1  -- Success
        elseif lowerResult:find("fail") or lowerResult:find("deny") or lowerResult:find("error") then
            result.status_id = 2  -- Failure
        else
            result.status_id = 99  -- Other
        end
    else
        result.status_id = 0  -- Unknown
    end
    
    -- Create observables for IP addresses and usernames
    local observables = {}
    local srcIp = getNestedField(result, 'src_endpoint.ip')
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local dstIp = getNestedField(result, 'dst_endpoint.ip')
    if dstIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "dst_endpoint.ip",
            value = dstIp
        })
    end
    
    local username = getNestedField(result, 'actor.user.name')
    if username then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.name",
            value = username
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped fields
    mappedPaths['user.key'] = true
    mappedPaths['user.groups'] = true
    mappedPaths['email'] = true
    mappedPaths['auth_device.key'] = true
    mappedPaths['auth_device.location.city'] = true
    mappedPaths['auth_device.location.country'] = true
    mappedPaths['access_device.location.city'] = true
    mappedPaths['access_device.location.country'] = true
    mappedPaths['application.key'] = true
    mappedPaths['object'] = true
    mappedPaths['host'] = true
    
    -- Handle pre-existing OCSF fields
    if event.category_name then mappedPaths['category_name'] = true end
    if event.category_uid then mappedPaths['category_uid'] = true end
    if event.class_uid then mappedPaths['class_uid'] = true end
    if event.activity_name then mappedPaths['activity_name'] = true end
    if event.activity_id then mappedPaths['activity_id'] = true end
    if event.type_uid then mappedPaths['type_uid'] = true end
    if event.OCSF_version then mappedPaths['OCSF_version'] = true end
    if event.observables then mappedPaths['observables'] = true end
    if event.class_name then mappedPaths['class_name'] = true end
    if event.type_name then mappedPaths['type_name'] = true end
    if event['user.type_id'] then mappedPaths['user.type_id'] = true end
    if event['dataSource.category'] then mappedPaths['dataSource.category'] = true end
    if event['dataSource.name'] then mappedPaths['dataSource.name'] = true end
    if event['dataSource.vendor'] then mappedPaths['dataSource.vendor'] = true end
    if event['site.id'] then mappedPaths['site.id'] = true end
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end