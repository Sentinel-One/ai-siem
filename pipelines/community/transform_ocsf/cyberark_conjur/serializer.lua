-- CyberArk Conjur to OCSF Authentication transformation
-- Maps CyberArk Conjur authentication events to OCSF Authentication class (3002)

local CLASS_UID = 3002
local CATEGORY_UID = 3
local CLASS_NAME = "Authentication"
local CATEGORY_NAME = "Identity & Access Management"

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

-- Replace userdata nil values (Observo sandbox quirk)
function no_nulls(d, rn)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = rn
            elseif type(v) == "table" then no_nulls(v, rn) end
        end
    end
    return d
end

-- Flatten nested table to dot-notation keys
function flattenObject(tbl, prefix, result)
    result = result or {}; prefix = prefix or ""
    for k, v in pairs(tbl) do
        local keyPath = prefix ~= "" and (prefix .. "." .. tostring(k)) or tostring(k)
        if type(v) == "table" then flattenObject(v, keyPath, result)
        else result[keyPath] = v end
    end
    return result
end

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Map CyberArk Conjur severity to OCSF severity_id
local function getSeverityId(level)
    if level == nil then return 0 end
    local severityMap = {
        ["FATAL"] = 6,
        ["CRITICAL"] = 5,
        ["HIGH"] = 4,
        ["ERROR"] = 4,
        ["WARN"] = 3,
        ["WARNING"] = 3,
        ["MEDIUM"] = 3,
        ["INFO"] = 1,
        ["INFORMATION"] = 1,
        ["INFORMATIONAL"] = 1,
        ["LOW"] = 2,
        ["DEBUG"] = 1,
        ["TRACE"] = 1
    }
    local upperLevel = string.upper(tostring(level))
    return severityMap[upperLevel] or 0
end

-- Map CyberArk Conjur event types to OCSF activity_id
local function getActivityId(eventType, action, result)
    if not eventType then return 99 end
    
    local eventTypeLower = string.lower(tostring(eventType))
    local actionLower = action and string.lower(tostring(action)) or ""
    
    -- Authentication activities
    if string.find(eventTypeLower, "login") or string.find(eventTypeLower, "signin") or string.find(eventTypeLower, "auth") then
        if string.find(actionLower, "fail") or string.find(eventTypeLower, "fail") then
            result.activity_name = "Logon Failed"
            return 2
        else
            result.activity_name = "Logon"
            return 1
        end
    elseif string.find(eventTypeLower, "logout") or string.find(eventTypeLower, "signout") then
        result.activity_name = "Logoff"
        return 3
    elseif string.find(eventTypeLower, "password") then
        if string.find(actionLower, "change") or string.find(eventTypeLower, "change") then
            result.activity_name = "Password Changed"
            return 5
        else
            result.activity_name = "Password Reset"
            return 4
        end
    elseif string.find(eventTypeLower, "mfa") or string.find(eventTypeLower, "2fa") or string.find(eventTypeLower, "multifactor") then
        result.activity_name = "MFA Authentication"
        return 6
    end
    
    -- Default
    result.activity_name = eventType or "Unknown"
    return 99
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timestampStr)
    if not timestampStr then return nil end
    
    -- Try ISO 8601 format: YYYY-MM-DDTHH:MM:SS.sssZ
    local year, month, day, hour, min, sec, ms = timestampStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z?")
    if year then
        local time = os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        })
        local milliseconds = ms and tonumber(ms:sub(1,3)) or 0
        if #ms == 1 then milliseconds = milliseconds * 100
        elseif #ms == 2 then milliseconds = milliseconds * 10 end
        return time * 1000 + milliseconds
    end
    
    -- Try Unix timestamp (seconds)
    local unixTime = tonumber(timestampStr)
    if unixTime then
        -- If it looks like seconds (reasonable range), convert to milliseconds
        if unixTime > 1000000000 and unixTime < 10000000000 then
            return unixTime * 1000
        elseif unixTime > 1000000000000 then
            return unixTime
        end
    end
    
    return nil
end

-- Field mappings for CyberArk Conjur events
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "raw_data", target = "raw_data"},
    {type = "direct", source = "status", target = "status"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    {type = "direct", source = "count", target = "count"},
    {type = "direct", source = "duration", target = "duration"},
    
    -- User information
    {type = "priority", source1 = "user", source2 = "username", source3 = "user_name", target = "actor.user.name"},
    {type = "priority", source1 = "user_id", source2 = "uid", source3 = "userid", target = "actor.user.uid"},
    {type = "priority", source1 = "domain", source2 = "user_domain", target = "actor.user.domain"},
    
    -- Source endpoint
    {type = "priority", source1 = "client_ip", source2 = "source_ip", source3 = "src_ip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "client_host", source2 = "source_host", source3 = "hostname", target = "src_endpoint.hostname"},
    {type = "priority", source1 = "client_port", source2 = "source_port", source3 = "port", target = "src_endpoint.port"},
    
    -- Destination endpoint
    {type = "priority", source1 = "server_ip", source2 = "dest_ip", source3 = "dst_ip", target = "dst_endpoint.ip"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "CyberArk Conjur"},
    {type = "computed", target = "metadata.product.vendor_name", value = "CyberArk"},
    {type = "computed", target = "metadata.version", value = "1.0"},
    
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME}
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
            if value == nil and mapping.source3 then 
                value = getNestedField(event, mapping.source3) 
            end
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
            if mapping.source3 then mappedPaths[mapping.source3] = true end
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end

    -- Set activity_id and activity_name based on event type
    local eventType = getValue(event, "event_type", nil) or getValue(event, "action", nil) or getValue(event, "operation", nil)
    local action = getValue(event, "action", nil) or getValue(event, "result", nil)
    local activityId = getActivityId(eventType, action, result)
    result.activity_id = activityId
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + activityId

    -- Set severity_id
    local severity = getValue(event, "severity", nil) or getValue(event, "level", nil) or getValue(event, "priority", nil)
    result.severity_id = getSeverityId(severity)

    -- Set status_id based on success/failure indicators
    local status = getValue(event, "status", nil) or getValue(event, "result", nil)
    if status then
        local statusLower = string.lower(tostring(status))
        if string.find(statusLower, "success") or string.find(statusLower, "ok") or statusLower == "0" then
            result.status_id = 1  -- Success
        elseif string.find(statusLower, "fail") or string.find(statusLower, "error") or string.find(statusLower, "denied") then
            result.status_id = 2  -- Failure
        else
            result.status_id = 99  -- Other
        end
        mappedPaths["status"] = true
        mappedPaths["result"] = true
    end

    -- Parse timestamp
    local timestamp = getValue(event, "timestamp", nil) or getValue(event, "@timestamp", nil) or 
                     getValue(event, "time", nil) or getValue(event, "event_time", nil)
    local eventTime = parseTimestamp(timestamp)
    result.time = eventTime or (os.time() * 1000)
    
    -- Mark timestamp fields as mapped
    mappedPaths["timestamp"] = true
    mappedPaths["@timestamp"] = true
    mappedPaths["time"] = true
    mappedPaths["event_time"] = true
    mappedPaths["event_type"] = true
    mappedPaths["action"] = true
    mappedPaths["operation"] = true
    mappedPaths["severity"] = true
    mappedPaths["level"] = true
    mappedPaths["priority"] = true

    -- Create observables for key fields
    local observables = {}
    if result.src_endpoint and result.src_endpoint.ip then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = result.src_endpoint.ip
        })
    end
    if result.actor and result.actor.user and result.actor.user.name then
        table.insert(observables, {
            type_id = 4,
            type = "User Name", 
            name = "actor.user.name",
            value = result.actor.user.name
        })
    end
    if #observables > 0 then
        result.observables = observables
    end

    -- Copy unmapped fields to preserve all data
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean up userdata nulls
    result = no_nulls(result, nil)

    return result
end