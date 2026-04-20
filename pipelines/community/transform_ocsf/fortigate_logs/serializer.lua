-- FortiGate Logs to OCSF Network Activity Transformation
-- Constants for OCSF Network Activity class
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

-- Map FortiGate severity levels to OCSF severity_id
local function getSeverityId(level)
    if level == nil then return 0 end
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        warning = 3,
        low = 2,
        information = 1,
        informational = 1,
        info = 1,
        debug = 1,
        emergency = 6,
        alert = 5,
        error = 4,
        err = 4,
        notice = 2
    }
    
    -- Handle both string and numeric levels
    if type(level) == "string" then
        return severityMap[string.lower(level)] or 0
    elseif type(level) == "number" then
        -- FortiGate numeric levels (0-7 syslog scale)
        if level >= 0 and level <= 1 then return 6  -- emergency/alert -> Fatal
        elseif level >= 2 and level <= 3 then return 5  -- critical/error -> Critical
        elseif level == 4 then return 3  -- warning -> Medium
        elseif level >= 5 and level <= 6 then return 2  -- notice/info -> Low
        elseif level == 7 then return 1  -- debug -> Informational
        end
    end
    return 0
end

-- Map FortiGate action to OCSF activity_id
local function getActivityId(action)
    if action == nil then return 99 end
    local actionMap = {
        accept = 1,    -- Allow
        allow = 1,     -- Allow
        permit = 1,    -- Allow
        deny = 2,      -- Deny
        block = 2,     -- Deny
        drop = 2,      -- Deny
        reject = 2,    -- Deny
        close = 3,     -- Close
        reset = 4,     -- Reset
        timeout = 5,   -- Timeout
        redirect = 6   -- Redirect
    }
    return actionMap[string.lower(action)] or 99
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr then return os.time() * 1000 end
    
    -- Try different FortiGate timestamp formats
    local patterns = {
        -- ISO format: 2023-01-01T12:00:00
        "(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)",
        -- Standard format: 2023-01-01 12:00:00
        "(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)",
        -- Epoch timestamp (numeric)
        "^(%d+)$"
    }
    
    for _, pattern in ipairs(patterns) do
        if pattern == "^(%d+)$" then
            local epoch = tonumber(timeStr)
            if epoch then
                -- Convert to milliseconds if it looks like seconds
                return epoch > 1000000000 and epoch * 1000 or epoch
            end
        else
            local yr, mo, dy, hr, mn, sc = timeStr:match(pattern)
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
        end
    end
    
    return os.time() * 1000
end

-- Main field mappings for FortiGate logs
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source endpoint mapping
    {type = "priority", source1 = "srcip", source2 = "src", target = "src_endpoint.ip"},
    {type = "priority", source1 = "srcport", source2 = "sport", target = "src_endpoint.port"},
    {type = "direct", source = "srcname", target = "src_endpoint.hostname"},
    {type = "direct", source = "srchostname", target = "src_endpoint.hostname"},
    
    -- Destination endpoint mapping
    {type = "priority", source1 = "dstip", source2 = "dst", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dstport", source2 = "dport", target = "dst_endpoint.port"},
    {type = "direct", source = "dstname", target = "dst_endpoint.hostname"},
    {type = "direct", source = "dsthostname", target = "dst_endpoint.hostname"},
    
    -- Protocol and network details
    {type = "priority", source1 = "proto", source2 = "protocol", target = "protocol_name"},
    {type = "direct", source = "service", target = "protocol_name"},
    
    -- Message and status
    {type = "priority", source1 = "msg", source2 = "message", target = "message"},
    {type = "direct", source = "logdesc", target = "message"},
    {type = "priority", source1 = "action", source2 = "status", target = "status"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    
    -- Counts and duration
    {type = "direct", source = "count", target = "count"},
    {type = "priority", source1 = "duration", source2 = "elapsed", target = "duration"},
    {type = "direct", source = "sentbyte", target = "traffic.bytes_out"},
    {type = "direct", source = "rcvdbyte", target = "traffic.bytes_in"},
    {type = "direct", source = "sentpkt", target = "traffic.packets_out"},
    {type = "direct", source = "rcvdpkt", target = "traffic.packets_in"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "FortiGate"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Fortinet"},
    {type = "priority", source1 = "devname", source2 = "device_name", target = "metadata.product.feature.name"},
    {type = "direct", source = "version", target = "metadata.version"},
    
    -- Additional context
    {type = "direct", source = "policyid", target = "policy.uid"},
    {type = "direct", source = "policyname", target = "policy.name"},
    {type = "direct", source = "user", target = "actor.user.name"},
    {type = "direct", source = "group", target = "actor.user.groups"},
    {type = "direct", source = "sessionid", target = "session.uid"}
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
            if (value == nil or value == "") and mapping.source2 then
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
    
    -- Set activity_id based on action
    local action = event.action or event.status
    local activityId = getActivityId(action)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    mappedPaths["action"] = true
    mappedPaths["status"] = true
    
    -- Set activity_name
    if action then
        result.activity_name = string.upper(string.sub(action, 1, 1)) .. string.lower(string.sub(action, 2))
    else
        result.activity_name = "Network Traffic"
    end
    
    -- Set severity_id
    local severity = event.level or event.severity or event.priority
    result.severity_id = getSeverityId(severity)
    mappedPaths["level"] = true
    mappedPaths["severity"] = true
    mappedPaths["priority"] = true
    
    -- Set timestamp
    local timestamp = event.date or event.time or event.timestamp or event.eventtime
    result.time = parseTimestamp(timestamp)
    mappedPaths["date"] = true
    mappedPaths["time"] = true
    mappedPaths["timestamp"] = true
    mappedPaths["eventtime"] = true
    
    -- Set status_id based on action
    if action then
        local statusMap = {
            accept = 1, allow = 1, permit = 1,  -- Success
            deny = 2, block = 2, drop = 2, reject = 2  -- Failure
        }
        result.status_id = statusMap[string.lower(action)] or 99
    else
        result.status_id = 99  -- Other
    end
    
    -- Convert numeric ports to integers
    if result.src_endpoint and result.src_endpoint.port then
        result.src_endpoint.port = tonumber(result.src_endpoint.port)
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        result.dst_endpoint.port = tonumber(result.dst_endpoint.port)
    end
    
    -- Set raw_data if available
    if event.raw or event.original then
        result.raw_data = event.raw or event.original
        mappedPaths["raw"] = true
        mappedPaths["original"] = true
    end
    
    -- Create observables for key network indicators
    local observables = {}
    if result.src_endpoint and result.src_endpoint.ip then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = result.src_endpoint.ip
        })
    end
    if result.dst_endpoint and result.dst_endpoint.ip then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "dst_endpoint.ip",
            value = result.dst_endpoint.ip
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve all data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values and empty tables
    result = no_nulls(result, nil)
    
    return result
end