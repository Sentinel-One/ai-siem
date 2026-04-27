-- Meraki Logs to OCSF Network Activity (4001) Transformation
-- Handles various Meraki network device log formats

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

-- Get severity ID from Meraki log levels
local function getSeverityId(level)
    if level == nil then return 0 end
    local severityMap = {
        ["err"] = 4,     -- High
        ["error"] = 4,   -- High
        ["warn"] = 3,    -- Medium
        ["warning"] = 3, -- Medium
        ["info"] = 1,    -- Informational
        ["notice"] = 1,  -- Informational
        ["debug"] = 1,   -- Informational
        ["crit"] = 5,    -- Critical
        ["critical"] = 5,-- Critical
        ["alert"] = 5,   -- Critical
        ["emerg"] = 6    -- Fatal (rarely used in Meraki)
    }
    local lowerLevel = string.lower(tostring(level))
    return severityMap[lowerLevel] or 0
end

-- Determine activity ID based on Meraki event types
local function getActivityId(event)
    local eventType = getNestedField(event, "type") or getNestedField(event, "event_type") or ""
    local msg = getNestedField(event, "msg") or getNestedField(event, "message") or ""
    
    -- Convert to lowercase for matching
    eventType = string.lower(tostring(eventType))
    msg = string.lower(tostring(msg))
    
    -- Meraki-specific activity mapping
    if string.find(eventType, "association") or string.find(msg, "association") then
        return 1 -- Open
    elseif string.find(eventType, "dhcp") or string.find(msg, "dhcp") then
        return 5 -- Allocate
    elseif string.find(eventType, "auth") or string.find(msg, "auth") then
        return 1 -- Open
    elseif string.find(eventType, "block") or string.find(msg, "block") or string.find(msg, "deny") then
        return 2 -- Close
    elseif string.find(eventType, "flow") or string.find(msg, "flow") then
        return 5 -- Allocate
    else
        return 99 -- Other
    end
end

-- Parse Meraki timestamp formats
local function parseTimestamp(timeStr)
    if not timeStr then return nil end
    
    -- Common Meraki timestamp formats:
    -- 1. Unix timestamp
    local unixTime = tonumber(timeStr)
    if unixTime then
        return unixTime * 1000 -- Convert to milliseconds
    end
    
    -- 2. ISO 8601 format: 2023-01-01T12:00:00Z
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        local timestamp = os.time({
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        })
        return timestamp * 1000
    end
    
    -- 3. Syslog format: Jan 01 12:00:00
    local months = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6, 
                   Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
    local mon, day, hour, min, sec = timeStr:match("(%w+)%s+(%d+)%s+(%d+):(%d+):(%d+)")
    if mon and months[mon] then
        local currentYear = os.date("*t").year
        local timestamp = os.time({
            year = currentYear,
            month = months[mon],
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

-- Clean empty tables recursively
local function cleanEmptyTables(tbl)
    if type(tbl) ~= "table" then return tbl end
    
    local cleaned = {}
    local hasContent = false
    
    for k, v in pairs(tbl) do
        if type(v) == "table" then
            local cleanedSubtable = cleanEmptyTables(v)
            if cleanedSubtable and next(cleanedSubtable) ~= nil then
                cleaned[k] = cleanedSubtable
                hasContent = true
            end
        elseif v ~= nil and v ~= "" then
            cleaned[k] = v
            hasContent = true
        end
    end
    
    return hasContent and cleaned or nil
end

-- Field mappings for Meraki logs
local fieldMappings = {
    -- Basic OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Message and raw data
    {type = "priority", source1 = "msg", source2 = "message", target = "message"},
    {type = "priority", source1 = "raw", source2 = "_raw", target = "raw_data"},
    
    -- Network endpoints
    {type = "priority", source1 = "src_ip", source2 = "src", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "sport", target = "src_endpoint.port"},
    {type = "priority", source1 = "dst_ip", source2 = "dst", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_port", source2 = "dport", target = "dst_endpoint.port"},
    {type = "direct", source = "src_mac", target = "src_endpoint.mac"},
    {type = "direct", source = "dst_mac", target = "dst_endpoint.mac"},
    
    -- Protocol information
    {type = "priority", source1 = "protocol", source2 = "proto", target = "protocol_name"},
    {type = "direct", source = "protocol_num", target = "protocol_ver"},
    
    -- Status information
    {type = "direct", source = "status", target = "status"},
    {type = "direct", source = "action", target = "status_detail"},
    
    -- Timing
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "start_time", target = "start_time"},
    {type = "direct", source = "end_time", target = "end_time"},
    
    -- Network specific
    {type = "direct", source = "bytes", target = "traffic.bytes"},
    {type = "direct", source = "packets", target = "traffic.packets"},
    {type = "direct", source = "vlan", target = "dst_endpoint.vlan_uid"},
    
    -- Device information
    {type = "direct", source = "device_name", target = "metadata.product.name"},
    {type = "direct", source = "device_type", target = "device.type"},
    {type = "direct", source = "device_serial", target = "device.uid"},
    
    -- User information
    {type = "direct", source = "user", target = "actor.user.name"},
    {type = "direct", source = "client_mac", target = "actor.user.uid"},
    
    -- SSID and wireless info
    {type = "direct", source = "ssid", target = "dst_endpoint.name"},
    {type = "direct", source = "radio", target = "device.interface_name"},
    {type = "direct", source = "channel", target = "device.interface_uid"}
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

    -- Set activity_id and type_uid
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set activity name based on activity_id
    local activityNames = {
        [1] = "Open",
        [2] = "Close", 
        [5] = "Allocate",
        [99] = "Other"
    }
    result.activity_name = activityNames[activityId] or "Network Activity"

    -- Set severity
    local severity = getNestedField(event, "severity") or getNestedField(event, "level") or 
                    getNestedField(event, "priority")
    result.severity_id = getSeverityId(severity)

    -- Parse timestamp
    local timeField = getNestedField(event, "timestamp") or getNestedField(event, "time") or 
                     getNestedField(event, "ts") or getNestedField(event, "@timestamp")
    local parsedTime = parseTimestamp(timeField)
    result.time = parsedTime or (os.time() * 1000)
    
    -- Mark timestamp fields as mapped
    mappedPaths["timestamp"] = true
    mappedPaths["time"] = true
    mappedPaths["ts"] = true
    mappedPaths["@timestamp"] = true
    mappedPaths["severity"] = true
    mappedPaths["level"] = true
    mappedPaths["priority"] = true
    mappedPaths["type"] = true
    mappedPaths["event_type"] = true

    -- Set metadata
    setNestedField(result, "metadata.product.vendor_name", "Cisco")
    setNestedField(result, "metadata.version", "1.0.0")

    -- Create observables for key network indicators
    local observables = {}
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
    
    if #observables > 0 then
        result.observables = observables
    end

    -- Set status_id based on action/status
    local statusDetail = getNestedField(result, "status_detail")
    if statusDetail then
        local statusLower = string.lower(tostring(statusDetail))
        if string.find(statusLower, "allow") or string.find(statusLower, "permit") then
            result.status_id = 1 -- Success
        elseif string.find(statusLower, "block") or string.find(statusLower, "deny") or 
               string.find(statusLower, "drop") then
            result.status_id = 2 -- Failure
        end
    end

    -- Collect unmapped fields
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean empty tables and nil values
    result = no_nulls(result, nil)
    result = cleanEmptyTables(result)

    return result
end