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

-- Map severity/priority to OCSF severity_id
local function getSeverityId(level)
    if level == nil then return 0 end
    local severityStr = tostring(level):lower()
    
    -- Numeric severity (common in network logs)
    local numSeverity = tonumber(level)
    if numSeverity then
        if numSeverity <= 1 then return 5 -- Critical
        elseif numSeverity <= 2 then return 4 -- High  
        elseif numSeverity <= 3 then return 3 -- Medium
        elseif numSeverity <= 4 then return 2 -- Low
        else return 1 -- Informational
        end
    end
    
    -- String-based severity mapping
    local severityMap = {
        critical = 5, high = 4, medium = 3, warning = 2, low = 2,
        info = 1, informational = 1, debug = 1, notice = 1,
        emergency = 5, alert = 5, error = 4, warn = 2
    }
    return severityMap[severityStr] or 0
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr then return os.time() * 1000 end
    
    -- Handle various timestamp formats common in network logs
    local patterns = {
        -- ISO format: 2023-12-01T15:30:45.123Z
        "(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?%d*Z?",
        -- Syslog format: Dec  1 15:30:45
        "(%w+)%s+(%d+)%s+(%d+):(%d+):(%d+)",
        -- Unix timestamp (seconds)
        "^(%d+)$"
    }
    
    -- Try ISO format first
    local year, month, day, hour, min, sec = timeStr:match(patterns[1])
    if year then
        return os.time({
            year = tonumber(year), month = tonumber(month), day = tonumber(day),
            hour = tonumber(hour), min = tonumber(min), sec = tonumber(sec),
            isdst = false
        }) * 1000
    end
    
    -- Try Unix timestamp
    local timestamp = timeStr:match(patterns[3])
    if timestamp then
        local ts = tonumber(timestamp)
        if ts then
            -- If timestamp is in seconds, convert to milliseconds
            return ts > 1000000000000 and ts or (ts * 1000)
        end
    end
    
    -- Default to current time if parsing fails
    return os.time() * 1000
end

-- Determine activity_id based on event type/action
local function getActivityId(event)
    local action = getNestedField(event, 'action') or 
                  getNestedField(event, 'type') or 
                  getNestedField(event, 'event_type') or
                  getNestedField(event, 'activity')
    
    if not action then return 99 end -- Other
    
    local actionStr = tostring(action):lower()
    
    -- Common network activity mappings
    local activityMap = {
        allow = 1, permit = 1, accept = 1,
        deny = 2, block = 2, drop = 2, reject = 2,
        connect = 5, connection = 5, established = 5,
        disconnect = 6, close = 6, closed = 6,
        traffic = 5, flow = 5,
        scan = 10, probe = 10
    }
    
    return activityMap[actionStr] or 99
end

-- Main field mappings for Fortinet logs
local fieldMappings = {
    -- Basic event info
    {type = "priority", source1 = "msg", source2 = "message", target = "message"},
    {type = "priority", source1 = "raw_log", source2 = "raw", target = "raw_data"},
    
    -- Network endpoints - source
    {type = "priority", source1 = "srcip", source2 = "src_ip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "srcport", source2 = "src_port", target = "src_endpoint.port"},
    {type = "priority", source1 = "srcname", source2 = "src_host", target = "src_endpoint.hostname"},
    
    -- Network endpoints - destination  
    {type = "priority", source1 = "dstip", source2 = "dst_ip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dstport", source2 = "dst_port", target = "dst_endpoint.port"},
    {type = "priority", source1 = "dstname", source2 = "dst_host", target = "dst_endpoint.hostname"},
    
    -- Protocol and connection info
    {type = "priority", source1 = "proto", source2 = "protocol", target = "protocol_name"},
    {type = "priority", source1 = "service", source2 = "app", target = "application.name"},
    
    -- Status and result
    {type = "priority", source1 = "status", source2 = "result", target = "status"},
    {type = "priority", source1 = "action", source2 = "disposition", target = "disposition"},
    
    -- Timing information
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "count", target = "count"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.vendor_name", value = "Fortinet"},
    {type = "priority", source1 = "devname", source2 = "device_name", target = "metadata.product.name"},
    {type = "priority", source1 = "version", source2 = "fw_version", target = "metadata.version"}
}

function processEvent(event)
    -- Input validation
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Process field mappings
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
    
    -- Set OCSF required fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = "Network Activity"
    result.category_name = "Network Activity"
    
    -- Determine activity_id and compute type_uid
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set activity name based on activity_id
    local activityNames = {
        [1] = "Allow", [2] = "Deny", [5] = "Connect", 
        [6] = "Disconnect", [10] = "Scan", [99] = "Other"
    }
    result.activity_name = activityNames[activityId] or "Other"
    
    -- Set severity
    local severity = getNestedField(event, 'level') or 
                    getNestedField(event, 'priority') or 
                    getNestedField(event, 'severity')
    result.severity_id = getSeverityId(severity)
    
    -- Parse timestamp
    local timeField = getNestedField(event, 'time') or 
                     getNestedField(event, 'timestamp') or 
                     getNestedField(event, 'date')
    result.time = parseTimestamp(timeField)
    
    -- Mark timestamp fields as mapped
    mappedPaths['time'] = true
    mappedPaths['timestamp'] = true
    mappedPaths['date'] = true
    mappedPaths['level'] = true
    mappedPaths['priority'] = true
    mappedPaths['severity'] = true
    
    -- Convert port numbers to integers if they exist
    if result.src_endpoint and result.src_endpoint.port then
        result.src_endpoint.port = tonumber(result.src_endpoint.port)
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        result.dst_endpoint.port = tonumber(result.dst_endpoint.port)
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values and empty tables
    result = no_nulls(result, nil)
    
    return result
end