-- Cisco IronPort Network Activity Parser
-- Transforms Cisco IronPort logs to OCSF Network Activity (4001)

-- Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local DEFAULT_ACTIVITY_ID = 99

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

function getValue(tbl, key, default)
    if type(tbl) ~= "table" then return default end
    local value = tbl[key]
    return value ~= nil and value or default
end

function copyUnmappedFields(event, mappedPaths, result)
    if type(event) ~= "table" then return end
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Parse timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    
    -- Try ISO format: 2023-12-01T10:30:45Z or 2023-12-01T10:30:45.123Z
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
    
    -- Try syslog format: Dec 01 10:30:45
    local monthMap = {Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
    local monthStr, dayStr, timeStr2 = timeStr:match("(%w+)%s+(%d+)%s+(%d+:%d+:%d+)")
    if monthStr and monthMap[monthStr] then
        local h, m, s = timeStr2:match("(%d+):(%d+):(%d+)")
        if h then
            return os.time({
                year = os.date("%Y"),
                month = monthMap[monthStr],
                day = tonumber(dayStr),
                hour = tonumber(h),
                min = tonumber(m),
                sec = tonumber(s),
                isdst = false
            }) * 1000
        end
    end
    
    return nil
end

-- Map severity level to OCSF severity_id
function getSeverityId(level)
    if not level then return 0 end
    if type(level) == "number" then
        if level <= 1 then return 1      -- Informational
        elseif level <= 3 then return 2  -- Low
        elseif level <= 5 then return 3  -- Medium
        elseif level <= 7 then return 4  -- High
        else return 5                    -- Critical
        end
    end
    
    local levelStr = tostring(level):lower()
    local severityMap = {
        critical = 5, crit = 5, fatal = 6, emergency = 6, emerg = 6,
        high = 4, alert = 4, error = 4, err = 4,
        medium = 3, warning = 3, warn = 3,
        low = 2, notice = 2,
        informational = 1, info = 1, debug = 1
    }
    return severityMap[levelStr] or 0
end

-- Determine activity ID and name from event data
function getActivityInfo(event)
    local action = getValue(event, "action", "")
    local eventType = getValue(event, "event_type", getValue(event, "type", ""))
    local activity = getValue(event, "activity", "")
    
    -- Map common network activities
    if action:match("connect") or eventType:match("connection") then
        return 1, "Connect"
    elseif action:match("disconnect") or eventType:match("disconnect") then
        return 2, "Disconnect"
    elseif action:match("send") or action:match("transmit") then
        return 5, "Send"
    elseif action:match("receive") or action:match("recv") then
        return 6, "Receive"
    elseif action:match("block") or action:match("deny") then
        return 2, "Deny"
    elseif action:match("allow") or action:match("permit") then
        return 1, "Allow"
    elseif action:match("scan") or activity:match("scan") then
        return 99, "Scan"
    else
        return DEFAULT_ACTIVITY_ID, action or eventType or activity or "Network Activity"
    end
end

-- Main field mappings for Cisco IronPort events
local fieldMappings = {
    -- Basic event info
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "raw_data", target = "raw_data"},
    {type = "direct", source = "original_message", target = "raw_data"},
    
    -- Status information
    {type = "direct", source = "status", target = "status"},
    {type = "direct", source = "status_code", target = "status_id"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    
    -- Timing
    {type = "direct", source = "count", target = "count"},
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "start_time", target = "start_time"},
    {type = "direct", source = "end_time", target = "end_time"},
    
    -- Source endpoint
    {type = "priority", source1 = "src_ip", source2 = "source_ip", source3 = "sip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "source_port", source3 = "sport", target = "src_endpoint.port"},
    {type = "priority", source1 = "src_host", source2 = "source_host", source3 = "shost", target = "src_endpoint.hostname"},
    
    -- Destination endpoint
    {type = "priority", source1 = "dst_ip", source2 = "dest_ip", source3 = "dip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_port", source2 = "dest_port", source3 = "dport", target = "dst_endpoint.port"},
    {type = "priority", source1 = "dst_host", source2 = "dest_host", source3 = "dhost", target = "dst_endpoint.hostname"},
    
    -- Protocol
    {type = "priority", source1 = "protocol", source2 = "proto", target = "protocol_name"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.vendor_name", value = "Cisco"},
    {type = "computed", target = "metadata.product.name", value = "IronPort"},
    {type = "direct", source = "version", target = "metadata.version"}
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
    
    -- Set OCSF required fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = "Network Activity"
    result.category_name = "Network Activity"
    
    -- Determine activity
    local activity_id, activity_name = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity
    local severity = getValue(event, "severity", getValue(event, "priority", getValue(event, "level", nil)))
    result.severity_id = getSeverityId(severity)
    mappedPaths.severity = true
    mappedPaths.priority = true
    mappedPaths.level = true
    
    -- Parse timestamp
    local timestamp = getValue(event, "timestamp", getValue(event, "time", getValue(event, "@timestamp", nil)))
    local parsedTime = parseTimestamp(timestamp)
    result.time = parsedTime or (os.time() * 1000)
    mappedPaths.timestamp = true
    mappedPaths.time = true
    mappedPaths["@timestamp"] = true
    
    -- Mark other common fields as mapped
    mappedPaths.action = true
    mappedPaths.event_type = true
    mappedPaths.type = true
    mappedPaths.activity = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end