-- Barracuda Firewall Logs OCSF Transformation
-- Maps firewall log events to OCSF Network Activity (class_uid=4001)

-- OCSF Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Convert various timestamp formats to milliseconds since epoch
local function parseTimestamp(timeStr)
    if type(timeStr) ~= "string" or timeStr == "" then return nil end
    
    -- Try ISO format: 2023-01-01T12:00:00Z or 2023-01-01 12:00:00
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d%d%d%d)[%-/](%d%d)[%-/](%d%d)[T%s](%d%d):(%d%d):(%d%d)")
    if yr then
        return os.time({year=tonumber(yr), month=tonumber(mo), day=tonumber(dy),
                       hour=tonumber(hr), min=tonumber(mn), sec=tonumber(sc), isdst=false}) * 1000
    end
    
    -- Try epoch seconds
    local epochSec = tonumber(timeStr)
    if epochSec and epochSec > 1000000000 then  -- reasonable epoch range
        return epochSec < 10000000000 and epochSec * 1000 or epochSec
    end
    
    return nil
end

-- Map severity/priority to OCSF severity_id
local function getSeverityId(severity)
    if type(severity) == "string" then
        severity = severity:lower()
        if severity:find("critical") or severity:find("emergency") then return 5
        elseif severity:find("high") or severity:find("alert") then return 4
        elseif severity:find("medium") or severity:find("warning") then return 3
        elseif severity:find("low") then return 2
        elseif severity:find("info") or severity:find("notice") then return 1
        end
    elseif type(severity) == "number" then
        -- Syslog priority levels (0=emergency, 7=debug)
        if severity <= 2 then return 5      -- emergency, alert, critical
        elseif severity <= 4 then return 4  -- error, warning
        elseif severity <= 6 then return 2  -- notice, info
        else return 1 end                   -- debug
    end
    return 0  -- Unknown
end

-- Map action/disposition to OCSF activity_id
local function getActivityId(action)
    if type(action) == "string" then
        action = action:lower()
        if action:find("allow") or action:find("accept") or action:find("permit") then
            return 1  -- Allow
        elseif action:find("deny") or action:find("drop") or action:find("block") or action:find("reject") then
            return 2  -- Deny
        elseif action:find("monitor") or action:find("log") then
            return 5  -- Monitor
        end
    end
    return 99  -- Other
end

-- Get activity name from activity_id
local function getActivityName(activityId)
    local activityNames = {
        [1] = "Allow",
        [2] = "Deny",
        [5] = "Monitor",
        [99] = "Other"
    }
    return activityNames[activityId] or "Unknown"
end

-- Main field mappings using table-driven approach
local fieldMappings = {
    -- Source endpoint mappings
    {type = "direct", source = "src_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "source_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "srcip", target = "src_endpoint.ip"},
    {type = "direct", source = "src_port", target = "src_endpoint.port"},
    {type = "direct", source = "source_port", target = "src_endpoint.port"},
    {type = "direct", source = "srcport", target = "src_endpoint.port"},
    {type = "direct", source = "src_host", target = "src_endpoint.hostname"},
    {type = "direct", source = "source_host", target = "src_endpoint.hostname"},
    
    -- Destination endpoint mappings
    {type = "direct", source = "dst_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dest_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dstip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dst_port", target = "dst_endpoint.port"},
    {type = "direct", source = "dest_port", target = "dst_endpoint.port"},
    {type = "direct", source = "dstport", target = "dst_endpoint.port"},
    {type = "direct", source = "dst_host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "dest_host", target = "dst_endpoint.hostname"},
    
    -- Protocol and connection info
    {type = "direct", source = "protocol", target = "protocol_name"},
    {type = "direct", source = "proto", target = "protocol_name"},
    {type = "direct", source = "bytes", target = "traffic.bytes"},
    {type = "direct", source = "packets", target = "traffic.packets"},
    {type = "direct", source = "duration", target = "duration"},
    
    -- Message and status
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "msg", target = "message"},
    {type = "direct", source = "status", target = "status"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "Barracuda Firewall"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Barracuda Networks"},
    {type = "computed", target = "metadata.version", value = "1.0.0"},
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
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set OCSF required fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = CLASS_NAME
    result.category_name = CATEGORY_NAME
    
    -- Determine activity_id from action/disposition
    local action = getValue(event, "action", "") or getValue(event, "disposition", "") or getValue(event, "verdict", "")
    local activityId = getActivityId(action)
    result.activity_id = activityId
    result.activity_name = getActivityName(activityId)
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity_id from priority/severity
    local severity = getValue(event, "severity", "") or getValue(event, "priority", "") or getValue(event, "level", "")
    result.severity_id = getSeverityId(severity)
    
    -- Parse timestamp - try multiple common field names
    local timestamp = getValue(event, "timestamp", "") or getValue(event, "time", "") or 
                     getValue(event, "datetime", "") or getValue(event, "log_time", "")
    local parsedTime = parseTimestamp(timestamp)
    result.time = parsedTime or (os.time() * 1000)
    
    -- Set raw_data if available
    local rawData = getValue(event, "raw", "") or getValue(event, "raw_data", "") or getValue(event, "original", "")
    if rawData ~= "" then
        result.raw_data = rawData
    end
    
    -- Convert port numbers to integers
    if result.src_endpoint and result.src_endpoint.port then
        local port = tonumber(result.src_endpoint.port)
        if port then result.src_endpoint.port = port end
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        local port = tonumber(result.dst_endpoint.port)
        if port then result.dst_endpoint.port = port end
    end
    
    -- Convert duration to integer if present
    if result.duration then
        local dur = tonumber(result.duration)
        if dur then result.duration = dur end
    end
    
    -- Set status_id if status is present
    if result.status then
        if result.status:lower():find("success") or result.status:lower():find("allow") then
            result.status_id = 1  -- Success
        elseif result.status:lower():find("fail") or result.status:lower():find("deny") then
            result.status_id = 2  -- Failure
        else
            result.status_id = 99  -- Other
        end
    end
    
    -- Build observables for enrichment
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
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end