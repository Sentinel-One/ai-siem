-- WatchGuard Firewall Logs to OCSF Network Activity transformation
-- OCSF Class: Network Activity (4001)

-- OCSF Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Activity ID mappings for common firewall actions
local ACTIVITY_MAPPINGS = {
    ["allow"] = 1,      -- Allow
    ["allowed"] = 1,
    ["accept"] = 1,
    ["deny"] = 2,       -- Deny
    ["denied"] = 2,
    ["block"] = 2,
    ["blocked"] = 2,
    ["drop"] = 2,
    ["dropped"] = 2,
    ["reject"] = 2,
    ["rejected"] = 2,
    ["close"] = 3,      -- Close
    ["closed"] = 3,
    ["reset"] = 3,
    ["timeout"] = 4,    -- Timeout
    ["log"] = 5,        -- Log
    ["monitor"] = 6,    -- Monitor
    ["other"] = 99      -- Other
}

-- Severity mapping for WatchGuard log levels
local function getSeverityId(level)
    if level == nil then return 0 end
    local levelStr = tostring(level):lower()
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        warning = 2,
        low = 2,
        info = 1,
        informational = 1,
        debug = 1,
        error = 4,
        alert = 5,
        emergency = 5,
        notice = 1
    }
    return severityMap[levelStr] or 0
end

-- Extract activity ID from action/disposition
local function getActivityId(event)
    -- Check common action fields
    local action = event.action or event.disposition or event.msg_id or ""
    local actionStr = tostring(action):lower()
    
    -- Direct mapping
    for pattern, activity_id in pairs(ACTIVITY_MAPPINGS) do
        if actionStr:find(pattern) then
            return activity_id
        end
    end
    
    -- Check message field for action keywords
    local message = event.message or event.msg or ""
    local messageStr = tostring(message):lower()
    for pattern, activity_id in pairs(ACTIVITY_MAPPINGS) do
        if messageStr:find(pattern) then
            return activity_id
        end
    end
    
    return 99 -- Other/Unknown
end

-- Get activity name from activity ID
local function getActivityName(activity_id)
    local activityNames = {
        [1] = "Allow",
        [2] = "Deny", 
        [3] = "Close",
        [4] = "Timeout",
        [5] = "Log",
        [6] = "Monitor",
        [99] = "Other"
    }
    return activityNames[activity_id] or "Other"
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if not timestamp then return os.time() * 1000 end
    
    local ts_str = tostring(timestamp)
    
    -- Try ISO 8601 format: 2024-01-01T12:00:00Z or 2024-01-01T12:00:00.000Z
    local year, month, day, hour, min, sec = ts_str:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
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
    
    -- Try syslog format: Jan 01 12:00:00
    local months = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6, Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
    local mon, d, h, m, s = ts_str:match("(%a%a%a)%s+(%d+)%s+(%d+):(%d+):(%d+)")
    if mon and months[mon] then
        local currentYear = tonumber(os.date("%Y"))
        return os.time({
            year = currentYear,
            month = months[mon],
            day = tonumber(d),
            hour = tonumber(h),
            min = tonumber(m),
            sec = tonumber(s),
            isdst = false
        }) * 1000
    end
    
    -- Try epoch timestamp (seconds or milliseconds)
    local epoch = tonumber(ts_str)
    if epoch then
        -- If less than year 2000 timestamp, assume it's seconds
        if epoch < 946684800000 then
            return epoch * 1000
        else
            return epoch
        end
    end
    
    -- Fallback to current time
    return os.time() * 1000
end

-- Helper functions from production Observo scripts
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

-- Field mappings for WatchGuard firewall logs
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source endpoint
    {type = "priority", source1 = "src_ip", source2 = "srcip", source3 = "source_ip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "srcport", source3 = "source_port", target = "src_endpoint.port"},
    {type = "priority", source1 = "src_host", source2 = "srchost", source3 = "source_host", target = "src_endpoint.hostname"},
    
    -- Destination endpoint  
    {type = "priority", source1 = "dst_ip", source2 = "dstip", source3 = "dest_ip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_port", source2 = "dstport", source3 = "dest_port", target = "dst_endpoint.port"},
    {type = "priority", source1 = "dst_host", source2 = "dsthost", source3 = "dest_host", target = "dst_endpoint.hostname"},
    
    -- Protocol and network details
    {type = "priority", source1 = "protocol", source2 = "proto", target = "protocol_name"},
    {type = "priority", source1 = "message", source2 = "msg", target = "message"},
    {type = "direct", source = "raw", target = "raw_data"},
    {type = "direct", source = "status", target = "status"},
    {type = "direct", source = "status_id", target = "status_id"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    {type = "direct", source = "count", target = "count"},
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "start_time", target = "start_time"},
    {type = "direct", source = "end_time", target = "end_time"},
    {type = "direct", source = "timezone_offset", target = "timezone_offset"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "WatchGuard Firewall"},
    {type = "computed", target = "metadata.product.vendor_name", value = "WatchGuard Technologies"},
    {type = "direct", source = "version", target = "metadata.version"},
}

-- Main processing function
function processEvent(event)
    -- Input validation
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
            if value == nil and mapping.source3 then 
                value = getNestedField(event, mapping.source3) 
            end
            if value ~= nil then 
                setNestedField(result, mapping.target, value) 
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
            if mapping.source3 then mappedPaths[mapping.source3] = true end
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity_id and type_uid
    local activity_id = getActivityId(event)
    result.activity_id = activity_id
    result.type_uid = CLASS_UID * 100 + activity_id
    result.activity_name = getActivityName(activity_id)
    
    -- Set severity_id
    local severity = event.severity or event.priority or event.level
    result.severity_id = getSeverityId(severity)
    
    -- Set timestamp
    local timestamp = event.timestamp or event.time or event.ts or event.date
    result.time = parseTimestamp(timestamp)
    
    -- Convert port numbers to integers if they exist
    if result.src_endpoint and result.src_endpoint.port then
        result.src_endpoint.port = tonumber(result.src_endpoint.port)
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        result.dst_endpoint.port = tonumber(result.dst_endpoint.port)
    end
    
    -- Mark timestamp fields as mapped
    mappedPaths.timestamp = true
    mappedPaths.time = true
    mappedPaths.ts = true
    mappedPaths.date = true
    mappedPaths.severity = true
    mappedPaths.priority = true
    mappedPaths.level = true
    mappedPaths.action = true
    mappedPaths.disposition = true
    mappedPaths.msg_id = true
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end