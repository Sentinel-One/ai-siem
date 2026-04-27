-- Citrix NetScaler Network Activity parser for OCSF
-- Maps NetScaler log events to OCSF Network Activity class (4001)

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
    if type(tbl) ~= "table" or key == nil then return default end
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

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Map NetScaler severity levels to OCSF severity_id
local function getSeverityId(severity)
    if severity == nil then return 0 end
    local severityStr = tostring(severity):lower()
    local severityMap = {
        critical = 5,
        high = 4,
        major = 4,
        medium = 3,
        minor = 2,
        low = 2,
        warning = 2,
        info = 1,
        informational = 1,
        notice = 1,
        debug = 1,
        error = 4,
        alert = 5,
        emergency = 6
    }
    return severityMap[severityStr] or 0
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if not timestamp then return os.time() * 1000 end
    
    -- Handle various NetScaler timestamp formats
    local timeStr = tostring(timestamp)
    
    -- ISO format: 2023-10-15T14:30:25Z or 2023-10-15T14:30:25.123Z
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
    if yr then
        return os.time({year=tonumber(yr), month=tonumber(mo), day=tonumber(dy),
                       hour=tonumber(hr), min=tonumber(mn), sec=tonumber(sc)}) * 1000
    end
    
    -- Unix timestamp (seconds or milliseconds)
    local unixTime = tonumber(timeStr)
    if unixTime then
        -- If less than year 2000, assume seconds, otherwise milliseconds
        if unixTime < 946684800000 then
            return unixTime * 1000
        else
            return unixTime
        end
    end
    
    -- Default to current time
    return os.time() * 1000
end

-- Determine activity_id based on NetScaler event type
local function getActivityId(event)
    local eventType = getValue(event, "event_type", "")
    local action = getValue(event, "action", "")
    local method = getValue(event, "method", "")
    
    -- Map common NetScaler activities
    local activityMap = {
        connection = 1,     -- Network connection
        request = 2,        -- Network request
        response = 3,       -- Network response
        accept = 1,         -- Accept connection
        deny = 5,           -- Deny/block
        drop = 5,           -- Drop packet
        allow = 1,          -- Allow traffic
        block = 5,          -- Block traffic
        redirect = 4,       -- Redirect
        rewrite = 4,        -- Rewrite
        transform = 4,      -- Transform
        load_balance = 6,   -- Load balance
        ssl_handshake = 7,  -- SSL handshake
        authentication = 8, -- Authentication
        session = 9,        -- Session event
        health_check = 10   -- Health check
    }
    
    -- Check event_type first
    if eventType ~= "" then
        local eventTypeLower = eventType:lower()
        for activity, id in pairs(activityMap) do
            if eventTypeLower:find(activity) then
                return id
            end
        end
    end
    
    -- Check action
    if action ~= "" then
        local actionLower = action:lower()
        for activity, id in pairs(activityMap) do
            if actionLower:find(activity) then
                return id
            end
        end
    end
    
    -- Check method
    if method ~= "" then
        local methodLower = method:lower()
        if methodLower:find("get") or methodLower:find("post") or methodLower:find("put") then
            return 2  -- Request
        end
    end
    
    return 99  -- Other/Unknown
end

-- Generate activity name based on activity_id
local function getActivityName(activityId, event)
    local activityNames = {
        [1] = "Accept",
        [2] = "Request", 
        [3] = "Response",
        [4] = "Redirect",
        [5] = "Deny",
        [6] = "Load Balance",
        [7] = "SSL Handshake",
        [8] = "Authentication",
        [9] = "Session",
        [10] = "Health Check",
        [99] = "Other"
    }
    
    local baseName = activityNames[activityId] or "Network Activity"
    local eventType = getValue(event, "event_type", "")
    if eventType ~= "" then
        return baseName .. " - " .. eventType
    end
    return baseName
end

-- Main field mappings for NetScaler logs
local fieldMappings = {
    -- Basic OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source endpoint mappings
    {type = "direct", source = "src_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "source_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "client_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "src_port", target = "src_endpoint.port"},
    {type = "direct", source = "source_port", target = "src_endpoint.port"},
    {type = "direct", source = "client_port", target = "src_endpoint.port"},
    {type = "direct", source = "src_host", target = "src_endpoint.hostname"},
    {type = "direct", source = "source_host", target = "src_endpoint.hostname"},
    
    -- Destination endpoint mappings
    {type = "direct", source = "dst_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dest_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "server_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dst_port", target = "dst_endpoint.port"},
    {type = "direct", source = "dest_port", target = "dst_endpoint.port"},
    {type = "direct", source = "server_port", target = "dst_endpoint.port"},
    {type = "direct", source = "dst_host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "dest_host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "server_name", target = "dst_endpoint.hostname"},
    
    -- Protocol and network details
    {type = "direct", source = "protocol", target = "protocol_name"},
    {type = "direct", source = "proto", target = "protocol_name"},
    
    -- Event details
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "msg", target = "message"},
    {type = "direct", source = "description", target = "message"},
    {type = "direct", source = "raw", target = "raw_data"},
    {type = "direct", source = "raw_data", target = "raw_data"},
    {type = "direct", source = "original_message", target = "raw_data"},
    
    -- Status mappings
    {type = "direct", source = "status", target = "status"},
    {type = "direct", source = "status_code", target = "status_id"},
    {type = "direct", source = "response_code", target = "status_id"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    
    -- Timing
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "response_time", target = "duration"},
    {type = "direct", source = "start_time", target = "start_time"},
    {type = "direct", source = "end_time", target = "end_time"},
    {type = "direct", source = "count", target = "count"},
    {type = "direct", source = "event_count", target = "count"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "NetScaler"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Citrix"},
    {type = "direct", source = "version", target = "metadata.version"},
    {type = "direct", source = "product_version", target = "metadata.version"},
    {type = "direct", source = "timezone", target = "timezone_offset"}
}

function processEvent(event)
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
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity_id and dependent fields
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.activity_name = getActivityName(activityId, event)
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity_id
    local severity = getValue(event, "severity", getValue(event, "priority", getValue(event, "level", nil)))
    result.severity_id = getSeverityId(severity)
    
    -- Set timestamp
    local timestamp = getValue(event, "timestamp", getValue(event, "time", getValue(event, "@timestamp", nil)))
    result.time = parseTimestamp(timestamp)
    
    -- Map additional timestamp fields to track in mappedPaths
    mappedPaths["timestamp"] = true
    mappedPaths["time"] = true
    mappedPaths["@timestamp"] = true
    mappedPaths["severity"] = true
    mappedPaths["priority"] = true
    mappedPaths["level"] = true
    mappedPaths["event_type"] = true
    mappedPaths["action"] = true
    mappedPaths["method"] = true
    
    -- Convert port numbers to integers if they exist
    if result.src_endpoint and result.src_endpoint.port then
        result.src_endpoint.port = tonumber(result.src_endpoint.port)
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        result.dst_endpoint.port = tonumber(result.dst_endpoint.port)
    end
    if result.status_id then
        result.status_id = tonumber(result.status_id)
    end
    if result.duration then
        result.duration = tonumber(result.duration)
    end
    if result.count then
        result.count = tonumber(result.count)
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
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up userdata nulls
    result = no_nulls(result, nil)
    
    return result
end