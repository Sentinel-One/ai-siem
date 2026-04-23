-- Zscaler DNS Firewall transformation to OCSF Network Activity
-- Class: Network Activity (4001)

local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Activity ID mapping for DNS activities
local ACTIVITY_MAP = {
    ["allow"] = 1,
    ["deny"] = 2,
    ["block"] = 2,
    ["drop"] = 2,
    ["permit"] = 1,
    ["forward"] = 6,
    ["redirect"] = 6,
    ["query"] = 6,
    ["response"] = 6
}

-- Severity mapping
local SEVERITY_MAP = {
    ["critical"] = 5,
    ["high"] = 4,
    ["medium"] = 3,
    ["low"] = 2,
    ["info"] = 1,
    ["informational"] = 1,
    ["warning"] = 3,
    ["error"] = 4,
    ["fatal"] = 6
}

-- Protocol mapping
local PROTOCOL_MAP = {
    ["17"] = "UDP",
    ["6"] = "TCP",
    ["udp"] = "UDP",
    ["tcp"] = "TCP"
}

-- Nested field access helpers
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

-- Parse timestamp to milliseconds
function parseTimestamp(timeStr)
    if not timeStr then return nil end
    
    -- Try ISO format first (YYYY-MM-DDTHH:MM:SS)
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        return os.time({year=tonumber(yr), month=tonumber(mo), day=tonumber(dy),
                       hour=tonumber(hr), min=tonumber(mn), sec=tonumber(sc), isdst=false}) * 1000
    end
    
    -- Try epoch format
    local epoch = tonumber(timeStr)
    if epoch then
        -- If it looks like seconds (less than year 2100), convert to ms
        if epoch < 4102444800 then
            return epoch * 1000
        else
            return epoch
        end
    end
    
    return nil
end

-- Get activity ID from action/verdict
function getActivityId(event)
    local action = event.action or event.verdict or event.disposition or ""
    action = string.lower(tostring(action))
    return ACTIVITY_MAP[action] or 6  -- Default to "Traffic" activity
end

-- Get severity ID
function getSeverityId(event)
    local severity = event.severity or event.priority or event.risk or ""
    severity = string.lower(tostring(severity))
    return SEVERITY_MAP[severity] or 1  -- Default to Informational
end

-- Get activity name
function getActivityName(event)
    local action = event.action or event.verdict or event.disposition
    if action then
        return "DNS " .. tostring(action):upper()
    end
    return "DNS Query"
end

function processEvent(event)
    if type(event) ~= "table" then return nil end

    local result = {}
    local mappedPaths = {}

    -- Field mappings for Zscaler DNS Firewall
    local fieldMappings = {
        -- Core OCSF fields
        {type = "computed", target = "class_uid", value = CLASS_UID},
        {type = "computed", target = "category_uid", value = CATEGORY_UID},
        {type = "computed", target = "class_name", value = "Network Activity"},
        {type = "computed", target = "category_name", value = "Network Activity"},
        
        -- Message and metadata
        {type = "direct", source = "message", target = "message"},
        {type = "direct", source = "raw", target = "raw_data"},
        {type = "direct", source = "raw_data", target = "raw_data"},
        
        -- Status fields
        {type = "direct", source = "status", target = "status"},
        {type = "direct", source = "status_code", target = "status_id"},
        {type = "direct", source = "status_detail", target = "status_detail"},
        {type = "direct", source = "reason", target = "status_detail"},
        
        -- Network endpoints - source
        {type = "priority", source1 = "src_ip", source2 = "sourceip", target = "src_endpoint.ip"},
        {type = "priority", source1 = "src_port", source2 = "sourceport", target = "src_endpoint.port"},
        {type = "priority", source1 = "src_host", source2 = "client_hostname", target = "src_endpoint.hostname"},
        {type = "direct", source = "client_ip", target = "src_endpoint.ip"},
        {type = "direct", source = "client_name", target = "src_endpoint.hostname"},
        
        -- Network endpoints - destination  
        {type = "priority", source1 = "dst_ip", source2 = "destip", target = "dst_endpoint.ip"},
        {type = "priority", source1 = "dst_port", source2 = "destport", target = "dst_endpoint.port"},
        {type = "priority", source1 = "dst_host", source2 = "hostname", target = "dst_endpoint.hostname"},
        {type = "direct", source = "domain", target = "dst_endpoint.hostname"},
        {type = "direct", source = "dns_query", target = "dst_endpoint.hostname"},
        {type = "direct", source = "query", target = "dst_endpoint.hostname"},
        
        -- Protocol
        {type = "direct", source = "protocol", target = "connection_info.protocol_name"},
        {type = "direct", source = "protocol_name", target = "connection_info.protocol_name"},
        
        -- DNS specific
        {type = "direct", source = "dns_type", target = "query.type"},
        {type = "direct", source = "record_type", target = "query.type"},
        {type = "direct", source = "dns_response", target = "answers.rdata"},
        {type = "direct", source = "response", target = "answers.rdata"},
        
        -- User/device info
        {type = "direct", source = "user", target = "actor.user.name"},
        {type = "direct", source = "username", target = "actor.user.name"},
        {type = "direct", source = "device_name", target = "device.name"},
        {type = "direct", source = "device_hostname", target = "device.hostname"},
        
        -- Location
        {type = "direct", source = "location", target = "src_endpoint.location.desc"},
        {type = "direct", source = "country", target = "src_endpoint.location.country"},
        {type = "direct", source = "city", target = "src_endpoint.location.city"},
        
        -- Categories and threats
        {type = "direct", source = "category", target = "category_name"},
        {type = "direct", source = "threat_name", target = "malware.name"},
        {type = "direct", source = "threat_type", target = "malware.classification_ids"},
        
        -- Counts and duration
        {type = "direct", source = "count", target = "count"},
        {type = "direct", source = "duration", target = "duration"},
        {type = "direct", source = "bytes_in", target = "traffic.bytes_in"},
        {type = "direct", source = "bytes_out", target = "traffic.bytes_out"}
    }

    -- Process mappings
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

    -- Set activity ID and compute type_uid
    local activity_id = getActivityId(event)
    result.activity_id = activity_id
    result.type_uid = CLASS_UID * 100 + activity_id
    result.activity_name = getActivityName(event)

    -- Set severity
    result.severity_id = getSeverityId(event)

    -- Handle timestamp
    local timestamp = parseTimestamp(event.timestamp or event.time or event.datetime or event.event_time)
    result.time = timestamp or (os.time() * 1000)

    -- Set protocol name if we have protocol number
    if result.connection_info and result.connection_info.protocol_name then
        local proto = result.connection_info.protocol_name
        if PROTOCOL_MAP[tostring(proto)] then
            result.connection_info.protocol_name = PROTOCOL_MAP[tostring(proto)]
        end
    end

    -- Set metadata
    setNestedField(result, "metadata.product.name", "Zscaler DNS Firewall")
    setNestedField(result, "metadata.product.vendor_name", "Zscaler")
    setNestedField(result, "metadata.version", "1.0.0")

    -- Mark additional mapped fields
    local additionalMapped = {
        "timestamp", "time", "datetime", "event_time", "action", "verdict", 
        "disposition", "severity", "priority", "risk"
    }
    for _, field in ipairs(additionalMapped) do
        mappedPaths[field] = true
    end

    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)

    return result
end