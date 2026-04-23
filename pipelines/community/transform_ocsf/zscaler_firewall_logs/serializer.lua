-- OCSF Network Activity transformation for Zscaler Firewall Logs
-- Class UID: 4001 (Network Activity)
-- Category UID: 4 (Network Activity)

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
    local value = tbl[key]
    return value ~= nil and value or default
end

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Convert various timestamp formats to milliseconds since epoch
function parseTimestamp(timeStr)
    if not timeStr or timeStr == "" then return nil end
    
    -- Handle epoch timestamp (seconds or milliseconds)
    local epochTime = tonumber(timeStr)
    if epochTime then
        if epochTime > 1000000000000 then
            return epochTime -- Already in milliseconds
        else
            return epochTime * 1000 -- Convert seconds to milliseconds
        end
    end
    
    -- Handle ISO 8601 format: YYYY-MM-DDTHH:MM:SS
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
    
    -- Handle other common formats
    yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)/(%d+)/(%d+) (%d+):(%d+):(%d+)")
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

-- Map severity/priority to OCSF severity_id
function getSeverityId(level)
    if level == nil then return 0 end
    
    local levelStr = tostring(level):lower()
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        warning = 3,
        warn = 3,
        low = 2,
        info = 1,
        informational = 1,
        information = 1,
        debug = 1,
        error = 4,
        fatal = 6,
        emergency = 5,
        alert = 5
    }
    
    return severityMap[levelStr] or 0
end

-- Determine activity based on action/event type
function getActivityInfo(event)
    local action = getValue(event, "action", "")
    local eventType = getValue(event, "event_type", "")
    local status = getValue(event, "status", "")
    
    -- Check common action fields
    local actionStr = tostring(action):lower()
    local eventTypeStr = tostring(eventType):lower()
    local statusStr = tostring(status):lower()
    
    -- Network activity mapping
    if actionStr:match("allow") or actionStr:match("permit") or statusStr:match("allow") then
        return 1, "Traffic Allowed"
    elseif actionStr:match("deny") or actionStr:match("block") or actionStr:match("drop") or statusStr:match("block") then
        return 2, "Traffic Denied"
    elseif actionStr:match("connect") or eventTypeStr:match("connect") then
        return 5, "Connection Established"
    elseif actionStr:match("disconnect") or eventTypeStr:match("disconnect") then
        return 6, "Connection Terminated"
    else
        return 99, "Other"
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- Basic OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source endpoint mappings
    {type = "priority", source1 = "src_ip", source2 = "source_ip", source3 = "srcip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "source_port", source3 = "srcport", target = "src_endpoint.port"},
    {type = "priority", source1 = "src_host", source2 = "source_host", source3 = "srchost", target = "src_endpoint.hostname"},
    
    -- Destination endpoint mappings
    {type = "priority", source1 = "dst_ip", source2 = "dest_ip", source3 = "dstip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_port", source2 = "dest_port", source3 = "dstport", target = "dst_endpoint.port"},
    {type = "priority", source1 = "dst_host", source2 = "dest_host", source3 = "dsthost", target = "dst_endpoint.hostname"},
    
    -- Protocol and traffic info
    {type = "priority", source1 = "protocol", source2 = "proto", target = "protocol_name"},
    {type = "priority", source1 = "bytes", source2 = "byte_count", target = "traffic.bytes"},
    {type = "priority", source1 = "packets", source2 = "packet_count", target = "traffic.packets"},
    
    -- Message and status
    {type = "priority", source1 = "message", source2 = "msg", source3 = "description", target = "message"},
    {type = "priority", source1 = "status", source2 = "result", target = "status"},
    {type = "direct", source = "status_code", target = "status_id"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    {type = "direct", source = "raw_data", target = "raw_data"},
    
    -- Duration and timing
    {type = "priority", source1 = "duration", source2 = "elapsed_time", target = "duration"},
    {type = "direct", source = "start_time", target = "start_time"},
    {type = "direct", source = "end_time", target = "end_time"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "Zscaler Firewall"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Zscaler"},
    {type = "direct", source = "version", target = "metadata.version"},
    {type = "direct", source = "timezone_offset", target = "timezone_offset"},
    
    -- Count field
    {type = "priority", source1 = "count", source2 = "event_count", target = "count"}
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

    -- Set activity_id and activity_name based on event analysis
    local activity_id, activity_name = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    
    -- Compute type_uid
    result.type_uid = CLASS_UID * 100 + activity_id

    -- Set severity_id based on various severity fields
    local severity = getValue(event, "severity", "") or 
                    getValue(event, "priority", "") or
                    getValue(event, "level", "") or
                    getValue(event, "risk", "")
    result.severity_id = getSeverityId(severity)

    -- Parse timestamp from various possible fields
    local timestamp = getValue(event, "timestamp", "") or
                     getValue(event, "time", "") or  
                     getValue(event, "datetime", "") or
                     getValue(event, "event_time", "") or
                     getValue(event, "@timestamp", "")
    
    local parsedTime = parseTimestamp(timestamp)
    if parsedTime then
        result.time = parsedTime
    else
        result.time = os.time() * 1000 -- Default to current time
    end
    
    -- Mark timestamp fields as mapped
    mappedPaths["timestamp"] = true
    mappedPaths["time"] = true
    mappedPaths["datetime"] = true
    mappedPaths["event_time"] = true
    mappedPaths["@timestamp"] = true

    -- Convert port numbers to integers if present
    if result.src_endpoint and result.src_endpoint.port then
        result.src_endpoint.port = tonumber(result.src_endpoint.port)
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        result.dst_endpoint.port = tonumber(result.dst_endpoint.port)
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

    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean up empty tables
    if result.src_endpoint and next(result.src_endpoint) == nil then
        result.src_endpoint = nil
    end
    if result.dst_endpoint and next(result.dst_endpoint) == nil then
        result.dst_endpoint = nil
    end
    if result.traffic and next(result.traffic) == nil then
        result.traffic = nil
    end
    if result.metadata and result.metadata.product and next(result.metadata.product) == nil then
        result.metadata.product = nil
    end
    if result.metadata and next(result.metadata) == nil then
        result.metadata = nil
    end

    return result
end