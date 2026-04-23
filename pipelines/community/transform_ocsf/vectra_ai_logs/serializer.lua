-- Constants for OCSF Network Activity class
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
    if type(tbl) ~= "table" then return default end
    local value = tbl[key]
    return value ~= nil and value or default
end

-- Convert severity to OCSF severity_id
local function getSeverityId(severity)
    if severity == nil then return 0 end
    local sev = string.lower(tostring(severity))
    local severityMap = {
        critical = 5, high = 4, medium = 3, low = 2, 
        informational = 1, info = 1, warning = 2,
        error = 4, fatal = 6, emergency = 5, alert = 5
    }
    return severityMap[sev] or 0
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if timeStr == nil then return os.time() * 1000 end
    
    -- Try ISO format first: 2023-12-01T10:30:45Z or 2023-12-01T10:30:45.123Z
    local yr, mo, dy, hr, mn, sc, ms = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z?")
    if yr then
        local timestamp = os.time({
            year = tonumber(yr), month = tonumber(mo), day = tonumber(dy),
            hour = tonumber(hr), min = tonumber(mn), sec = tonumber(sc)
        })
        local milliseconds = ms and tonumber(ms) or 0
        if string.len(ms or "") == 3 then
            return timestamp * 1000 + milliseconds
        else
            return timestamp * 1000
        end
    end
    
    -- Try Unix timestamp (seconds)
    local unixTime = tonumber(timeStr)
    if unixTime then
        -- If it's already in milliseconds (> year 2000 in seconds)
        if unixTime > 946684800000 then
            return unixTime
        else
            return unixTime * 1000
        end
    end
    
    return os.time() * 1000
end

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Clean empty tables recursively
local function cleanEmptyTables(tbl)
    if type(tbl) ~= "table" then return tbl end
    
    local cleaned = {}
    local hasContent = false
    
    for k, v in pairs(tbl) do
        if type(v) == "table" then
            local cleanedValue = cleanEmptyTables(v)
            if cleanedValue and next(cleanedValue) ~= nil then
                cleaned[k] = cleanedValue
                hasContent = true
            end
        elseif v ~= nil and v ~= "" then
            cleaned[k] = v
            hasContent = true
        end
    end
    
    return hasContent and cleaned or nil
end

-- Main transformation function
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Field mappings for Vectra AI logs
    local fieldMappings = {
        -- Core OCSF fields
        {type = "computed", target = "class_uid", value = CLASS_UID},
        {type = "computed", target = "category_uid", value = CATEGORY_UID},
        {type = "computed", target = "class_name", value = "Network Activity"},
        {type = "computed", target = "category_name", value = "Network Activity"},
        
        -- Message and raw data
        {type = "priority", source1 = "message", source2 = "msg", source3 = "description", target = "message"},
        {type = "direct", source = "raw", target = "raw_data"},
        
        -- Status information
        {type = "direct", source = "status", target = "status"},
        {type = "direct", source = "status_id", target = "status_id"},
        {type = "direct", source = "status_detail", target = "status_detail"},
        
        -- Count and duration
        {type = "direct", source = "count", target = "count"},
        {type = "direct", source = "duration", target = "duration"},
        
        -- Source endpoint information
        {type = "priority", source1 = "src_ip", source2 = "source_ip", source3 = "srcip", target = "src_endpoint.ip"},
        {type = "priority", source1 = "src_port", source2 = "source_port", source3 = "srcport", target = "src_endpoint.port"},
        {type = "priority", source1 = "src_host", source2 = "source_host", source3 = "srchost", target = "src_endpoint.hostname"},
        
        -- Destination endpoint information
        {type = "priority", source1 = "dst_ip", source2 = "dest_ip", source3 = "dstip", target = "dst_endpoint.ip"},
        {type = "priority", source1 = "dst_port", source2 = "dest_port", source3 = "dstport", target = "dst_endpoint.port"},
        {type = "priority", source1 = "dst_host", source2 = "dest_host", source3 = "dsthost", target = "dst_endpoint.hostname"},
        
        -- Protocol
        {type = "priority", source1 = "protocol", source2 = "proto", target = "protocol_name"},
        
        -- Metadata
        {type = "computed", target = "metadata.product.name", value = "Vectra AI"},
        {type = "computed", target = "metadata.product.vendor_name", value = "Vectra AI"},
        {type = "priority", source1 = "version", source2 = "product_version", target = "metadata.version"},
        
        -- Additional Vectra-specific fields
        {type = "direct", source = "detection_id", target = "unmapped.detection_id"},
        {type = "direct", source = "detection_name", target = "unmapped.detection_name"},
        {type = "direct", source = "threat_score", target = "unmapped.threat_score"},
        {type = "direct", source = "certainty_score", target = "unmapped.certainty_score"},
        {type = "direct", source = "host_id", target = "unmapped.host_id"},
        {type = "direct", source = "host_name", target = "unmapped.host_name"},
        {type = "direct", source = "category", target = "unmapped.category"},
        {type = "direct", source = "tags", target = "unmapped.tags"},
    }
    
    -- Apply field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getNestedField(event, mapping.source)
            if value ~= nil then
                setNestedField(result, mapping.target, value)
                mappedPaths[mapping.source] = true
            end
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
                mappedPaths[mapping.source1] = true
                if mapping.source2 then mappedPaths[mapping.source2] = true end
                if mapping.source3 then mappedPaths[mapping.source3] = true end
            end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity information
    local activityName = getValue(event, "event_type", getValue(event, "detection_type", getValue(event, "activity", "Network Activity")))
    result.activity_name = activityName
    
    -- Determine activity_id based on event type
    local activityId = 99 -- Default: Other
    local eventType = string.lower(getValue(event, "event_type", getValue(event, "detection_type", "")))
    if string.find(eventType, "connection") or string.find(eventType, "flow") then
        activityId = 1 -- Open
    elseif string.find(eventType, "traffic") then
        activityId = 6 -- Traffic
    elseif string.find(eventType, "detection") then
        activityId = 99 -- Other (security detection)
    end
    
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    local severity = getValue(event, "severity", getValue(event, "priority", getValue(event, "risk_score", "unknown")))
    result.severity_id = getSeverityId(severity)
    
    -- Set timestamp
    local timestamp = getValue(event, "timestamp", getValue(event, "time", getValue(event, "event_time")))
    result.time = parseTimestamp(timestamp)
    
    -- Set start and end times if available
    local startTime = getValue(event, "start_time", getValue(event, "first_seen"))
    if startTime then
        result.start_time = parseTimestamp(startTime)
        mappedPaths["start_time"] = true
        mappedPaths["first_seen"] = true
    end
    
    local endTime = getValue(event, "end_time", getValue(event, "last_seen"))
    if endTime then
        result.end_time = parseTimestamp(endTime)
        mappedPaths["end_time"] = true
        mappedPaths["last_seen"] = true
    end
    
    -- Mark common timestamp fields as mapped
    mappedPaths["timestamp"] = true
    mappedPaths["time"] = true
    mappedPaths["event_time"] = true
    
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
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean empty tables
    result = cleanEmptyTables(result)
    
    return result
end