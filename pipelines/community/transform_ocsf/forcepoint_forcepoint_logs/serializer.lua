-- Forcepoint network logs to OCSF Network Activity transformation
-- Handles various Forcepoint network security events

local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Helper functions for production reliability
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
    
    -- Try ISO format: YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS
    local year, month, day, hour, min, sec = timeStr:match("(%d%d%d%d)-(%d%d)-(%d%d)[T ](%d%d):(%d%d):(%d%d)")
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
    
    -- Try epoch timestamp (seconds or milliseconds)
    local epochTime = tonumber(timeStr)
    if epochTime then
        -- If less than year 2000, assume seconds; otherwise milliseconds
        if epochTime < 946684800000 then
            return epochTime * 1000
        else
            return epochTime
        end
    end
    
    return nil
end

-- Map Forcepoint severity to OCSF severity_id
function getSeverityId(severity)
    if not severity then return 0 end
    local sev = tostring(severity):lower()
    
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        low = 2,
        info = 1,
        informational = 1,
        warning = 3,
        error = 4,
        fatal = 6,
        emergency = 5,
        alert = 5,
        notice = 1
    }
    
    return severityMap[sev] or 0
end

-- Determine activity_id based on event content
function getActivityId(event)
    local action = getValue(event, 'action', ''):lower()
    local eventType = getValue(event, 'event_type', ''):lower()
    local category = getValue(event, 'category', ''):lower()
    
    -- Network activity mapping
    if action:find('allow') or action:find('permit') then
        return 1 -- Allow
    elseif action:find('deny') or action:find('block') or action:find('drop') then
        return 2 -- Deny
    elseif action:find('connect') or eventType:find('connect') then
        return 5 -- Connect
    elseif action:find('disconnect') or eventType:find('disconnect') then
        return 6 -- Disconnect
    elseif category:find('traffic') or category:find('network') then
        return 1 -- Generic network traffic
    else
        return 99 -- Other
    end
end

-- Get activity name based on activity_id
function getActivityName(activityId, event)
    local activityNames = {
        [1] = "Allow",
        [2] = "Deny", 
        [5] = "Connect",
        [6] = "Disconnect",
        [99] = "Other"
    }
    
    local name = activityNames[activityId] or "Unknown"
    local action = getValue(event, 'action', '')
    if action ~= '' then
        name = name .. " - " .. action
    end
    
    return name
end

function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Core OCSF fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = "Network Activity"
    result.category_name = "Network Activity"
    
    -- Determine activity and type
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.activity_name = getActivityName(activityId, event)
    
    -- Field mappings for Forcepoint logs
    local fieldMappings = {
        -- Timing
        {type = "direct", source = "timestamp", target = "time_dt"},
        {type = "direct", source = "time", target = "time_dt"},
        {type = "direct", source = "event_time", target = "time_dt"},
        
        -- Network endpoints
        {type = "direct", source = "src_ip", target = "src_endpoint.ip"},
        {type = "direct", source = "source_ip", target = "src_endpoint.ip"},
        {type = "direct", source = "client_ip", target = "src_endpoint.ip"},
        {type = "direct", source = "src_port", target = "src_endpoint.port"},
        {type = "direct", source = "source_port", target = "src_endpoint.port"},
        {type = "direct", source = "src_host", target = "src_endpoint.hostname"},
        {type = "direct", source = "source_host", target = "src_endpoint.hostname"},
        
        {type = "direct", source = "dst_ip", target = "dst_endpoint.ip"},
        {type = "direct", source = "dest_ip", target = "dst_endpoint.ip"},
        {type = "direct", source = "destination_ip", target = "dst_endpoint.ip"},
        {type = "direct", source = "dst_port", target = "dst_endpoint.port"},
        {type = "direct", source = "dest_port", target = "dst_endpoint.port"},
        {type = "direct", source = "destination_port", target = "dst_endpoint.port"},
        {type = "direct", source = "dst_host", target = "dst_endpoint.hostname"},
        {type = "direct", source = "dest_host", target = "dst_endpoint.hostname"},
        
        -- Protocol and connection details
        {type = "direct", source = "protocol", target = "connection_info.protocol_name"},
        {type = "direct", source = "proto", target = "connection_info.protocol_name"},
        {type = "direct", source = "bytes", target = "traffic.bytes"},
        {type = "direct", source = "bytes_in", target = "traffic.bytes_in"},
        {type = "direct", source = "bytes_out", target = "traffic.bytes_out"},
        {type = "direct", source = "packets", target = "traffic.packets"},
        {type = "direct", source = "duration", target = "duration"},
        
        -- User and session
        {type = "direct", source = "user", target = "actor.user.name"},
        {type = "direct", source = "username", target = "actor.user.name"},
        {type = "direct", source = "user_name", target = "actor.user.name"},
        {type = "direct", source = "session_id", target = "actor.session.uid"},
        
        -- Event details
        {type = "direct", source = "message", target = "message"},
        {type = "direct", source = "msg", target = "message"},
        {type = "direct", source = "description", target = "message"},
        {type = "direct", source = "rule", target = "metadata.rule.name"},
        {type = "direct", source = "rule_name", target = "metadata.rule.name"},
        {type = "direct", source = "policy", target = "metadata.policy.name"},
        {type = "direct", source = "category", target = "category_name"},
        
        -- Status and severity
        {type = "direct", source = "status", target = "status"},
        {type = "direct", source = "severity", target = "severity"},
        {type = "direct", source = "priority", target = "severity"},
        {type = "direct", source = "level", target = "severity"},
        
        -- Device and product info
        {type = "direct", source = "device", target = "metadata.product.name"},
        {type = "direct", source = "product", target = "metadata.product.name"},
        {type = "direct", source = "vendor", target = "metadata.product.vendor_name"}
    }
    
    -- Apply field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getValue(event, mapping.source, nil)
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
                mappedPaths[mapping.source] = true
            end
        end
    end
    
    -- Set time from parsed timestamp
    local timeValue = getNestedField(result, 'time_dt')
    if timeValue then
        local parsedTime = parseTimestamp(timeValue)
        if parsedTime then
            result.time = parsedTime
        end
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set severity_id from severity field
    local severityField = result.severity or getValue(event, 'severity', nil)
    result.severity_id = getSeverityId(severityField)
    
    -- Set product metadata defaults
    if not getNestedField(result, 'metadata.product.name') then
        setNestedField(result, 'metadata.product.name', 'Forcepoint')
    end
    if not getNestedField(result, 'metadata.product.vendor_name') then
        setNestedField(result, 'metadata.product.vendor_name', 'Forcepoint')
    end
    setNestedField(result, 'metadata.version', '1.0.0')
    
    -- Protocol name normalization
    local protoName = getNestedField(result, 'connection_info.protocol_name')
    if protoName then
        result.protocol_name = tostring(protoName):upper()
    end
    
    -- Set raw_data if available
    local rawData = getValue(event, 'raw', nil) or getValue(event, 'original', nil)
    if rawData then
        result.raw_data = rawData
    end
    
    -- Add observables for key network indicators
    local observables = {}
    local srcIp = getNestedField(result, 'src_endpoint.ip')
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local dstIp = getNestedField(result, 'dst_endpoint.ip')
    if dstIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "dst_endpoint.ip",
            value = dstIp
        })
    end
    
    local userName = getNestedField(result, 'actor.user.name')
    if userName then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.name", 
            value = userName
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end