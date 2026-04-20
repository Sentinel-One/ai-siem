-- Palo Alto Networks logs to OCSF Network Activity transformation
-- Class UID: 4001 (Network Activity), Category UID: 4 (Network Activity)

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

-- Replace userdata nil values
function no_nulls(d, rn)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = rn
            elseif type(v) == "table" then no_nulls(v, rn) end
        end
    end
    return d
end

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Map Palo Alto action to OCSF activity_id
local function getActivityId(action)
    if action == nil then return 99 end
    local actionMap = {
        allow = 1,      -- Allow
        deny = 2,       -- Deny
        drop = 2,       -- Deny
        block = 2,      -- Deny
        reset = 3,      -- Reset
        ["reset-client"] = 3,
        ["reset-server"] = 3,
        ["reset-both"] = 3,
        alert = 99,     -- Other
        log = 99        -- Other
    }
    return actionMap[string.lower(tostring(action))] or 99
end

-- Map severity to OCSF severity_id
local function getSeverityId(severity)
    if severity == nil then return 0 end
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        low = 2,
        informational = 1,
        info = 1,
        warning = 3,
        error = 4
    }
    return severityMap[string.lower(tostring(severity))] or 0
end

-- Convert timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if timeStr == nil then return os.time() * 1000 end
    
    -- Try ISO format first (YYYY-MM-DDTHH:MM:SS)
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
    
    -- Try MM/DD/YYYY HH:MM:SS format
    mo, dy, yr, hr, mn, sc = timeStr:match("(%d+)/(%d+)/(%d+) (%d+):(%d+):(%d+)")
    if mo then
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
    
    -- If numeric timestamp, assume seconds and convert to ms
    local numTime = tonumber(timeStr)
    if numTime then
        -- If less than a reasonable epoch value, assume it's already in ms
        if numTime > 1000000000000 then
            return numTime
        else
            return numTime * 1000
        end
    end
    
    return os.time() * 1000
end

-- Get activity name based on action and type
local function getActivityName(action, logType)
    local actionStr = tostring(action or "unknown"):lower()
    local typeStr = tostring(logType or ""):lower()
    
    if actionStr == "allow" then
        return "Network Traffic Allowed"
    elseif actionStr == "deny" or actionStr == "drop" or actionStr == "block" then
        return "Network Traffic Denied"
    elseif actionStr:find("reset") then
        return "Network Connection Reset"
    elseif typeStr:find("threat") then
        return "Network Threat Detected"
    elseif typeStr:find("url") then
        return "URL Filtering"
    elseif typeStr:find("wildfire") then
        return "Malware Detection"
    else
        return "Network Activity"
    end
end

-- Main transformation function
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Field mappings for common Palo Alto log fields
    local fieldMappings = {
        -- Core OCSF fields
        {type = "computed", target = "class_uid", value = CLASS_UID},
        {type = "computed", target = "category_uid", value = CATEGORY_UID},
        {type = "computed", target = "class_name", value = "Network Activity"},
        {type = "computed", target = "category_name", value = "Network Activity"},
        
        -- Source endpoint mapping
        {type = "priority", source1 = "src", source2 = "sourceip", source3 = "source_ip", target = "src_endpoint.ip"},
        {type = "priority", source1 = "sport", source2 = "source_port", target = "src_endpoint.port"},
        {type = "priority", source1 = "srchost", source2 = "source_host", target = "src_endpoint.hostname"},
        
        -- Destination endpoint mapping  
        {type = "priority", source1 = "dst", source2 = "destip", source3 = "dest_ip", target = "dst_endpoint.ip"},
        {type = "priority", source1 = "dport", source2 = "dest_port", target = "dst_endpoint.port"},
        {type = "priority", source1 = "dsthost", source2 = "dest_host", target = "dst_endpoint.hostname"},
        
        -- Protocol and network details
        {type = "direct", source = "proto", target = "protocol_name"},
        {type = "direct", source = "protocol", target = "protocol_name"},
        {type = "direct", source = "app", target = "metadata.product.feature.name"},
        {type = "direct", source = "application", target = "metadata.product.feature.name"},
        
        -- Traffic and session details
        {type = "direct", source = "bytes", target = "traffic.bytes"},
        {type = "direct", source = "packets", target = "traffic.packets"},
        {type = "direct", source = "bytes_sent", target = "traffic.bytes_out"},
        {type = "direct", source = "bytes_received", target = "traffic.bytes_in"},
        {type = "direct", source = "session_id", target = "connection_info.uid"},
        {type = "direct", source = "sessionid", target = "connection_info.uid"},
        
        -- Message and raw data
        {type = "priority", source1 = "message", source2 = "msg", source3 = "description", target = "message"},
        {type = "direct", source = "raw", target = "raw_data"},
        
        -- User information
        {type = "priority", source1 = "user", source2 = "username", source3 = "srcuser", target = "actor.user.name"},
        
        -- URL and threat information
        {type = "direct", source = "url", target = "http_request.url.url_string"},
        {type = "direct", source = "threat", target = "malware.name"},
        {type = "direct", source = "threat_name", target = "malware.name"},
        {type = "direct", source = "category", target = "category_name"},
        
        -- Device information
        {type = "computed", target = "metadata.product.name", value = "Palo Alto Networks Firewall"},
        {type = "computed", target = "metadata.product.vendor_name", value = "Palo Alto Networks"},
        {type = "direct", source = "device_name", target = "device.name"},
        {type = "direct", source = "serial", target = "device.uid"}
    }
    
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
    
    -- Set activity_id based on action
    local action = getValue(event, "action", nil) or getValue(event, "act", nil)
    local activityId = getActivityId(action)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    mappedPaths["action"] = true
    mappedPaths["act"] = true
    
    -- Set severity_id
    local severity = getValue(event, "severity", nil) or getValue(event, "sev", nil)
    result.severity_id = getSeverityId(severity)
    mappedPaths["severity"] = true
    mappedPaths["sev"] = true
    
    -- Set activity_name
    local logType = getValue(event, "type", nil) or getValue(event, "logtype", nil)
    result.activity_name = getActivityName(action, logType)
    mappedPaths["type"] = true
    mappedPaths["logtype"] = true
    
    -- Handle timestamp
    local timestamp = getValue(event, "time", nil) or getValue(event, "timestamp", nil) or 
                     getValue(event, "receive_time", nil) or getValue(event, "generated_time", nil)
    result.time = parseTimestamp(timestamp)
    mappedPaths["time"] = true
    mappedPaths["timestamp"] = true
    mappedPaths["receive_time"] = true
    mappedPaths["generated_time"] = true
    
    -- Set status based on action
    if action then
        if string.lower(tostring(action)) == "allow" then
            result.status = "Success"
            result.status_id = 1
        else
            result.status = "Failure"  
            result.status_id = 2
        end
    end
    
    -- Convert numeric ports to integers
    if result.src_endpoint and result.src_endpoint.port then
        result.src_endpoint.port = tonumber(result.src_endpoint.port) or result.src_endpoint.port
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        result.dst_endpoint.port = tonumber(result.dst_endpoint.port) or result.dst_endpoint.port
    end
    
    -- Build observables array
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
    if result.actor and result.actor.user and result.actor.user.name then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.name",
            value = result.actor.user.name
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up and return
    return no_nulls(result, nil)
end