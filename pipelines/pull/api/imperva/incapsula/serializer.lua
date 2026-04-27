-- OCSF constants for Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Helper functions for safe field access
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

-- Convert timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if timestamp == nil or timestamp == "" then
        return os.time() * 1000
    end
    
    -- Try ISO format first (YYYY-MM-DDTHH:MM:SSZ)
    local yr, mo, dy, hr, mn, sc = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        local timeTable = {
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        }
        return os.time(timeTable) * 1000
    end
    
    -- Try epoch seconds
    local epochSecs = tonumber(timestamp)
    if epochSecs then
        -- If it looks like seconds (reasonable range), convert to ms
        if epochSecs > 1000000000 and epochSecs < 10000000000 then
            return epochSecs * 1000
        end
        -- If it's already milliseconds, return as-is
        if epochSecs > 1000000000000 then
            return epochSecs
        end
    end
    
    -- Default to current time
    return os.time() * 1000
end

-- Map severity levels to OCSF severity_id
local function getSeverityId(severity)
    if severity == nil then return 0 end
    
    local severityStr = string.upper(tostring(severity))
    
    -- Direct numeric mapping
    local numericSeverity = tonumber(severity)
    if numericSeverity then
        if numericSeverity >= 0 and numericSeverity <= 6 then
            return numericSeverity
        end
    end
    
    -- String-based mapping
    local severityMap = {
        ["CRITICAL"] = 5,
        ["HIGH"] = 4,
        ["MEDIUM"] = 3,
        ["LOW"] = 2,
        ["INFO"] = 1,
        ["INFORMATIONAL"] = 1,
        ["DEBUG"] = 1,
        ["WARNING"] = 2,
        ["ERROR"] = 4,
        ["FATAL"] = 6,
        ["ALERT"] = 5
    }
    
    return severityMap[severityStr] or 0
end

-- Determine activity ID based on event type or action
local function getActivityId(event)
    local action = getNestedField(event, 'action') or 
                   getNestedField(event, 'event_type') or
                   getNestedField(event, 'activity') or
                   getNestedField(event, 'method')
    
    if action then
        local actionStr = string.upper(tostring(action))
        
        -- Common network activity mappings
        if actionStr:find("CONNECT") or actionStr:find("ESTABLISH") then
            return 1 -- Connect
        elseif actionStr:find("DISCONNECT") or actionStr:find("CLOSE") then
            return 2 -- Disconnect  
        elseif actionStr:find("DENY") or actionStr:find("BLOCK") or actionStr:find("DROP") then
            return 3 -- Refuse
        elseif actionStr:find("ALLOW") or actionStr:find("ACCEPT") then
            return 4 -- Traffic
        elseif actionStr:find("SCAN") then
            return 5 -- Scan
        end
    end
    
    return 99 -- Other
end

-- Main transformation function
function processEvent(event)
    -- Validate input
    if type(event) ~= "table" then
        return nil
    end
    
    local result = {}
    local mappedPaths = {}
    
    -- Field mappings for Incapsula logs
    local fieldMappings = {
        -- Direct field mappings
        {type = "direct", source = "src_ip", target = "src_endpoint.ip"},
        {type = "direct", source = "source_ip", target = "src_endpoint.ip"},
        {type = "direct", source = "client_ip", target = "src_endpoint.ip"},
        {type = "direct", source = "src_port", target = "src_endpoint.port"},
        {type = "direct", source = "source_port", target = "src_endpoint.port"},
        {type = "direct", source = "dst_ip", target = "dst_endpoint.ip"},
        {type = "direct", source = "dest_ip", target = "dst_endpoint.ip"},
        {type = "direct", source = "server_ip", target = "dst_endpoint.ip"},
        {type = "direct", source = "dst_port", target = "dst_endpoint.port"},
        {type = "direct", source = "dest_port", target = "dst_endpoint.port"},
        {type = "direct", source = "server_port", target = "dst_endpoint.port"},
        {type = "direct", source = "protocol", target = "protocol_name"},
        {type = "direct", source = "proto", target = "protocol_name"},
        {type = "direct", source = "message", target = "message"},
        {type = "direct", source = "msg", target = "message"},
        {type = "direct", source = "description", target = "message"},
        {type = "direct", source = "raw", target = "raw_data"},
        {type = "direct", source = "raw_data", target = "raw_data"},
        {type = "direct", source = "status", target = "status"},
        {type = "direct", source = "status_code", target = "status_id"},
        {type = "direct", source = "response_code", target = "status_id"},
        {type = "direct", source = "count", target = "count"},
        {type = "direct", source = "duration", target = "duration"},
        {type = "direct", source = "start_time", target = "start_time"},
        {type = "direct", source = "end_time", target = "end_time"},
        {type = "direct", source = "hostname", target = "src_endpoint.hostname"},
        {type = "direct", source = "host", target = "dst_endpoint.hostname"},
        {type = "direct", source = "server_name", target = "dst_endpoint.hostname"},
        
        -- Priority mappings (try multiple sources)
        {type = "priority", source1 = "timestamp", source2 = "time", target = "_timestamp"},
        {type = "priority", source1 = "severity", source2 = "level", target = "_severity"},
        {type = "priority", source1 = "site_id", source2 = "account_id", target = "metadata.labels.site_id"},
        
        -- Computed values
        {type = "computed", target = "class_uid", value = CLASS_UID},
        {type = "computed", target = "category_uid", value = CATEGORY_UID},
        {type = "computed", target = "class_name", value = "Network Activity"},
        {type = "computed", target = "category_name", value = "Network Activity"},
        {type = "computed", target = "metadata.product.name", value = "Incapsula"},
        {type = "computed", target = "metadata.product.vendor_name", value = "Imperva"},
        {type = "computed", target = "metadata.version", value = "1.0.0"}
    }
    
    -- Process all field mappings
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
            if mapping.source2 then
                mappedPaths[mapping.source2] = true
            end
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity_id and type_uid based on event analysis
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set activity_name based on activity_id
    local activityNames = {
        [1] = "Connect",
        [2] = "Disconnect", 
        [3] = "Refuse",
        [4] = "Traffic",
        [5] = "Scan",
        [99] = "Other"
    }
    result.activity_name = activityNames[activityId] or "Network Activity"
    
    -- Process timestamp
    local timestamp = getNestedField(result, "_timestamp")
    result.time = parseTimestamp(timestamp)
    result["_timestamp"] = nil -- Remove temporary field
    
    -- Process severity
    local severity = getNestedField(result, "_severity")
    result.severity_id = getSeverityId(severity)
    result["_severity"] = nil -- Remove temporary field
    
    -- Set default values for required fields if missing
    local function setDefault(path, val)
        if getNestedField(result, path) == nil then
            setNestedField(result, path, val)
        end
    end
    
    setDefault('severity_id', 0)
    setDefault('time', os.time() * 1000)
    
    -- Convert numeric port values
    local srcPort = getNestedField(result, "src_endpoint.port")
    if srcPort then
        result.src_endpoint.port = tonumber(srcPort)
    end
    
    local dstPort = getNestedField(result, "dst_endpoint.port")  
    if dstPort then
        result.dst_endpoint.port = tonumber(dstPort)
    end
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up empty nested tables
    local function cleanEmptyTables(tbl)
        if type(tbl) ~= "table" then return end
        for k, v in pairs(tbl) do
            if type(v) == "table" then
                cleanEmptyTables(v)
                -- Check if table is now empty
                local isEmpty = true
                for _ in pairs(v) do
                    isEmpty = false
                    break
                end
                if isEmpty then
                    tbl[k] = nil
                end
            elseif v == nil or v == "" then
                tbl[k] = nil
            end
        end
    end
    
    cleanEmptyTables(result)
    
    return result
end