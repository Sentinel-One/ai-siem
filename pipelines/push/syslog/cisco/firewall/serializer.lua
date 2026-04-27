-- Cisco Firewall to OCSF Network Activity transformation
-- Maps Cisco firewall logs to OCSF Network Activity (class_uid=4001)

-- OCSF constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

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
    local value = tbl[key]
    return value ~= nil and value or default
end

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Clean empty tables
function cleanEmptyTables(tbl)
    if type(tbl) ~= "table" then return tbl end
    local hasContent = false
    for k, v in pairs(tbl) do
        if type(v) == "table" then
            local cleaned = cleanEmptyTables(v)
            if cleaned and next(cleaned) ~= nil then
                tbl[k] = cleaned
                hasContent = true
            else
                tbl[k] = nil
            end
        elseif v ~= nil and v ~= "" then
            hasContent = true
        end
    end
    return hasContent and tbl or nil
end

-- Map severity level to OCSF severity_id
local function getSeverityId(level)
    if level == nil then return 0 end
    local severityMap = {
        ["0"] = 1,  -- Informational
        ["1"] = 1,  -- Informational
        ["2"] = 1,  -- Informational
        ["3"] = 1,  -- Informational
        ["4"] = 2,  -- Low
        ["5"] = 3,  -- Medium
        ["6"] = 4,  -- High
        ["7"] = 5,  -- Critical
        ["emergency"] = 5,   -- Critical
        ["alert"] = 5,       -- Critical
        ["critical"] = 5,    -- Critical
        ["error"] = 4,       -- High
        ["warning"] = 3,     -- Medium
        ["notice"] = 2,      -- Low
        ["info"] = 1,        -- Informational
        ["debug"] = 1        -- Informational
    }
    return severityMap[tostring(level):lower()] or 0
end

-- Parse Cisco firewall timestamp to milliseconds
local function parseTimestamp(timestampStr)
    if not timestampStr then return nil end
    
    -- Try various timestamp formats common in Cisco logs
    -- Format: MMM dd hh:mm:ss (e.g., "Jan 15 10:30:45")
    local month, day, hour, min, sec = timestampStr:match("(%a+)%s+(%d+)%s+(%d+):(%d+):(%d+)")
    if month and day then
        local monthMap = {
            Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6,
            Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12
        }
        local currentYear = os.date("%Y")
        local timeTable = {
            year = tonumber(currentYear),
            month = monthMap[month],
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }
        return os.time(timeTable) * 1000
    end
    
    -- ISO format fallback
    local yr, mo, dy, hr, mn, sc = timestampStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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

-- Determine activity based on Cisco firewall event
local function getNetworkActivity(event)
    local action = getValue(event, "action", "")
    local eventType = getValue(event, "event_type", "")
    local message = getValue(event, "message", "")
    
    -- Common Cisco firewall actions
    if action:match("Built") or action:match("built") then
        return {id = 1, name = "Open"}
    elseif action:match("Teardown") or action:match("teardown") then
        return {id = 2, name = "Close"}
    elseif action:match("Deny") or action:match("deny") or action:match("blocked") then
        return {id = 2, name = "Deny"}
    elseif action:match("Permit") or action:match("permit") or action:match("allowed") then
        return {id = 1, name = "Allow"}
    elseif message:match("connection") or eventType:match("connection") then
        return {id = 5, name = "Traffic"}
    else
        return {id = 99, name = "Other"}
    end
end

-- Main field mappings for Cisco Firewall events
local fieldMappings = {
    -- Basic identifiers
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    
    -- Source endpoint mappings
    {type = "priority", source1 = "src_ip", source2 = "source_ip", source3 = "srcip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "source_port", source3 = "srcport", target = "src_endpoint.port"},
    {type = "priority", source1 = "src_host", source2 = "source_host", source3 = "srchost", target = "src_endpoint.hostname"},
    
    -- Destination endpoint mappings
    {type = "priority", source1 = "dst_ip", source2 = "dest_ip", source3 = "dstip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_port", source2 = "dest_port", source3 = "dstport", target = "dst_endpoint.port"},
    {type = "priority", source1 = "dst_host", source2 = "dest_host", source3 = "dsthost", target = "dst_endpoint.hostname"},
    
    -- Protocol and network details
    {type = "priority", source1 = "protocol", source2 = "proto", target = "protocol_name"},
    {type = "direct", source = "bytes", target = "traffic.bytes"},
    {type = "priority", source1 = "packets", source2 = "pkts", target = "traffic.packets"},
    
    -- Message and status
    {type = "priority", source1 = "message", source2 = "msg", source3 = "description", target = "message"},
    {type = "priority", source1 = "action", source2 = "disposition", target = "status"},
    {type = "direct", source = "raw", target = "raw_data"},
    
    -- Duration and timing
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "count", target = "count"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "Cisco Firewall"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Cisco"},
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

    -- Determine network activity
    local activity = getNetworkActivity(event)
    result.activity_id = activity.id
    result.activity_name = activity.name
    result.type_uid = CLASS_UID * 100 + activity.id

    -- Set severity
    local severity = getValue(event, "severity", getValue(event, "priority", "0"))
    result.severity_id = getSeverityId(severity)

    -- Parse timestamp
    local timestampFields = {"timestamp", "time", "datetime", "event_time", "log_time"}
    local eventTime = nil
    for _, field in ipairs(timestampFields) do
        eventTime = getNestedField(event, field)
        if eventTime then
            mappedPaths[field] = true
            break
        end
    end
    
    if eventTime then
        result.time = parseTimestamp(eventTime) or (os.time() * 1000)
    else
        result.time = os.time() * 1000
    end

    -- Set status_id based on action
    local action = getValue(event, "action", "")
    if action:match("[Dd]eny") or action:match("[Bb]lock") then
        result.status_id = 2  -- Failure
    elseif action:match("[Pp]ermit") or action:match("[Aa]llow") then
        result.status_id = 1  -- Success
    else
        result.status_id = 99  -- Other
    end

    -- Convert numeric ports to integers
    if result.src_endpoint and result.src_endpoint.port then
        result.src_endpoint.port = tonumber(result.src_endpoint.port) or result.src_endpoint.port
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        result.dst_endpoint.port = tonumber(result.dst_endpoint.port) or result.dst_endpoint.port
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

    -- Clean empty tables
    result = cleanEmptyTables(result)

    return result
end