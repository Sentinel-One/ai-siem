-- OCSF Network Activity class constants
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

-- Flatten nested table to dot-notation keys
function flattenObject(tbl, prefix, result)
    result = result or {}; prefix = prefix or ""
    for k, v in pairs(tbl) do
        local keyPath = prefix ~= "" and (prefix .. "." .. tostring(k)) or tostring(k)
        if type(v) == "table" then flattenObject(v, keyPath, result)
        else result[keyPath] = v end
    end
    return result
end

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Map result codes to severity levels
local function getSeverityId(result_str, reason_str)
    if result_str == nil and reason_str == nil then return 0 end
    local result_lower = result_str and string.lower(result_str) or ""
    local reason_lower = reason_str and string.lower(reason_str) or ""
    
    -- Success/allowed events are informational
    if string.match(result_lower, "success") or string.match(result_lower, "allow") then
        return 1
    end
    
    -- Blocked/denied events are medium severity
    if string.match(result_lower, "block") or string.match(result_lower, "deny") or string.match(result_lower, "fail") then
        return 3
    end
    
    -- Authentication failures are high severity
    if string.match(reason_lower, "auth") or string.match(reason_lower, "credential") then
        return 4
    end
    
    return 0 -- Unknown
end

-- Parse ISO timestamp to milliseconds since epoch
local function parseTimestamp(timestamp_str)
    if not timestamp_str or type(timestamp_str) ~= "string" then
        return os.time() * 1000
    end
    
    -- Match ISO 8601 format: 2023-01-01T12:00:00Z or 2023-01-01T12:00:00.123Z
    local yr, mo, dy, hr, mn, sc = timestamp_str:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        local time_sec = os.time({
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        })
        return time_sec * 1000
    end
    
    return os.time() * 1000
end

-- Field mappings for Cisco FMC logs
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    {type = "direct", source = "user.name", target = "actor.user.name"},
    {type = "direct", source = "username", target = "actor.user.name"},
    {type = "direct", source = "application.name", target = "app_name"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "txid", target = "metadata.correlation_uid"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    {type = "direct", source = "host", target = "src_endpoint.hostname"},
    
    -- Computed/static fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "Cisco FMC"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Cisco"},
}

function processEvent(event)
    -- Validate input
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
    
    -- Handle activity_id and activity_name from event
    local activity_id = getNestedField(event, 'activity_id') or 99
    local activity_name = getNestedField(event, 'activity_name') or 
                         getNestedField(event, 'event.type') or 
                         "Network Activity"
    
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity based on result and reason
    local severity_id = getSeverityId(getNestedField(event, 'result'), getNestedField(event, 'reason'))
    result.severity_id = severity_id
    
    -- Parse timestamp - try isotimestamp first, then timestamp
    local timestamp_str = getNestedField(event, 'isotimestamp') or getNestedField(event, 'timestamp')
    result.time = parseTimestamp(timestamp_str)
    
    -- Build observables array for key network indicators
    local observables = {}
    local src_ip = getNestedField(event, 'access_device.ip') or getNestedField(event, 'host')
    local dst_ip = getNestedField(event, 'auth_device.ip')
    local username = getNestedField(event, 'user.name') or getNestedField(event, 'username')
    local hostname = getNestedField(event, 'access_device.hostname')
    
    if src_ip then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = src_ip
        })
    end
    
    if dst_ip then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "dst_endpoint.ip",
            value = dst_ip
        })
    end
    
    if username then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.name",
            value = username
        })
    end
    
    if hostname then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "src_endpoint.hostname",
            value = hostname
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths for unmapped collection
    local additionalMappedPaths = {
        'isotimestamp', 'timestamp', 'activity_id', 'activity_name', 
        'event.type', 'result', 'reason', 'class_uid', 'category_uid',
        'type_uid', 'class_name', 'category_name', 'type_name',
        'OCSF_version', 'observables'
    }
    
    for _, path in ipairs(additionalMappedPaths) do
        mappedPaths[path] = true
    end
    
    -- Collect unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values and empty tables
    result = no_nulls(result, nil)
    
    return result
end