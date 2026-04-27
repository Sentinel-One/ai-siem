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

-- Severity mapping function
local function getSeverityId(result_field, reason_field)
    -- Map based on result status and reason
    if result_field then
        local lower_result = string.lower(tostring(result_field))
        if string.find(lower_result, "success") or string.find(lower_result, "allow") then
            return 1 -- Informational
        elseif string.find(lower_result, "fail") or string.find(lower_result, "deny") or string.find(lower_result, "block") then
            return 3 -- Medium
        elseif string.find(lower_result, "error") or string.find(lower_result, "critical") then
            return 4 -- High
        end
    end
    
    if reason_field then
        local lower_reason = string.lower(tostring(reason_field))
        if string.find(lower_reason, "timeout") or string.find(lower_reason, "expired") then
            return 2 -- Low
        elseif string.find(lower_reason, "invalid") or string.find(lower_reason, "unauthorized") then
            return 3 -- Medium
        end
    end
    
    return 0 -- Unknown
end

-- Convert timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if timestamp == nil then return nil end
    
    local ts_str = tostring(timestamp)
    
    -- Try ISO 8601 format: YYYY-MM-DDTHH:MM:SS(.sss)Z
    local yr, mo, dy, hr, mn, sc = ts_str:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        local time_table = {
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        }
        return os.time(time_table) * 1000
    end
    
    -- Try Unix timestamp (seconds or milliseconds)
    local num_ts = tonumber(ts_str)
    if num_ts then
        -- If less than year 2000 in milliseconds, assume it's seconds
        if num_ts < 946684800000 then
            return num_ts * 1000
        else
            return num_ts
        end
    end
    
    return nil
end

-- OCSF constants for Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Field mappings for Cisco Meraki logs
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Activity mapping - use existing activity_id if present, otherwise default
    {type = "direct", source = "activity_id", target = "activity_id"},
    {type = "direct", source = "activity_name", target = "activity_name"},
    {type = "direct", source = "type_uid", target = "type_uid"},
    
    -- Message and metadata
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "txid", target = "metadata.correlation_uid"},
    {type = "direct", source = "dataSource.vendor", target = "metadata.product.vendor_name"},
    {type = "direct", source = "dataSource.name", target = "metadata.product.name"},
    {type = "direct", source = "OCSF_version", target = "metadata.version"},
    
    -- Source endpoint (access device)
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
    {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
    
    -- Destination endpoint (auth device)
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
    {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
    
    -- User information
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "user.groups", target = "actor.user.groups"},
    {type = "direct", source = "user.type_id", target = "actor.user.type_id"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    
    -- Application information
    {type = "direct", source = "application.name", target = "app_name"},
    {type = "direct", source = "application.key", target = "app_uid"},
    
    -- Site information
    {type = "direct", source = "site.id", target = "metadata.tenant_uid"},
    
    -- Host and object
    {type = "direct", source = "host", target = "device.hostname"},
    {type = "direct", source = "object", target = "resource.name"},
    
    -- Result and status
    {type = "direct", source = "result", target = "status"},
    {type = "direct", source = "reason", target = "status_detail"},
    
    -- Observables
    {type = "direct", source = "observables", target = "observables"}
}

function processEvent(event)
    -- Input validation
    if type(event) ~= "table" then 
        return nil 
    end

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
            if value ~= nil and value ~= "" then 
                setNestedField(result, mapping.target, value) 
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end

    -- Set OCSF required defaults if not already set
    local function setDefault(path, val)
        if getNestedField(result, path) == nil then 
            setNestedField(result, path, val) 
        end
    end
    
    setDefault('class_uid', CLASS_UID)
    setDefault('category_uid', CATEGORY_UID)
    setDefault('class_name', 'Network Activity')
    setDefault('category_name', 'Network Activity')
    
    -- Set activity_id and activity_name based on event type or default
    local activity_id = getNestedField(result, 'activity_id')
    if activity_id == nil then
        local event_type = getNestedField(event, 'event.type')
        if event_type then
            activity_id = 99 -- Other
            setNestedField(result, 'activity_name', tostring(event_type))
        else
            activity_id = 99
            setNestedField(result, 'activity_name', 'Network Activity')
        end
        setNestedField(result, 'activity_id', activity_id)
    end
    
    -- Compute type_uid
    local type_uid = getNestedField(result, 'type_uid')
    if type_uid == nil then
        setNestedField(result, 'type_uid', CLASS_UID * 100 + activity_id)
    end

    -- Set severity based on result and reason
    local severity_id = getSeverityId(getNestedField(event, 'result'), getNestedField(event, 'reason'))
    setNestedField(result, 'severity_id', severity_id)

    -- Parse timestamp - try isotimestamp first, then timestamp
    local event_time = nil
    local iso_ts = getNestedField(event, 'isotimestamp')
    if iso_ts then
        event_time = parseTimestamp(iso_ts)
        mappedPaths['isotimestamp'] = true
    end
    
    if not event_time then
        local ts = getNestedField(event, 'timestamp')
        if ts then
            event_time = parseTimestamp(ts)
            mappedPaths['timestamp'] = true
        end
    end
    
    if event_time then
        setNestedField(result, 'time', event_time)
    else
        -- Default to current time if no timestamp available
        setNestedField(result, 'time', os.time() * 1000)
    end

    -- Set status_id based on status
    local status = getNestedField(result, 'status')
    if status then
        local lower_status = string.lower(tostring(status))
        if string.find(lower_status, "success") or string.find(lower_status, "allow") then
            setNestedField(result, 'status_id', 1) -- Success
        elseif string.find(lower_status, "fail") or string.find(lower_status, "deny") or string.find(lower_status, "block") then
            setNestedField(result, 'status_id', 2) -- Failure
        else
            setNestedField(result, 'status_id', 99) -- Other
        end
    end

    -- Mark additional mapped paths for nested fields
    mappedPaths['access_device.hostname'] = true
    mappedPaths['access_device.ip'] = true
    mappedPaths['access_device.location.city'] = true
    mappedPaths['access_device.location.country'] = true
    mappedPaths['auth_device.ip'] = true
    mappedPaths['auth_device.name'] = true
    mappedPaths['auth_device.location.city'] = true
    mappedPaths['auth_device.location.country'] = true
    mappedPaths['user.name'] = true
    mappedPaths['user.key'] = true
    mappedPaths['user.groups'] = true
    mappedPaths['user.type_id'] = true
    mappedPaths['application.name'] = true
    mappedPaths['application.key'] = true
    mappedPaths['dataSource.vendor'] = true
    mappedPaths['dataSource.name'] = true
    mappedPaths['dataSource.category'] = true
    mappedPaths['site.id'] = true
    mappedPaths['event.type'] = true

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean up null values
    result = no_nulls(result, nil)

    return result
end