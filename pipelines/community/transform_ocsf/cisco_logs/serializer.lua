-- Constants for OCSF Network Activity class
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

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Convert ISO timestamp to milliseconds since epoch
function parseISOTimestamp(timestamp)
    if not timestamp or type(timestamp) ~= "string" then return nil end
    local year, month, day, hour, min, sec = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
    return nil
end

-- Map result/reason to severity_id
function getSeverityId(result, reason)
    if result == nil and reason == nil then return 0 end
    local resultStr = tostring(result or ""):lower()
    local reasonStr = tostring(reason or ""):lower()
    
    -- Critical/High severity indicators
    if resultStr:match("fail") or resultStr:match("error") or resultStr:match("deny") or
       reasonStr:match("blocked") or reasonStr:match("fail") or reasonStr:match("error") then
        return 4 -- High
    end
    
    -- Success/Allow indicators
    if resultStr:match("success") or resultStr:match("allow") or resultStr:match("permit") then
        return 1 -- Informational
    end
    
    -- Warning indicators
    if resultStr:match("warn") or reasonStr:match("warn") then
        return 2 -- Low
    end
    
    return 0 -- Unknown
end

-- Field mappings for Cisco logs to OCSF Network Activity
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Direct mappings from existing OCSF fields if present
    {type = "direct", source = "activity_id", target = "activity_id"},
    {type = "direct", source = "activity_name", target = "activity_name"},
    {type = "direct", source = "type_uid", target = "type_uid"},
    {type = "direct", source = "message", target = "message"},
    
    -- Source endpoint mappings
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    
    -- User information
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "user.groups", target = "actor.user.groups"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    {type = "direct", source = "user.type_id", target = "actor.user.type_id"},
    
    -- Application/service information
    {type = "direct", source = "application.name", target = "metadata.product.name"},
    {type = "direct", source = "application.key", target = "metadata.product.uid"},
    
    -- Data source information
    {type = "direct", source = "dataSource.vendor", target = "metadata.product.vendor_name"},
    {type = "direct", source = "dataSource.name", target = "metadata.log_name"},
    {type = "direct", source = "dataSource.category", target = "metadata.log_provider"},
    
    -- Location information
    {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
    {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
    {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
    {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
    
    -- Transaction and other identifiers
    {type = "direct", source = "txid", target = "metadata.correlation_uid"},
    {type = "direct", source = "site.id", target = "metadata.tenant_uid"},
    {type = "direct", source = "host", target = "device.hostname"},
    {type = "direct", source = "OCSF_version", target = "metadata.version"},
    {type = "direct", source = "observables", target = "observables"},
}

function processEvent(event)
    if type(event) ~= "table" then return nil end

    local result = {}
    local mappedPaths = {}

    -- Apply field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getNestedField(event, mapping.source)
            if value ~= nil then 
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source] = true
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if value == nil and mapping.source2 then 
                value = getNestedField(event, mapping.source2) 
            end
            if value ~= nil then 
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
    
    setDefault('activity_id', 99) -- Other
    setDefault('activity_name', event.activity_name or event["event.type"] or 'Network Activity')
    
    -- Calculate type_uid if not already set
    if not result.type_uid then
        local activity_id = result.activity_id or 99
        result.type_uid = CLASS_UID * 100 + activity_id
    end
    
    -- Set severity based on result and reason
    if not result.severity_id then
        result.severity_id = getSeverityId(event.result, event.reason)
    end
    
    -- Handle time field - try multiple timestamp sources
    local eventTime = getNestedField(event, 'isotimestamp') or 
                      getNestedField(event, 'timestamp')
    
    if eventTime then
        local parsedTime = parseISOTimestamp(eventTime)
        if parsedTime then
            result.time = parsedTime
        end
        mappedPaths['isotimestamp'] = true
        mappedPaths['timestamp'] = true
    end
    
    -- Default to current time if no timestamp found
    if not result.time then
        result.time = os.time() * 1000
    end

    -- Add status information if available
    if event.result then
        result.status = tostring(event.result)
        if event.result == "SUCCESS" or event.result == "ALLOW" then
            result.status_id = 1 -- Success
        elseif event.result == "FAILURE" or event.result == "DENY" then
            result.status_id = 2 -- Failure
        else
            result.status_id = 99 -- Other
        end
        mappedPaths['result'] = true
    end
    
    if event.reason then
        result.status_detail = tostring(event.reason)
        mappedPaths['reason'] = true
    end

    -- Create observables for key network indicators
    local observables = {}
    local srcIP = getNestedField(result, 'src_endpoint.ip')
    if srcIP then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIP
        })
    end
    
    local dstIP = getNestedField(result, 'dst_endpoint.ip')
    if dstIP then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "dst_endpoint.ip",
            value = dstIP
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

    -- Copy unmapped fields to preserve all data
    copyUnmappedFields(event, mappedPaths, result)

    return result
end