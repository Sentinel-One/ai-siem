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

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timestamp)
    if not timestamp or type(timestamp) ~= "string" then
        return os.time() * 1000
    end
    
    -- Handle ISO format: 2024-01-01T12:00:00.123Z or 2024-01-01T12:00:00Z
    local year, month, day, hour, min, sec, ms = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)")
    if year then
        local timeMs = os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }) * 1000
        
        -- Add milliseconds if present
        if ms and ms ~= "" then
            local msNum = tonumber(ms)
            if msNum then
                -- Pad or truncate to 3 digits
                if #ms == 1 then msNum = msNum * 100
                elseif #ms == 2 then msNum = msNum * 10
                elseif #ms > 3 then msNum = math.floor(msNum / math.pow(10, #ms - 3))
                end
                timeMs = timeMs + msNum
            end
        end
        
        return timeMs
    end
    
    -- Fallback to current time
    return os.time() * 1000
end

-- Map result values to severity
function getSeverityId(result, reason)
    if not result then return 0 end
    
    local resultLower = string.lower(tostring(result))
    
    -- Critical/Fatal conditions
    if resultLower:match("critical") or resultLower:match("fatal") or resultLower:match("emergency") then
        return 5
    end
    
    -- High severity
    if resultLower:match("error") or resultLower:match("fail") or resultLower:match("denied") or 
       resultLower:match("blocked") or resultLower:match("reject") then
        return 4
    end
    
    -- Medium severity  
    if resultLower:match("warn") or resultLower:match("timeout") or resultLower:match("challenge") then
        return 3
    end
    
    -- Low severity
    if resultLower:match("success") or resultLower:match("allow") or resultLower:match("permit") then
        return 2
    end
    
    -- Informational
    if resultLower:match("info") or resultLower:match("audit") or resultLower:match("log") then
        return 1
    end
    
    return 0 -- Unknown
end

-- Field mapping configuration
local fieldMappings = {
    -- Direct field mappings
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    {type = "direct", source = "user.name", target = "actor.user.name"},
    {type = "direct", source = "username", target = "actor.user.name"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "user.groups", target = "actor.user.groups"},
    {type = "direct", source = "application.name", target = "app_name"},
    {type = "direct", source = "application.key", target = "app_uid"},
    {type = "direct", source = "txid", target = "activity_id"},
    {type = "direct", source = "result", target = "status"},
    {type = "direct", source = "reason", target = "status_detail"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "host", target = "src_endpoint.hostname"},
    {type = "direct", source = "object", target = "dst_endpoint.resource_uid"},
    {type = "direct", source = "dataSource.name", target = "metadata.product.name"},
    {type = "direct", source = "dataSource.vendor", target = "metadata.product.vendor_name"},
    {type = "direct", source = "OCSF_version", target = "metadata.version"},
    {type = "direct", source = "observables", target = "observables"},
    
    -- Location mappings
    {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
    {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
    {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
    {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
    
    -- Priority mappings (use first available)
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "priority", source1 = "access_device.hostname", source2 = "host", target = "src_endpoint.hostname"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
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
            
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if (value == nil or value == "") and mapping.source2 then
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
    
    -- Set timestamp - prioritize isotimestamp over timestamp
    local eventTime = getNestedField(event, 'isotimestamp') or getNestedField(event, 'timestamp')
    result.time = parseTimestamp(eventTime)
    mappedPaths["isotimestamp"] = true
    mappedPaths["timestamp"] = true
    
    -- Set activity details
    local activityId = getNestedField(event, 'activity_id') or getNestedField(event, 'txid')
    if activityId and type(activityId) == "number" then
        result.activity_id = activityId
    else
        result.activity_id = 99 -- Other/Unknown
    end
    mappedPaths["activity_id"] = true
    
    -- Set activity name
    local activityName = getNestedField(event, 'activity_name') or 
                        getNestedField(event, 'event.type') or
                        getNestedField(event, 'application.name')
    if activityName then
        result.activity_name = tostring(activityName)
    else
        result.activity_name = "Network Activity"
    end
    mappedPaths["activity_name"] = true
    mappedPaths["event.type"] = true
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + result.activity_id
    
    -- Set severity based on result and reason
    local resultVal = getNestedField(event, 'result')
    local reasonVal = getNestedField(event, 'reason')
    result.severity_id = getSeverityId(resultVal, reasonVal)
    
    -- Set status_id based on result
    if resultVal then
        local resultLower = string.lower(tostring(resultVal))
        if resultLower:match("success") or resultLower:match("allow") or resultLower:match("permit") then
            result.status_id = 1 -- Success
        elseif resultLower:match("fail") or resultLower:match("den") or resultLower:match("block") or resultLower:match("reject") then
            result.status_id = 2 -- Failure
        else
            result.status_id = 99 -- Other
        end
    else
        result.status_id = 0 -- Unknown
    end
    
    -- Set user type if available
    local userTypeId = getNestedField(event, 'user.type_id')
    if userTypeId then
        setNestedField(result, "actor.user.type_id", userTypeId)
    end
    mappedPaths["user.type_id"] = true
    
    -- Handle pre-existing OCSF fields that might override our mappings
    local existingClassUid = getNestedField(event, 'class_uid')
    local existingCategoryUid = getNestedField(event, 'category_uid')
    local existingTypeUid = getNestedField(event, 'type_uid')
    
    if existingClassUid and type(existingClassUid) == "number" then
        result.class_uid = existingClassUid
    end
    if existingCategoryUid and type(existingCategoryUid) == "number" then
        result.category_uid = existingCategoryUid
    end
    if existingTypeUid and type(existingTypeUid) == "number" then
        result.type_uid = existingTypeUid
    end
    
    mappedPaths["class_uid"] = true
    mappedPaths["category_uid"] = true
    mappedPaths["type_uid"] = true
    mappedPaths["class_name"] = true
    mappedPaths["type_name"] = true
    mappedPaths["category_name"] = true
    
    -- Create observables if we have key network indicators
    local observables = {}
    local srcIp = getNestedField(result, "src_endpoint.ip")
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local dstIp = getNestedField(result, "dst_endpoint.ip")
    if dstIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "dst_endpoint.ip",
            value = dstIp
        })
    end
    
    local userName = getNestedField(result, "actor.user.name")
    if userName then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.name", 
            value = userName
        })
    end
    
    if #observables > 0 then
        if not result.observables then
            result.observables = observables
        end
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up empty values
    result = no_nulls(result, nil)
    
    return result
end