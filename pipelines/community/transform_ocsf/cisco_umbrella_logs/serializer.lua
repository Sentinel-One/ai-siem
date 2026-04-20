-- Cisco Umbrella Network Activity parser for OCSF v1.0.0
-- Maps Cisco Umbrella logs to OCSF Network Activity class (4001)

-- OCSF Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

-- Helper functions (production-proven from Observo scripts)
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

-- Severity mapping for Cisco Umbrella results
local function getSeverityId(result, reason)
    if result == nil then return 0 end
    
    local resultLower = string.lower(tostring(result))
    local reasonLower = reason and string.lower(tostring(reason)) or ""
    
    -- High severity for blocks and security events
    if resultLower:find("blocked") or resultLower:find("denied") or 
       reasonLower:find("malware") or reasonLower:find("phishing") or 
       reasonLower:find("threat") then
        return 4 -- High
    end
    
    -- Medium for policy violations
    if reasonLower:find("policy") or reasonLower:find("category") then
        return 3 -- Medium
    end
    
    -- Low for allowed but monitored
    if resultLower:find("allowed") or resultLower:find("permitted") then
        return 1 -- Informational
    end
    
    return 0 -- Unknown
end

-- Activity mapping based on event type and result
local function getActivityInfo(eventType, result, categoryName)
    local activityId = 99  -- Other by default
    local activityName = "Other Network Activity"
    
    if eventType then
        local eventTypeLower = string.lower(tostring(eventType))
        
        -- DNS activity
        if eventTypeLower:find("dns") then
            activityId = 6  -- DNS Activity
            activityName = "DNS Query"
        -- Authentication activity  
        elseif eventTypeLower:find("auth") or eventTypeLower:find("login") then
            activityId = 1  -- Network Connection
            activityName = "Authentication"
        -- Connection activity
        elseif eventTypeLower:find("connect") or eventTypeLower:find("session") then
            activityId = 1  -- Network Connection
            activityName = "Network Connection"
        end
    end
    
    -- Override based on result
    if result then
        local resultLower = string.lower(tostring(result))
        if resultLower:find("blocked") or resultLower:find("denied") then
            activityName = activityName .. " (Blocked)"
        elseif resultLower:find("allowed") or resultLower:find("permitted") then
            activityName = activityName .. " (Allowed)"
        end
    end
    
    -- Use category name if available and activity is generic
    if categoryName and activityId == 99 then
        activityName = tostring(categoryName) .. " Activity"
    end
    
    return activityId, activityName
end

-- Convert ISO timestamp to milliseconds since epoch
local function convertTimestamp(timestamp)
    if not timestamp or timestamp == "" then
        return os.time() * 1000
    end
    
    -- Handle ISO format: 2023-01-01T12:00:00Z or with timezone
    local pattern = "(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)"
    local year, month, day, hour, min, sec = timestamp:match(pattern)
    
    if year then
        local time_table = {
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }
        return os.time(time_table) * 1000
    end
    
    -- Try Unix timestamp (seconds)
    local unix_time = tonumber(timestamp)
    if unix_time then
        -- If timestamp is in seconds, convert to milliseconds
        if unix_time < 1e12 then
            return unix_time * 1000
        else
            return unix_time  -- Already in milliseconds
        end
    end
    
    return os.time() * 1000  -- Default to current time
end

-- Field mappings for Cisco Umbrella to OCSF
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    {type = "direct", source = "user.name", target = "actor.user.name"},
    {type = "direct", source = "username", target = "actor.user.name"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    {type = "direct", source = "user.groups", target = "actor.user.groups"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "user.type_id", target = "actor.user.type_id"},
    {type = "direct", source = "application.name", target = "app_name"},
    {type = "direct", source = "application.key", target = "app_uid"},
    {type = "direct", source = "txid", target = "transaction_uid"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "object", target = "resource.name"},
    {type = "direct", source = "site.id", target = "metadata.tenant_uid"},
    
    -- Location data
    {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
    {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
    {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
    {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
    
    -- Data source metadata
    {type = "direct", source = "dataSource.name", target = "metadata.product.name"},
    {type = "direct", source = "dataSource.vendor", target = "metadata.product.vendor_name"},
    {type = "direct", source = "dataSource.category", target = "metadata.product.feature.name"},
    {type = "direct", source = "OCSF_version", target = "metadata.version"},
    
    -- Status information
    {type = "direct", source = "result", target = "status"},
    {type = "direct", source = "reason", target = "status_detail"},
    
    -- OCSF fields that might already be set
    {type = "direct", source = "observables", target = "observables"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.vendor_name", value = "Cisco"},
    {type = "computed", target = "metadata.product.name", value = "Umbrella"},
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
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end

    -- Handle timestamp conversion
    local timeValue = getNestedField(event, 'isotimestamp') or 
                     getNestedField(event, 'timestamp')
    result.time = convertTimestamp(timeValue)
    mappedPaths['isotimestamp'] = true
    mappedPaths['timestamp'] = true

    -- Determine activity and severity
    local eventType = getNestedField(event, 'event.type')
    local result_value = getNestedField(event, 'result')
    local reason = getNestedField(event, 'reason')
    local categoryName = getNestedField(event, 'category_name')
    
    local activityId, activityName = getActivityInfo(eventType, result_value, categoryName)
    result.activity_id = getNestedField(event, 'activity_id') or activityId
    result.activity_name = getNestedField(event, 'activity_name') or activityName
    result.severity_id = getSeverityId(result_value, reason)
    result.type_uid = CLASS_UID * 100 + result.activity_id

    mappedPaths['event.type'] = true
    mappedPaths['result'] = true
    mappedPaths['reason'] = true
    mappedPaths['category_name'] = true
    mappedPaths['activity_id'] = true
    mappedPaths['activity_name'] = true
    mappedPaths['class_uid'] = true
    mappedPaths['type_uid'] = true

    -- Set status_id based on result
    if result_value then
        local resultLower = string.lower(tostring(result_value))
        if resultLower:find("success") or resultLower:find("allowed") then
            result.status_id = 1  -- Success
        elseif resultLower:find("fail") or resultLower:find("block") or resultLower:find("denied") then
            result.status_id = 2  -- Failure
        else
            result.status_id = 99  -- Other
        end
    end

    -- Build observables array for key network indicators
    local observables = getNestedField(event, 'observables') or {}
    
    -- Add IP addresses as observables
    local srcIp = getNestedField(result, 'src_endpoint.ip')
    if srcIp then
        table.insert(observables, {
            name = "src_endpoint.ip",
            type_id = 2,
            type = "IP Address",
            value = srcIp
        })
    end
    
    local dstIp = getNestedField(result, 'dst_endpoint.ip')
    if dstIp then
        table.insert(observables, {
            name = "dst_endpoint.ip", 
            type_id = 2,
            type = "IP Address",
            value = dstIp
        })
    end
    
    -- Add hostname as observable
    local hostname = getNestedField(result, 'dst_endpoint.hostname') or getNestedField(event, 'host')
    if hostname then
        table.insert(observables, {
            name = "dst_endpoint.hostname",
            type_id = 1,
            type = "Hostname",
            value = hostname
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    return result
end