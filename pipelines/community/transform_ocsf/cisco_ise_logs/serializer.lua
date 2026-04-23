-- Cisco ISE Logs Parser for OCSF Network Activity Class
-- Maps Cisco ISE authentication and network access events to OCSF format

-- Constants
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
local function parseTimestamp(timestamp)
    if not timestamp or type(timestamp) ~= "string" then return nil end
    
    -- Try ISO format: YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS
    local year, month, day, hour, min, sec = timestamp:match("(%d+)-(%d+)-(%d+)[T ](%d+):(%d+):(%d+)")
    if year then
        local timeTable = {
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }
        return os.time(timeTable) * 1000
    end
    
    return nil
end

-- Map Cisco ISE result to severity
local function getSeverityId(result, reason)
    if not result then return 0 end
    
    local resultLower = string.lower(tostring(result))
    
    -- Success cases
    if resultLower:find("success") or resultLower:find("allowed") or resultLower:find("passed") then
        return 1 -- Informational
    end
    
    -- Authentication failures
    if resultLower:find("fail") or resultLower:find("denied") or resultLower:find("reject") then
        if reason then
            local reasonLower = string.lower(tostring(reason))
            -- Critical security events
            if reasonLower:find("attack") or reasonLower:find("malicious") or reasonLower:find("breach") then
                return 5 -- Critical
            end
            -- High priority failures
            if reasonLower:find("authentication") or reasonLower:find("authorization") then
                return 4 -- High
            end
        end
        return 3 -- Medium (general failures)
    end
    
    return 0 -- Unknown
end

-- Determine activity based on event type and result
local function getActivityInfo(eventType, result, reason)
    local activityId = 99 -- Other
    local activityName = "Network Access"
    
    if eventType then
        local eventTypeLower = string.lower(tostring(eventType))
        if eventTypeLower:find("auth") then
            activityId = 1 -- Authenticate
            activityName = "Authentication"
        elseif eventTypeLower:find("access") or eventTypeLower:find("connect") then
            activityId = 5 -- Connect
            activityName = "Network Access"
        elseif eventTypeLower:find("disconnect") or eventTypeLower:find("logout") then
            activityId = 6 -- Disconnect  
            activityName = "Network Disconnect"
        end
    end
    
    return activityId, activityName
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "txid", target = "metadata.correlation_uid"},
    {type = "direct", source = "application.name", target = "metadata.product.name"},
    {type = "direct", source = "result", target = "status"},
    {type = "direct", source = "reason", target = "status_detail"},
    
    -- User information - priority mapping (try multiple sources)
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "user.groups", target = "actor.user.groups"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    {type = "direct", source = "user.type_id", target = "actor.user.type_id"},
    
    -- Device location information
    {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
    {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
    {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
    {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
    
    -- Metadata
    {type = "direct", source = "dataSource.vendor", target = "metadata.product.vendor_name"},
    {type = "direct", source = "OCSF_version", target = "metadata.version"},
    {type = "direct", source = "site.id", target = "metadata.product.feature.name"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
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
            if value ~= nil and value ~= "" then 
                setNestedField(result, mapping.target, value) 
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity information based on event context
    local eventType = getNestedField(event, "event.type")
    local result_value = getNestedField(event, "result")
    local reason = getNestedField(event, "reason")
    local activityId, activityName = getActivityInfo(eventType, result_value, reason)
    
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity based on result and reason
    result.severity_id = getSeverityId(result_value, reason)
    
    -- Handle timestamp - try multiple sources
    local timestamp = getNestedField(event, "isotimestamp") or 
                     getNestedField(event, "timestamp")
    
    if timestamp then
        local parsedTime = parseTimestamp(timestamp)
        if parsedTime then
            result.time = parsedTime
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end
    
    -- Mark additional mapped paths
    mappedPaths["isotimestamp"] = true
    mappedPaths["timestamp"] = true
    mappedPaths["event.type"] = true
    
    -- Set status_id based on result
    if result_value then
        local resultLower = string.lower(tostring(result_value))
        if resultLower:find("success") or resultLower:find("allowed") then
            result.status_id = 1 -- Success
        elseif resultLower:find("fail") or resultLower:find("denied") then
            result.status_id = 2 -- Failure
        else
            result.status_id = 99 -- Other
        end
    end
    
    -- Create observables for key network indicators
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
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end