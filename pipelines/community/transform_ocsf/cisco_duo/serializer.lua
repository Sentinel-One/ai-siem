-- Cisco Duo Authentication Events to OCSF Transformation
-- Class: Authentication (3002), Category: Identity & Access Management (3)

local CLASS_UID = 3002
local CATEGORY_UID = 3

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
    if not timestamp or timestamp == "" then return nil end
    
    -- Handle ISO format: YYYY-MM-DDTHH:MM:SS[.sss][Z|±HH:MM]
    local year, month, day, hour, min, sec = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if year and month and day and hour and min and sec then
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
    
    -- Fallback: if timestamp is already numeric, assume seconds and convert to ms
    local numTs = tonumber(timestamp)
    if numTs then
        -- If less than year 2000 in seconds, assume it's already milliseconds
        if numTs < 946684800 then return numTs
        else return numTs * 1000 end
    end
    
    return nil
end

-- Map Duo result to OCSF status and activity
local function mapAuthResult(result, reason)
    local status_id = 99  -- Other
    local activity_id = 99  -- Other
    local activity_name = "Authentication"
    local status_detail = reason or ""
    
    if result then
        local resultLower = string.lower(result)
        if resultLower == "success" or resultLower == "allow" then
            status_id = 1  -- Success
            activity_id = 1  -- Logon
            activity_name = "Authentication Success"
        elseif resultLower == "failure" or resultLower == "deny" or resultLower == "error" then
            status_id = 2  -- Failure
            activity_id = 2  -- Logon Failure
            activity_name = "Authentication Failure"
        elseif resultLower == "fraud" then
            status_id = 2  -- Failure
            activity_id = 2  -- Logon Failure
            activity_name = "Authentication Fraud"
        end
    end
    
    return status_id, activity_id, activity_name, status_detail
end

-- Determine severity based on result and reason
local function getSeverityId(result, reason)
    if not result then return 0 end  -- Unknown
    
    local resultLower = string.lower(result)
    if resultLower == "fraud" then return 4 end  -- High
    if resultLower == "failure" or resultLower == "deny" or resultLower == "error" then
        return 3  -- Medium
    end
    if resultLower == "success" or resultLower == "allow" then
        return 1  -- Informational
    end
    
    return 0  -- Unknown
end

-- Field mappings for Cisco Duo events
local fieldMappings = {
    -- Basic OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Authentication"},
    {type = "computed", target = "category_name", value = "Identity & Access Management"},
    
    -- User information
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    {type = "direct", source = "user.groups", target = "actor.user.groups"},
    
    -- Source endpoint (access device)
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "host", target = "src_endpoint.hostname"},
    
    -- Destination endpoint (auth device)
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    
    -- Application/Service
    {type = "direct", source = "application.name", target = "metadata.product.name"},
    {type = "direct", source = "application.key", target = "metadata.product.uid"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Cisco"},
    
    -- Transaction and context
    {type = "direct", source = "txid", target = "metadata.correlation_uid"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "object", target = "metadata.labels"},
    
    -- Location information for enrichment
    {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
    {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
    {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
    {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
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
            if value == nil or value == "" then
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
    
    -- Parse timestamp - prefer isotimestamp, fallback to timestamp
    local eventTime = getNestedField(event, 'isotimestamp') or getNestedField(event, 'timestamp')
    if eventTime then
        local parsedTime = parseTimestamp(eventTime)
        if parsedTime then
            result.time = parsedTime
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end
    mappedPaths['isotimestamp'] = true
    mappedPaths['timestamp'] = true
    
    -- Map authentication result to OCSF status and activity
    local authResult = getNestedField(event, 'result')
    local authReason = getNestedField(event, 'reason')
    local status_id, activity_id, activity_name, status_detail = mapAuthResult(authResult, authReason)
    
    result.status_id = status_id
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id
    result.severity_id = getSeverityId(authResult, authReason)
    
    if status_detail and status_detail ~= "" then
        result.status_detail = status_detail
    end
    
    mappedPaths['result'] = true
    mappedPaths['reason'] = true
    
    -- Create observables for key security indicators
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
    
    local userName = getNestedField(result, 'actor.user.name')
    if userName then
        table.insert(observables, {
            type_id = 4,
            type = "User Name", 
            name = "actor.user.name",
            value = userName
        })
    end
    
    local userEmail = getNestedField(result, 'actor.user.email_addr')
    if userEmail then
        table.insert(observables, {
            type_id = 5,
            type = "Email Address",
            name = "actor.user.email_addr", 
            value = userEmail
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Handle pre-existing OCSF fields from source (override our computed values if present)
    local existingFields = {'category_name', 'category_uid', 'class_uid', 'activity_name', 
                           'activity_id', 'type_uid', 'OCSF_version', 'observables', 
                           'class_name', 'type_name', 'user.type_id'}
    
    for _, field in ipairs(existingFields) do
        local value = getNestedField(event, field)
        if value ~= nil then
            setNestedField(result, field, value)
        end
        mappedPaths[field] = true
    end
    
    -- Handle data source metadata
    local dsFields = {'dataSource.category', 'dataSource.name', 'dataSource.vendor', 'site.id'}
    for _, field in ipairs(dsFields) do
        local value = getNestedField(event, field)
        if value ~= nil then
            setNestedField(result, "metadata." .. field:gsub("dataSource%.", ""), value)
        end
        mappedPaths[field] = true
    end
    
    -- Set defaults for required OCSF fields if not already set
    local function setDefault(path, val)
        if getNestedField(result, path) == nil then
            setNestedField(result, path, val)
        end
    end
    
    setDefault('severity_id', 0)
    setDefault('activity_id', 99)
    setDefault('type_uid', CLASS_UID * 100 + 99)
    setDefault('activity_name', 'Authentication')
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end