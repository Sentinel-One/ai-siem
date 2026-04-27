-- Cisco Meraki Flow Logs OCSF Transformation
-- Transforms Cisco Meraki network flow events to OCSF Network Activity format

-- OCSF constants for Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Helper functions for nested field access and value handling
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

-- Convert ISO timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if not timestamp then return nil end
    
    -- Handle ISO format: 2023-10-15T14:30:25Z or 2023-10-15T14:30:25.123Z
    local yr, mo, dy, hr, mn, sc = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
    
    -- Handle Unix timestamp (seconds)
    local unixTime = tonumber(timestamp)
    if unixTime then
        return unixTime < 1000000000000 and unixTime * 1000 or unixTime
    end
    
    return nil
end

-- Map result/status to severity
local function getSeverityId(result, reason)
    if not result then return 1 end -- Informational by default
    
    local resultLower = tostring(result):lower()
    if resultLower:match("success") or resultLower:match("allow") then
        return 1 -- Informational
    elseif resultLower:match("deny") or resultLower:match("block") then
        return 3 -- Medium
    elseif resultLower:match("fail") or resultLower:match("error") then
        return 4 -- High
    end
    
    return 1 -- Default to Informational
end

-- Determine activity based on event data
local function getActivityInfo(event)
    local eventType = getNestedField(event, 'event.type')
    local result = getValue(event, 'result', '')
    local activityName = getValue(event, 'activity_name', '')
    
    -- Use existing activity_id if present, otherwise default
    local activityId = getValue(event, 'activity_id', 99) -- Other
    
    -- Generate activity name if not present
    if activityName == '' then
        if eventType then
            activityName = eventType
        elseif result then
            activityName = "Network " .. result
        else
            activityName = "Network Flow"
        end
    end
    
    return activityId, activityName
end

-- Main field mappings using table-driven approach
local fieldMappings = {
    -- Direct field mappings
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "txid", target = "metadata.correlation_uid"},
    {type = "direct", source = "user.name", target = "actor.user.name"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "user.type_id", target = "actor.user.type_id"},
    {type = "direct", source = "application.name", target = "app_name"},
    {type = "direct", source = "application.key", target = "app_uid"},
    {type = "direct", source = "reason", target = "status_detail"},
    {type = "direct", source = "host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "object", target = "resource.name"},
    
    -- Access device mappings (source endpoint)
    {type = "direct", source = "access_device.ip", target = "src_endpoint.ip"},
    {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
    {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
    
    -- Auth device mappings (destination endpoint)  
    {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
    {type = "direct", source = "auth_device.key", target = "dst_endpoint.uid"},
    {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
    {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
    
    -- Metadata mappings
    {type = "direct", source = "dataSource.name", target = "metadata.product.name"},
    {type = "direct", source = "dataSource.vendor", target = "metadata.product.vendor_name"},
    {type = "direct", source = "site.id", target = "metadata.product.uid"},
    {type = "direct", source = "OCSF_version", target = "metadata.version"},
    {type = "direct", source = "observables", target = "observables"},
    
    -- User priority mapping (username fallback)
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "priority", source1 = "user.name", source2 = "email", target = "actor.user.email_addr"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"}
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
    
    -- Set required OCSF fields with defaults
    local function setDefault(path, val)
        if getNestedField(result, path) == nil then
            setNestedField(result, path, val)
        end
    end
    
    -- Activity information
    local activityId, activityName = getActivityInfo(event)
    setDefault('activity_id', activityId)
    setDefault('activity_name', activityName)
    setDefault('type_uid', CLASS_UID * 100 + activityId)
    
    -- Time handling - prioritize isotimestamp, then timestamp
    local eventTime = getNestedField(event, 'isotimestamp') or getNestedField(event, 'timestamp')
    local parsedTime = parseTimestamp(eventTime)
    result.time = parsedTime or (os.time() * 1000)
    mappedPaths['isotimestamp'] = true
    mappedPaths['timestamp'] = true
    
    -- Severity based on result
    local severityId = getSeverityId(getValue(event, 'result', ''), getValue(event, 'reason', ''))
    setDefault('severity_id', severityId)
    
    -- Status information
    local resultValue = getValue(event, 'result', '')
    if resultValue ~= '' then
        result.status = resultValue
        if resultValue:lower():match("success") or resultValue:lower():match("allow") then
            result.status_id = 1 -- Success
        else
            result.status_id = 2 -- Failure
        end
        mappedPaths['result'] = true
    end
    
    -- Set default metadata if missing
    setDefault('metadata.product.name', 'Cisco Meraki')
    setDefault('metadata.product.vendor_name', 'Cisco')
    
    -- Handle user groups array
    local userGroups = getNestedField(event, 'user.groups')
    if userGroups and type(userGroups) == "table" then
        setNestedField(result, 'actor.user.groups', userGroups)
        mappedPaths['user.groups'] = true
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end