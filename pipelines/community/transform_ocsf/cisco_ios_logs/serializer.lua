-- Cisco IOS Network Activity OCSF Transformation Script
-- Target: Network Activity (class_uid=4001, category_uid=4)

-- Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Helper functions
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

-- Severity mapping for network events
local function getSeverityId(level)
    if level == nil then return 0 end
    local severityMap = {
        critical = 5, Critical = 5, CRITICAL = 5,
        high = 4, High = 4, HIGH = 4,
        medium = 3, Medium = 3, MEDIUM = 3,
        low = 2, Low = 2, LOW = 2,
        info = 1, Info = 1, INFO = 1,
        informational = 1, Informational = 1, INFORMATIONAL = 1,
        warning = 3, Warning = 3, WARNING = 3,
        error = 4, Error = 4, ERROR = 4,
        fatal = 6, Fatal = 6, FATAL = 6
    }
    return severityMap[tostring(level)] or 0
end

-- Activity mapping based on event type or result
local function getActivityInfo(event)
    local eventType = getNestedField(event, 'event.type') or event.event_type
    local result = event.result
    local activityName = getNestedField(event, 'activity_name')
    
    -- Use existing activity_id if present
    local activityId = getNestedField(event, 'activity_id')
    if activityId and type(activityId) == "number" then
        return activityId, activityName or "Network Activity"
    end
    
    -- Map based on event type or result
    if eventType then
        local eventTypeLower = string.lower(tostring(eventType))
        if string.find(eventTypeLower, "connect") then
            return 1, "Connect"
        elseif string.find(eventTypeLower, "disconnect") then
            return 2, "Disconnect"
        elseif string.find(eventTypeLower, "deny") or string.find(eventTypeLower, "block") then
            return 2, "Deny"
        elseif string.find(eventTypeLower, "allow") or string.find(eventTypeLower, "permit") then
            return 1, "Allow"
        end
    end
    
    if result then
        local resultLower = string.lower(tostring(result))
        if string.find(resultLower, "success") or string.find(resultLower, "allow") then
            return 1, "Allow"
        elseif string.find(resultLower, "fail") or string.find(resultLower, "deny") or string.find(resultLower, "block") then
            return 2, "Deny"
        end
    end
    
    -- Default activity
    return 99, activityName or "Network Activity"
end

-- Parse timestamp to milliseconds
local function parseTimestamp(timeStr)
    if not timeStr then return nil end
    
    -- Try ISO format first (2023-10-15T14:30:00.123Z)
    local year, month, day, hour, min, sec, ms = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)")
    if year then
        local timestamp = os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        })
        local milliseconds = ms and tonumber(ms) or 0
        if #tostring(ms) == 1 then milliseconds = milliseconds * 100
        elseif #tostring(ms) == 2 then milliseconds = milliseconds * 10 end
        return timestamp * 1000 + milliseconds
    end
    
    -- If numeric timestamp, assume seconds and convert to ms
    local numTime = tonumber(timeStr)
    if numTime then
        -- If less than year 2000 in seconds, assume it's already in ms
        if numTime < 946684800 then
            return numTime
        else
            return numTime * 1000
        end
    end
    
    return nil
end

-- Main transformation function
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Field mappings
    local fieldMappings = {
        -- Core OCSF fields
        {type = "computed", target = "class_uid", value = CLASS_UID},
        {type = "computed", target = "category_uid", value = CATEGORY_UID},
        {type = "computed", target = "class_name", value = "Network Activity"},
        {type = "computed", target = "category_name", value = "Network Activity"},
        
        -- Source endpoint mappings
        {type = "priority", source1 = "access_device.ip", source2 = "auth_device.ip", target = "src_endpoint.ip"},
        {type = "direct", source = "access_device.hostname", target = "src_endpoint.hostname"},
        
        -- Destination endpoint mappings
        {type = "direct", source = "auth_device.ip", target = "dst_endpoint.ip"},
        {type = "direct", source = "auth_device.name", target = "dst_endpoint.hostname"},
        
        -- Actor/User mappings
        {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
        {type = "direct", source = "user.key", target = "actor.user.uid"},
        {type = "direct", source = "user.type_id", target = "actor.user.type_id"},
        {type = "direct", source = "user.groups", target = "actor.user.groups"},
        {type = "direct", source = "email", target = "actor.user.email_addr"},
        
        -- Device mappings
        {type = "direct", source = "access_device.hostname", target = "device.hostname"},
        {type = "direct", source = "access_device.ip", target = "device.ip"},
        {type = "direct", source = "host", target = "device.hostname"},
        
        -- Application/Service mappings
        {type = "direct", source = "application.name", target = "app_name"},
        {type = "direct", source = "application.key", target = "app_uid"},
        
        -- Location mappings
        {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
        {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
        {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
        {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
        
        -- Metadata
        {type = "computed", target = "metadata.product.name", value = "Cisco IOS"},
        {type = "computed", target = "metadata.product.vendor_name", value = "Cisco"},
        {type = "direct", source = "dataSource.name", target = "metadata.product.name"},
        {type = "direct", source = "dataSource.vendor", target = "metadata.product.vendor_name"},
        {type = "direct", source = "OCSF_version", target = "metadata.version"},
        
        -- Event details
        {type = "direct", source = "message", target = "message"},
        {type = "direct", source = "txid", target = "transaction_uid"},
        {type = "direct", source = "reason", target = "status_detail"},
        {type = "direct", source = "result", target = "status"},
        {type = "direct", source = "object", target = "resource.name"},
        
        -- Observables
        {type = "direct", source = "observables", target = "observables"}
    }
    
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
    
    -- Handle timestamp
    local timestamp = getNestedField(event, 'isotimestamp') or getNestedField(event, 'timestamp')
    local timeMs = parseTimestamp(timestamp)
    if timeMs then
        result.time = timeMs
    else
        result.time = os.time() * 1000
    end
    mappedPaths['isotimestamp'] = true
    mappedPaths['timestamp'] = true
    
    -- Set activity information
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    mappedPaths['activity_id'] = true
    mappedPaths['activity_name'] = true
    mappedPaths['event.type'] = true
    mappedPaths['event_type'] = true
    mappedPaths['result'] = true
    
    -- Set severity
    local severity = getNestedField(event, 'severity') or 
                    getNestedField(event, 'priority') or
                    (event.result and (string.find(string.lower(event.result), "fail") and "high" or "low"))
    result.severity_id = getSeverityId(severity)
    mappedPaths['severity'] = true
    mappedPaths['priority'] = true
    
    -- Set status_id based on result
    if result.status then
        local statusLower = string.lower(tostring(result.status))
        if string.find(statusLower, "success") or string.find(statusLower, "allow") or string.find(statusLower, "permit") then
            result.status_id = 1  -- Success
        elseif string.find(statusLower, "fail") or string.find(statusLower, "deny") or string.find(statusLower, "block") then
            result.status_id = 2  -- Failure
        else
            result.status_id = 99  -- Other
        end
    end
    
    -- Create observables if not already present
    if not result.observables then
        local observables = {}
        
        -- Add IP addresses as observables
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
        
        -- Add user as observable
        if result.actor and result.actor.user and result.actor.user.name then
            table.insert(observables, {
                type_id = 4,
                type = "User Name",
                name = "actor.user.name",
                value = result.actor.user.name
            })
        end
        
        if #observables > 0 then
            result.observables = observables
        end
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end