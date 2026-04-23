-- Constants for Linux Authentication Events
local CLASS_UID = 3002
local CATEGORY_UID = 3
local CLASS_NAME = "Authentication"
local CATEGORY_NAME = "Identity & Access Management"

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
    if type(tbl) ~= "table" then return default end
    local value = tbl[key]
    return value ~= nil and value or default
end

function copyUnmappedFields(event, mappedPaths, result)
    if type(event) ~= "table" then return end
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Get severity based on Linux auth events (failed=high, success=informational)
local function getSeverityId(event)
    local status = getValue(event, 'status', ''):lower()
    local result = getValue(event, 'result', ''):lower()
    local message = getValue(event, 'message', ''):lower()
    
    -- Failed authentications are high severity
    if status:match('fail') or result:match('fail') or 
       message:match('fail') or message:match('invalid') or
       message:match('denied') or message:match('error') then
        return 4 -- High
    end
    
    -- Successful authentications are informational
    if status:match('success') or result:match('success') or
       message:match('success') or message:match('accepted') then
        return 1 -- Informational
    end
    
    return 0 -- Unknown
end

-- Get activity ID based on auth event type
local function getActivityId(event)
    local message = getValue(event, 'message', ''):lower()
    local eventType = getValue(event, 'event_type', ''):lower()
    
    -- Logon/Login events
    if message:match('session opened') or message:match('login') or 
       message:match('logon') or eventType:match('login') then
        return 1 -- Logon
    end
    
    -- Logout events
    if message:match('session closed') or message:match('logout') or
       message:match('logoff') or eventType:match('logout') then
        return 2 -- Logout
    end
    
    -- Authentication failure
    if message:match('authentication failure') or message:match('auth.*fail') or
       message:match('invalid.*password') or message:match('login.*fail') then
        return 3 -- Authentication Failure
    end
    
    return 99 -- Other
end

-- Get activity name from activity ID
local function getActivityName(activityId)
    local activityNames = {
        [1] = "Logon",
        [2] = "Logout", 
        [3] = "Authentication Failure",
        [99] = "Other"
    }
    return activityNames[activityId] or "Unknown"
end

-- Parse timestamp to milliseconds
local function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    
    -- Try common Linux timestamp formats
    -- ISO format: 2023-01-01T12:00:00Z or 2023-01-01T12:00:00.123Z
    local year, month, day, hour, min, sec = timeStr:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
    if year then
        return os.time({
            year = tonumber(year),
            month = tonumber(month), 
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec)
        }) * 1000
    end
    
    -- Unix timestamp (seconds)
    local timestamp = tonumber(timeStr)
    if timestamp and timestamp > 1000000000 then
        -- If it looks like seconds since epoch, convert to ms
        if timestamp < 10000000000 then
            return timestamp * 1000
        end
        -- Already in milliseconds
        return timestamp
    end
    
    return nil
end

-- Field mappings for Linux authentication events
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    
    -- Message and raw data
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "raw", target = "raw_data"},
    {type = "direct", source = "raw_data", target = "raw_data"},
    
    -- User information
    {type = "direct", source = "user", target = "actor.user.name"},
    {type = "direct", source = "username", target = "actor.user.name"},
    {type = "direct", source = "user_name", target = "actor.user.name"},
    {type = "direct", source = "uid", target = "actor.user.uid"},
    {type = "direct", source = "user_id", target = "actor.user.uid"},
    {type = "direct", source = "domain", target = "actor.user.domain"},
    
    -- Network information
    {type = "direct", source = "src_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "source_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "client_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "remote_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "src_host", target = "src_endpoint.hostname"},
    {type = "direct", source = "source_host", target = "src_endpoint.hostname"},
    {type = "direct", source = "hostname", target = "src_endpoint.hostname"},
    {type = "direct", source = "src_port", target = "src_endpoint.port"},
    {type = "direct", source = "source_port", target = "src_endpoint.port"},
    {type = "direct", source = "dst_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dest_ip", target = "dst_endpoint.ip"},
    
    -- Status information
    {type = "direct", source = "status", target = "status"},
    {type = "direct", source = "result", target = "status"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    {type = "direct", source = "error", target = "status_detail"},
    
    -- Metadata
    {type = "direct", source = "product", target = "metadata.product.name"},
    {type = "direct", source = "vendor", target = "metadata.product.vendor_name"},
    {type = "direct", source = "version", target = "metadata.version"},
    {type = "direct", source = "count", target = "count"},
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "start_time", target = "start_time"},
    {type = "direct", source = "end_time", target = "end_time"},
    {type = "direct", source = "timezone_offset", target = "timezone_offset"}
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
    
    -- Set activity-specific fields
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.activity_name = getActivityName(activityId)
    result.type_uid = CLASS_UID * 100 + activityId
    result.severity_id = getSeverityId(event)
    
    -- Handle timestamp
    local eventTime = getNestedField(event, 'timestamp') or 
                     getNestedField(event, 'time') or
                     getNestedField(event, 'event_time') or
                     getNestedField(event, '@timestamp')
    
    if eventTime then
        local parsedTime = parseTimestamp(tostring(eventTime))
        if parsedTime then
            result.time = parsedTime
        end
    end
    
    -- Default time if not parsed
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set status_id based on status
    if result.status then
        local status = tostring(result.status):lower()
        if status:match('success') or status:match('ok') then
            result.status_id = 1 -- Success
        elseif status:match('fail') or status:match('error') or status:match('denied') then
            result.status_id = 2 -- Failure
        else
            result.status_id = 99 -- Other
        end
    end
    
    -- Add metadata defaults
    if not getNestedField(result, 'metadata.product.name') then
        setNestedField(result, 'metadata.product.name', 'Linux Authentication')
    end
    if not getNestedField(result, 'metadata.product.vendor_name') then
        setNestedField(result, 'metadata.product.vendor_name', 'Linux')
    end
    
    -- Mark additional mapped paths
    mappedPaths['timestamp'] = true
    mappedPaths['time'] = true
    mappedPaths['event_time'] = true
    mappedPaths['@timestamp'] = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end