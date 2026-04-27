-- BeyondTrust PasswordSafe Authentication Event Transformation
-- Target OCSF Class: Authentication (3002)

-- Constants
local CLASS_UID = 3002
local CATEGORY_UID = 3
local CLASS_NAME = "Authentication"
local CATEGORY_NAME = "Identity & Access Management"

-- Helper Functions
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

-- Severity mapping for BeyondTrust PasswordSafe events
local function getSeverityId(level)
    if level == nil then return 0 end
    local severityStr = tostring(level):lower()
    local severityMap = {
        critical = 5, high = 4, medium = 3, warning = 2, low = 2,
        information = 1, informational = 1, info = 1, error = 4,
        success = 1, failure = 3, fail = 3, alert = 4
    }
    return severityMap[severityStr] or 0
end

-- Activity ID mapping based on authentication events
local function getActivityId(eventType, action, result)
    if not eventType and not action then return 99 end
    
    local eventStr = (tostring(eventType or "") .. " " .. tostring(action or "") .. " " .. tostring(result or "")):lower()
    
    -- Authentication activities
    if eventStr:find("login") or eventStr:find("logon") or eventStr:find("signin") then
        if eventStr:find("success") or eventStr:find("successful") then return 1 end -- Logon
        if eventStr:find("fail") or eventStr:find("error") or eventStr:find("invalid") then return 2 end -- Logon Failure
        return 1
    elseif eventStr:find("logout") or eventStr:find("logoff") or eventStr:find("signout") then
        return 3 -- Logoff
    elseif eventStr:find("password") then
        if eventStr:find("change") or eventStr:find("reset") or eventStr:find("update") then return 4 end -- Password Change
    elseif eventStr:find("account") then
        if eventStr:find("lock") then return 5 end -- Account Locked
        if eventStr:find("unlock") then return 6 end -- Account Unlocked
    elseif eventStr:find("session") then
        if eventStr:find("start") or eventStr:find("create") then return 1 end
        if eventStr:find("end") or eventStr:find("terminate") then return 3 end
    end
    
    return 99 -- Other
end

-- Activity name mapping
local function getActivityName(activityId)
    local activityNames = {
        [1] = "Logon",
        [2] = "Logon Failure", 
        [3] = "Logoff",
        [4] = "Password Change",
        [5] = "Account Locked",
        [6] = "Account Unlocked",
        [99] = "Other"
    }
    return activityNames[activityId] or "Other"
end

-- Convert timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if not timestamp then return os.time() * 1000 end
    
    local timeStr = tostring(timestamp)
    
    -- Try ISO format: YYYY-MM-DDTHH:MM:SS
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)%-(%d+)%-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        local time = os.time({
            year = tonumber(yr), month = tonumber(mo), day = tonumber(dy),
            hour = tonumber(hr), min = tonumber(mn), sec = tonumber(sc)
        })
        return time * 1000
    end
    
    -- Try slash format: MM/DD/YYYY HH:MM:SS
    mo, dy, yr, hr, mn, sc = timeStr:match("(%d+)/(%d+)/(%d+) (%d+):(%d+):(%d+)")
    if mo then
        local time = os.time({
            year = tonumber(yr), month = tonumber(mo), day = tonumber(dy),
            hour = tonumber(hr), min = tonumber(mn), sec = tonumber(sc)
        })
        return time * 1000
    end
    
    -- Try epoch seconds
    local epochSec = tonumber(timeStr)
    if epochSec then
        return epochSec * 1000
    end
    
    return os.time() * 1000
end

-- Status mapping
local function getStatusId(status, result)
    if not status and not result then return 0 end
    
    local statusStr = (tostring(status or "") .. " " .. tostring(result or "")):lower()
    
    if statusStr:find("success") or statusStr:find("successful") or statusStr:find("ok") then
        return 1 -- Success
    elseif statusStr:find("fail") or statusStr:find("error") or statusStr:find("invalid") or statusStr:find("denied") then
        return 2 -- Failure
    end
    
    return 0 -- Unknown
end

-- Field mappings for BeyondTrust PasswordSafe
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    
    -- Message and raw data
    {type = "priority", source1 = "message", source2 = "event_message", source3 = "description", target = "message"},
    {type = "priority", source1 = "raw", source2 = "raw_data", source3 = "original_message", target = "raw_data"},
    
    -- Actor (user) information
    {type = "priority", source1 = "username", source2 = "user", source3 = "userid", target = "actor.user.name"},
    {type = "priority", source1 = "userid", source2 = "user_id", source3 = "uid", target = "actor.user.uid"},
    {type = "priority", source1 = "domain", source2 = "user_domain", source3 = "realm", target = "actor.user.domain"},
    
    -- Source endpoint
    {type = "priority", source1 = "src_ip", source2 = "source_ip", source3 = "client_ip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_host", source2 = "source_host", source3 = "hostname", target = "src_endpoint.hostname"},
    {type = "priority", source1 = "src_port", source2 = "source_port", source3 = "port", target = "src_endpoint.port"},
    
    -- Destination endpoint
    {type = "priority", source1 = "dst_ip", source2 = "dest_ip", source3 = "server_ip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_host", source2 = "dest_host", source3 = "server_host", target = "dst_endpoint.hostname"},
    {type = "priority", source1 = "dst_port", source2 = "dest_port", source3 = "server_port", target = "dst_endpoint.port"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "BeyondTrust PasswordSafe"},
    {type = "computed", target = "metadata.product.vendor_name", value = "BeyondTrust"},
    {type = "priority", source1 = "version", source2 = "product_version", target = "metadata.version"},
    
    -- Additional fields
    {type = "priority", source1 = "session_id", source2 = "sessionid", target = "session.uid"},
    {type = "priority", source1 = "duration", source2 = "elapsed_time", target = "duration"},
    {type = "priority", source1 = "count", source2 = "event_count", target = "count"}
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
            if value == nil and mapping.source3 then
                value = getNestedField(event, mapping.source3)
            end
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
            if mapping.source3 then mappedPaths[mapping.source3] = true end
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set time from various timestamp fields
    local timeValue = parseTimestamp(
        getNestedField(event, "timestamp") or 
        getNestedField(event, "time") or 
        getNestedField(event, "event_time") or
        getNestedField(event, "datetime")
    )
    result.time = timeValue
    mappedPaths["timestamp"] = true
    mappedPaths["time"] = true
    mappedPaths["event_time"] = true
    mappedPaths["datetime"] = true
    
    -- Determine activity_id and activity_name
    local eventType = getNestedField(event, "event_type") or getNestedField(event, "type")
    local action = getNestedField(event, "action") or getNestedField(event, "event_action")
    local eventResult = getNestedField(event, "result") or getNestedField(event, "status")
    
    local activityId = getActivityId(eventType, action, eventResult)
    result.activity_id = activityId
    result.activity_name = getActivityName(activityId)
    result.type_uid = CLASS_UID * 100 + activityId
    
    mappedPaths["event_type"] = true
    mappedPaths["type"] = true
    mappedPaths["action"] = true
    mappedPaths["event_action"] = true
    mappedPaths["result"] = true
    mappedPaths["status"] = true
    
    -- Set severity
    local severity = getNestedField(event, "severity") or getNestedField(event, "priority") or getNestedField(event, "level")
    result.severity_id = getSeverityId(severity)
    mappedPaths["severity"] = true
    mappedPaths["priority"] = true
    mappedPaths["level"] = true
    
    -- Set status information
    local status = getNestedField(event, "status") or getNestedField(event, "result")
    if status then
        result.status = tostring(status)
        result.status_id = getStatusId(status, eventResult)
        local statusDetail = getNestedField(event, "status_detail") or getNestedField(event, "reason")
        if statusDetail then
            result.status_detail = tostring(statusDetail)
            mappedPaths["status_detail"] = true
            mappedPaths["reason"] = true
        end
    end
    
    -- Set start_time and end_time if available
    local startTime = getNestedField(event, "start_time") or getNestedField(event, "session_start")
    if startTime then
        result.start_time = parseTimestamp(startTime)
        mappedPaths["start_time"] = true
        mappedPaths["session_start"] = true
    end
    
    local endTime = getNestedField(event, "end_time") or getNestedField(event, "session_end")
    if endTime then
        result.end_time = parseTimestamp(endTime)
        mappedPaths["end_time"] = true
        mappedPaths["session_end"] = true
    end
    
    -- Set timezone offset if available
    local timezoneOffset = getNestedField(event, "timezone_offset") or getNestedField(event, "tz_offset")
    if timezoneOffset then
        result.timezone_offset = tonumber(timezoneOffset)
        mappedPaths["timezone_offset"] = true
        mappedPaths["tz_offset"] = true
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end