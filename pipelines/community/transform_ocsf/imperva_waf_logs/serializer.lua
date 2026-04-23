-- Imperva WAF Logs Parser for OCSF HTTP Activity
-- Class UID 4002 (HTTP Activity), Category UID 4 (Network Activity)

local CLASS_UID = 4002
local CATEGORY_UID = 4

-- Nested field access
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

-- Replace userdata nil values
function no_nulls(d, rn)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = rn
            elseif type(v) == "table" then no_nulls(v, rn) end
        end
    end
    return d
end

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Map severity levels to OCSF severity_id
local function getSeverityId(severity)
    if severity == nil then return 0 end
    local severityStr = tostring(severity):lower()
    
    -- Imperva WAF common severity mappings
    if severityStr:match("critical") or severityStr:match("emergency") then return 5 end
    if severityStr:match("high") or severityStr:match("alert") then return 4 end
    if severityStr:match("medium") or severityStr:match("warning") then return 3 end
    if severityStr:match("low") or severityStr:match("notice") then return 2 end
    if severityStr:match("info") or severityStr:match("informational") then return 1 end
    
    -- Numeric severity mapping (common in WAF logs)
    local numSeverity = tonumber(severity)
    if numSeverity then
        if numSeverity >= 9 then return 5 end -- Critical
        if numSeverity >= 7 then return 4 end -- High
        if numSeverity >= 5 then return 3 end -- Medium
        if numSeverity >= 3 then return 2 end -- Low
        if numSeverity >= 1 then return 1 end -- Informational
    end
    
    return 0 -- Unknown
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if timestamp == nil then return os.time() * 1000 end
    
    -- Handle various timestamp formats common in WAF logs
    local timeStr = tostring(timestamp)
    
    -- ISO 8601 format: 2023-10-15T14:30:45Z or 2023-10-15T14:30:45.123Z
    local year, month, day, hour, min, sec = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
    
    -- Unix timestamp (seconds or milliseconds)
    local unixTime = tonumber(timeStr)
    if unixTime then
        -- If timestamp is in seconds (typical range), convert to milliseconds
        if unixTime < 9999999999 then
            return unixTime * 1000
        else
            return unixTime
        end
    end
    
    -- Syslog format: Oct 15 14:30:45
    local monthNames = {Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
    local monthStr, dayStr, timeStr2 = timeStr:match("(%a+)%s+(%d+)%s+(%d+:%d+:%d+)")
    if monthStr and monthNames[monthStr] then
        local currentYear = os.date("%Y")
        local hour2, min2, sec2 = timeStr2:match("(%d+):(%d+):(%d+)")
        local timeTable = {
            year = tonumber(currentYear),
            month = monthNames[monthStr],
            day = tonumber(dayStr),
            hour = tonumber(hour2),
            min = tonumber(min2),
            sec = tonumber(sec2),
            isdst = false
        }
        return os.time(timeTable) * 1000
    end
    
    return os.time() * 1000
end

-- Determine activity based on event type or action
local function getActivityInfo(event)
    local action = getNestedField(event, 'action') or getNestedField(event, 'event_type') or 
                   getNestedField(event, 'activity') or getNestedField(event, 'method')
    
    if action then
        local actionStr = tostring(action):lower()
        if actionStr:match("block") or actionStr:match("deny") or actionStr:match("reject") then
            return 2, "Block" -- HTTP Response
        elseif actionStr:match("allow") or actionStr:match("permit") or actionStr:match("accept") then
            return 1, "Allow" -- HTTP Request
        elseif actionStr:match("redirect") then
            return 3, "Redirect"
        end
    end
    
    -- Default to HTTP Request if no specific action found
    return 1, "HTTP Request"
end

-- Field mappings for Imperva WAF logs
local fieldMappings = {
    -- Basic event info
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "raw", target = "raw_data"},
    {type = "direct", source = "raw_data", target = "raw_data"},
    {type = "direct", source = "count", target = "count"},
    {type = "direct", source = "duration", target = "duration"},
    
    -- HTTP Request fields
    {type = "priority", source1 = "url", source2 = "request_url", source3 = "uri", target = "http_request.url.url_string"},
    {type = "priority", source1 = "method", source2 = "http_method", source3 = "request_method", target = "http_request.http_method"},
    {type = "priority", source1 = "user_agent", source2 = "useragent", source3 = "ua", target = "http_request.user_agent"},
    {type = "priority", source1 = "referer", source2 = "referrer", source3 = "http_referer", target = "http_request.referrer"},
    {type = "priority", source1 = "http_version", source2 = "version", target = "http_request.version"},
    {type = "priority", source1 = "host", source2 = "hostname", source3 = "server_name", target = "http_request.url.hostname"},
    
    -- HTTP Response fields
    {type = "priority", source1 = "status", source2 = "status_code", source3 = "response_code", target = "http_response.code"},
    {type = "priority", source1 = "status_message", source2 = "response_message", target = "http_response.message"},
    {type = "priority", source1 = "response_size", source2 = "content_length", target = "http_response.length"},
    
    -- Source/Client info
    {type = "priority", source1 = "src_ip", source2 = "source_ip", source3 = "client_ip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "source_port", source3 = "client_port", target = "src_endpoint.port"},
    {type = "priority", source1 = "src_country", source2 = "source_country", target = "src_endpoint.location.country"},
    
    -- Destination/Server info
    {type = "priority", source1 = "dst_ip", source2 = "dest_ip", source3 = "server_ip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_port", source2 = "dest_port", source3 = "server_port", target = "dst_endpoint.port"},
    
    -- Security fields
    {type = "priority", source1 = "rule_id", source2 = "ruleid", source3 = "policy_id", target = "metadata.rule_id"},
    {type = "priority", source1 = "rule_name", source2 = "rulename", source3 = "policy_name", target = "metadata.rule_name"},
    {type = "priority", source1 = "attack_type", source2 = "threat_type", source3 = "violation_type", target = "metadata.attack_type"},
    {type = "priority", source1 = "session_id", source2 = "sessionid", target = "session.uid"},
    
    -- User information
    {type = "priority", source1 = "user", source2 = "username", source3 = "user_name", target = "actor.user.name"},
    {type = "priority", source1 = "user_id", source2 = "userid", target = "actor.user.uid"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "Imperva WAF"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Imperva"},
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
    
    -- Set timestamp
    local timestamp = getNestedField(event, 'timestamp') or getNestedField(event, 'time') or 
                     getNestedField(event, 'event_time') or getNestedField(event, '@timestamp')
    result.time = parseTimestamp(timestamp)
    
    -- Set activity and type_uid
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    local severity = getNestedField(event, 'severity') or getNestedField(event, 'priority') or 
                    getNestedField(event, 'level') or getNestedField(event, 'risk_score')
    result.severity_id = getSeverityId(severity)
    
    -- Set status based on HTTP response code or action
    local statusCode = getNestedField(result, 'http_response.code')
    if statusCode then
        local code = tonumber(statusCode)
        if code then
            if code >= 200 and code < 300 then
                result.status = "Success"
                result.status_id = 1
            elseif code >= 400 then
                result.status = "Failure"
                result.status_id = 2
            else
                result.status = "Unknown"
                result.status_id = 0
            end
        end
    else
        -- Use action-based status
        local action = getNestedField(event, 'action') or getNestedField(event, 'disposition')
        if action then
            local actionStr = tostring(action):lower()
            if actionStr:match("block") or actionStr:match("deny") or actionStr:match("reject") then
                result.status = "Failure"
                result.status_id = 2
            elseif actionStr:match("allow") or actionStr:match("permit") then
                result.status = "Success"
                result.status_id = 1
            end
        end
    end
    
    -- Set default status if not determined
    if not result.status then
        result.status = "Unknown"
        result.status_id = 0
    end
    
    -- Mark timestamp fields as mapped
    mappedPaths['timestamp'] = true
    mappedPaths['time'] = true
    mappedPaths['event_time'] = true
    mappedPaths['@timestamp'] = true
    mappedPaths['severity'] = true
    mappedPaths['priority'] = true
    mappedPaths['level'] = true
    mappedPaths['risk_score'] = true
    mappedPaths['action'] = true
    mappedPaths['disposition'] = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values
    result = no_nulls(result, nil)
    
    return result
end