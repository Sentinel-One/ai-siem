-- Cisco ASA Logs to OCSF Network Activity transformation
-- Target: OCSF Network Activity (class_uid=4001, category_uid=4)

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

-- Parse ISO timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr then return nil end
    
    -- Try ISO 8601 format: 2023-12-01T10:30:45.123Z
    local yr, mo, dy, hr, mn, sc, ms = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z?")
    if yr then
        local timestamp = os.time({
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        })
        -- Add milliseconds if present
        local milliseconds = ms and tonumber(ms) or 0
        if #ms == 3 then
            return timestamp * 1000 + milliseconds
        elseif #ms > 0 then
            -- Adjust for different ms precision
            return timestamp * 1000 + math.floor(milliseconds / math.pow(10, #ms - 3))
        else
            return timestamp * 1000
        end
    end
    
    -- Fallback: try to parse as epoch seconds
    local epochSecs = tonumber(timeStr)
    if epochSecs then
        -- If it looks like seconds (not milliseconds), convert
        if epochSecs < 1e12 then
            return epochSecs * 1000
        else
            return epochSecs
        end
    end
    
    return nil
end

-- Get severity ID based on various severity indicators
local function getSeverityId(event)
    -- Check for explicit severity in different fields
    local severity = event.severity or event.priority or event.level
    if severity then
        local severityStr = tostring(severity):lower()
        if severityStr:match("critical") or severityStr:match("fatal") then return 5
        elseif severityStr:match("high") or severityStr:match("error") then return 4
        elseif severityStr:match("medium") or severityStr:match("warn") then return 3
        elseif severityStr:match("low") then return 2
        elseif severityStr:match("info") then return 1
        end
    end
    
    -- Check result field for severity hints
    local result = event.result
    if result then
        local resultStr = tostring(result):lower()
        if resultStr:match("fail") or resultStr:match("deny") or resultStr:match("block") then
            return 4 -- High for security denials
        elseif resultStr:match("allow") or resultStr:match("permit") or resultStr:match("success") then
            return 1 -- Informational for allowed traffic
        end
    end
    
    -- Default to Unknown
    return 0
end

-- Determine activity based on event type and context
local function getActivityInfo(event)
    local eventType = event["event.type"] or event.event_type
    local activityName = event.activity_name
    local activityId = event.activity_id
    
    -- If activity_id is already set, use it
    if activityId and tonumber(activityId) then
        return tonumber(activityId), activityName or "Network Activity"
    end
    
    -- Map based on event type or other indicators
    if eventType then
        local typeStr = tostring(eventType):lower()
        if typeStr:match("connect") or typeStr:match("session") then
            return 1, "Open"
        elseif typeStr:match("disconnect") or typeStr:match("close") then
            return 2, "Close"
        elseif typeStr:match("deny") or typeStr:match("block") then
            return 5, "Refuse"
        elseif typeStr:match("allow") or typeStr:match("permit") then
            return 1, "Open"
        end
    end
    
    -- Check result for activity hints
    local result = event.result
    if result then
        local resultStr = tostring(result):lower()
        if resultStr:match("deny") or resultStr:match("block") or resultStr:match("drop") then
            return 5, "Refuse"
        elseif resultStr:match("allow") or resultStr:match("permit") then
            return 1, "Open"
        end
    end
    
    -- Default activity
    return 99, activityName or "Other"
end

-- Field mappings for Cisco ASA logs to OCSF
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Message and raw data
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "raw_data", target = "raw_data"},
    
    -- Source endpoint mappings
    {type = "priority", source1 = "access_device.ip", source2 = "src_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "src_port", target = "src_endpoint.port"},
    {type = "priority", source1 = "access_device.hostname", source2 = "src_host", target = "src_endpoint.hostname"},
    
    -- Destination endpoint mappings  
    {type = "priority", source1 = "auth_device.ip", source2 = "dst_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dst_port", target = "dst_endpoint.port"},
    {type = "priority", source1 = "auth_device.name", source2 = "dst_host", target = "dst_endpoint.hostname"},
    
    -- Protocol
    {type = "direct", source = "protocol", target = "protocol_name"},
    {type = "direct", source = "protocol_name", target = "protocol_name"},
    
    -- User information
    {type = "priority", source1 = "user.name", source2 = "username", target = "actor.user.name"},
    {type = "direct", source = "user.key", target = "actor.user.uid"},
    {type = "direct", source = "user.type_id", target = "actor.user.type_id"},
    {type = "direct", source = "user.groups", target = "actor.user.groups"},
    {type = "direct", source = "email", target = "actor.user.email_addr"},
    
    -- Device information
    {type = "direct", source = "host", target = "device.hostname"},
    
    -- Application information
    {type = "direct", source = "application.name", target = "app_name"},
    {type = "direct", source = "application.key", target = "app_uid"},
    
    -- Transaction and session
    {type = "direct", source = "txid", target = "transaction_uid"},
    
    -- Status information
    {type = "direct", source = "result", target = "status"},
    {type = "direct", source = "reason", target = "status_detail"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.vendor_name", value = "Cisco"},
    {type = "computed", target = "metadata.product.name", value = "ASA"},
    {type = "direct", source = "OCSF_version", target = "metadata.version"},
    {type = "direct", source = "dataSource.name", target = "metadata.log_name"},
    {type = "direct", source = "dataSource.vendor", target = "metadata.log_provider"},
    
    -- Location information
    {type = "direct", source = "access_device.location.city", target = "src_endpoint.location.city"},
    {type = "direct", source = "access_device.location.country", target = "src_endpoint.location.country"},
    {type = "direct", source = "auth_device.location.city", target = "dst_endpoint.location.city"},
    {type = "direct", source = "auth_device.location.country", target = "dst_endpoint.location.country"},
    
    -- Additional fields
    {type = "direct", source = "count", target = "count"},
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "start_time", target = "start_time"},
    {type = "direct", source = "end_time", target = "end_time"},
    {type = "direct", source = "timezone_offset", target = "timezone_offset"}
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

    -- Handle time conversion
    local eventTime = getNestedField(event, 'isotimestamp') or 
                     getNestedField(event, 'timestamp') or 
                     getNestedField(event, '@timestamp')
    local timeMs = parseTimestamp(eventTime)
    result.time = timeMs or (os.time() * 1000)
    
    -- Mark timestamp fields as mapped
    mappedPaths['isotimestamp'] = true
    mappedPaths['timestamp'] = true
    mappedPaths['@timestamp'] = true

    -- Set activity information
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Mark activity fields as mapped
    mappedPaths['activity_id'] = true
    mappedPaths['activity_name'] = true
    mappedPaths['event.type'] = true
    mappedPaths['event_type'] = true

    -- Set severity
    result.severity_id = getSeverityId(event)
    mappedPaths['severity'] = true
    mappedPaths['priority'] = true
    mappedPaths['level'] = true
    mappedPaths['result'] = true

    -- Create observables for key network indicators
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
    
    local dstIp = getNestedField(result, 'dst_endpoint.ip')
    if dstIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "dst_endpoint.ip", 
            value = dstIp
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
    mappedPaths['observables'] = true

    -- Set status_id based on status
    if result.status then
        local statusStr = tostring(result.status):lower()
        if statusStr:match("success") or statusStr:match("allow") or statusStr:match("permit") then
            result.status_id = 1  -- Success
        elseif statusStr:match("fail") or statusStr:match("deny") or statusStr:match("block") then
            result.status_id = 2  -- Failure
        else
            result.status_id = 99 -- Other
        end
    end

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    return result
end