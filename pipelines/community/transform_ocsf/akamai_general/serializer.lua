-- OCSF Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Parse ISO8601 timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
    if timeStr == nil or timeStr == "" then return nil end
    
    -- Handle ISO8601 format: 2023-10-15T14:30:45Z or 2023-10-15T14:30:45.123Z
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
        else
            return timestamp * 1000
        end
    end
    
    -- Handle Unix timestamp (seconds or milliseconds)
    local numTime = tonumber(timeStr)
    if numTime then
        -- If less than 13 digits, assume seconds; otherwise milliseconds
        return numTime < 10000000000000 and numTime * 1000 or numTime
    end
    
    return nil
end

-- Map severity levels to OCSF severity_id
function getSeverityId(level)
    if level == nil then return 0 end
    
    local levelStr = string.lower(tostring(level))
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        warning = 2,
        low = 2,
        info = 1,
        informational = 1,
        information = 1,
        debug = 1,
        error = 4,
        fatal = 6
    }
    
    return severityMap[levelStr] or 0
end

-- Field mappings for Akamai general logs
local fieldMappings = {
    -- Basic OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    
    -- Network endpoints
    {type = "priority", source1 = "src_ip", source2 = "source_ip", source3 = "client_ip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "source_port", target = "src_endpoint.port"},
    {type = "priority", source1 = "src_host", source2 = "source_host", source3 = "hostname", target = "src_endpoint.hostname"},
    
    {type = "priority", source1 = "dst_ip", source2 = "dest_ip", source3 = "destination_ip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_port", source2 = "dest_port", source3 = "destination_port", target = "dst_endpoint.port"},
    {type = "priority", source1 = "dst_host", source2 = "dest_host", source3 = "destination_host", target = "dst_endpoint.hostname"},
    
    -- Protocol and connection details
    {type = "priority", source1 = "protocol", source2 = "proto", target = "protocol_name"},
    {type = "priority", source1 = "method", source2 = "http_method", target = "http_request.http_method"},
    {type = "priority", source1 = "url", source2 = "uri", source3 = "request_uri", target = "http_request.url.url_string"},
    {type = "priority", source1 = "user_agent", source2 = "useragent", target = "http_request.user_agent"},
    {type = "priority", source1 = "referer", source2 = "referrer", target = "http_request.http_headers.Referer"},
    
    -- Response details
    {type = "priority", source1 = "status_code", source2 = "response_code", source3 = "http_status", target = "http_response.code"},
    {type = "priority", source1 = "response_size", source2 = "bytes_sent", target = "http_response.length"},
    
    -- Generic message and status
    {type = "priority", source1 = "message", source2 = "msg", source3 = "description", target = "message"},
    {type = "priority", source1 = "status", source2 = "event_status", target = "status"},
    {type = "priority", source1 = "status_detail", source2 = "status_message", target = "status_detail"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "Akamai"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Akamai Technologies"},
    {type = "computed", target = "metadata.version", value = "1.0.0"},
    
    -- Timing
    {type = "priority", source1 = "duration", source2 = "response_time", target = "duration"},
    {type = "priority", source1 = "bytes", source2 = "byte_count", target = "traffic.bytes"},
    {type = "priority", source1 = "packets", source2 = "packet_count", target = "traffic.packets"}
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
    local eventTime = getNestedField(event, 'timestamp') or 
                     getNestedField(event, 'time') or 
                     getNestedField(event, 'event_time') or
                     getNestedField(event, 'log_time')
    
    local parsedTime = parseTimestamp(eventTime)
    result.time = parsedTime or (os.time() * 1000)

    -- Set severity
    local severity = getNestedField(event, 'severity') or 
                    getNestedField(event, 'level') or 
                    getNestedField(event, 'priority')
    result.severity_id = getSeverityId(severity)

    -- Determine activity based on event content
    local activity_name = "Network Traffic"
    local activity_id = 1
    
    -- Check for HTTP activity
    if getNestedField(result, 'http_request.http_method') or 
       getNestedField(result, 'http_response.code') then
        activity_name = "HTTP Activity"
        activity_id = 2
    end
    
    -- Check for specific Akamai events
    local eventType = getNestedField(event, 'event_type') or 
                     getNestedField(event, 'log_type')
    if eventType then
        if string.find(string.lower(eventType), "security") then
            activity_name = "Security Event"
            activity_id = 6
        elseif string.find(string.lower(eventType), "access") then
            activity_name = "Access Log"
            activity_id = 1
        end
    end

    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id

    -- Set status_id based on HTTP response code if available
    local httpCode = getNestedField(result, 'http_response.code')
    if httpCode then
        local code = tonumber(httpCode)
        if code and code >= 200 and code < 300 then
            result.status_id = 1  -- Success
        elseif code and code >= 400 then
            result.status_id = 2  -- Failure
        else
            result.status_id = 99 -- Other
        end
    else
        result.status_id = 0  -- Unknown
    end

    -- Set raw_data to preserve original event
    if type(event) == "table" then
        local json = require('json')
        local status, encoded = pcall(json.encode, event)
        if status then
            result.raw_data = encoded
        end
    end

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean up nil values
    no_nulls(result, nil)

    return result
end