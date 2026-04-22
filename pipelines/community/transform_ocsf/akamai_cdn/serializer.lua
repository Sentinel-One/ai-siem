-- Constants for OCSF HTTP Activity class
local CLASS_UID = 4002
local CATEGORY_UID = 4

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

local function parseEmbeddedPayload(payload)
    if type(payload) == "table" then
        return payload
    end
    local parsed = {}
    if type(payload) ~= "string" or payload == "" then
        return parsed
    end

    if payload:sub(1, 1) == "{" and json and json.decode then
        local ok, decoded = pcall(function() return json.decode(payload) end)
        if ok and type(decoded) == "table" then
            return decoded
        end
    end

    for k, v in payload:gmatch('([%w_%.%-]+)%s*=%s*"([^"]*)"') do
        parsed[k] = v
    end
    for k, v in payload:gmatch('([%w_%.%-]+)%s*=%s*([^%s"]+)') do
        if parsed[k] == nil then
            parsed[k] = v
        end
    end
    return parsed
end

local function normalizeEvent(event)
    local normalized = {}
    for k, v in pairs(event) do normalized[k] = v end

    local payload = event["message"]
    if payload == nil then payload = event["raw"] end
    local embedded = parseEmbeddedPayload(payload)
    for k, v in pairs(embedded) do
        if normalized[k] == nil then normalized[k] = v end
    end

    -- Akamai CDN aliases in message payload
    if normalized["reqMethod"] and not normalized["method"] then
        normalized["method"] = normalized["reqMethod"]
    end
    if normalized["statusCode"] and not normalized["status_code"] then
        normalized["status_code"] = normalized["statusCode"]
    end
    if normalized["cliIP"] and not normalized["client_ip"] then
        normalized["client_ip"] = normalized["cliIP"]
    end
    if normalized["edgeIP"] and not normalized["server_ip"] then
        normalized["server_ip"] = normalized["edgeIP"]
    end
    if normalized["turnAroundTimeMSec"] and not normalized["response_time"] then
        normalized["response_time"] = normalized["turnAroundTimeMSec"]
    end
    if normalized["bytes"] and not normalized["bytes_sent"] then
        normalized["bytes_sent"] = normalized["bytes"]
    end
    if normalized["reqPath"] and not normalized["uri"] then
        normalized["uri"] = normalized["reqPath"]
    end
    if normalized["reqHost"] and not normalized["host"] then
        normalized["host"] = normalized["reqHost"]
    end
    if normalized["reqHost"] and normalized["reqPath"] and not normalized["url"] then
        normalized["url"] = "https://" .. tostring(normalized["reqHost"]) .. tostring(normalized["reqPath"])
    end

    return normalized
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

-- Convert HTTP status code to severity
function getHttpSeverityId(statusCode)
    if not statusCode then return 0 end
    local code = tonumber(statusCode)
    if not code then return 0 end
    
    if code >= 200 and code < 300 then return 1 -- Informational (success)
    elseif code >= 300 and code < 400 then return 2 -- Low (redirect)
    elseif code >= 400 and code < 500 then return 3 -- Medium (client error)
    elseif code >= 500 then return 4 -- High (server error)
    else return 0 -- Unknown
    end
end

-- Parse timestamp to milliseconds
function parseTimestamp(timestamp)
    if not timestamp then
        local okNow, nowTs = pcall(function() return os.time() end)
        return ((okNow and nowTs) and nowTs or 0) * 1000
    end
    
    -- Try ISO format: YYYY-MM-DDTHH:MM:SS
    local yr, mo, dy, hr, mn, sc = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        local okTime, ts = pcall(function()
            return os.time({
                year = tonumber(yr),
                month = tonumber(mo),
                day = tonumber(dy),
                hour = tonumber(hr),
                min = tonumber(mn),
                sec = tonumber(sc),
                isdst = false
            })
        end)
        if okTime and ts then return ts * 1000 end
    end
    
    -- Try Unix timestamp
    local unixTime = tonumber(timestamp)
    if unixTime then
        -- If timestamp looks like seconds, convert to milliseconds
        if unixTime < 10000000000 then
            return unixTime * 1000
        else
            return unixTime
        end
    end
    
    local okNow, nowTs = pcall(function() return os.time() end)
    return ((okNow and nowTs) and nowTs or 0) * 1000
end

-- Get HTTP activity ID based on method
function getHttpActivityId(method)
    if not method then return 99 end
    local methodUpper = string.upper(method)
    
    -- Map common HTTP methods to activity IDs
    local methodMap = {
        GET = 1,
        POST = 2,
        PUT = 3,
        DELETE = 4,
        HEAD = 5,
        OPTIONS = 6,
        PATCH = 7,
        CONNECT = 8,
        TRACE = 9
    }
    
    return methodMap[methodUpper] or 99
end

-- Field mappings for Akamai CDN logs
local fieldMappings = {
    -- Basic OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- HTTP Request fields
    {type = "priority", source1 = "url", source2 = "uri", source3 = "request_url", target = "http_request.url"},
    {type = "priority", source1 = "method", source2 = "http_method", source3 = "request_method", target = "http_request.http_method"},
    {type = "priority", source1 = "user_agent", source2 = "userAgent", source3 = "ua", target = "http_request.user_agent"},
    {type = "priority", source1 = "referrer", source2 = "referer", source3 = "http_referrer", target = "http_request.referrer"},
    {type = "priority", source1 = "http_version", source2 = "version", target = "http_request.version"},
    
    -- HTTP Response fields
    {type = "priority", source1 = "status", source2 = "status_code", source3 = "response_code", target = "http_response.code"},
    {type = "priority", source1 = "status_message", source2 = "response_message", target = "http_response.message"},
    
    -- Network/endpoint fields
    {type = "priority", source1 = "client_ip", source2 = "clientip", source3 = "src_ip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "server_ip", source2 = "serverip", source3 = "dst_ip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "client_port", source2 = "src_port", target = "src_endpoint.port"},
    {type = "priority", source1 = "server_port", source2 = "dst_port", target = "dst_endpoint.port"},
    
    -- Timing fields
    {type = "priority", source1 = "response_time", source2 = "duration", source3 = "time_taken", target = "duration"},
    {type = "priority", source1 = "bytes_sent", source2 = "response_size", target = "traffic.bytes_out"},
    {type = "priority", source1 = "bytes_received", source2 = "request_size", target = "traffic.bytes_in"},
    
    -- Message/raw data
    {type = "priority", source1 = "message", source2 = "log_message", target = "message"},
    {type = "priority", source1 = "raw_data", source2 = "raw", target = "raw_data"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "Akamai CDN"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Akamai"},
    {type = "computed", target = "metadata.version", value = "1.0"},
}

function processEvent(event)
    -- Input validation
    if type(event) ~= "table" then return nil end
    event = normalizeEvent(event)
    
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
            local value = nil
            -- Try sources in priority order
            if mapping.source1 then 
                value = getNestedField(event, mapping.source1)
                mappedPaths[mapping.source1] = true
            end
            if value == nil and mapping.source2 then 
                value = getNestedField(event, mapping.source2)
                mappedPaths[mapping.source2] = true
            end
            if value == nil and mapping.source3 then 
                value = getNestedField(event, mapping.source3)
                mappedPaths[mapping.source3] = true
            end
            
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
            end
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity_id based on HTTP method
    local httpMethod = getNestedField(result, "http_request.http_method")
    local activityId = getHttpActivityId(httpMethod)
    result.activity_id = activityId
    
    -- Set activity_name
    if httpMethod then
        result.activity_name = string.upper(httpMethod) .. " Request"
    else
        result.activity_name = "HTTP Request"
    end
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity based on HTTP status code
    local statusCode = getNestedField(result, "http_response.code")
    result.severity_id = getHttpSeverityId(statusCode)
    
    -- Set timestamp
    local timestamp = getNestedField(event, "timestamp") or 
                     getNestedField(event, "time") or 
                     getNestedField(event, "datetime") or
                     getNestedField(event, "log_time")
    result.time = parseTimestamp(timestamp)
    
    -- Set status information
    if statusCode then
        result.status_id = tonumber(statusCode)
        result.status = "HTTP " .. tostring(statusCode)
        
        -- Add status detail for common codes
        local statusDetails = {
            ["200"] = "OK",
            ["201"] = "Created", 
            ["301"] = "Moved Permanently",
            ["302"] = "Found",
            ["400"] = "Bad Request",
            ["401"] = "Unauthorized",
            ["403"] = "Forbidden",
            ["404"] = "Not Found",
            ["500"] = "Internal Server Error",
            ["502"] = "Bad Gateway",
            ["503"] = "Service Unavailable"
        }
        result.status_detail = statusDetails[tostring(statusCode)]
    end
    
    -- Convert duration to milliseconds if needed
    local duration = getNestedField(result, "duration")
    if duration and tonumber(duration) then
        local durationNum = tonumber(duration)
        -- If duration looks like seconds (< 1000), convert to ms
        if durationNum < 1000 then
            result.duration = durationNum * 1000
        else
            result.duration = durationNum
        end
    end
    
    -- Set count (default for single event)
    result.count = 1
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end
