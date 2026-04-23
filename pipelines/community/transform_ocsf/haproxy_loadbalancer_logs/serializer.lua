-- HAProxy Load Balancer Logs to OCSF HTTP Activity (4002) transformation
-- Maps HAProxy access logs to OCSF format with proper field extraction

-- OCSF Constants
local CLASS_UID = 4002
local CATEGORY_UID = 4
local CLASS_NAME = "HTTP Activity"
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

-- Parse HAProxy timestamp to milliseconds since epoch
local function parseHAProxyTime(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    
    -- HAProxy format: [08/Dec/2023:14:30:15.123]
    local day, month, year, hour, min, sec, ms = timeStr:match("%[(%d+)/(%w+)/(%d+):(%d+):(%d+):(%d+)%.(%d+)%]")
    if not day then
        -- Try without milliseconds: [08/Dec/2023:14:30:15]
        day, month, year, hour, min, sec = timeStr:match("%[(%d+)/(%w+)/(%d+):(%d+):(%d+):(%d+)%]")
        ms = "000"
    end
    
    if day then
        local monthMap = {
            Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6,
            Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12
        }
        local monthNum = monthMap[month]
        if monthNum then
            local timestamp = os.time({
                year = tonumber(year),
                month = monthNum,
                day = tonumber(day),
                hour = tonumber(hour),
                min = tonumber(min),
                sec = tonumber(sec),
                isdst = false
            })
            return timestamp * 1000 + tonumber(ms or 0)
        end
    end
    
    return nil
end

-- Map HTTP status code to severity
local function getStatusSeverity(statusCode)
    if not statusCode then return 0 end
    local code = tonumber(statusCode)
    if not code then return 0 end
    
    if code >= 500 then return 4      -- High (5xx server errors)
    elseif code >= 400 then return 3  -- Medium (4xx client errors)
    elseif code >= 300 then return 1  -- Informational (3xx redirects)
    elseif code >= 200 then return 1  -- Informational (2xx success)
    else return 2                     -- Low (other codes)
    end
end

-- Determine activity based on HTTP method and status
local function getHttpActivity(method, statusCode)
    if not method then return {id = 1, name = "Connect"} end
    
    local methodUpper = string.upper(method)
    local code = tonumber(statusCode)
    
    -- Map common HTTP methods to OCSF activities
    if methodUpper == "GET" then
        return {id = 1, name = "Connect"}
    elseif methodUpper == "POST" then
        return {id = 2, name = "Create"}
    elseif methodUpper == "PUT" or methodUpper == "PATCH" then
        return {id = 3, name = "Update"}
    elseif methodUpper == "DELETE" then
        return {id = 4, name = "Delete"}
    else
        return {id = 99, name = "Other"}
    end
end

function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Field mappings for HAProxy logs
    local fieldMappings = {
        -- Direct mappings
        {type = "direct", source = "message", target = "message"},
        {type = "direct", source = "raw_data", target = "raw_data"},
        {type = "direct", source = "client_ip", target = "src_endpoint.ip"},
        {type = "direct", source = "client_port", target = "src_endpoint.port"},
        {type = "direct", source = "frontend_name", target = "proxy.name"},
        {type = "direct", source = "backend_name", target = "dst_endpoint.name"},
        {type = "direct", source = "server_name", target = "dst_endpoint.instance_uid"},
        {type = "direct", source = "time_request", target = "duration"},
        {type = "direct", source = "time_connect", target = "start_time"},
        {type = "direct", source = "time_response", target = "end_time"},
        {type = "direct", source = "http_status_code", target = "http_response.code"},
        {type = "direct", source = "bytes_read", target = "traffic.bytes_in"},
        {type = "direct", source = "captured_request_cookie", target = "http_request.http_headers.cookie"},
        {type = "direct", source = "captured_response_cookie", target = "http_response.http_headers.set_cookie"},
        {type = "direct", source = "termination_state", target = "status_detail"},
        {type = "direct", source = "actconn", target = "connection_info.sessions"},
        {type = "direct", source = "feconn", target = "proxy.sessions"},
        {type = "direct", source = "beconn", target = "dst_endpoint.sessions"},
        {type = "direct", source = "srvconn", target = "dst_endpoint.instance_sessions"},
        {type = "direct", source = "retries", target = "attempts"},
        {type = "direct", source = "srv_queue", target = "dst_endpoint.queue_size"},
        {type = "direct", source = "backend_queue", target = "proxy.queue_size"},
        
        -- HTTP request fields
        {type = "direct", source = "http_request", target = "http_request.url.url_string"},
        {type = "direct", source = "http_method", target = "http_request.http_method"},
        {type = "direct", source = "http_version", target = "http_request.version"},
        {type = "direct", source = "http_user_agent", target = "http_request.user_agent"},
        {type = "direct", source = "http_referer", target = "http_request.referrer"},
        
        -- Computed values
        {type = "computed", target = "class_uid", value = CLASS_UID},
        {type = "computed", target = "category_uid", value = CATEGORY_UID},
        {type = "computed", target = "class_name", value = CLASS_NAME},
        {type = "computed", target = "category_name", value = CATEGORY_NAME},
        {type = "computed", target = "metadata.product.name", value = "HAProxy"},
        {type = "computed", target = "metadata.product.vendor_name", value = "HAProxy Technologies"},
    }
    
    -- Process field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getNestedField(event, mapping.source)
            if value ~= nil then
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source] = true
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Handle timestamp conversion
    local timeField = event.timestamp or event.time_local or event.time
    if timeField then
        local parsedTime = parseHAProxyTime(timeField)
        if parsedTime then
            result.time = parsedTime
        end
        mappedPaths.timestamp = true
        mappedPaths.time_local = true
        mappedPaths.time = true
    end
    
    -- Set default time if not parsed
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Determine activity based on HTTP method and status
    local httpMethod = event.http_method or event.method
    local statusCode = event.http_status_code or event.status_code
    local activity = getHttpActivity(httpMethod, statusCode)
    result.activity_id = activity.id
    result.activity_name = activity.name
    result.type_uid = CLASS_UID * 100 + activity.id
    
    -- Set severity based on HTTP status code
    result.severity_id = getStatusSeverity(statusCode)
    
    -- Set HTTP response message based on status code
    if statusCode then
        local code = tonumber(statusCode)
        if code then
            if code == 200 then result.http_response.message = "OK"
            elseif code == 404 then result.http_response.message = "Not Found"
            elseif code == 500 then result.http_response.message = "Internal Server Error"
            elseif code == 502 then result.http_response.message = "Bad Gateway"
            elseif code == 503 then result.http_response.message = "Service Unavailable"
            end
        end
    end
    
    -- Set status based on HTTP status code
    if statusCode then
        local code = tonumber(statusCode)
        if code and code >= 200 and code < 300 then
            result.status = "Success"
            result.status_id = 1
        elseif code and code >= 400 then
            result.status = "Failure"
            result.status_id = 2
        else
            result.status = "Unknown"
            result.status_id = 0
        end
    else
        result.status = "Unknown"
        result.status_id = 0
    end
    
    -- Mark additional mapped paths
    mappedPaths.http_method = true
    mappedPaths.method = true
    mappedPaths.http_status_code = true
    mappedPaths.status_code = true
    
    -- Set observables for key network indicators
    local observables = {}
    if event.client_ip then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = event.client_ip
        })
    end
    if httpMethod then
        table.insert(observables, {
            type_id = 7,
            type = "HTTP Method",
            name = "http_request.http_method",
            value = httpMethod
        })
    end
    if statusCode then
        table.insert(observables, {
            type_id = 8,
            type = "HTTP Status Code",
            name = "http_response.code",
            value = statusCode
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values and empty tables
    result = no_nulls(result, nil)
    
    return result
end