-- Apache HTTP Logs to OCSF HTTP Activity transformation
-- Class UID 4002 - HTTP Activity

local CLASS_UID = 4002
local CATEGORY_UID = 4
local DEFAULT_ACTIVITY_ID = 1  -- HTTP request activity

-- HTTP status code to severity mapping
local function getHttpSeverityId(statusCode)
    if not statusCode then return 1 end -- Informational for unknown
    local code = tonumber(statusCode)
    if not code then return 1 end
    
    if code >= 500 then return 4      -- High for server errors (5xx)
    elseif code >= 400 then return 3  -- Medium for client errors (4xx)
    elseif code >= 300 then return 2  -- Low for redirects (3xx)
    elseif code >= 200 then return 1  -- Informational for success (2xx)
    else return 1 end                 -- Informational for 1xx
end

-- Extract HTTP method from message or other fields
local function extractHttpMethod(message, userAgent)
    if not message then return nil end
    local method = message:match('^([A-Z]+)%s+')
    return method
end

-- Extract HTTP status code from message
local function extractStatusCode(message)
    if not message then return nil end
    -- Look for status code pattern (typically 3-digit number)
    local code = message:match('%s+(%d%d%d)%s+')
    return code and tonumber(code) or nil
end

-- Extract URL from message
local function extractUrl(message)
    if not message then return nil end
    -- Look for URL pattern after HTTP method
    local url = message:match('^[A-Z]+%s+([^%s]+)')
    return url
end

-- Parse Apache common/combined log format timestamp
local function parseApacheTimestamp(timestamp)
    if not timestamp then return nil end
    
    -- Handle ISO format if present
    if timestamp:match('%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d') then
        local year, month, day, hour, min, sec = timestamp:match('(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)')
        if year then
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
    end
    
    -- Handle Apache log format [dd/MMM/yyyy:hh:mm:ss ±timezone]
    local day, month, year, hour, min, sec = timestamp:match('%[(%d%d)/(%w%w%w)/(%d%d%d%d):(%d%d):(%d%d):(%d%d)')
    if day then
        local months = {Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
        local monthNum = months[month]
        if monthNum then
            return os.time({
                year = tonumber(year),
                month = monthNum,
                day = tonumber(day),
                hour = tonumber(hour),
                min = tonumber(min),
                sec = tonumber(sec),
                isdst = false
            }) * 1000
        end
    end
    
    return nil
end

-- Nested field access helpers
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

-- Clean empty tables and nil values
function cleanResult(tbl)
    if type(tbl) ~= "table" then return tbl end
    local cleaned = {}
    for k, v in pairs(tbl) do
        if v ~= nil and v ~= "" then
            if type(v) == "table" then
                local cleanedSub = cleanResult(v)
                if next(cleanedSub) ~= nil then -- not empty
                    cleaned[k] = cleanedSub
                end
            else
                cleaned[k] = v
            end
        end
    end
    return cleaned
end

-- Copy unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    local unmapped = {}
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            unmapped[k] = v
        end
    end
    if next(unmapped) then
        result.unmapped = unmapped
    end
end

function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Required OCSF fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = "HTTP Activity"
    result.category_name = "Network Activity"
    
    -- Default activity for HTTP request
    local activityId = DEFAULT_ACTIVITY_ID
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.activity_name = "HTTP Request"
    
    -- Parse message for HTTP details
    local message = event.message
    mappedPaths.message = true
    
    if message then
        result.message = message
        result.raw_data = message
        
        -- Extract HTTP method
        local httpMethod = extractHttpMethod(message)
        if httpMethod then
            setNestedField(result, "http_request.http_method", httpMethod)
        end
        
        -- Extract URL
        local url = extractUrl(message)
        if url then
            setNestedField(result, "http_request.url.url_string", url)
        end
        
        -- Extract status code
        local statusCode = extractStatusCode(message)
        if statusCode then
            setNestedField(result, "http_response.code", statusCode)
            result.status_id = statusCode
            result.severity_id = getHttpSeverityId(statusCode)
        end
    end
    
    -- Source IP address
    if event.sourceIPAddress then
        setNestedField(result, "src_endpoint.ip", event.sourceIPAddress)
        mappedPaths.sourceIPAddress = true
    end
    
    -- User agent
    if event.userAgent then
        setNestedField(result, "http_request.user_agent", event.userAgent)
        mappedPaths.userAgent = true
    end
    
    -- User identity information
    local userName = getNestedField(event, "userIdentity.sessionContext.sessionIssuer.userName")
    if not userName then
        userName = getNestedField(event, "userIdentity.principalId")
    end
    if userName then
        setNestedField(result, "actor.user.name", userName)
        mappedPaths["userIdentity.sessionContext.sessionIssuer.userName"] = true
        mappedPaths["userIdentity.principalId"] = true
    end
    
    -- Set user type
    local userType = getNestedField(event, "userIdentity.type")
    if userType then
        setNestedField(result, "actor.user.type", userType)
        mappedPaths["userIdentity.type"] = true
    end
    
    -- Host information from request parameters
    local host = getNestedField(event, "requestParameters.Host")
    if host then
        setNestedField(result, "dst_endpoint.hostname", host)
        mappedPaths["requestParameters.Host"] = true
    end
    
    -- AWS region and account info
    if event.awsRegion then
        setNestedField(result, "cloud.region", event.awsRegion)
        mappedPaths.awsRegion = true
    end
    
    if event.recipientAccountId then
        setNestedField(result, "cloud.account.uid", event.recipientAccountId)
        mappedPaths.recipientAccountId = true
    end
    
    -- Error information
    if event.errorCode then
        setNestedField(result, "status_detail", event.errorCode)
        mappedPaths.errorCode = true
    end
    
    if event.errorMessage then
        if not result.message then
            result.message = event.errorMessage
        end
        setNestedField(result, "status_detail", event.errorMessage)
        mappedPaths.errorMessage = true
    end
    
    -- TLS details
    local tlsVersion = getNestedField(event, "tlsDetails.tlsVersion")
    if tlsVersion then
        setNestedField(result, "tls.version", tlsVersion)
        mappedPaths["tlsDetails.tlsVersion"] = true
    end
    
    local cipherSuite = getNestedField(event, "tlsDetails.cipherSuite")
    if cipherSuite then
        setNestedField(result, "tls.cipher", cipherSuite)
        mappedPaths["tlsDetails.cipherSuite"] = true
    end
    
    -- Event time parsing
    local eventTime = event.eventTime
    if eventTime then
        local parsedTime = parseApacheTimestamp(eventTime)
        if parsedTime then
            result.time = parsedTime
        else
            result.time = os.time() * 1000  -- fallback to current time
        end
        mappedPaths.eventTime = true
    else
        result.time = os.time() * 1000
    end
    
    -- Default severity if not set
    if not result.severity_id then
        result.severity_id = 1  -- Informational
    end
    
    -- Event ID and version
    if event.eventID then
        setNestedField(result, "metadata.correlation_uid", event.eventID)
        mappedPaths.eventID = true
    end
    
    if event.eventVersion then
        setNestedField(result, "metadata.version", event.eventVersion)
        mappedPaths.eventVersion = true
    end
    
    -- Set metadata
    setNestedField(result, "metadata.product.name", "Apache HTTP Server")
    setNestedField(result, "metadata.product.vendor_name", "Apache Software Foundation")
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean and return result
    return cleanResult(result)
end