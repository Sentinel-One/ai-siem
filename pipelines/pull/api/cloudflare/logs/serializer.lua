-- Cloudflare Logs to OCSF HTTP Activity Transformation
-- Maps Cloudflare log events to OCSF HTTP Activity class (4002)

-- Constants
local CLASS_UID = 4002
local CATEGORY_UID = 4

-- Nested field access helper
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

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Determine severity based on error codes and messages
local function getSeverityId(errorCode, errorMessage, eventCategory)
    if errorCode ~= nil and errorCode ~= "" then
        -- Error conditions - medium to high severity
        return 4
    end
    if errorMessage ~= nil and errorMessage ~= "" then
        -- Warning/error messages - medium severity
        return 3
    end
    if eventCategory and eventCategory:find("Error") then
        return 4
    end
    -- Default to informational for successful operations
    return 1
end

-- Determine activity ID based on event characteristics
local function getActivityId(event)
    local errorCode = event.errorCode
    local errorMessage = event.errorMessage
    
    if errorCode or errorMessage then
        return 2 -- HTTP Response
    end
    return 1 -- HTTP Request
end

-- Get activity name based on activity ID
local function getActivityName(activityId)
    if activityId == 1 then
        return "HTTP Request"
    elseif activityId == 2 then
        return "HTTP Response"
    end
    return "HTTP Activity"
end

-- Parse ISO timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr or timeStr == "" then
        return os.time() * 1000
    end
    
    -- Try to parse ISO 8601 format
    local year, month, day, hour, min, sec = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
        return timestamp * 1000
    end
    
    -- Fallback to current time
    return os.time() * 1000
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct field mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "errorCode", target = "status_detail"},
    {type = "direct", source = "errorMessage", target = "http_response.message"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", source2 = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.user.name"},
    
    -- Request parameters as URL components
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.path"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "http_response.headers.access_key_id"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "http_response.headers.expiration"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "http_request.headers.x-amz-id-2"},
    
    -- Resources
    {type = "direct", source = "resources.accountId", target = "resources.cloud_partition"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "CloudFlare"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Cloudflare"},
}

function processEvent(event)
    -- Input validation
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
            if value ~= nil and value ~= "" then 
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set OCSF required fields with computed values
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.activity_name = getActivityName(activityId)
    result.type_uid = CLASS_UID * 100 + activityId
    result.severity_id = getSeverityId(event.errorCode, event.errorMessage, event.eventCategory)
    
    -- Parse and set timestamp
    result.time = parseTimestamp(event.eventTime)
    
    -- Build HTTP request URL if components are available
    local hostname = getNestedField(result, "http_request.url.hostname")
    local path = getNestedField(result, "http_request.url.path")
    if hostname then
        local url = "https://" .. hostname
        if path and path ~= "" then
            url = url .. "/" .. path
        end
        setNestedField(result, "http_request.url.url_string", url)
    end
    
    -- Set HTTP method if determinable from context
    if event.requestParameters then
        setNestedField(result, "http_request.http_method", "GET") -- Default assumption for API calls
    end
    
    -- Set status code based on error presence
    if event.errorCode then
        setNestedField(result, "http_response.code", 400) -- Client error
        setNestedField(result, "status_id", 2) -- Failure
    else
        setNestedField(result, "http_response.code", 200) -- Success
        setNestedField(result, "status_id", 1) -- Success
    end
    
    -- Add observables for enrichment
    local observables = {}
    if event.sourceIPAddress then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "src_endpoint.ip",
            value = event.sourceIPAddress
        })
    end
    if getNestedField(event, "userIdentity.principalId") then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.uid", 
            value = event.userIdentity.principalId
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped fields
    mappedPaths["eventTime"] = true
    mappedPaths["requestParameters"] = true
    if event.userIdentity then
        for key, _ in pairs(event.userIdentity) do
            mappedPaths["userIdentity." .. key] = true
        end
    end
    if event.responseElements then
        for key, _ in pairs(event.responseElements) do
            mappedPaths["responseElements." .. key] = true
        end
    end
    if event.additionalEventData then
        for key, _ in pairs(event.additionalEventData) do
            mappedPaths["additionalEventData." .. key] = true
        end
    end
    if event.tlsDetails then
        for key, _ in pairs(event.tlsDetails) do
            mappedPaths["tlsDetails." .. key] = true
        end
    end
    if event.resources then
        for key, _ in pairs(event.resources) do
            mappedPaths["resources." .. key] = true
        end
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end