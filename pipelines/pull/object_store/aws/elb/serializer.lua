-- AWS Elastic Load Balancer Logs to OCSF HTTP Activity (4002) transformation
-- Handles ELB access logs and maps to OCSF schema

local CLASS_UID = 4002
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

-- Parse ISO timestamp to milliseconds
function parseTimestamp(timestamp)
    if not timestamp then return nil end
    local year, month, day, hour, min, sec = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
    return nil
end

-- Determine severity based on error codes and status
function getSeverityId(errorCode, errorMessage, responseCode)
    if errorCode or errorMessage then
        return 4 -- High for errors
    end
    
    if responseCode then
        local code = tonumber(responseCode)
        if code and code >= 500 then
            return 4 -- High for server errors
        elseif code and code >= 400 then
            return 3 -- Medium for client errors
        elseif code and code >= 300 then
            return 2 -- Low for redirects
        elseif code and code >= 200 then
            return 1 -- Informational for success
        end
    end
    
    return 0 -- Unknown
end

-- Determine activity ID based on HTTP method or event type
function getActivityId(userAgent, eventCategory, method)
    -- If we can extract HTTP method from user agent or other fields
    if method then
        local upperMethod = string.upper(method)
        if upperMethod == "GET" then return 1
        elseif upperMethod == "POST" then return 2
        elseif upperMethod == "PUT" then return 3
        elseif upperMethod == "DELETE" then return 4
        elseif upperMethod == "HEAD" then return 5
        elseif upperMethod == "OPTIONS" then return 6
        end
    end
    
    -- Default to generic HTTP request
    return 99 -- Other
end

-- Field mappings for table-driven approach
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "awsRegion", target = "metadata.product.region"},
    {type = "direct", source = "eventID", target = "metadata.correlation_uid"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "errorMessage", target = "http_response.message"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "vpcEndpointId", target = "metadata.product.vpc_uid"},
    
    -- User identity mappings
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Request/Response mappings
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.path"},
    {type = "direct", source = "requestParameters.instanceId", target = "metadata.product.feature.name"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "dst_endpoint.location.region"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "http_response.content_type"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "http_response.header.expires"},
    
    -- Additional data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    
    -- Static values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "AWS Elastic Load Balancer"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"}
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

    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    local timestamp = parseTimestamp(eventTime)
    if timestamp then
        result.time = timestamp
        result.start_time = timestamp
    else
        result.time = os.time() * 1000
    end

    -- Determine activity ID and type_uid
    local httpMethod = nil -- ELB logs might not have method directly
    local activityId = getActivityId(event.userAgent, event.eventCategory, httpMethod)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId

    -- Set activity name
    if httpMethod then
        result.activity_name = httpMethod .. " Request"
    elseif event.eventCategory then
        result.activity_name = event.eventCategory
    else
        result.activity_name = "HTTP Request"
    end

    -- Set severity
    result.severity_id = getSeverityId(event.errorCode, event.errorMessage, nil)

    -- Set status based on error
    if event.errorCode or event.errorMessage then
        result.status = "Failure"
        result.status_id = 2
        result.status_detail = event.errorCode or "Unknown Error"
    else
        result.status = "Success"
        result.status_id = 1
    end

    -- Build HTTP request URL if we have components
    if getNestedField(result, "http_request.url.hostname") then
        local hostname = getNestedField(result, "http_request.url.hostname")
        local path = getNestedField(result, "http_request.url.path") or "/"
        setNestedField(result, "http_request.url.url_string", "https://" .. hostname .. path)
    end

    -- Set raw_data if message exists
    if event.message then
        result.raw_data = event.message
    end

    -- Create observables
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
            name = "actor.user.name",
            value = getNestedField(event, "userIdentity.principalId")
        })
    end
    if #observables > 0 then
        result.observables = observables
    end

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean up userdata nulls
    result = no_nulls(result, nil)

    return result
end