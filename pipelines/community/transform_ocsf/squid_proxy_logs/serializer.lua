-- Constants for OCSF HTTP Activity class
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

-- Convert ISO timestamp to milliseconds since epoch
function convertTimestamp(timeStr)
    if not timeStr or timeStr == "" then return nil end
    
    -- Try ISO format: 2024-01-01T12:00:00Z
    local year, month, day, hour, min, sec = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
function getSeverityId(event)
    local errorCode = event.errorCode
    local errorMessage = event.errorMessage
    
    -- If there are errors, set higher severity
    if errorCode or errorMessage then
        return 4 -- High severity for errors
    end
    
    -- Default to informational for normal HTTP activity
    return 1
end

-- Get activity name based on event content
function getActivityName(event)
    if event.errorCode then
        return "HTTP Error - " .. tostring(event.errorCode)
    elseif event.eventCategory then
        return "HTTP " .. tostring(event.eventCategory)
    else
        return "HTTP Request"
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source IP mapping
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    
    -- User agent mapping
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    
    -- Error mappings
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Request parameters as HTTP details
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.path"},
    
    -- AWS specific metadata
    {type = "direct", source = "awsRegion", target = "metadata.product.feature.name"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Raw message
    {type = "direct", source = "message", target = "message"},
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
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set OCSF required fields with defaults
    local function setDefault(path, val)
        if getNestedField(result, path) == nil then 
            setNestedField(result, path, val)
        end
    end
    
    setDefault('activity_id', 99) -- Other activity
    setDefault('severity_id', getSeverityId(event))
    setDefault('activity_name', getActivityName(event))
    
    -- Calculate type_uid
    local activityId = getNestedField(result, 'activity_id') or 99
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set timestamp - try eventTime first, then current time
    local eventTime = event.eventTime
    if eventTime then
        result.time = convertTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set product metadata
    setNestedField(result, "metadata.product.name", "AWS CloudTrail")
    setNestedField(result, "metadata.product.vendor_name", "Amazon Web Services")
    
    -- Set HTTP status based on error presence
    if event.errorCode then
        setNestedField(result, "http_response.code", 500) -- Server error
        setNestedField(result, "http_response.message", event.errorMessage or "Internal Server Error")
    else
        setNestedField(result, "http_response.code", 200) -- Success
        setNestedField(result, "http_response.message", "OK")
    end
    
    -- Set HTTP method (default to GET for proxy logs)
    setDefault('http_request.http_method', 'GET')
    
    -- Create observables for key fields
    local observables = {}
    if event.sourceIPAddress then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "src_endpoint.ip",
            value = event.sourceIPAddress
        })
    end
    if event.userIdentity and event.userIdentity.principalId then
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
    
    -- Track mapped paths for unmapped field collection
    mappedPaths.eventTime = true
    mappedPaths.eventID = true
    mappedPaths.eventCategory = true
    mappedPaths.recipientAccountId = true
    mappedPaths["userIdentity.invokedBy"] = true
    mappedPaths["userIdentity.sessionContext.sessionIssuer.principalId"] = true
    mappedPaths["requestParameters.instanceId"] = true
    mappedPaths["requestParameters.availabilityZone"] = true
    mappedPaths["responseElements.credentials.accessKeyId"] = true
    mappedPaths["responseElements.credentials.expiration"] = true
    mappedPaths["additionalEventData.x-amz-id-2"] = true
    mappedPaths.vpcEndpointId = true
    mappedPaths["resources.accountId"] = true
    mappedPaths["resources.type"] = true
    mappedPaths["resources.ARN"] = true
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values and empty tables
    result = no_nulls(result, nil)
    
    return result
end