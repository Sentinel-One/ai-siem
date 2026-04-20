-- Helper functions for nested field access and table operations
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
    local value = tbl[key]
    return value ~= nil and value or default
end

function no_nulls(d, rn)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = rn
            elseif type(v) == "table" then no_nulls(v, rn) end
        end
    end
    return d
end

function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Constants for OCSF Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Severity mapping function
local function getSeverityId(errorCode, errorMessage)
    if errorCode ~= nil and errorCode ~= "" then
        return 4  -- High severity for errors
    elseif errorMessage ~= nil and errorMessage ~= "" then
        return 3  -- Medium severity for messages with errors
    else
        return 1  -- Informational for normal activity
    end
end

-- Activity detection based on event content
local function getActivityId(event)
    local errorCode = event.errorCode
    local errorMessage = event.errorMessage
    
    if errorCode ~= nil and errorCode ~= "" then
        return 2  -- Deny activity for errors
    elseif event.eventCategory == "Management" then
        return 5  -- Create activity for management events
    else
        return 1  -- Allow activity for general network traffic
    end
end

-- Parse ISO timestamp to milliseconds since epoch
local function parseTime(timeStr)
    if not timeStr then return nil end
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

-- Field mapping configuration
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Direct field mappings
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "errorCode", target = "status"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "vpcEndpointId", target = "connection_info.boundary"},
    {type = "direct", source = "apiVersion", target = "metadata.version"},
    
    -- Nested field mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.session.issuer"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "dst_endpoint.zone"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "resources.ARN", target = "resource.uid"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    {type = "direct", source = "resources.accountId", target = "resource.owner.uid"},
}

function processEvent(event)
    if type(event) ~= "table" then return nil end

    local result = {}
    local mappedPaths = {}

    -- Process field mappings
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

    -- Set activity-specific fields
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.severity_id = getSeverityId(event.errorCode, event.errorMessage)

    -- Set activity name based on activity
    if activityId == 1 then
        result.activity_name = "Allow"
    elseif activityId == 2 then
        result.activity_name = "Deny"
    elseif activityId == 5 then
        result.activity_name = "Create"
    else
        result.activity_name = "Unknown"
    end

    -- Parse and set time
    local eventTime = parseTime(event.eventTime)
    result.time = eventTime or (os.time() * 1000)

    -- Set metadata
    setNestedField(result, "metadata.product.name", "SQL Database")
    setNestedField(result, "metadata.product.vendor_name", "Unknown")

    -- Set protocol if TLS details present
    if getNestedField(event, "tlsDetails.tlsVersion") then
        result.protocol_name = "HTTPS"
    end

    -- Set status_id based on error presence
    if event.errorCode or event.errorMessage then
        result.status_id = 2  -- Failure
    else
        result.status_id = 1  -- Success
    end

    -- Mark additional mapped paths for unmapped field collection
    local additionalMappedPaths = {
        "eventTime", "eventCategory", "eventVersion", "additionalEventData"
    }
    for _, path in ipairs(additionalMappedPaths) do
        mappedPaths[path] = true
    end

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean up nil values
    result = no_nulls(result, nil)

    return result
end