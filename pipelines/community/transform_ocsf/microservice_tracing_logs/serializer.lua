-- Constants for OCSF Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Helper functions for nested field access
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

-- Parse ISO timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        return os.time({
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        }) * 1000
    end
    return nil
end

-- Determine severity based on error conditions
local function getSeverityId(event)
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        return 4  -- High severity for errors
    end
    local eventCategory = getValue(event, 'eventCategory', '')
    if eventCategory == 'Data' then
        return 2  -- Low severity for data events
    elseif eventCategory == 'Management' then
        return 3  -- Medium severity for management events
    end
    return 1  -- Informational by default
end

-- Determine activity name based on event details
local function getActivityName(event)
    local eventCategory = getValue(event, 'eventCategory', '')
    local errorCode = getNestedField(event, 'errorCode')
    local bucketName = getNestedField(event, 'requestParameters.bucketName')
    local instanceId = getNestedField(event, 'requestParameters.instanceId')
    
    if errorCode then
        return "Network Error: " .. errorCode
    elseif bucketName then
        return "S3 Network Activity"
    elseif instanceId then
        return "EC2 Network Activity"
    elseif eventCategory ~= '' then
        return eventCategory .. " Network Activity"
    else
        return "Unknown Network Activity"
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- Basic event fields
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- Source endpoint information
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "src_endpoint.hostname"},
    
    -- User identity information
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Request/Response details
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "dst_endpoint.zone"},
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.expiration_time"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Additional metadata
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "vpcEndpointId", target = "network_endpoint.vpc_uid"},
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- Resources information
    {type = "direct", source = "resources.accountId", target = "resource.account_uid"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    {type = "direct", source = "resources.ARN", target = "resource.uid"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "AWS CloudTrail"},
    {type = "computed", target = "metadata.product.vendor_name", value = "AWS"},
}

-- Main processing function
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

    -- Set activity_id based on event category
    local eventCategory = getValue(event, 'eventCategory', '')
    local activityId = 99  -- Other by default
    if eventCategory == 'Data' then
        activityId = 5  -- Traffic
    elseif eventCategory == 'Management' then
        activityId = 1  -- Create
    end
    result.activity_id = activityId

    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + activityId

    -- Set severity
    result.severity_id = getSeverityId(event)

    -- Set activity name
    result.activity_name = getActivityName(event)

    -- Parse timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime) or (os.time() * 1000)
    else
        result.time = os.time() * 1000
    end

    -- Set status based on error conditions
    if getNestedField(event, 'errorCode') then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end

    -- Add protocol information if TLS details are present
    if getNestedField(event, 'tlsDetails.tlsVersion') then
        result.protocol_name = "HTTPS"
    else
        result.protocol_name = "HTTP"
    end

    -- Set timezone offset (assume UTC for AWS events)
    result.timezone_offset = 0

    -- Mark additional mapped paths for unmapped field collection
    local additionalMapped = {
        'eventCategory', 'eventTime', 'class_uid', 'category_uid'
    }
    for _, path in ipairs(additionalMapped) do
        mappedPaths[path] = true
    end

    -- Collect unmapped fields
    copyUnmappedFields(event, mappedPaths, result)

    return result
end