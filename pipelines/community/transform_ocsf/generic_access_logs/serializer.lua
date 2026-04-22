-- OCSF Network Activity transformation for generic access logs
local CLASS_UID = 4001
local CATEGORY_UID = 4
local DEFAULT_ACTIVITY_ID = 1  -- Traffic

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

-- Collect unmapped fields to preserve data
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
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

-- Determine severity based on error conditions and event type
function getSeverityId(event)
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        return 4  -- High severity for errors
    elseif getNestedField(event, 'eventCategory') == 'Management' then
        return 2  -- Low severity for management events
    else
        return 1  -- Informational for regular traffic
    end
end

-- Generate activity name based on event characteristics
function getActivityName(event)
    local eventCategory = getNestedField(event, 'eventCategory')
    local errorCode = getNestedField(event, 'errorCode')
    local bucketName = getNestedField(event, 'requestParameters.bucketName')
    
    if errorCode then
        return "Network Error - " .. errorCode
    elseif eventCategory then
        return "Network " .. eventCategory
    elseif bucketName then
        return "Network Access to " .. bucketName
    else
        return "Network Traffic"
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- Basic OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Network endpoints
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- Message and raw data
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- Status information
    {type = "direct", source = "errorCode", target = "status_detail"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- TLS details for protocol information
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Metadata
    {type = "direct", source = "apiVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account_uid"},
    
    -- Additional event data
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "eventVersion", target = "metadata.log_version"},
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
}

function processEvent(event)
    -- Validate input
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
    
    -- Set required OCSF fields
    result.activity_id = DEFAULT_ACTIVITY_ID
    result.type_uid = CLASS_UID * 100 + DEFAULT_ACTIVITY_ID
    result.severity_id = getSeverityId(event)
    result.activity_name = getActivityName(event)
    
    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
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
    
    -- Set metadata product information
    if not getNestedField(result, 'metadata.product') then
        setNestedField(result, 'metadata.product.name', 'Generic Access Logs')
        setNestedField(result, 'metadata.product.vendor_name', 'Unknown')
    end
    
    -- Handle user identity mapping
    local userPrincipalId = getNestedField(event, 'userIdentity.principalId')
    local userName = getNestedField(event, 'userIdentity.sessionContext.sessionIssuer.userName')
    local accessKeyId = getNestedField(event, 'userIdentity.accessKeyId')
    
    if userName then
        setNestedField(result, 'actor.user.name', userName)
        mappedPaths['userIdentity.sessionContext.sessionIssuer.userName'] = true
    elseif userPrincipalId then
        setNestedField(result, 'actor.user.uid', userPrincipalId)
        mappedPaths['userIdentity.principalId'] = true
    end
    
    if accessKeyId then
        setNestedField(result, 'actor.user.credential_uid', accessKeyId)
        mappedPaths['userIdentity.accessKeyId'] = true
    end
    
    -- Mark additional user identity fields as mapped
    mappedPaths['userIdentity.type'] = true
    mappedPaths['userIdentity.invokedBy'] = true
    mappedPaths['userIdentity.sessionContext.sessionIssuer.principalId'] = true
    
    -- Handle resources array
    local resourcesAccount = getNestedField(event, 'resources.accountId')
    local resourcesType = getNestedField(event, 'resources.type')
    local resourcesArn = getNestedField(event, 'resources.ARN')
    
    if resourcesArn then
        setNestedField(result, 'resources.uid', resourcesArn)
        mappedPaths['resources.ARN'] = true
    end
    if resourcesType then
        setNestedField(result, 'resources.type', resourcesType)
        mappedPaths['resources.type'] = true
    end
    if resourcesAccount then
        mappedPaths['resources.accountId'] = true
    end
    
    -- Handle request parameters
    local bucketName = getNestedField(event, 'requestParameters.bucketName')
    local instanceId = getNestedField(event, 'requestParameters.instanceId')
    local availabilityZone = getNestedField(event, 'requestParameters.availabilityZone')
    
    if bucketName then
        setNestedField(result, 'dst_endpoint.resource_uid', bucketName)
        mappedPaths['requestParameters.bucketName'] = true
    end
    if instanceId then
        setNestedField(result, 'cloud.instance_uid', instanceId)
        mappedPaths['requestParameters.instanceId'] = true
    end
    if availabilityZone then
        setNestedField(result, 'cloud.availability_zone', availabilityZone)
        mappedPaths['requestParameters.availabilityZone'] = true
    end
    
    -- Handle response elements
    local responseAccessKey = getNestedField(event, 'responseElements.credentials.accessKeyId')
    local responseExpiration = getNestedField(event, 'responseElements.credentials.expiration')
    
    if responseAccessKey then
        mappedPaths['responseElements.credentials.accessKeyId'] = true
    end
    if responseExpiration then
        mappedPaths['responseElements.credentials.expiration'] = true
    end
    
    -- Mark class_uid and category_uid as mapped if they exist in source
    mappedPaths['class_uid'] = true
    mappedPaths['category_uid'] = true
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end