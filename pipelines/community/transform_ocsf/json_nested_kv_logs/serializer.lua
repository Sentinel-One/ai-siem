-- OCSF Network Activity transformation for json_nested_kv_logs
-- Maps various log sources to OCSF Network Activity class (4001)

local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Production helper functions
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

function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Get severity from various fields
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    -- If there are errors, treat as high severity
    if errorCode or errorMessage then
        return 4  -- High
    end
    
    -- Default to informational for network activity
    return 1  -- Informational
end

-- Determine activity based on event content
local function getActivityInfo(event)
    local eventCategory = getNestedField(event, 'eventCategory')
    local errorCode = getNestedField(event, 'errorCode')
    
    if errorCode then
        return 2, "Connection Failed"  -- Failed connection
    elseif eventCategory == "Management" then
        return 5, "Traffic"  -- Management traffic
    else
        return 1, "Connection"  -- Generic connection
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- Host/destination mappings
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.instance_uid"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"},
    {type = "computed", target = "metadata.version", value = "1.0.0"},
    
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
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
    
    -- Set activity and type information
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set status based on errors
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        result.status = "Failure"
        result.status_id = 2  -- Failure
    else
        result.status = "Success"
        result.status_id = 1  -- Success
    end
    
    -- Handle timestamp conversion
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime and type(eventTime) == "string" then
        -- Parse ISO 8601 timestamp: 2023-01-01T12:00:00Z
        local year, month, day, hour, min, sec = eventTime:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        if year then
            result.time = os.time({
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
    
    -- Default time if not set
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set protocol name if TLS details are present
    if getNestedField(event, 'tlsDetails.tlsVersion') then
        result.protocol_name = "HTTPS"
    else
        result.protocol_name = "HTTP"
    end
    
    -- Set product name based on service
    local productName = "AWS CloudTrail"
    if getNestedField(event, 'requestParameters.bucketName') then
        productName = "AWS S3"
    elseif getNestedField(event, 'requestParameters.instanceId') then
        productName = "AWS EC2"
    end
    setNestedField(result, "metadata.product.name", productName)
    
    -- Add observables for enrichment
    local observables = {}
    local srcIp = getNestedField(result, 'src_endpoint.ip')
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local hostname = getNestedField(result, 'dst_endpoint.hostname')
    if hostname then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "dst_endpoint.hostname", 
            value = hostname
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths
    mappedPaths.eventTime = true
    mappedPaths.eventCategory = true
    mappedPaths["userIdentity.sessionContext.sessionIssuer.principalId"] = true
    mappedPaths["requestParameters.instanceId"] = true
    mappedPaths["requestParameters.availabilityZone"] = true
    mappedPaths["responseElements.credentials.accessKeyId"] = true
    mappedPaths["responseElements.credentials.expiration"] = true
    mappedPaths["additionalEventData.x-amz-id-2"] = true
    mappedPaths["resources.accountId"] = true
    mappedPaths["resources.type"] = true
    mappedPaths["resources.ARN"] = true
    mappedPaths.eventVersion = true
    mappedPaths["userIdentity.invokedBy"] = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end