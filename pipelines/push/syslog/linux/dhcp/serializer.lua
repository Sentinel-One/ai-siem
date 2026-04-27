-- DHCP Logs to OCSF Authentication Class Transformation
-- Maps DHCP log events to OCSF Authentication schema (class_uid=3002)

-- OCSF Constants
local CLASS_UID = 3002
local CATEGORY_UID = 3
local CLASS_NAME = "Authentication"
local CATEGORY_NAME = "Identity & Access Management"

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

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
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

-- Determine activity based on event context
function getActivityInfo(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    local eventCategory = getNestedField(event, 'eventCategory')
    
    -- Check for authentication failure indicators
    if errorCode or errorMessage then
        return 2, "Logon", "Authentication failure"
    end
    
    -- Check for successful authentication indicators
    local credentials = getNestedField(event, 'responseElements.credentials.accessKeyId')
    if credentials then
        return 1, "Logon", "Authentication success"
    end
    
    -- Default to unknown authentication activity
    return 99, "Other", "Authentication activity"
end

-- Map severity based on error conditions
function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 3  -- Medium severity for authentication failures
    end
    
    return 1  -- Informational for successful authentications
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "eventTime", target = "start_time"},
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- User identity mappings with priority
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "resource.name"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "resource.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resource.uid"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    {type = "direct", source = "resources.accountId", target = "resource.owner"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"},
}

-- Main transformation function
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
    
    -- Set activity information
    local activity_id, activity_name, status_detail = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set time from eventTime
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        local timestamp = parseTimestamp(eventTime)
        if timestamp then
            result.time = timestamp
        end
    end
    
    -- Default time if not set
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set status information for failures
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Set product information
    setNestedField(result, "metadata.product.name", "AWS CloudTrail")
    
    -- Add observables for enrichment
    local observables = {}
    local sourceIP = getNestedField(event, 'sourceIPAddress')
    if sourceIP then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = sourceIP
        })
    end
    
    local userName = getNestedField(result, 'actor.user.name')
    if userName then
        table.insert(observables, {
            type_id = 4,
            type = "User Name", 
            name = "actor.user.name",
            value = userName
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Add raw data for forensics
    if event.message then
        result.raw_data = event.message
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Mark mapped paths for nested fields
    mappedPaths["userIdentity.principalId"] = true
    mappedPaths["userIdentity.accessKeyId"] = true
    mappedPaths["userIdentity.type"] = true
    mappedPaths["userIdentity.invokedBy"] = true
    mappedPaths["userIdentity.sessionContext.sessionIssuer.principalId"] = true
    mappedPaths["userIdentity.sessionContext.sessionIssuer.userName"] = true
    mappedPaths["requestParameters.bucketName"] = true
    mappedPaths["requestParameters.Host"] = true
    mappedPaths["requestParameters.instanceId"] = true
    mappedPaths["requestParameters.availabilityZone"] = true
    mappedPaths["responseElements.credentials.accessKeyId"] = true
    mappedPaths["responseElements.credentials.expiration"] = true
    mappedPaths["additionalEventData.x-amz-id-2"] = true
    mappedPaths["tlsDetails.cipherSuite"] = true
    mappedPaths["tlsDetails.tlsVersion"] = true
    mappedPaths["resources.accountId"] = true
    mappedPaths["resources.type"] = true
    mappedPaths["resources.ARN"] = true
    
    return result
end