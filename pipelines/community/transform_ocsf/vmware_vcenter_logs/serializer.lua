-- VMware vCenter Logs to OCSF Network Activity transformation
-- Maps vCenter log events to OCSF class_uid 4001 (Network Activity)

local CLASS_UID = 4001
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

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Convert ISO timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    
    -- Parse ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS.sssZ
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
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

-- Determine severity based on error conditions and event category
local function getSeverityId(event)
    -- Check for error conditions
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        return 4 -- High severity for errors
    end
    
    -- Check event category for severity hints
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory == "Management" then
        return 3 -- Medium severity for management events
    elseif eventCategory == "Data" then
        return 2 -- Low severity for data events
    end
    
    return 1 -- Informational by default
end

-- Get activity name based on event context
local function getActivityName(event)
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        return "Network Error: " .. errorCode
    end
    
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        return "Network " .. eventCategory .. " Activity"
    end
    
    return "Network Activity"
end

-- Field mappings for vCenter logs to OCSF Network Activity
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Network endpoints
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- Message and raw data
    {type = "direct", source = "message", target = "message"},
    
    -- Status and error information
    {type = "direct", source = "errorCode", target = "status"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "VMware vCenter"},
    {type = "computed", target = "metadata.product.vendor_name", value = "VMware"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "metadata.version"},
    
    -- Protocol information from TLS details
    {type = "direct", source = "tlsDetails.tlsVersion", target = "protocol_name"},
    
    -- User agent information
    {type = "direct", source = "userAgent", target = "unmapped.user_agent"},
    
    -- AWS specific fields (preserve in unmapped)
    {type = "direct", source = "awsRegion", target = "unmapped.aws_region"},
    {type = "direct", source = "recipientAccountId", target = "unmapped.recipient_account_id"},
    {type = "direct", source = "vpcEndpointId", target = "unmapped.vpc_endpoint_id"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "unmapped.bucket_name"},
    {type = "direct", source = "requestParameters.instanceId", target = "unmapped.instance_id"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "unmapped.availability_zone"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "unmapped.cipher_suite"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "unmapped.amz_id_2"},
}

function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Apply field mappings
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
    
    -- Set activity_id based on event characteristics
    local activityId = 99 -- Other by default
    if getNestedField(event, 'errorCode') then
        activityId = 2 -- Deny
    elseif getNestedField(event, 'eventCategory') == "Data" then
        activityId = 5 -- Traffic
    elseif getNestedField(event, 'eventCategory') == "Management" then
        activityId = 6 -- Other (management)
    end
    
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.activity_name = getActivityName(event)
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000 -- Current time as fallback
    end
    
    -- Set status_id based on error presence
    if getNestedField(event, 'errorCode') then
        result.status_id = 2 -- Failure
    else
        result.status_id = 1 -- Success
    end
    
    -- Mark additional mapped paths for nested fields
    mappedPaths["userIdentity.principalId"] = true
    mappedPaths["userIdentity.accessKeyId"] = true
    mappedPaths["userIdentity.type"] = true
    mappedPaths["userIdentity.invokedBy"] = true
    mappedPaths["userIdentity.sessionContext.sessionIssuer.principalId"] = true
    mappedPaths["userIdentity.sessionContext.sessionIssuer.userName"] = true
    mappedPaths["responseElements.credentials.accessKeyId"] = true
    mappedPaths["responseElements.credentials.expiration"] = true
    mappedPaths["resources.accountId"] = true
    mappedPaths["resources.type"] = true
    mappedPaths["resources.ARN"] = true
    
    -- Copy unmapped fields to preserve all data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Add user identity information to unmapped if present
    local userIdentity = getNestedField(event, 'userIdentity')
    if userIdentity then
        setNestedField(result, "unmapped.user_identity", userIdentity)
    end
    
    local responseElements = getNestedField(event, 'responseElements')
    if responseElements then
        setNestedField(result, "unmapped.response_elements", responseElements)
    end
    
    local resources = getNestedField(event, 'resources')
    if resources then
        setNestedField(result, "unmapped.resources", resources)
    end
    
    return result
end