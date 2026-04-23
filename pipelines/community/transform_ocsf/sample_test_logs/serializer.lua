-- Network Activity OCSF transformation for sample_test_logs
-- Maps AWS CloudTrail-like events to OCSF Network Activity class

-- OCSF constants
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

-- Map error severity to OCSF severity_id
local function getSeverityId(errorCode, errorMessage)
    if errorCode or errorMessage then
        return 4 -- High severity for errors
    end
    return 1 -- Informational for normal activity
end

-- Determine activity based on event characteristics
local function getActivityInfo(event)
    local eventCategory = getValue(event, 'eventCategory', '')
    local errorCode = getValue(event, 'errorCode', '')
    local userAgent = getValue(event, 'userAgent', '')
    
    if errorCode ~= '' then
        return 2, "Traffic" -- Network traffic with error
    elseif eventCategory == 'Data' then
        return 5, "Access" -- Data access
    elseif userAgent ~= '' then
        return 1, "Open" -- Network connection
    else
        return 99, "Other" -- Unknown activity
    end
end

-- Field mapping configuration
local fieldMappings = {
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "metadata.product.name"},
    {type = "direct", source = "awsRegion", target = "metadata.product.feature.name"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "metadata.product.version"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "protocol_name"},
    {type = "direct", source = "errorCode", target = "status_detail"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "vpcEndpointId", target = "dst_endpoint.uid"},
    {type = "direct", source = "recipientAccountId", target = "metadata.tenant_uid"},
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"}
}

function processEvent(event)
    -- Input validation
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
    
    -- Determine activity and set required OCSF fields
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity based on error conditions
    local errorCode = getValue(event, 'errorCode', '')
    local errorMessage = getValue(event, 'errorMessage', '')
    result.severity_id = getSeverityId(errorCode, errorMessage)
    
    -- Set status based on error conditions
    if errorCode ~= '' or errorMessage ~= '' then
        result.status = "Failure"
        result.status_id = 0 -- Failure
        if not result.status_detail then
            result.status_detail = errorCode ~= '' and errorCode or errorMessage
        end
    else
        result.status = "Success"
        result.status_id = 1 -- Success
    end
    
    -- Parse timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        local timestamp = parseTimestamp(eventTime)
        if timestamp then
            result.time = timestamp
        end
    end
    
    -- Default time if parsing failed
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set timezone offset (assume UTC for AWS events)
    result.timezone_offset = 0
    
    -- Create observables for security enrichment
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
    
    local userPrincipalId = getNestedField(event, 'userIdentity.principalId')
    if userPrincipalId then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.uid",
            value = userPrincipalId
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark mapped paths for unmapped field collection
    local additionalMappedPaths = {
        'eventTime', 'userIdentity.principalId', 'userIdentity.accessKeyId',
        'userIdentity.type', 'userIdentity.invokedBy',
        'userIdentity.sessionContext.sessionIssuer.principalId',
        'userIdentity.sessionContext.sessionIssuer.userName',
        'requestParameters.bucketName', 'requestParameters.instanceId',
        'requestParameters.availabilityZone', 'responseElements.credentials.accessKeyId',
        'responseElements.credentials.expiration', 'additionalEventData.x-amz-id-2',
        'tlsDetails.cipherSuite', 'resources.accountId', 'resources.type',
        'resources.ARN'
    }
    
    for _, path in ipairs(additionalMappedPaths) do
        mappedPaths[path] = true
    end
    
    -- Copy unmapped fields to preserve all data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end