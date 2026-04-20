-- Microsoft Active Directory Logs to OCSF Network Activity transformation
-- Class UID: 4001 (Network Activity), Category UID: 4 (Network Activity)

local CLASS_UID = 4001
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

-- Map error codes to severity
local function getSeverityId(errorCode, errorMessage)
    if errorCode then
        -- High severity for authentication/authorization failures
        if string.match(errorCode, "AccessDenied") or string.match(errorCode, "Forbidden") then
            return 4 -- High
        elseif string.match(errorCode, "InvalidUser") or string.match(errorCode, "AuthFailure") then
            return 4 -- High
        elseif string.match(errorCode, "Throttling") or string.match(errorCode, "ServiceUnavailable") then
            return 3 -- Medium
        elseif errorCode ~= "" then
            return 2 -- Low for other errors
        end
    end
    return 1 -- Informational for successful events
end

-- Parse ISO 8601 timestamp to milliseconds
local function parseTimestamp(timeStr)
    if not timeStr then return os.time() * 1000 end
    
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
    
    return os.time() * 1000
end

-- Field mappings table
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "eventID", target = "metadata.event_code"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "connection_info.uid"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- User identity mappings
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Resource information  
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "dst_endpoint.availability_zone"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.expiration_time"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
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

    -- Set activity based on event category and error status
    local activityId = 99 -- Unknown by default
    local activityName = "Unknown Activity"
    
    local eventCategory = event.eventCategory
    local errorCode = event.errorCode
    
    if eventCategory == "Management" then
        activityId = 1 -- Create
        activityName = "Management Activity"
    elseif eventCategory == "Data" then
        activityId = 2 -- Read
        activityName = "Data Access"
    elseif errorCode then
        activityId = 6 -- Deny
        activityName = "Access Denied"
    else
        activityId = 5 -- Allow
        activityName = "Network Allow"
    end

    -- Set OCSF required fields
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity based on error codes
    result.severity_id = getSeverityId(event.errorCode, event.errorMessage)
    
    -- Set timestamp
    result.time = parseTimestamp(event.eventTime)
    
    -- Set status based on error presence
    if event.errorCode then
        result.status = "Failure"
        result.status_id = 2 -- Failure
    else
        result.status = "Success" 
        result.status_id = 1 -- Success
    end
    
    -- Set metadata
    setNestedField(result, "metadata.product.name", "AWS CloudTrail")
    setNestedField(result, "metadata.product.vendor_name", "Amazon Web Services")
    
    -- Set raw data for debugging
    if event.message then
        result.raw_data = event.message
    end
    
    -- Create observables for key network indicators
    local observables = {}
    if event.sourceIPAddress then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "src_endpoint.ip",
            value = event.sourceIPAddress
        })
    end
    if getNestedField(event, "userIdentity.sessionContext.sessionIssuer.userName") or 
       getNestedField(event, "userIdentity.principalId") then
        local userName = getNestedField(event, "userIdentity.sessionContext.sessionIssuer.userName") or 
                        getNestedField(event, "userIdentity.principalId")
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
    
    -- Mark additional mapped paths for unmapped collection
    mappedPaths["eventTime"] = true
    mappedPaths["eventCategory"] = true
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end