-- Mail Server Logs to OCSF Network Activity transformation
-- Class: Network Activity (4001), Category: Network Activity (4)

-- OCSF Constants
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
function parseEventTime(timeStr)
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

-- Determine severity based on error conditions and event category
function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    local eventCategory = getNestedField(event, 'eventCategory')
    
    -- High severity for errors
    if errorCode or errorMessage then
        return 4 -- High
    end
    
    -- Medium severity for management events
    if eventCategory == "Management" then
        return 3 -- Medium
    end
    
    -- Low severity for data events
    if eventCategory == "Data" then
        return 2 -- Low
    end
    
    -- Default to informational
    return 1 -- Informational
end

-- Get activity name based on event context
function getActivityName(event)
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

-- Field mappings for mail server logs
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source endpoint mapping
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "src_endpoint.hostname"},
    
    -- Destination endpoint from request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.hostname"},
    
    -- Protocol and TLS details
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Message and raw data
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- Metadata
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- User identity information
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    
    -- Resources
    {type = "direct", source = "resources.accountId", target = "cloud.account_uid"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- Instance details
    {type = "direct", source = "requestParameters.instanceId", target = "cloud.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.expiration_time"},
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
    
    -- Set activity_id and compute type_uid
    local activity_id = 99 -- Other activity
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        activity_id = 6 -- Refuse (for errors)
    else
        activity_id = 1 -- Open (for successful connections)
    end
    
    result.activity_id = activity_id
    result.type_uid = CLASS_UID * 100 + activity_id
    result.activity_name = getActivityName(event)
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Parse and set time
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        local parsedTime = parseEventTime(eventTime)
        if parsedTime then
            result.time = parsedTime
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end
    
    -- Set status based on errors
    if errorCode then
        result.status = "Failure"
        result.status_id = 2 -- Failure
    else
        result.status = "Success"
        result.status_id = 1 -- Success
    end
    
    -- Set metadata product information
    setNestedField(result, "metadata.product.name", "Mail Server")
    setNestedField(result, "metadata.product.vendor_name", "Unknown")
    
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
    
    local principalId = getNestedField(event, 'userIdentity.principalId')
    if principalId then
        table.insert(observables, {
            type_id = 4,
            type = "User ID",
            name = "actor.user.uid",
            value = principalId
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths for unmapped field collection
    mappedPaths["eventTime"] = true
    mappedPaths["eventID"] = true
    mappedPaths["eventCategory"] = true
    mappedPaths["recipientAccountId"] = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end