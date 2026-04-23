-- OCSF Network Activity transformation for jruby_application_logs
-- Maps AWS-style log events to OCSF Network Activity class (4001)

-- OCSF constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Severity mapping based on error conditions and event types
local function getSeverityId(event)
    -- Critical: TLS/security issues
    if getNestedField(event, 'tlsDetails.tlsVersion') and 
       string.find(getNestedField(event, 'tlsDetails.tlsVersion') or '', 'TLSv1%.0') then
        return 5 -- Critical for old TLS
    end
    
    -- High: Error conditions
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        return 4 -- High for errors
    end
    
    -- Medium: Authentication events
    if getNestedField(event, 'userIdentity.accessKeyId') or 
       getNestedField(event, 'responseElements.credentials.accessKeyId') then
        return 3 -- Medium for auth events
    end
    
    -- Low: Regular network activity
    if getNestedField(event, 'sourceIPAddress') then
        return 2 -- Low for network events
    end
    
    return 1 -- Informational as default
end

-- Activity detection based on event characteristics
local function getActivityInfo(event)
    local eventCategory = getNestedField(event, 'eventCategory')
    local errorCode = getNestedField(event, 'errorCode')
    local requestParams = getNestedField(event, 'requestParameters')
    
    -- Network connection attempts
    if errorCode then
        return 5, "Network Connection Failed" -- Connection failure
    end
    
    -- Data access patterns
    if requestParams and (requestParams.bucketName or requestParams.instanceId) then
        return 1, "Network Connection" -- Data access connection
    end
    
    -- Authentication flows
    if getNestedField(event, 'userIdentity.accessKeyId') then
        return 1, "Network Authentication" -- Auth connection
    end
    
    -- Default network activity
    return 1, "Network Activity" -- Generic network activity
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
    {type = "direct", source = "vpcEndpointId", target = "connection_info.uid"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Request parameters as destination info
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "dst_endpoint.zone"},
    
    -- User identity mapping
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- Resource information
    {type = "direct", source = "resources.accountId", target = "resources[0].account_uid"},
    {type = "direct", source = "resources.type", target = "resources[0].type"},
    {type = "direct", source = "resources.ARN", target = "resources[0].uid"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"},
    {type = "computed", target = "metadata.product.name", value = "AWS CloudTrail"},
    {type = "computed", target = "metadata.version", value = "1.0"},
    {type = "computed", target = "protocol_name", value = "HTTPS"}
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
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Handle status based on errors
    if getNestedField(event, 'errorCode') then
        result.status = "Failure"
        result.status_id = 2 -- Failure
    else
        result.status = "Success" 
        result.status_id = 1 -- Success
    end
    
    -- Parse timestamp - handle ISO format from eventTime
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        -- Parse ISO timestamp: 2023-12-07T10:30:45Z
        local year, month, day, hour, min, sec = eventTime:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
            result.time = timestamp * 1000 -- Convert to milliseconds
        end
    end
    
    -- Default time if not parsed
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Create observables for key network indicators
    local observables = {}
    local srcIp = getNestedField(event, 'sourceIPAddress')
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local userAgent = getNestedField(event, 'userAgent')
    if userAgent then
        table.insert(observables, {
            type_id = 7,
            type = "User Agent",
            name = "http_request.user_agent", 
            value = userAgent
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths for unmapped collection
    mappedPaths["eventTime"] = true
    mappedPaths["eventVersion"] = true
    mappedPaths["eventCategory"] = true
    
    -- Collect unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end