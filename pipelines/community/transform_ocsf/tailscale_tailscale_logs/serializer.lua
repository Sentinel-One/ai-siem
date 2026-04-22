-- Tailscale Network Activity OCSF transformation script
-- Maps Tailscale network logs to OCSF Network Activity class (4001)

-- OCSF constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Map severity based on event category or error conditions
function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    local eventCategory = getNestedField(event, 'eventCategory')
    
    -- High severity for errors
    if errorCode or errorMessage then
        return 4 -- High
    end
    
    -- Medium for security-related categories
    if eventCategory and (
        string.find(string.lower(eventCategory), "security") or
        string.find(string.lower(eventCategory), "auth") or
        string.find(string.lower(eventCategory), "access")
    ) then
        return 3 -- Medium
    end
    
    -- Default to informational
    return 1 -- Informational
end

-- Determine activity based on event content
function getActivityInfo(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    local eventCategory = getNestedField(event, 'eventCategory')
    local userAgent = getNestedField(event, 'userAgent')
    local requestParams = getNestedField(event, 'requestParameters')
    
    -- Connection attempt with error
    if errorCode or errorMessage then
        return 5, "Connection Failed" -- Connection failure activity
    end
    
    -- API/service access
    if requestParams or userAgent then
        return 1, "Connection Established" -- Connection established
    end
    
    -- Default network traffic
    return 99, eventCategory or "Network Activity"
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct field mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "metadata.product.name"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.provider"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.uid"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Request/response details
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resources[1].uid"},
    {type = "direct", source = "resources.type", target = "resources[1].type"},
    {type = "direct", source = "resources.accountId", target = "resources[1].account_uid"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.vendor_name", value = "Tailscale"},
}

-- Main transformation function
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
    
    -- Set activity information
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set status based on error conditions
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    if errorCode or errorMessage then
        result.status = "Failure"
        result.status_id = 2 -- Failure
    else
        result.status = "Success"
        result.status_id = 1 -- Success
    end
    
    -- Set protocol information if available
    if getNestedField(event, 'tlsDetails.tlsVersion') then
        result.protocol_name = "HTTPS"
    end
    
    -- Create observables for key network indicators
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
    
    local hostname = getNestedField(event, 'requestParameters.Host')
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
    
    -- Add raw data for forensics
    result.raw_data = event
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end