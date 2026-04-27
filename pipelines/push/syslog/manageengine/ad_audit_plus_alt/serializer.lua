-- ManageEngine AD Audit Plus transformation to OCSF Authentication class
-- Class UID: 3002 (Authentication), Category UID: 3 (Identity & Access Management)

local CLASS_UID = 3002
local CATEGORY_UID = 3

-- Helper functions for safe field access
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

-- Parse ISO timestamp to milliseconds since epoch
function parseEventTime(timeStr)
    if not timeStr then return nil end
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

-- Map AWS event categories to OCSF activity IDs
function getActivityId(eventCategory)
    local activityMap = {
        ["Data"] = 1,           -- Logon
        ["Management"] = 2,     -- Logoff
        ["Insight"] = 99        -- Other
    }
    return activityMap[eventCategory] or 99
end

-- Map error codes to severity
function getSeverityId(errorCode, errorMessage)
    if errorCode then
        -- Authentication failures are high severity
        if string.find(errorCode:lower(), "access") or 
           string.find(errorCode:lower(), "denied") or
           string.find(errorCode:lower(), "unauthorized") then
            return 4 -- High
        end
        return 3 -- Medium for other errors
    end
    if errorMessage then
        return 2 -- Low for events with error messages
    end
    return 1 -- Informational for normal events
end

-- Get activity name based on event details
function getActivityName(event)
    local errorCode = getNestedField(event, "errorCode")
    local eventCategory = event.eventCategory
    
    if errorCode then
        return "Authentication Failed"
    elseif eventCategory == "Data" then
        return "Data Access Authentication"
    elseif eventCategory == "Management" then
        return "Management Authentication"
    else
        return "Authentication Activity"
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct field mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "src_endpoint.user_agent"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.name"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "auth_protocol_id"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "expiration_time"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Authentication"},
    {type = "computed", target = "category_name", value = "Identity & Access Management"},
    {type = "computed", target = "metadata.product.name", value = "ManageEngine AD Audit Plus"},
    {type = "computed", target = "metadata.product.vendor_name", value = "ManageEngine"}
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
    
    -- Set OCSF required fields with dynamic values
    local activityId = getActivityId(event.eventCategory)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.severity_id = getSeverityId(getNestedField(event, "errorCode"), getNestedField(event, "errorMessage"))
    result.activity_name = getActivityName(event)
    
    -- Set authentication status
    if getNestedField(event, "errorCode") then
        result.status_id = 2  -- Failure
        result.status = "Failure"
    else
        result.status_id = 1  -- Success
        result.status = "Success"
    end
    
    -- Parse and set event time
    local eventTime = parseEventTime(event.eventTime)
    if eventTime then
        result.time = eventTime
    else
        result.time = os.time() * 1000  -- Current time as fallback
    end
    
    -- Mark additional mapped paths
    mappedPaths["eventTime"] = true
    mappedPaths["eventCategory"] = true
    
    -- Handle resources array
    if event.resources and type(event.resources) == "table" then
        for i, resource in ipairs(event.resources) do
            if resource.accountId then
                setNestedField(result, "resources." .. i .. ".account_uid", resource.accountId)
            end
            if resource.type then
                setNestedField(result, "resources." .. i .. ".type", resource.type)
            end
            if resource.ARN then
                setNestedField(result, "resources." .. i .. ".uid", resource.ARN)
            end
        end
        mappedPaths["resources"] = true
    end
    
    -- Set raw_data if original event exists
    if event then
        result.raw_data = event
    end
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end