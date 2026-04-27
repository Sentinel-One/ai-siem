-- Okta Logs to OCSF Authentication transformation
-- Maps Okta authentication events to OCSF class 3002

-- OCSF constants
local CLASS_UID = 3002
local CATEGORY_UID = 3
local CLASS_NAME = "Authentication"
local CATEGORY_NAME = "Identity & Access Management"

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

-- Map error codes/messages to severity
function getSeverityId(errorCode, errorMessage)
    if errorCode then
        -- Authentication failures are typically medium severity
        if string.find(string.lower(errorCode), "access") or 
           string.find(string.lower(errorCode), "denied") or
           string.find(string.lower(errorCode), "unauthorized") then
            return 3 -- Medium
        end
        return 2 -- Low for other errors
    end
    if errorMessage then
        local lowerMsg = string.lower(errorMessage)
        if string.find(lowerMsg, "fail") or string.find(lowerMsg, "denied") then
            return 3 -- Medium
        end
    end
    return 1 -- Informational for successful events
end

-- Determine activity based on event content
function getActivityInfo(event)
    local errorCode = event.errorCode
    local errorMessage = event.errorMessage
    
    if errorCode or errorMessage then
        return 2, "Logon" -- Failed authentication
    else
        return 1, "Logon" -- Successful authentication
    end
end

-- Parse ISO timestamp to milliseconds
function parseTimestamp(timeStr)
    if not timeStr then return nil end
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

-- Field mappings configuration
local fieldMappings = {
    -- Direct field mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "src_endpoint.user_agent"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- User identity mappings with priority fallback
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    
    -- Request/response parameters
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "auth_protocol_id"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resource.uid"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    {type = "direct", source = "resources.accountId", target = "resource.owner.account.uid"},
    
    -- Static/computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.vendor_name", value = "Okta"},
    {type = "computed", target = "metadata.product.name", value = "Okta Logs"}
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
    
    -- Set severity based on error information
    result.severity_id = getSeverityId(event.errorCode, event.errorMessage)
    
    -- Set status information
    if event.errorCode or event.errorMessage then
        result.status = "Failure"
        result.status_id = 2
        if event.errorMessage then
            result.status_detail = event.errorMessage
        end
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Parse timestamp
    local eventTime = parseTimestamp(event.eventTime)
    if eventTime then
        result.time = eventTime
    else
        result.time = os.time() * 1000
    end
    
    -- Set enrichment data
    local enrichments = {}
    if event.sourceIPAddress then
        table.insert(enrichments, {
            name = "src_endpoint.ip",
            type = "IP Address",
            value = event.sourceIPAddress
        })
    end
    if getNestedField(event, "userIdentity.sessionContext.sessionIssuer.userName") then
        table.insert(enrichments, {
            name = "actor.user.name",
            type = "User Name", 
            value = getNestedField(event, "userIdentity.sessionContext.sessionIssuer.userName")
        })
    end
    if #enrichments > 0 then
        result.enrichments = enrichments
    end
    
    -- Mark additional mapped paths for unmapped collection
    local additionalMapped = {
        "eventTime", "errorCode", "errorMessage", "eventCategory"
    }
    for _, path in ipairs(additionalMapped) do
        mappedPaths[path] = true
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end