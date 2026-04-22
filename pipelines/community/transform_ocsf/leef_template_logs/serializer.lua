-- LEEF Template Network Activity Parser (OCSF 4001)
-- Transforms generic LEEF-style logs to OCSF Network Activity format

local CLASS_UID = 4001
local CATEGORY_UID = 4

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

-- Convert ISO timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr or timeStr == "" then return nil end
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

-- Map severity based on error codes and event categories
local function getSeverityId(event)
    local errorCode = event.errorCode
    local eventCategory = event.eventCategory
    
    -- Critical errors
    if errorCode and (errorCode == "AccessDenied" or errorCode == "Forbidden") then
        return 4 -- High
    end
    
    -- Medium for general errors
    if errorCode then
        return 3 -- Medium
    end
    
    -- Event category based severity
    if eventCategory then
        local category = tostring(eventCategory):lower()
        if category:match("error") or category:match("fail") then
            return 3 -- Medium
        elseif category:match("warn") then
            return 2 -- Low
        elseif category:match("info") then
            return 1 -- Informational
        end
    end
    
    return 1 -- Default to Informational
end

-- Determine activity ID based on event type
local function getActivityId(event)
    local eventCategory = event.eventCategory
    if eventCategory then
        local category = tostring(eventCategory):lower()
        if category:match("data") or category:match("management") then
            return 5 -- Traffic
        end
    end
    return 99 -- Other
end

-- Field mapping configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "metadata.labels.region"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "vpcEndpointId", target = "metadata.labels.vpc_endpoint"},
    {type = "direct", source = "apiVersion", target = "metadata.labels.api_version"},
    
    -- Nested field mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.issuer"},
    
    -- Request/Response parameters
    {type = "direct", source = "requestParameters.bucketName", target = "metadata.labels.bucket_name"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "metadata.labels.instance_id"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "metadata.labels.availability_zone"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_detail"},
    {type = "direct", source = "errorMessage", target = "status_code"},
    
    -- Resource information
    {type = "direct", source = "resources.accountId", target = "cloud.account.uid"},
    {type = "direct", source = "resources.type", target = "cloud.resource.type"},
    {type = "direct", source = "resources.ARN", target = "cloud.resource.uid"},
    {type = "direct", source = "recipientAccountId", target = "dst_endpoint.uid"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "LEEF Template"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Unknown"}
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
    
    -- Set activity-specific fields
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.severity_id = getSeverityId(event)
    
    -- Set activity name based on event category or default
    local eventCategory = event.eventCategory or "Network Activity"
    result.activity_name = tostring(eventCategory)
    
    -- Handle timestamp
    local eventTime = event.eventTime
    if eventTime then
        local parsedTime = parseTimestamp(eventTime)
        if parsedTime then
            result.time = parsedTime
        end
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set status based on error information
    if event.errorCode then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"  
        result.status_id = 1
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
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths for unmapped field collection
    mappedPaths["eventTime"] = true
    mappedPaths["eventCategory"] = true
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end