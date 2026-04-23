-- Azure Logs to OCSF Network Activity transformation
-- Maps Azure log events to OCSF class_uid 4001 (Network Activity)

-- OCSF constants
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

-- Collect unmapped fields to preserve data
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timestamp)
    if not timestamp or type(timestamp) ~= "string" then return nil end
    local year, month, day, hour, min, sec = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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

-- Map severity based on event context
function getSeverityId(event)
    local errorCode = event.errorCode
    local errorMessage = event.errorMessage
    
    if errorCode or errorMessage then
        return 4  -- High for errors
    end
    
    -- Check for security-related events
    local eventCategory = event.eventCategory
    if eventCategory and string.lower(eventCategory) == "security" then
        return 3  -- Medium for security events
    end
    
    return 1  -- Informational as default
end

-- Determine activity based on event context
function getActivityInfo(event)
    local errorCode = event.errorCode
    local requestParams = event.requestParameters
    
    if errorCode then
        return {
            activity_id = 5,  -- Refuse
            activity_name = "Connection Refused"
        }
    elseif requestParams then
        return {
            activity_id = 1,  -- Open
            activity_name = "Network Connection"
        }
    else
        return {
            activity_id = 99,  -- Other
            activity_name = "Network Activity"
        }
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account_uid"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Host information as destination
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.resource"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- User identity information
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resources"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "Azure Logs"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Microsoft"}
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
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity information
    local activityInfo = getActivityInfo(event)
    result.activity_id = activityInfo.activity_id
    result.activity_name = activityInfo.activity_name
    
    -- Compute type_uid
    result.type_uid = CLASS_UID * 100 + result.activity_id
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set timestamp
    local eventTime = event.eventTime
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set status_id based on error presence
    if event.errorCode then
        result.status_id = 2  -- Failure
    else
        result.status_id = 1  -- Success
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
    if event["requestParameters.Host"] then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "dst_endpoint.hostname",
            value = event["requestParameters.Host"]
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths for unmapped collection
    local additionalMapped = {
        "eventTime", "tlsDetails", "requestParameters", "responseElements",
        "additionalEventData", "userIdentity", "resources"
    }
    for _, path in ipairs(additionalMapped) do
        mappedPaths[path] = true
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end