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

-- Replace userdata nil values (Observo sandbox quirk)
function no_nulls(d, rn)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = rn
            elseif type(v) == "table" then no_nulls(v, rn) end
        end
    end
    return d
end

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- OCSF constants for Network Activity
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Severity mapping function
local function getSeverityId(errorCode, errorMessage)
    -- Map based on error conditions or default to informational
    if errorCode and errorCode ~= "" then
        if errorCode:match("[Ff]ailed") or errorCode:match("[Ee]rror") then
            return 4 -- High
        elseif errorCode:match("[Dd]enied") or errorCode:match("Access") then
            return 3 -- Medium
        else
            return 2 -- Low
        end
    elseif errorMessage and errorMessage ~= "" then
        return 3 -- Medium for any error message
    end
    return 1 -- Informational for successful operations
end

-- Field mappings configuration
local fieldMappings = {
    -- Basic event information
    {type = "direct", source = "eventID", target = "metadata.correlation_uid"},
    {type = "direct", source = "eventCategory", target = "category_name"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "message", target = "message"},
    
    -- Network endpoints
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "vpcEndpointId", target = "dst_endpoint.vpc_uid"},
    
    -- User identity
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.issuer"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.session.creator.name"},
    
    -- Request/Response details
    {type = "direct", source = "requestParameters.bucketName", target = "resources.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "resources.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.expiration_time"},
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "response.request_uid"},
    
    -- TLS details (network security)
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Resource information
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- OCSF required fields (computed)
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"}
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
    
    -- Set activity information based on event category or default
    local eventCategory = event.eventCategory or "Unknown"
    local activityId = 99 -- Other
    local activityName = "Network Activity"
    
    -- Map common AWS CloudTrail events to network activities
    if eventCategory:match("Data") then
        activityId = 6 -- Traffic
        activityName = "Data Transfer"
    elseif eventCategory:match("Management") then
        activityId = 1 -- Unknown/Other
        activityName = "Management Activity"
    end
    
    setNestedField(result, "activity_id", activityId)
    setNestedField(result, "activity_name", activityName)
    
    -- Compute type_uid
    setNestedField(result, "type_uid", CLASS_UID * 100 + activityId)
    
    -- Set severity based on error conditions
    local errorCode = getNestedField(event, "errorCode")
    local errorMessage = getNestedField(event, "errorMessage")
    local severityId = getSeverityId(errorCode, errorMessage)
    setNestedField(result, "severity_id", severityId)
    
    -- Set status based on error presence
    if errorCode or errorMessage then
        setNestedField(result, "status", "Failure")
        setNestedField(result, "status_id", 0) -- Unknown/Other failure
    else
        setNestedField(result, "status", "Success")
        setNestedField(result, "status_id", 1) -- Success
    end
    
    -- Process timestamp - convert eventTime to milliseconds since epoch
    local eventTime = getNestedField(event, "eventTime")
    if eventTime then
        -- Try to parse ISO 8601 format (common in AWS CloudTrail)
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
            setNestedField(result, "time", timestamp * 1000)
        else
            -- Fallback to current time if parsing fails
            setNestedField(result, "time", os.time() * 1000)
        end
    else
        setNestedField(result, "time", os.time() * 1000)
    end
    
    -- Set metadata
    setNestedField(result, "metadata.product.name", "Zscaler")
    setNestedField(result, "metadata.product.vendor_name", "Zscaler")
    
    -- Add observables for enrichment
    local observables = {}
    local srcIp = getNestedField(result, "src_endpoint.ip")
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local dstHost = getNestedField(result, "dst_endpoint.hostname")
    if dstHost then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "dst_endpoint.hostname", 
            value = dstHost
        })
    end
    
    local userId = getNestedField(result, "actor.user.uid")
    if userId then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.uid",
            value = userId
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up userdata nulls
    no_nulls(result, nil)
    
    return result
end