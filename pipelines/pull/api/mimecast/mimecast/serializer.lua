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

-- Activity mapping based on event types
local function getActivityInfo(eventCategory)
    local activityMap = {
        ["Data"] = {id = 1, name = "Traffic"},
        ["Management"] = {id = 2, name = "Connection"},
        ["Insight"] = {id = 3, name = "Quality"},
        ["CloudTrail"] = {id = 1, name = "Traffic"}
    }
    return activityMap[eventCategory] or {id = 99, name = "Other"}
end

-- Severity mapping
local function getSeverityId(errorCode, eventCategory)
    if errorCode then
        -- Error events are higher severity
        if eventCategory == "Management" then return 4 end -- High
        return 3 -- Medium
    end
    return 1 -- Informational for normal events
end

-- Convert ISO timestamp to milliseconds since epoch
local function parseEventTime(timeStr)
    if not timeStr or type(timeStr) ~= "string" then
        return os.time() * 1000 -- Default to current time
    end
    
    -- Parse ISO format: 2023-01-01T12:00:00Z or 2023-01-01T12:00:00.123Z
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

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.zone"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Nested mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.issuer.uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.session.issuer.name"},
    
    -- Request/Response parameters
    {type = "direct", source = "requestParameters.bucketName", target = "dst_endpoint.name"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.availability_zone"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Resources
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "Mimecast"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Mimecast"}
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
    
    -- Set activity information based on event category
    local eventCategory = getValue(event, "eventCategory", "Unknown")
    local activityInfo = getActivityInfo(eventCategory)
    result.activity_id = activityInfo.id
    result.activity_name = activityInfo.name
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + activityInfo.id
    
    -- Set severity based on error conditions
    local errorCode = getValue(event, "errorCode", nil)
    local severityId = getSeverityId(errorCode, eventCategory)
    result.severity_id = severityId
    
    -- Set time from eventTime
    local eventTime = getValue(event, "eventTime", nil)
    result.time = parseEventTime(eventTime)
    
    -- Set status information
    if errorCode then
        setNestedField(result, "status", "Failure")
        setNestedField(result, "status_id", 2) -- Failure
        setNestedField(result, "status_code", errorCode)
    else
        setNestedField(result, "status", "Success")
        setNestedField(result, "status_id", 1) -- Success
    end
    
    -- Create observables for key network indicators
    local observables = {}
    local sourceIP = getValue(event, "sourceIPAddress", nil)
    if sourceIP then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = sourceIP
        })
    end
    
    local hostname = getNestedField(event, "requestParameters.Host")
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
    
    -- Mark mapped paths for unmapped field collection
    mappedPaths["eventCategory"] = true
    mappedPaths["errorCode"] = true
    mappedPaths["eventTime"] = true
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values
    result = no_nulls(result, nil)
    
    return result
end