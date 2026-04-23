-- Cloudflare WAF Logs to OCSF HTTP Activity transformation
-- OCSF Class: HTTP Activity (4002), Category: Network Activity (4)

local CLASS_UID = 4002
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
function parseTimestamp(timestamp)
    if not timestamp then return nil end
    local yr, mo, dy, hr, mn, sc, ms = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)")
    if yr then
        local time_sec = os.time({
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        })
        local milliseconds = ms and tonumber(ms) or 0
        if string.len(ms or "") == 3 then
            return time_sec * 1000 + milliseconds
        else
            return time_sec * 1000
        end
    end
    return nil
end

-- Determine severity based on error conditions
function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        -- Errors are typically medium severity for HTTP activities
        return 3
    end
    
    -- Default to informational for successful HTTP activities
    return 1
end

-- Determine HTTP activity type
function getActivityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        return 2 -- HTTP Response - error response
    end
    return 1 -- HTTP Request - normal request
end

-- Field mappings for Cloudflare WAF logs
local fieldMappings = {
    -- Basic event metadata
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Network and endpoint information
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    
    -- HTTP request details
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    
    -- Actor information
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "http_response.code"},
    {type = "direct", source = "errorMessage", target = "http_response.message"},
    
    -- TLS information
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Additional metadata
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "eventCategory", target = "category_name"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "resources.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "cloud.instance.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
}

function processEvent(event)
    if type(event) ~= "table" then return nil end

    local result = {}
    local mappedPaths = {}

    -- Apply field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getNestedField(event, mapping.source)
            if value ~= nil then 
                setNestedField(result, mapping.target, value) 
            end
            mappedPaths[mapping.source] = true
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if value == nil and mapping.source2 then 
                value = getNestedField(event, mapping.source2) 
            end
            if value ~= nil then 
                setNestedField(result, mapping.target, value) 
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end

    -- Set required OCSF fields with defaults
    local function setDefault(path, val)
        if getNestedField(result, path) == nil then 
            setNestedField(result, path, val) 
        end
    end
    
    -- Activity determination
    local activityId = getActivityId(event)
    setDefault('activity_id', activityId)
    setDefault('type_uid', CLASS_UID * 100 + activityId)
    
    -- Severity determination
    local severityId = getSeverityId(event)
    setDefault('severity_id', severityId)
    
    -- Activity name based on activity type
    local activityName = "HTTP Request"
    if activityId == 2 then
        activityName = "HTTP Response"
    end
    setDefault('activity_name', activityName)

    -- Time handling - convert eventTime to milliseconds
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        local timeMs = parseTimestamp(eventTime)
        if timeMs then
            result.time = timeMs
        end
    end
    -- Fallback to current time if no valid timestamp
    if not result.time then 
        result.time = os.time() * 1000 
    end

    -- Set metadata for Cloudflare WAF
    setNestedField(result, "metadata.product.name", "WAF")
    setNestedField(result, "metadata.product.vendor_name", "Cloudflare")

    -- Create observables for key indicators
    local observables = {}
    local srcIP = getNestedField(result, 'src_endpoint.ip')
    if srcIP then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIP
        })
    end
    
    local userName = getNestedField(result, 'actor.user.name')
    if userName then
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

    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)

    return result
end