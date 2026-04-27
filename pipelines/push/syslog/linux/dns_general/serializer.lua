-- DNS Activity OCSF Transformation Script
-- Class UID: 4003 (DNS Activity), Category UID: 4 (Network Activity)

local CLASS_UID = 4003
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

-- Flatten nested table to dot-notation keys
function flattenObject(tbl, prefix, result)
    result = result or {}; prefix = prefix or ""
    for k, v in pairs(tbl) do
        local keyPath = prefix ~= "" and (prefix .. "." .. tostring(k)) or tostring(k)
        if type(v) == "table" then flattenObject(v, keyPath, result)
        else result[keyPath] = v end
    end
    return result
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
local function parseTimestamp(timestamp)
    if not timestamp or type(timestamp) ~= "string" then
        return os.time() * 1000
    end
    
    local yr, mo, dy, hr, mn, sc = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
    
    return os.time() * 1000
end

-- Get severity ID based on event category or error presence
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 4  -- High severity for errors
    end
    
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        if eventCategory == "Management" then
            return 3  -- Medium severity for management events
        elseif eventCategory == "Data" then
            return 2  -- Low severity for data events
        end
    end
    
    return 1  -- Informational by default
end

-- Determine activity based on event context
local function getActivityInfo(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 2, "Query"  -- DNS Query with error
    end
    
    -- Default to DNS query activity
    return 1, "Query"
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct field mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "metadata.product.name"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "awsRegion", target = "metadata.product.feature.name"},
    {type = "direct", source = "recipientAccountId", target = "metadata.tenant_uid"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "vpcEndpointId", target = "src_endpoint.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.uid"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Request parameters as DNS query context
    {type = "direct", source = "requestParameters.bucketName", target = "query.hostname"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "dst_endpoint.availability_zone"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.expiration_time"},
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "response.request_uid"},
    
    -- Resource information
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- Fixed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "DNS Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"}
}

function processEvent(event)
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
    
    -- Compute type_uid
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set time from eventTime
    local eventTime = getNestedField(event, 'eventTime')
    result.time = parseTimestamp(eventTime)
    
    -- Set status information based on errors
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    if errorCode or errorMessage then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Add DNS-specific query information if hostname is available
    local hostname = getNestedField(result, 'query.hostname')
    if hostname then
        if not result.query then result.query = {} end
        if not result.query.type then result.query.type = "A" end  -- Default to A record
        if not result.query.class then result.query.class = "IN" end  -- Default to Internet class
    end
    
    -- Set default rcode for DNS responses
    if errorCode then
        result.rcode = errorCode
        result.rcode_id = 2  -- SERVFAIL equivalent
    else
        result.rcode = "NOERROR"
        result.rcode_id = 0
    end
    
    -- Add observables for enrichment
    local observables = {}
    local srcIp = getNestedField(result, 'src_endpoint.ip')
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local queryHostname = getNestedField(result, 'query.hostname')
    if queryHostname then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "query.hostname", 
            value = queryHostname
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths
    mappedPaths['eventTime'] = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values
    result = no_nulls(result, nil)
    
    return result
end