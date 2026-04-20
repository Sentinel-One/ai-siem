-- Juniper Logs to OCSF Network Activity transformation
-- Class: Network Activity (4001), Category: Network Activity (4)

local CLASS_UID = 4001
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

-- Map error codes to severity
local function getSeverityId(errorCode, eventCategory)
    if errorCode and errorCode ~= "" then
        return 4 -- High severity for errors
    elseif eventCategory then
        local category = string.lower(tostring(eventCategory))
        if string.find(category, "error") or string.find(category, "fail") then
            return 4 -- High
        elseif string.find(category, "warn") then
            return 3 -- Medium
        else
            return 1 -- Informational
        end
    end
    return 0 -- Unknown
end

-- Detect activity based on event context
local function getActivityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local requestParams = getNestedField(event, 'requestParameters')
    
    if errorCode and errorCode ~= "" then
        return 6 -- Refuse - network traffic blocked/refused
    elseif requestParams then
        return 1 -- Allow - network traffic allowed
    else
        return 99 -- Other
    end
end

-- Extract port from Host header if available
local function extractPort(hostHeader)
    if not hostHeader or hostHeader == "" then return nil end
    local _, _, port = string.find(hostHeader, ":(%d+)$")
    return port and tonumber(port) or nil
end

-- Field mappings for Juniper logs
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Network endpoints
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- Message and raw data
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "errorCode", target = "status"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "Juniper"},
    {type = "direct", source = "apiVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "metadata.cloud.region"},
    
    -- User agent and identity
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Additional context
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
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

    -- Set activity ID and type_uid
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set activity name based on activity
    if activityId == 1 then
        result.activity_name = "Allow"
    elseif activityId == 6 then
        result.activity_name = "Refuse"
    else
        result.activity_name = "Other"
    end

    -- Set severity
    result.severity_id = getSeverityId(getNestedField(event, 'errorCode'), getNestedField(event, 'eventCategory'))

    -- Handle time conversion from eventTime
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime and type(eventTime) == "string" then
        -- Parse ISO 8601 timestamp: 2023-01-01T12:00:00Z or 2023-01-01T12:00:00.000Z
        local year, month, day, hour, min, sec = eventTime:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
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
        else
            result.time = os.time() * 1000 -- Current time as fallback
        end
    else
        result.time = os.time() * 1000 -- Current time as fallback
    end

    -- Extract port from Host header if available
    local hostHeader = getNestedField(event, 'requestParameters.Host')
    if hostHeader then
        local port = extractPort(hostHeader)
        if port then
            setNestedField(result, "dst_endpoint.port", port)
        end
        mappedPaths["requestParameters.Host"] = true
    end

    -- Set status_id based on error code
    if getNestedField(event, 'errorCode') then
        result.status_id = 2 -- Failure
    else
        result.status_id = 1 -- Success
    end

    -- Add observables for network indicators
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
    
    local dstHost = getNestedField(result, 'dst_endpoint.hostname')
    if dstHost then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "dst_endpoint.hostname",
            value = dstHost
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end

    -- Collect unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean up nil values and empty tables
    result = no_nulls(result, nil)

    return result
end