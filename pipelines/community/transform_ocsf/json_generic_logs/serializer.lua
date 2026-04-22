-- Constants for OCSF Network Activity class
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

-- Map severity based on event characteristics
function getSeverityId(event)
    -- Check for error conditions first
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        return 4 -- High severity for errors
    end
    
    -- Check event category for severity hints
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        if eventCategory:lower():find("error") or eventCategory:lower():find("fail") then
            return 4 -- High
        elseif eventCategory:lower():find("warn") then
            return 3 -- Medium
        end
    end
    
    -- Default to informational for network activities
    return 1
end

-- Determine activity based on event characteristics
function getActivityInfo(event)
    local activity_id = 99 -- Other by default
    local activity_name = "Network Activity"
    
    -- Try to determine activity from various fields
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        activity_id = 2 -- Refuse
        activity_name = "Network Connection Refused"
    else
        activity_id = 1 -- Allow/Accept
        activity_name = "Network Connection Established"
    end
    
    return activity_id, activity_name
end

-- Field mappings for generic JSON logs to OCSF Network Activity
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "metadata.product.name"},
    {type = "direct", source = "awsRegion", target = "metadata.cloud.region"},
    {type = "direct", source = "eventID", target = "uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "vpcEndpointId", target = "connection_info.boundary"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.vendor_name", value = "Unknown"},
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
    local activity_id, activity_name = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id

    -- Set severity
    result.severity_id = getSeverityId(event)

    -- Handle timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        local timestamp = parseTimestamp(eventTime)
        if timestamp then
            result.time = timestamp
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end

    -- Handle protocol information if available
    local tlsVersion = getNestedField(event, 'tlsDetails.tlsVersion')
    if tlsVersion then
        result.protocol_name = "HTTPS"
        result.protocol_ver = tlsVersion
    end

    -- Set status based on error conditions
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    if errorCode then
        result.status_code = errorCode
        result.status = "Failure"
        result.status_id = 2 -- Failure
        if errorMessage then
            result.status_detail = errorMessage
        end
    else
        result.status = "Success"
        result.status_id = 1 -- Success
    end

    -- Add observables for enrichment
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

    -- Mark additional mapped paths
    mappedPaths["eventTime"] = true
    mappedPaths["errorCode"] = true
    mappedPaths["errorMessage"] = true

    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean up nil values and empty tables
    result = no_nulls(result, nil)

    return result
end