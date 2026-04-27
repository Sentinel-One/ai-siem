-- OCSF HTTP Activity transformation for nginx_kvlog_logs
-- Maps nginx key-value log format to OCSF HTTP Activity (class_uid=4002)

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

-- Get severity based on HTTP status code or error conditions
local function getSeverityId(event)
    -- Check for explicit error codes/messages first
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        return 4 -- High severity for explicit errors
    end
    
    -- Try to extract HTTP status from various possible fields
    local status = getNestedField(event, 'responseElements.statusCode') or 
                   getNestedField(event, 'status') or 
                   getNestedField(event, 'http_status')
    
    if status then
        local statusNum = tonumber(status)
        if statusNum then
            if statusNum >= 500 then return 4      -- High: Server errors
            elseif statusNum >= 400 then return 3  -- Medium: Client errors
            elseif statusNum >= 300 then return 1  -- Informational: Redirects
            else return 1                          -- Informational: Success
            end
        end
    end
    
    return 1 -- Default to Informational for HTTP activity
end

-- Parse ISO timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    
    -- Parse ISO 8601 format: 2023-12-01T15:30:45Z or with fractional seconds
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

-- Get activity name based on event context
local function getActivityName(event)
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        return "HTTP Error: " .. errorCode
    end
    
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        return "HTTP " .. eventCategory
    end
    
    return "HTTP Request"
end

-- Field mappings using table-driven approach
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source IP and user agent
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- User identity mappings
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.uid"},
    
    -- Request/response details
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "http_response.code"},
    {type = "direct", source = "errorMessage", target = "http_response.message"},
    
    -- Message and raw data
    {type = "direct", source = "message", target = "message"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "nginx"},
    {type = "computed", target = "metadata.product.vendor_name", value = "nginx"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    
    -- Additional context
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
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

    -- Set activity_id and activity_name
    local activityId = 1 -- Default to "HTTP Request"
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        activityId = 99 -- Other/Error
    end
    result.activity_id = activityId
    result.activity_name = getActivityName(event)
    
    -- Compute type_uid
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Parse timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Add observables for key fields
    local observables = {}
    if getNestedField(event, 'sourceIPAddress') then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "src_endpoint.ip",
            value = getNestedField(event, 'sourceIPAddress')
        })
    end
    if getNestedField(event, 'userAgent') then
        table.insert(observables, {
            type_id = 6,
            type = "User Agent",
            name = "http_request.user_agent", 
            value = getNestedField(event, 'userAgent')
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths for unmapped collection
    mappedPaths['eventTime'] = true
    mappedPaths['eventCategory'] = true
    
    -- Collect unmapped fields
    copyUnmappedFields(event, mappedPaths, result)

    return result
end