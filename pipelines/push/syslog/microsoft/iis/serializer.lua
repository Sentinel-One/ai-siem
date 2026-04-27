-- IIS W3C Log Format to OCSF Network Activity Transformation
-- Class: Network Activity (4001), Category: Network Activity (4)

-- OCSF Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local DEFAULT_ACTIVITY_ID = 1 -- Network traffic
local DEFAULT_SEVERITY = 1    -- Informational

-- Helper Functions
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

-- Parse ISO timestamp to milliseconds
local function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
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

-- Determine severity based on error codes and response status
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 3 -- Medium for errors
    end
    
    -- Check for security-related events
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory == "Management" or eventCategory == "Data" then
        return 2 -- Low for data access
    end
    
    return 1 -- Informational by default
end

-- Get activity name based on event context
local function getActivityName(event)
    local eventCategory = getNestedField(event, 'eventCategory')
    local errorCode = getNestedField(event, 'errorCode')
    
    if errorCode then
        return "Network Error"
    elseif eventCategory then
        return "Network " .. eventCategory
    else
        return "Network Traffic"
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "activity_id", value = DEFAULT_ACTIVITY_ID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source endpoint mapping
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- User identity mapping
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.uid"},
    
    -- HTTP/Network details
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.hostname"},
    
    -- TLS information
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- AWS specific fields
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Metadata
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "metadata.product.version"},
    {type = "computed", target = "metadata.product.name", value = "AWS CloudTrail"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"},
    
    -- Raw data preservation
    {type = "direct", source = "message", target = "message"},
}

function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Process field mappings
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
    
    -- Set computed fields
    result.type_uid = CLASS_UID * 100 + DEFAULT_ACTIVITY_ID
    result.severity_id = getSeverityId(event)
    result.activity_name = getActivityName(event)
    
    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set status based on errors
    if getNestedField(event, 'errorCode') then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Create observables for key network indicators
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
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end