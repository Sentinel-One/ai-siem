-- DNS Activity OCSF Transformation
-- Class: DNS Activity (4003), Category: Network Activity (4)

local CLASS_UID = 4003
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
    if not timeStr or type(timeStr) ~= "string" then return nil end
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
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

-- Get severity based on event category and error presence
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 4  -- High severity for errors
    end
    
    return 1  -- Informational for normal DNS activity
end

-- Field mappings for DNS Activity
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "DNS Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source IP mapping
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    
    -- Message and metadata
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "metadata.product.name"},
    {type = "direct", source = "awsRegion", target = "metadata.region"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    
    -- User identity mapping to actor
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    
    -- DNS query parameters (map from request parameters)
    {type = "direct", source = "requestParameters.Host", target = "query.hostname"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.expiration_time"},
    
    -- Error handling
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- Resource information
    {type = "direct", source = "resources.accountId", target = "metadata.tenant_uid"},
    {type = "direct", source = "resources.type", target = "metadata.resource_type"},
    {type = "direct", source = "resources.ARN", target = "metadata.resource_uid"},
    
    -- VPC and network details
    {type = "direct", source = "vpcEndpointId", target = "src_endpoint.vpc_uid"},
    {type = "direct", source = "recipientAccountId", target = "dst_endpoint.account_uid"},
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

    -- Set activity based on event category or default
    local eventCategory = getValue(event, 'eventCategory', '')
    local activityId = 99  -- Other
    local activityName = "DNS Query"
    
    if eventCategory == "Data" then
        activityId = 1  -- Query
        activityName = "DNS Query"
    elseif eventCategory == "Management" then
        activityId = 2  -- Response  
        activityName = "DNS Response"
    end
    
    result.activity_id = activityId
    result.activity_name = activityName
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set status based on error presence
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success" 
        result.status_id = 1
    end
    
    -- Set metadata product info
    if not result.metadata then result.metadata = {} end
    if not result.metadata.product then result.metadata.product = {} end
    result.metadata.product.vendor_name = "Unknown"
    if not result.metadata.product.name then
        result.metadata.product.name = "DNS Service"
    end
    
    -- Add observables for key network indicators
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
    
    local hostname = getNestedField(result, 'query.hostname')
    if hostname then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "query.hostname", 
            value = hostname
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Preserve unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end