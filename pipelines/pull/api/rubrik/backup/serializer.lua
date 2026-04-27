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

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Map severity based on error conditions and event category
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    local eventCategory = getNestedField(event, 'eventCategory')
    
    -- Critical errors
    if errorCode and (string.find(errorCode, "AccessDenied") or 
                      string.find(errorCode, "Unauthorized") or 
                      string.find(errorCode, "SecurityToken")) then
        return 5  -- Critical
    end
    
    -- High severity for any error
    if errorCode or errorMessage then
        return 4  -- High
    end
    
    -- Medium for management events
    if eventCategory == "Management" then
        return 3  -- Medium
    end
    
    -- Low for data events
    if eventCategory == "Data" then
        return 2  -- Low
    end
    
    return 1  -- Informational (default)
end

-- Get activity name based on event details
local function getActivityName(event)
    local errorCode = getNestedField(event, 'errorCode')
    local eventCategory = getNestedField(event, 'eventCategory')
    local bucketName = getNestedField(event, 'requestParameters.bucketName')
    local instanceId = getNestedField(event, 'requestParameters.instanceId')
    
    if errorCode then
        return "Error: " .. errorCode
    elseif bucketName then
        return "S3 Bucket Access"
    elseif instanceId then
        return "EC2 Instance Access"
    elseif eventCategory then
        return eventCategory .. " Activity"
    else
        return "Network Activity"
    end
end

-- Parse ISO timestamp to milliseconds
local function parseTimestamp(timeStr)
    if not timeStr then return nil end
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

local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Network endpoints
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- User identity
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    
    -- AWS specific fields
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- Request/Response details
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.bucketName", target = "resource.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "resource.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    {type = "direct", source = "resources.ARN", target = "resource.uid"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Additional data
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "vpcEndpointId", target = "network_endpoint.vpc_uid"},
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"}
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
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if value == nil or value == "" then
                value = getNestedField(event, mapping.source2)
            end
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set required OCSF fields with defaults
    result.activity_id = result.activity_id or 99
    result.type_uid = CLASS_UID * 100 + (result.activity_id or 99)
    result.severity_id = getSeverityId(event)
    result.activity_name = getActivityName(event)
    
    -- Set metadata
    setNestedField(result, "metadata.product.name", "Rubrik Backup")
    setNestedField(result, "metadata.product.vendor_name", "Rubrik")
    
    -- Parse timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    mappedPaths['eventTime'] = true
    
    -- Set status based on error conditions
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
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
    
    -- Preserve unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end