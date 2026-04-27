-- OCSF constants for HashiCorp HCP Vault Logs
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

-- Map error codes to severity levels
local function getSeverityId(errorCode, errorMessage, eventCategory)
    if errorCode and errorCode ~= "" then
        -- Error events get higher severity
        if errorCode:match("Denied") or errorCode:match("Forbidden") then
            return 4  -- High
        elseif errorCode:match("Unauthorized") then
            return 3  -- Medium
        else
            return 2  -- Low
        end
    end
    
    if eventCategory then
        if eventCategory:match("Management") then
            return 2  -- Low
        elseif eventCategory:match("Data") then
            return 1  -- Informational
        end
    end
    
    return 1  -- Informational (default)
end

-- Determine activity based on event properties
local function getActivityInfo(event)
    local errorCode = getValue(event, 'errorCode', '')
    local eventCategory = getValue(event, 'eventCategory', '')
    
    if errorCode and errorCode ~= "" then
        return 5, "Connect"  -- Connection attempt with error
    elseif eventCategory:match("Management") then
        return 4, "Traffic"  -- Management traffic
    elseif eventCategory:match("Data") then
        return 1, "Open"     -- Data access
    else
        return 99, "Other"   -- Unknown activity
    end
end

-- Parse ISO timestamp to milliseconds
local function parseTimestamp(timestamp)
    if not timestamp or timestamp == "" then
        return os.time() * 1000
    end
    
    -- Handle ISO 8601 format: 2023-12-01T10:30:45Z or with milliseconds
    local year, month, day, hour, min, sec, ms = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z?")
    
    if year then
        local time_sec = os.time({
            year = tonumber(year),
            month = tonumber(month), 
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec)
        })
        
        -- Add milliseconds if present
        local milliseconds = 0
        if ms and ms ~= "" then
            milliseconds = tonumber(ms:sub(1, 3)) or 0
        end
        
        return time_sec * 1000 + milliseconds
    end
    
    return os.time() * 1000
end

-- Field mappings for HashiCorp HCP Vault logs
local fieldMappings = {
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Network endpoint information
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    
    -- User/Actor information
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    
    -- Request/Response details
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.path"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- TLS information
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Metadata
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Additional metadata
    {type = "computed", target = "metadata.product.name", value = "HashiCorp HCP Vault"},
    {type = "computed", target = "metadata.product.vendor_name", value = "HashiCorp"},
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
            if (value == nil or value == "") and mapping.source2 then
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
    
    -- Set activity information
    local activity_id, activity_name = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity based on error conditions
    result.severity_id = getSeverityId(event.errorCode, event.errorMessage, event.eventCategory)
    
    -- Parse timestamp
    result.time = parseTimestamp(event.eventTime)
    
    -- Set status information
    if event.errorCode and event.errorCode ~= "" then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"  
        result.status_id = 1
    end
    
    -- Add observables for security analysis
    local observables = {}
    if event.sourceIPAddress then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = event.sourceIPAddress
        })
    end
    if getNestedField(event, "userIdentity.principalId") then
        table.insert(observables, {
            type_id = 4,
            type = "User Name", 
            name = "actor.user.name",
            value = getNestedField(event, "userIdentity.principalId")
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Handle resources array
    if event.resources and type(event.resources) == "table" then
        result.resources = {}
        for i, resource in ipairs(event.resources) do
            if type(resource) == "table" then
                local res = {}
                if resource.ARN then res.uid = resource.ARN end
                if resource.type then res.type = resource.type end
                if resource.accountId then res.account_uid = resource.accountId end
                table.insert(result.resources, res)
            end
        end
        mappedPaths["resources"] = true
    end
    
    -- Preserve raw data for forensics
    if event.message then
        result.raw_data = event.message
    end
    
    -- Copy unmapped fields to preserve all data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end