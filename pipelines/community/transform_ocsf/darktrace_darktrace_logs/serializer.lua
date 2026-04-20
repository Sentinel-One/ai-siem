-- OCSF Detection Finding transformation for Darktrace logs
-- Class: Detection Finding (2004), Category: Findings (2)

local CLASS_UID = 2004
local CATEGORY_UID = 2
local DEFAULT_ACTIVITY_ID = 1 -- Create

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

-- Severity mapping based on event characteristics
local function getSeverityId(event)
    -- Check for explicit severity indicators
    local errorCode = event.errorCode
    local errorMessage = event.errorMessage
    local eventCategory = event.eventCategory
    
    -- High severity for errors
    if errorCode and errorCode ~= "" then return 4 end
    if errorMessage and errorMessage ~= "" then return 4 end
    
    -- Medium severity for certain categories
    if eventCategory == "Management" or eventCategory == "Data" then return 3 end
    
    -- Default to informational
    return 1
end

-- Activity ID mapping based on event type
local function getActivityId(event)
    local eventCategory = event.eventCategory
    if eventCategory == "Management" then return 2 -- Update
    elseif eventCategory == "Data" then return 3 -- Delete  
    else return DEFAULT_ACTIVITY_ID end -- Create
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr or timeStr == "" then return os.time() * 1000 end
    
    -- Try ISO format parsing
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        local timestamp = os.time({
            year = tonumber(yr),
            month = tonumber(mo),
            day = tonumber(dy),
            hour = tonumber(hr),
            min = tonumber(mn),
            sec = tonumber(sc),
            isdst = false
        })
        return timestamp * 1000
    end
    
    -- Fallback to current time
    return os.time() * 1000
end

-- Field mappings configuration
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Detection Finding"},
    {type = "computed", target = "category_name", value = "Findings"},
    
    -- Message and raw data
    {type = "direct", source = "message", target = "message"},
    
    -- Metadata fields
    {type = "direct", source = "awsRegion", target = "metadata.region"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "recipientAccountId", target = "metadata.account_uid"},
    {type = "computed", target = "metadata.product.name", value = "Darktrace"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Darktrace"},
    
    -- Network/source information
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- User identity information
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    
    -- Finding information
    {type = "direct", source = "eventID", target = "finding_info.uid"},
    {type = "direct", source = "eventCategory", target = "finding_info.types"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Resource information
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "resources.name"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "resources.data.instance_id"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "resources.region"},
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
            
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if value == nil and mapping.source2 then
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
    
    -- Set required OCSF fields with dynamic values
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.severity_id = getSeverityId(event)
    
    -- Set timestamp
    result.time = parseTimestamp(event.eventTime)
    
    -- Set activity name based on event
    local activityName = "Detection"
    if event.eventCategory then
        activityName = event.eventCategory .. " Detection"
    end
    result.activity_name = activityName
    
    -- Set finding info title (required field)
    local findingTitle = "Darktrace Detection"
    if event.errorMessage then
        findingTitle = "Error: " .. event.errorMessage
    elseif event.eventCategory then
        findingTitle = event.eventCategory .. " Event"
    end
    setNestedField(result, "finding_info.title", findingTitle)
    
    -- Set finding description
    local findingDesc = "Darktrace security detection event"
    if event.message then
        findingDesc = event.message
    elseif event.errorMessage then
        findingDesc = event.errorMessage
    end
    setNestedField(result, "finding_info.desc", findingDesc)
    
    -- Set finding creation time to event time
    setNestedField(result, "finding_info.created_time", result.time)
    
    -- Set status based on errors
    if event.errorCode or event.errorMessage then
        result.status = "Failure"
        result.status_id = 2
        if event.errorMessage then
            result.status_detail = event.errorMessage
        end
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Add observables for key indicators
    local observables = {}
    if event.sourceIPAddress then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "source_ip",
            value = event.sourceIPAddress
        })
    end
    if getNestedField(event, "userIdentity.principalId") then
        table.insert(observables, {
            type_id = 4,
            type = "User",
            name = "principal_id", 
            value = getNestedField(event, "userIdentity.principalId")
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark mapped paths for unmapped field collection
    mappedPaths["eventTime"] = true
    mappedPaths["errorCode"] = true
    mappedPaths["errorMessage"] = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end