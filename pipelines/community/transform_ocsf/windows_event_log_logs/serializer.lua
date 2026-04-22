-- Windows Event Log to OCSF Network Activity transformation
-- Class: Network Activity (4001), Category: Network Activity (4)

local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Helper functions
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
function parseEventTime(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
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

-- Determine activity based on event characteristics
function getActivityInfo(event)
    local eventCategory = event.eventCategory
    local eventID = event.eventID
    local errorCode = event.errorCode
    
    -- Default activity
    local activity_id = 99 -- Other
    local activity_name = "Network Activity"
    
    -- Map based on event characteristics
    if eventCategory == "Data" then
        activity_id = 5 -- Traffic
        activity_name = "Network Traffic"
    elseif eventID then
        if eventID == "AssumeRole" or eventID == "GetSessionToken" then
            activity_id = 1 -- Open
            activity_name = "Network Connection Open"
        elseif string.find(tostring(eventID), "Connect") then
            activity_id = 1 -- Open
            activity_name = "Network Connection Open"
        elseif string.find(tostring(eventID), "Close") or string.find(tostring(eventID), "Disconnect") then
            activity_id = 2 -- Close
            activity_name = "Network Connection Close"
        else
            activity_id = 5 -- Traffic
            activity_name = "Network Traffic"
        end
    elseif errorCode then
        activity_id = 6 -- Refuse
        activity_name = "Network Connection Refused"
    end
    
    return activity_id, activity_name
end

-- Determine severity based on event characteristics
function getSeverityId(event)
    if event.errorCode or event.errorMessage then
        return 4 -- High - errors indicate potential issues
    elseif event.eventCategory == "Management" then
        return 3 -- Medium - management events
    else
        return 1 -- Informational - normal activity
    end
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "metadata.version"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resource.uid"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    {type = "direct", source = "resources.accountId", target = "resource.owner.account.uid"},
    
    -- Fixed OCSF values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "AWS CloudTrail"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"},
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
    
    -- Set activity information
    local activity_id, activity_name = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set time from eventTime
    local eventTime = parseEventTime(event.eventTime)
    result.time = eventTime or (os.time() * 1000)
    
    -- Set status based on error information
    if event.errorCode then
        result.status = "Failure"
        result.status_id = 2 -- Failure
    else
        result.status = "Success"
        result.status_id = 1 -- Success
    end
    
    -- Set protocol name if TLS details are present
    if event.tlsDetails then
        result.protocol_name = "HTTPS"
    end
    
    -- Add observables for enrichment
    local observables = {}
    if event.sourceIPAddress then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = event.sourceIPAddress
        })
    end
    if event.userIdentity and event.userIdentity.principalId then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.uid",
            value = event.userIdentity.principalId
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths
    mappedPaths.eventTime = true
    mappedPaths.eventCategory = true
    mappedPaths.eventID = true
    mappedPaths.eventVersion = true
    mappedPaths.recipientAccountId = true
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end