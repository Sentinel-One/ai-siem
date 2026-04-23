-- OCSF Detection Finding transformation for spam detection logs
-- Class: Detection Finding (2004), Category: Findings (2)

local CLASS_UID = 2004
local CATEGORY_UID = 2

-- Nested field access
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

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
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

-- Map severity to OCSF severity_id
function getSeverityId(event)
    -- Check for error conditions (higher severity)
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        return 4 -- High
    end
    
    -- Check event category for severity hints
    local eventCategory = event.eventCategory
    if eventCategory then
        local category = string.lower(tostring(eventCategory))
        if string.find(category, "error") or string.find(category, "fail") then
            return 4 -- High
        elseif string.find(category, "warn") then
            return 3 -- Medium
        elseif string.find(category, "info") then
            return 1 -- Informational
        end
    end
    
    -- Default to medium for spam detection findings
    return 3
end

-- Determine activity based on event characteristics
function getActivityInfo(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 2, "Update" -- Error condition detected
    end
    
    -- Default to creation of new finding
    return 1, "Create"
end

-- Field mappings for spam detection logs
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "eventID", target = "finding_info.uid"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Session context
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.issuer_uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.session.issuer"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "resource.name"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "resource.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.expiration_time"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Resources
    {type = "direct", source = "resources.accountId", target = "resource.owner"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    {type = "direct", source = "resources.ARN", target = "resource.uid"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Detection Finding"},
    {type = "computed", target = "category_name", value = "Findings"},
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
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set time from eventTime
    local eventTime = event.eventTime
    if eventTime then
        result.time = parseTimestamp(eventTime)
        mappedPaths["eventTime"] = true
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set finding information
    if not getNestedField(result, "finding_info.uid") then
        result.finding_info = result.finding_info or {}
        result.finding_info.uid = event.eventID or ("finding_" .. tostring(result.time))
    end
    
    -- Set finding title based on event characteristics
    result.finding_info = result.finding_info or {}
    if not result.finding_info.title then
        local errorCode = getNestedField(event, 'errorCode')
        local eventCategory = event.eventCategory
        if errorCode then
            result.finding_info.title = "Spam Detection Error: " .. tostring(errorCode)
        elseif eventCategory then
            result.finding_info.title = "Spam Detection Event: " .. tostring(eventCategory)
        else
            result.finding_info.title = "Spam Detection Finding"
        end
    end
    
    -- Set finding description
    if not result.finding_info.desc then
        local message = event.message
        local errorMessage = getNestedField(event, 'errorMessage')
        result.finding_info.desc = message or errorMessage or "Automated spam detection event"
    end
    
    -- Set finding types
    result.finding_info.types = {"Spam Detection", "Security"}
    
    -- Set created time to event time
    if result.time then
        result.finding_info.created_time = result.time
    end
    
    -- Set metadata
    result.metadata = result.metadata or {}
    result.metadata.product = result.metadata.product or {}
    result.metadata.product.name = "Spam Detection System"
    result.metadata.product.vendor_name = "Unknown"
    result.metadata.version = event.eventVersion or "1.0"
    
    -- Set status based on error conditions
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        result.status_id = 2 -- Failure
        result.status = "Failure"
    else
        result.status_id = 1 -- Success  
        result.status = "Success"
    end
    
    -- Set confidence (medium confidence for automated detection)
    result.confidence_id = 2 -- Medium
    
    -- Set impact based on severity
    if result.severity_id >= 4 then
        result.impact_id = 3 -- High
    elseif result.severity_id >= 3 then
        result.impact_id = 2 -- Medium
    else
        result.impact_id = 1 -- Low
    end
    
    -- Set risk level
    result.risk_level_id = result.severity_id <= 2 and 1 or (result.severity_id <= 4 and 2 or 3)
    
    -- Create observables for key indicators
    local observables = {}
    
    if event.sourceIPAddress then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = event.sourceIPAddress
        })
    end
    
    local principalId = getNestedField(event, 'userIdentity.principalId')
    if principalId then
        table.insert(observables, {
            type_id = 4,
            type = "User",
            name = "actor.user.uid", 
            value = principalId
        })
    end
    
    if event.eventID then
        table.insert(observables, {
            type_id = 20,
            type = "Other",
            name = "finding_info.uid",
            value = event.eventID
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end