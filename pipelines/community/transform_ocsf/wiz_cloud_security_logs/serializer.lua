-- Wiz Cloud Security Logs to OCSF Detection Finding transformation
-- Maps AWS CloudTrail-like events from Wiz to OCSF Detection Finding (2004)

local CLASS_UID = 2004
local CATEGORY_UID = 2

-- Field mappings configuration
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Detection Finding"},
    {type = "computed", target = "category_name", value = "Findings"},
    
    -- Finding info mappings
    {type = "direct", source = "eventID", target = "finding_info.uid"},
    {type = "direct", source = "eventCategory", target = "finding_info.title"},
    {type = "direct", source = "message", target = "finding_info.desc"},
    {type = "direct", source = "message", target = "message"},
    
    -- Metadata mappings
    {type = "computed", target = "metadata.product.name", value = "Wiz Cloud Security"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Wiz"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "metadata.version"},
    
    -- Cloud/AWS specific fields
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.uid"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "resources.name"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "resources.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.expiration_time"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Additional data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "http_request.x_amz_id_2"},
    
    -- Resources
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"}
}

-- Helper functions (production-proven)
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

function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Severity mapping based on event category and error presence
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local eventCategory = getNestedField(event, 'eventCategory')
    
    if errorCode then
        return 4  -- High severity for errors
    elseif eventCategory then
        local category = string.lower(tostring(eventCategory))
        if string.find(category, 'data') or string.find(category, 'management') then
            return 3  -- Medium for data/management events
        elseif string.find(category, 'insight') then
            return 1  -- Informational for insights
        else
            return 2  -- Low for other categories
        end
    end
    return 0  -- Unknown
end

-- Activity ID mapping based on event category
local function getActivityId(event)
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        local category = string.lower(tostring(eventCategory))
        if string.find(category, 'data') then
            return 1  -- Create
        elseif string.find(category, 'management') then
            return 2  -- Update
        else
            return 99  -- Other
        end
    end
    return 99  -- Other/Unknown
end

-- Main transformation function
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
    
    -- Set activity_id and type_uid
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set activity name
    local eventCategory = getNestedField(event, 'eventCategory')
    result.activity_name = eventCategory and ("Wiz " .. tostring(eventCategory)) or "Wiz Security Event"
    
    -- Handle time conversion
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        -- Parse ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
        local year, month, day, hour, min, sec = eventTime:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        if year then
            result.time = os.time({
                year = tonumber(year),
                month = tonumber(month),
                day = tonumber(day),
                hour = tonumber(hour),
                min = tonumber(min),
                sec = tonumber(sec),
                isdst = false
            }) * 1000
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end
    
    -- Set finding_info defaults if not present
    if not result.finding_info then
        result.finding_info = {}
    end
    if not result.finding_info.uid then
        result.finding_info.uid = getNestedField(event, 'eventID') or ("wiz_" .. tostring(result.time))
    end
    if not result.finding_info.title then
        result.finding_info.title = eventCategory or "Wiz Security Finding"
    end
    
    -- Set status based on error presence
    local errorCode = getNestedField(event, 'errorCode')
    if errorCode then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Create observables for key indicators
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
    
    local principalId = getNestedField(event, 'userIdentity.principalId')
    if principalId then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.uid",
            value = principalId
        })
    end
    
    local bucketName = getNestedField(event, 'requestParameters.bucketName')
    if bucketName then
        table.insert(observables, {
            type_id = 10,
            type = "Resource Name",
            name = "resources.name",
            value = bucketName
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end