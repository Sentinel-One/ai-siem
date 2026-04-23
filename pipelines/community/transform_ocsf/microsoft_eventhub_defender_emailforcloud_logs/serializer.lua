-- Microsoft Event Hub Defender for Office 365 Email Logs to OCSF Detection Finding
-- Maps security events to OCSF Detection Finding (class_uid=2004)

-- OCSF constants
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

-- Convert severity to OCSF severity_id
local function getSeverityId(level)
    if level == nil then return 1 end
    local severityMap = {
        Critical = 5,
        High = 4,
        Medium = 3,
        Low = 2,
        Info = 1,
        Information = 1,
        Informational = 1,
        Error = 4,
        Warning = 3,
        Alert = 4
    }
    return severityMap[level] or 1
end

-- Get activity ID based on event category or type
local function getActivityId(eventCategory, eventName)
    if eventCategory then
        local categoryMap = {
            Management = 1,
            Data = 2,
            Insight = 3
        }
        return categoryMap[eventCategory] or 99
    end
    return 99 -- Unknown activity
end

-- Convert ISO timestamp to milliseconds since epoch
local function convertTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then
        return os.time() * 1000
    end
    
    -- Parse ISO 8601 timestamp: YYYY-MM-DDTHH:MM:SS.sssZ
    local year, month, day, hour, min, sec = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if year then
        local timestamp = os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        })
        return timestamp * 1000
    end
    
    return os.time() * 1000
end

-- Field mappings configuration
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Detection Finding"},
    {type = "computed", target = "category_name", value = "Findings"},
    
    -- Event identification
    {type = "direct", source = "eventID", target = "finding_info.uid"},
    {type = "direct", source = "message", target = "finding_info.title"},
    {type = "direct", source = "message", target = "message"},
    
    -- Time fields
    {type = "direct", source = "eventTime", target = "_eventTime"},
    
    -- User identity mapping
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    
    -- Network/source information
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- AWS specific fields
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Request details
    {type = "direct", source = "requestParameters.bucketName", target = "resources.name"},
    {type = "direct", source = "requestParameters.instanceId", target = "resources.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "Microsoft Defender for Office 365"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Microsoft"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"}
}

function processEvent(event)
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
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity_id and compute type_uid
    local activityId = getActivityId(event.eventCategory, event.eventName)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set activity name
    if event.eventCategory then
        result.activity_name = event.eventCategory .. " Activity"
    else
        result.activity_name = "Detection Finding"
    end
    
    -- Convert timestamp
    local eventTime = getNestedField(result, "_eventTime")
    if eventTime then
        result.time = convertTimestamp(eventTime)
        result._eventTime = nil -- Remove temp field
    else
        result.time = os.time() * 1000
    end
    
    -- Set severity based on error presence or event category
    local severityId = 1 -- Default to Informational
    if event.errorCode or event.errorMessage then
        severityId = 4 -- High severity for errors
    elseif event.eventCategory == "Management" then
        severityId = 2 -- Low severity for management events
    elseif event.eventCategory == "Data" then
        severityId = 3 -- Medium severity for data events
    end
    result.severity_id = severityId
    
    -- Set finding info defaults
    if not result.finding_info then result.finding_info = {} end
    if not result.finding_info.uid then
        result.finding_info.uid = event.eventID or ("finding_" .. tostring(result.time))
    end
    if not result.finding_info.title then
        result.finding_info.title = "Security Event Detected"
    end
    
    -- Set description from available fields
    local desc_parts = {}
    if event.eventCategory then
        table.insert(desc_parts, "Category: " .. event.eventCategory)
    end
    if event.errorMessage then
        table.insert(desc_parts, "Error: " .. event.errorMessage)
    end
    if event.sourceIPAddress then
        table.insert(desc_parts, "Source IP: " .. event.sourceIPAddress)
    end
    if #desc_parts > 0 then
        result.finding_info.desc = table.concat(desc_parts, "; ")
    end
    
    -- Set status based on error presence
    if event.errorCode then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end
    
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
    if getNestedField(event, "userIdentity.sessionContext.sessionIssuer.userName") then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.name",
            value = getNestedField(event, "userIdentity.sessionContext.sessionIssuer.userName")
        })
    end
    if event.eventID then
        table.insert(observables, {
            type_id = 1,
            type = "Other",
            name = "finding_info.uid",
            value = event.eventID
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Add raw data for forensics
    result.raw_data = event
    
    -- Set confidence based on data completeness
    local confidence = 0
    if event.eventID then confidence = confidence + 30 end
    if event.sourceIPAddress then confidence = confidence + 20 end
    if event.eventTime then confidence = confidence + 20 end
    if getNestedField(event, "userIdentity.principalId") then confidence = confidence + 30 end
    result.confidence_id = math.min(confidence, 100)
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end