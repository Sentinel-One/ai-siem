-- Log4Shell Detection Logs Parser for OCSF Detection Finding Class
-- Maps log4shell detection events to OCSF Detection Finding format

-- OCSF Constants
local CLASS_UID = 2004
local CATEGORY_UID = 2
local CLASS_NAME = "Detection Finding"
local CATEGORY_NAME = "Findings"

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

-- Severity mapping for log4shell detections
local function getSeverityId(errorCode, message)
    -- Log4shell is typically high severity
    if errorCode then return 4 end -- High
    if message and string.find(string.lower(message), "log4") then return 5 end -- Critical
    return 4 -- Default to High for log4shell detections
end

-- Activity ID mapping based on event characteristics
local function getActivityId(event)
    local errorCode = getValue(event, "errorCode", "")
    local message = getValue(event, "message", "")
    
    -- Detection Finding activities: 1=Create, 2=Update, 99=Other
    if errorCode and errorCode ~= "" then return 1 end -- Create detection
    return 99 -- Other
end

-- Field mappings for log4shell detection events
local fieldMappings = {
    -- OCSF Required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    
    -- AWS/Event metadata
    {type = "direct", source = "awsRegion", target = "metadata.product.feature.name"},
    {type = "direct", source = "eventID", target = "finding_info.uid"},
    {type = "direct", source = "eventCategory", target = "finding_info.types"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    
    -- Network/Source information
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- User identity information
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    
    -- Error/Detection details
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "message", target = "message"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "resources.name"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "resources.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "response.code"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "response.message"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- VPC and API info
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- Resource information
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
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
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity_id and compute type_uid
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity based on detection characteristics
    result.severity_id = getSeverityId(event.errorCode, event.message)
    
    -- Set activity name
    if event.errorCode then
        result.activity_name = "Log4Shell Detection - " .. event.errorCode
    elseif event.message then
        result.activity_name = "Log4Shell Detection Event"
    else
        result.activity_name = "Security Detection"
    end
    
    -- Set finding_info.title
    local title = "Log4Shell Vulnerability Detection"
    if event.errorCode then
        title = title .. " (" .. event.errorCode .. ")"
    end
    setNestedField(result, "finding_info.title", title)
    
    -- Set finding_info.desc if message available
    if event.message then
        setNestedField(result, "finding_info.desc", event.message)
    end
    
    -- Set finding_info.uid if not already set
    if not getNestedField(result, "finding_info.uid") then
        setNestedField(result, "finding_info.uid", event.eventID or "unknown")
    end
    
    -- Handle time conversion from eventTime
    local eventTime = event.eventTime
    if eventTime then
        -- Parse ISO 8601 timestamp
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
    
    -- Set default status
    if event.errorCode then
        result.status_id = 2 -- Failure
        result.status = "Failure"
    else
        result.status_id = 1 -- Success
        result.status = "Success"
    end
    
    -- Set metadata product information
    setNestedField(result, "metadata.product.name", "Log4Shell Detection System")
    setNestedField(result, "metadata.product.vendor_name", "AWS CloudTrail")
    
    -- Set confidence and impact for log4shell detection
    result.confidence_id = 3 -- High confidence for log4shell detections
    result.impact_id = 4 -- High impact
    result.risk_level_id = 4 -- High risk
    
    -- Mark mapped source fields
    for _, mapping in ipairs(fieldMappings) do
        if mapping.source then
            mappedPaths[mapping.source] = true
        end
    end
    mappedPaths["eventTime"] = true
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end