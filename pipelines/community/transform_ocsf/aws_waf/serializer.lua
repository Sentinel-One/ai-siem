-- AWS WAF Latest Parser - OCSF HTTP Activity (4002)
-- Transforms AWS WAF events to OCSF HTTP Activity format

-- OCSF Constants
local CLASS_UID = 4002
local CATEGORY_UID = 4
local CLASS_NAME = "HTTP Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Severity mapping function
local function getSeverityId(errorCode, eventCategory)
    -- Default to informational for successful requests
    if errorCode == nil or errorCode == "" then
        return 1  -- Informational
    end
    
    -- Map based on error types
    local errorStr = tostring(errorCode):upper()
    if errorStr:match("4%d%d") then
        return 2  -- Low (4xx client errors)
    elseif errorStr:match("5%d%d") then
        return 4  -- High (5xx server errors)
    elseif errorStr:match("ERROR") or errorStr:match("FAIL") then
        return 3  -- Medium
    else
        return 1  -- Informational
    end
end

-- Activity ID mapping based on event characteristics
local function getActivityId(eventCategory, errorCode)
    if errorCode and errorCode ~= "" then
        return 2  -- HTTP Response Error
    else
        return 1  -- HTTP Request
    end
end

-- Field mapping configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "errorCode", target = "http_response.code"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    
    -- Nested field mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.resource"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.name", value = "AWS WAF"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"},
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
    
    -- Set activity_id and type_uid based on event characteristics
    local errorCode = getNestedField(event, "errorCode")
    local eventCategory = getNestedField(event, "eventCategory")
    local activityId = getActivityId(eventCategory, errorCode)
    
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set activity name based on activity_id
    if activityId == 1 then
        result.activity_name = "HTTP Request"
    elseif activityId == 2 then
        result.activity_name = "HTTP Response Error"
    else
        result.activity_name = "HTTP Activity"
    end
    
    -- Set severity
    result.severity_id = getSeverityId(errorCode, eventCategory)
    
    -- Handle time conversion
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        -- Try to parse ISO 8601 format
        local yr, mo, dy, hr, mn, sc = eventTime:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        if yr then
            result.time = os.time({
                year = tonumber(yr),
                month = tonumber(mo),
                day = tonumber(dy),
                hour = tonumber(hr),
                min = tonumber(mn),
                sec = tonumber(sc),
                isdst = false
            }) * 1000
        else
            -- Try epoch format
            local timestamp = tonumber(eventTime)
            if timestamp then
                result.time = timestamp < 1e12 and timestamp * 1000 or timestamp
            else
                result.time = os.time() * 1000
            end
        end
    else
        result.time = os.time() * 1000
    end
    
    -- Set HTTP status based on error code
    if errorCode then
        local httpCode = tonumber(errorCode)
        if httpCode and httpCode >= 100 and httpCode <= 599 then
            setNestedField(result, "http_response.code", httpCode)
        end
    end
    
    -- Build observables for enrichment
    local observables = {}
    local sourceIP = getNestedField(event, "sourceIPAddress")
    if sourceIP then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = sourceIP
        })
    end
    
    local userAgent = getNestedField(event, "userAgent")
    if userAgent then
        table.insert(observables, {
            type_id = 6,
            type = "User Agent",
            name = "http_request.user_agent", 
            value = userAgent
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Mark additional mapped paths for nested fields
    mappedPaths["userIdentity"] = true
    mappedPaths["requestParameters"] = true
    mappedPaths["responseElements"] = true
    mappedPaths["tlsDetails"] = true
    mappedPaths["resources"] = true
    mappedPaths["additionalEventData"] = true
    mappedPaths["eventTime"] = true
    mappedPaths["eventCategory"] = true
    mappedPaths["eventID"] = true
    mappedPaths["eventVersion"] = true
    mappedPaths["awsRegion"] = true
    mappedPaths["recipientAccountId"] = true
    mappedPaths["sourceIPAddress"] = true
    mappedPaths["userAgent"] = true
    mappedPaths["errorCode"] = true
    mappedPaths["errorMessage"] = true
    mappedPaths["vpcEndpointId"] = true
    mappedPaths["apiVersion"] = true
    mappedPaths["message"] = true
    mappedPaths["class_uid"] = true
    mappedPaths["category_uid"] = true
    
    -- Collect unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end