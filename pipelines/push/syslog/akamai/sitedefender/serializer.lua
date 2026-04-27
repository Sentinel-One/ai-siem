-- Akamai Site Defender OCSF HTTP Activity Transformation
-- Maps Akamai Site Defender events to OCSF HTTP Activity class (4002)

-- OCSF Constants
local CLASS_UID = 4002
local CATEGORY_UID = 4
local CLASS_NAME = "HTTP Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Get severity ID based on error codes and event category
local function getSeverityId(errorCode, errorMessage, eventCategory)
    -- If there's an error, map based on type
    if errorCode then
        local errorStr = tostring(errorCode):lower()
        -- Security/access errors are high severity
        if errorStr:match("403") or errorStr:match("401") or errorStr:match("access") then
            return 4  -- High
        elseif errorStr:match("500") or errorStr:match("error") then
            return 3  -- Medium
        elseif errorStr:match("404") or errorStr:match("400") then
            return 2  -- Low
        end
    end
    
    -- Check error message for severity indicators
    if errorMessage then
        local msgStr = tostring(errorMessage):lower()
        if msgStr:match("denied") or msgStr:match("unauthorized") or msgStr:match("forbidden") then
            return 4  -- High
        elseif msgStr:match("error") or msgStr:match("failed") then
            return 3  -- Medium
        end
    end
    
    -- Default based on event category if available
    if eventCategory then
        local catStr = tostring(eventCategory):lower()
        if catStr:match("security") or catStr:match("threat") then
            return 4  -- High
        end
    end
    
    return 1  -- Informational (default for HTTP activities)
end

-- Parse ISO 8601 timestamp to milliseconds
local function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    
    -- Try to parse ISO 8601 format: YYYY-MM-DDTHH:MM:SS.sssZ
    local year, month, day, hour, min, sec, ms = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z?")
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
        -- Convert to milliseconds and add millisecond part if present
        local msVal = ms and tonumber(ms) or 0
        if #ms == 3 then
            return timestamp * 1000 + msVal
        else
            return timestamp * 1000
        end
    end
    
    return nil
end

-- Field mappings configuration
local fieldMappings = {
    -- OCSF Required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    
    -- Source IP mapping
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    
    -- User Agent mapping
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.uid"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.hostname"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "http_response.code"},
    {type = "direct", source = "errorMessage", target = "http_response.message"},
    
    -- Event metadata
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "eventCategory", target = "category_name"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- VPC endpoint
    {type = "direct", source = "vpcEndpointId", target = "cloud.provider"},
    
    -- Message
    {type = "direct", source = "message", target = "message"},
    
    -- Resource information
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"}
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
    local eventName = getNestedField(event, "eventName") or "HTTP Request"
    result.activity_name = eventName
    
    -- Determine activity_id based on event type or default to 1 (Access)
    local activityId = 1  -- Default to Access
    if eventName then
        local nameStr = tostring(eventName):lower()
        if nameStr:match("get") or nameStr:match("read") then
            activityId = 1  -- Access
        elseif nameStr:match("post") or nameStr:match("put") or nameStr:match("create") then
            activityId = 2  -- Create
        elseif nameStr:match("delete") then
            activityId = 3  -- Delete
        elseif nameStr:match("patch") or nameStr:match("update") then
            activityId = 4  -- Update
        end
    end
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId

    -- Set severity based on error information
    local errorCode = getNestedField(event, "errorCode")
    local errorMessage = getNestedField(event, "errorMessage")
    local eventCategory = getNestedField(event, "eventCategory")
    result.severity_id = getSeverityId(errorCode, errorMessage, eventCategory)

    -- Parse timestamp
    local eventTime = getNestedField(event, "eventTime")
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end

    -- Set metadata
    result.metadata = result.metadata or {}
    result.metadata.product = result.metadata.product or {}
    result.metadata.product.name = "Akamai Site Defender"
    result.metadata.product.vendor_name = "Akamai"

    -- Set HTTP method if determinable from event name
    if eventName then
        local nameStr = tostring(eventName):lower()
        if nameStr:match("get") then
            setNestedField(result, "http_request.http_method", "GET")
        elseif nameStr:match("post") then
            setNestedField(result, "http_request.http_method", "POST")
        elseif nameStr:match("put") then
            setNestedField(result, "http_request.http_method", "PUT")
        elseif nameStr:match("delete") then
            setNestedField(result, "http_request.http_method", "DELETE")
        elseif nameStr:match("patch") then
            setNestedField(result, "http_request.http_method", "PATCH")
        elseif nameStr:match("head") then
            setNestedField(result, "http_request.http_method", "HEAD")
        elseif nameStr:match("options") then
            setNestedField(result, "http_request.http_method", "OPTIONS")
        end
    end

    -- Add observables for enrichment
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
    
    local userName = getNestedField(event, "userIdentity.sessionContext.sessionIssuer.userName")
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

    -- Mark all mapped source paths to avoid duplication in unmapped
    local allMappedPaths = {
        sourceIPAddress = true,
        userAgent = true,
        ["userIdentity.principalId"] = true,
        ["userIdentity.accessKeyId"] = true,
        ["userIdentity.type"] = true,
        ["userIdentity.sessionContext.sessionIssuer.userName"] = true,
        ["userIdentity.sessionContext.sessionIssuer.principalId"] = true,
        ["requestParameters.bucketName"] = true,
        ["requestParameters.Host"] = true,
        errorCode = true,
        errorMessage = true,
        eventID = true,
        eventTime = true,
        eventVersion = true,
        eventCategory = true,
        eventName = true,
        awsRegion = true,
        recipientAccountId = true,
        apiVersion = true,
        ["tlsDetails.cipherSuite"] = true,
        ["tlsDetails.tlsVersion"] = true,
        vpcEndpointId = true,
        message = true,
        ["resources.accountId"] = true,
        ["resources.type"] = true,
        ["resources.ARN"] = true
    }

    -- Collect unmapped fields
    copyUnmappedFields(event, allMappedPaths, result)

    return result
end