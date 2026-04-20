-- Microsoft EventHub Defender Email Logs to OCSF Detection Finding (2004)

-- Constants
local CLASS_UID = 2004
local CATEGORY_UID = 2
local CLASS_NAME = "Detection Finding"
local CATEGORY_NAME = "Findings"

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

-- Map severity levels to OCSF severity_id
local function getSeverityId(errorCode, errorMessage, eventCategory)
    -- Map based on error codes and event categories
    if errorCode then
        local errorStr = tostring(errorCode):lower()
        if errorStr:find("critical") or errorStr:find("fatal") then return 5 end
        if errorStr:find("high") or errorStr:find("error") then return 4 end
        if errorStr:find("medium") or errorStr:find("warning") then return 3 end
        if errorStr:find("low") then return 2 end
    end
    
    if errorMessage then
        local msgStr = tostring(errorMessage):lower()
        if msgStr:find("critical") or msgStr:find("fatal") then return 5 end
        if msgStr:find("high") or msgStr:find("error") then return 4 end
        if msgStr:find("medium") or msgStr:find("warning") then return 3 end
        if msgStr:find("low") then return 2 end
    end
    
    -- Default based on presence of error
    if errorCode or errorMessage then return 4 end -- High for errors
    return 1 -- Informational for normal events
end

-- Generate finding UID based on event data
local function generateFindingUid(event)
    local eventId = getValue(event, "eventID", "")
    local timestamp = getValue(event, "eventTime", "")
    local sourceIP = getValue(event, "sourceIPAddress", "")
    
    if eventId ~= "" then
        return eventId
    elseif timestamp ~= "" and sourceIP ~= "" then
        return timestamp .. "_" .. sourceIP
    else
        return tostring(os.time()) .. "_" .. tostring(math.random(10000, 99999))
    end
end

-- Field mappings table-driven approach
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "eventID", target = "metadata.correlation_uid"},
    {type = "direct", source = "awsRegion", target = "metadata.region"},
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.issuer.uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.session.issuer.name"},
    
    -- Request/Response mappings
    {type = "direct", source = "requestParameters.bucketName", target = "resources[0].name"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.http_headers.Host"},
    {type = "direct", source = "requestParameters.instanceId", target = "cloud.instance.uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "http_response.response_elements.credentials.access_key_id"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "http_response.response_elements.credentials.expiration"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Resource mappings
    {type = "direct", source = "resources.accountId", target = "resources[0].account_uid"},
    {type = "direct", source = "resources.type", target = "resources[0].type"},
    {type = "direct", source = "resources.ARN", target = "resources[0].uid"},
    
    -- Error mappings
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.extension.x_amz_id_2"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
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
    
    -- Set activity_id and activity_name based on event category
    local eventCategory = getValue(event, "eventCategory", "")
    local activity_id = 99 -- Default: Other
    local activity_name = "Email Security Detection"
    
    if eventCategory ~= "" then
        activity_name = "Email Security: " .. eventCategory
        if eventCategory:lower():find("threat") then
            activity_id = 1 -- Create
        elseif eventCategory:lower():find("block") then
            activity_id = 2 -- Update
        elseif eventCategory:lower():find("allow") then
            activity_id = 3 -- Delete
        end
    end
    
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity based on error information
    local errorCode = getValue(event, "errorCode", nil)
    local errorMessage = getValue(event, "errorMessage", nil)
    result.severity_id = getSeverityId(errorCode, errorMessage, eventCategory)
    
    -- Handle time conversion from ISO string to milliseconds
    local eventTime = getValue(event, "eventTime", "")
    if eventTime ~= "" then
        -- Parse ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
        local year, month, day, hour, min, sec = eventTime:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
            result.time = timestamp * 1000
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end
    
    -- Set finding_info (required for Detection Finding class)
    result.finding_info = {
        uid = generateFindingUid(event),
        title = activity_name,
        desc = getValue(event, "message", "Email security detection event"),
        created_time = result.time
    }
    
    -- Set status information
    if errorCode or errorMessage then
        result.status_id = 2 -- Failure
        result.status = "Failure"
    else
        result.status_id = 1 -- Success
        result.status = "Success"
    end
    
    -- Set metadata product information
    setNestedField(result, "metadata.product.name", "Microsoft Defender for Office 365")
    setNestedField(result, "metadata.product.vendor_name", "Microsoft")
    
    -- Set confidence based on data quality
    local confidence_id = 3 -- Medium confidence by default
    if getValue(event, "eventID", "") ~= "" and getValue(event, "sourceIPAddress", "") ~= "" then
        confidence_id = 4 -- High confidence
    end
    result.confidence_id = confidence_id
    
    -- Mark mapped paths for unmapped field collection
    mappedPaths["eventCategory"] = true
    mappedPaths["eventTime"] = true
    
    -- Collect unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Set raw_data to preserve original event
    result.raw_data = require('json').encode(event)
    
    return result
end