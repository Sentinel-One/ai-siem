-- Constants for OCSF Authentication class
local CLASS_UID = 3002
local CATEGORY_UID = 3
local CLASS_NAME = "Authentication"
local CATEGORY_NAME = "Identity & Access Management"

-- Helper Functions (production-proven from Observo scripts)
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

function no_nulls(d, rn)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = rn
            elseif type(v) == "table" then no_nulls(v, rn) end
        end
    end
    return d
end

function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Parse ISO timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        return os.time({year=tonumber(yr), month=tonumber(mo), day=tonumber(dy),
                       hour=tonumber(hr), min=tonumber(mn), sec=tonumber(sc), isdst=false}) * 1000
    end
    return nil
end

-- Map error codes/messages to severity
function getSeverityId(errorCode, errorMessage)
    if errorCode or errorMessage then
        -- Authentication failures are typically medium severity
        if errorCode and (string.find(errorCode, "AccessDenied") or string.find(errorCode, "SigninFailure")) then
            return 3 -- Medium
        end
        if errorMessage and (string.find(errorMessage, "failed") or string.find(errorMessage, "denied")) then
            return 3 -- Medium  
        end
        return 2 -- Low for other errors
    end
    return 1 -- Informational for successful authentications
end

-- Determine activity based on event context
function getActivityInfo(event)
    local errorCode = getValue(event, "errorCode", "")
    local errorMessage = getValue(event, "errorMessage", "")
    local eventCategory = getValue(event, "eventCategory", "")
    
    -- Check for authentication failure indicators
    if errorCode ~= "" or errorMessage ~= "" then
        return 2, "Logon" -- Failed authentication attempt
    end
    
    -- Check for successful authentication indicators
    if string.find(eventCategory, "signin") or string.find(eventCategory, "authentication") then
        return 1, "Logon" -- Successful authentication
    end
    
    -- Default to generic logon
    return 1, "Logon"
end

-- Field mapping configuration
local fieldMappings = {
    -- Core identity mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "src_endpoint.hostname"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.uid"},
    {type = "direct", source = "awsRegion", target = "actor.user.domain"},
    
    -- Event metadata
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "recipientAccountId", target = "metadata.product.name"},
    {type = "computed", target = "metadata.product.vendor_name", value = "AWS"},
    
    -- Status and error information
    {type = "direct", source = "errorCode", target = "status_detail"},
    {type = "direct", source = "errorMessage", target = "message"},
    
    -- Request details
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "vpcEndpointId", target = "dst_endpoint.uid"},
    
    -- TLS information
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- OCSF core fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME}
}

function processEvent(event)
    -- Validate input
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
            if value == nil or value == "" then
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
    
    -- Set activity and type information
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity based on error conditions
    result.severity_id = getSeverityId(getValue(event, "errorCode", ""), getValue(event, "errorMessage", ""))
    
    -- Set status based on error presence
    if getValue(event, "errorCode", "") ~= "" or getValue(event, "errorMessage", "") ~= "" then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success" 
        result.status_id = 1
    end
    
    -- Parse and set timestamp
    local eventTime = getValue(event, "eventTime", "")
    if eventTime ~= "" then
        local parsedTime = parseTimestamp(eventTime)
        if parsedTime then
            result.time = parsedTime
        else
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end
    
    -- Mark additional mapped fields for unmapped collection
    local additionalMapped = {
        "eventCategory", "eventTime", "eventVersion", "recipientAccountId",
        "userIdentity", "requestParameters", "responseElements", 
        "additionalEventData", "tlsDetails", "apiVersion", "resources"
    }
    for _, field in ipairs(additionalMapped) do
        mappedPaths[field] = true
    end
    
    -- Collect unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values
    result = no_nulls(result, nil)
    
    return result
end