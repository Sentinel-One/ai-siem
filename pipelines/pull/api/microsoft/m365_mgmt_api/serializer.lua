-- Microsoft 365 Management API Logs to OCSF API Activity Transformation
-- OCSF Class: API Activity (6003), Category: Application Activity (6)

local CLASS_UID = 6003
local CATEGORY_UID = 6

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

-- Severity mapping based on error conditions and event types
local function getSeverityId(event)
    -- Check for error conditions
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        -- API errors are typically medium severity
        return 3
    end
    
    -- Check event category for severity hints
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        local category = string.lower(eventCategory)
        if string.find(category, 'data') or string.find(category, 'management') then
            return 2  -- Low severity for data/management events
        end
    end
    
    -- Default to informational for successful API calls
    return 1
end

-- Parse ISO 8601 timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if not timestamp then return nil end
    
    -- Parse ISO 8601 format: 2024-01-15T10:30:45.123Z
    local year, month, day, hour, min, sec, ms = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z?")
    
    if year then
        local timeTable = {
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }
        
        local epochSec = os.time(timeTable)
        local milliseconds = ms and tonumber(ms:sub(1, 3):ljust(3, '0')) or 0
        return epochSec * 1000 + milliseconds
    end
    
    return nil
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "eventID", target = "api.request.uid"},
    {type = "direct", source = "eventVersion", target = "api.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "errorCode", target = "api.response.error"},
    {type = "direct", source = "errorMessage", target = "api.response.error_message"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "vpcEndpointId", target = "api.service.vpc_endpoint"},
    
    -- User identity mappings with priority
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Account and resource mappings
    {type = "direct", source = "recipientAccountId", target = "actor.user.account.uid"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "api.request.bucket_name"},
    {type = "direct", source = "requestParameters.Host", target = "api.request.host"},
    {type = "direct", source = "requestParameters.instanceId", target = "api.request.instance_id"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "api.request.availability_zone"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "api.response.access_key_id"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "api.response.credential_expiration"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "api.request.x_amz_id_2"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "API Activity"},
    {type = "computed", target = "category_name", value = "Application Activity"},
    {type = "computed", target = "metadata.product.name", value = "Microsoft 365 Management API"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Microsoft"},
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
    
    -- Set OCSF required fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    
    -- Set activity based on event category or default
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        result.activity_name = eventCategory
        result.activity_id = 1  -- Create
    else
        result.activity_name = "Unknown"
        result.activity_id = 99  -- Other
    end
    
    -- Calculate type_uid
    result.type_uid = result.class_uid * 100 + result.activity_id
    
    -- Set severity based on error conditions
    result.severity_id = getSeverityId(event)
    
    -- Parse timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        local parsedTime = parseTimestamp(eventTime)
        if parsedTime then
            result.time = parsedTime
            mappedPaths['eventTime'] = true
        end
    end
    
    -- Default to current time if no valid timestamp
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Set API operation name
    if eventCategory then
        setNestedField(result, "api.operation", eventCategory)
    end
    
    -- Set service name based on AWS service indicators
    local bucketName = getNestedField(event, 'requestParameters.bucketName')
    local instanceId = getNestedField(event, 'requestParameters.instanceId')
    if bucketName then
        setNestedField(result, "api.service.name", "S3")
    elseif instanceId then
        setNestedField(result, "api.service.name", "EC2")
    else
        setNestedField(result, "api.service.name", "AWS API")
    end
    
    -- Set response code based on error presence
    if getNestedField(event, 'errorCode') then
        setNestedField(result, "api.response.code", 400)  -- Generic error code
    else
        setNestedField(result, "api.response.code", 200)  -- Success
    end
    
    -- Add observables for enrichment
    local observables = {}
    local sourceIP = getNestedField(event, 'sourceIPAddress')
    if sourceIP then
        table.insert(observables, {
            name = "src_endpoint.ip",
            type_id = 2,
            type = "IP Address",
            value = sourceIP
        })
    end
    
    local userName = getNestedField(result, 'actor.user.name')
    if userName then
        table.insert(observables, {
            name = "actor.user.name",
            type_id = 4,
            type = "User Name",
            value = userName
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end