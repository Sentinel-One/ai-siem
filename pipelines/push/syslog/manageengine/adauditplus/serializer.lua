-- Constants for OCSF Process Activity class
local CLASS_UID = 1007
local CATEGORY_UID = 1
local CLASS_NAME = "Process Activity"
local CATEGORY_NAME = "System Activity"

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

-- Safe value access with default
function getValue(tbl, key, default)
    local value = tbl[key]
    return value ~= nil and value or default
end

-- Replace userdata nil values
function no_nulls(d, rn)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = rn
            elseif type(v) == "table" then no_nulls(v, rn) end
        end
    end
    return d
end

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Map severity based on event characteristics
function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    -- If there are errors, treat as medium severity
    if errorCode or errorMessage then
        return 3 -- Medium
    end
    
    -- Default to informational
    return 1
end

-- Determine activity based on event characteristics
function getActivityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 2 -- Terminate - process ended with error
    end
    
    return 1 -- Launch - default process activity
end

-- Get activity name based on activity_id
function getActivityName(activity_id)
    local activityNames = {
        [1] = "Launch",
        [2] = "Terminate",
        [99] = "Other"
    }
    return activityNames[activity_id] or "Other"
end

-- Parse ISO timestamp to epoch milliseconds
function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then
        return os.time() * 1000
    end
    
    local year, month, day, hour, min, sec = timeStr:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
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

-- Field mappings for ManageEngine ADAuditPlus logs
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "metadata.product.name"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "apiVersion", target = "metadata.version"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- User identity mappings
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.principalId", target = "actor.user.name"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    
    -- Process-related mappings (inferred from request context)
    {type = "direct", source = "requestParameters.instanceId", target = "process.uid"},
    {type = "direct", source = "requestParameters.bucketName", target = "process.name"},
    
    -- Resource mappings
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "end_time"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = CLASS_NAME},
    {type = "computed", target = "category_name", value = CATEGORY_NAME},
    {type = "computed", target = "metadata.product.vendor_name", value = "ManageEngine"}
}

function processEvent(event)
    -- Validate input
    if type(event) ~= "table" then
        return nil
    end
    
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
                mappedPaths[mapping.source2] = true
            end
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source1] = true
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity_id and related fields
    local activity_id = getActivityId(event)
    result.activity_id = activity_id
    result.activity_name = getActivityName(activity_id)
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    result.time = parseTimestamp(eventTime)
    
    -- Set status based on error presence
    if getNestedField(event, 'errorCode') or getNestedField(event, 'errorMessage') then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Set raw_data if message exists
    if event.message then
        result.raw_data = event.message
    end
    
    -- Mark additional mapped fields
    mappedPaths['eventTime'] = true
    mappedPaths['eventID'] = true
    mappedPaths['eventCategory'] = true
    mappedPaths['eventVersion'] = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nil values
    result = no_nulls(result, nil)
    
    return result
end