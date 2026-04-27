-- Confluent Kafka Logs to OCSF Network Activity transformation
-- Maps Kafka log events to OCSF class_uid 4001 (Network Activity)

-- Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4

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

-- Get severity ID based on error conditions
local function getSeverityId(event)
    local errorCode = getNestedField(event, 'errorCode')
    local errorMessage = getNestedField(event, 'errorMessage')
    
    if errorCode or errorMessage then
        return 4 -- High severity for errors
    end
    
    local eventCategory = getNestedField(event, 'eventCategory')
    if eventCategory then
        if string.lower(eventCategory):find('management') then
            return 3 -- Medium for management events
        elseif string.lower(eventCategory):find('data') then
            return 2 -- Low for data events
        end
    end
    
    return 1 -- Informational by default
end

-- Get activity ID and name based on event type
local function getActivityInfo(event)
    local eventCategory = getNestedField(event, 'eventCategory')
    local errorCode = getNestedField(event, 'errorCode')
    
    if errorCode then
        return 2, "Traffic" -- Network traffic with error
    end
    
    if eventCategory then
        if string.lower(eventCategory):find('management') then
            return 1, "Open" -- Network connection/open
        elseif string.lower(eventCategory):find('data') then
            return 2, "Traffic" -- Network traffic
        end
    end
    
    return 99, "Other" -- Unknown activity
end

-- Parse ISO timestamp to milliseconds
local function parseTime(timeStr)
    if not timeStr then return nil end
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

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "requestParameters.Host", target = "dst_endpoint.hostname"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "vpcEndpointId", target = "dst_endpoint.vpc_uid"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", 
     source2 = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.user.name"},
    
    -- Computed values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "Confluent Kafka"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Confluent"}
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
            if not value or value == "" then
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
    
    -- Set time from eventTime
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTime(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    mappedPaths['eventTime'] = true
    
    -- Set activity info
    local activityId, activityName = getActivityInfo(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set status based on error conditions
    if getNestedField(event, 'errorCode') then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Set protocol if TLS details present
    if getNestedField(event, 'tlsDetails.tlsVersion') then
        result.protocol_name = "HTTPS"
    end
    
    -- Handle resources array
    local resources = getNestedField(event, 'resources')
    if resources and type(resources) == "table" then
        if #resources > 0 then
            for i, resource in ipairs(resources) do
                if resource.ARN then
                    setNestedField(result, "resources." .. i .. ".uid", resource.ARN)
                end
                if resource.type then
                    setNestedField(result, "resources." .. i .. ".type", resource.type)
                end
                if resource.accountId then
                    setNestedField(result, "resources." .. i .. ".account_uid", resource.accountId)
                end
            end
        end
        mappedPaths['resources'] = true
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up and return
    return no_nulls(result, nil)
end