-- Google Cloud DNS Logs to OCSF DNS Activity transformation
-- Class: DNS Activity (4003), Category: Network Activity (4)

local CLASS_UID = 4003
local CATEGORY_UID = 4
local DEFAULT_ACTIVITY_ID = 1 -- Query

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

-- Parse ISO timestamp to milliseconds since epoch
function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
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

-- Map severity level to OCSF severity_id
function getSeverityId(level)
    if level == nil then return 1 end -- Default to Informational
    local severityMap = {
        ["CRITICAL"] = 5, ["Critical"] = 5, ["critical"] = 5,
        ["HIGH"] = 4, ["High"] = 4, ["high"] = 4,
        ["MEDIUM"] = 3, ["Medium"] = 3, ["medium"] = 3,
        ["LOW"] = 2, ["Low"] = 2, ["low"] = 2,
        ["INFO"] = 1, ["INFORMATIONAL"] = 1, ["Information"] = 1, ["info"] = 1,
        ["ERROR"] = 4, ["Error"] = 4, ["error"] = 4,
        ["WARNING"] = 3, ["Warning"] = 3, ["warning"] = 3
    }
    return severityMap[level] or 1
end

-- Determine DNS activity based on event data
function getDNSActivity(event)
    -- Default to Query activity
    local activityId = 1
    local activityName = "Query"
    
    -- Check for specific DNS operations in message or event category
    local message = event.message or ""
    local eventCategory = event.eventCategory or ""
    
    if string.find(message:lower(), "response") or string.find(eventCategory:lower(), "response") then
        activityId = 2
        activityName = "Response"
    elseif string.find(message:lower(), "update") or string.find(eventCategory:lower(), "update") then
        activityId = 3
        activityName = "Update"
    end
    
    return activityId, activityName
end

-- Field mappings configuration
local fieldMappings = {
    -- Basic event fields
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    
    -- User identity fields
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.session.issuer"},
    
    -- Error fields
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- Request parameters (potential DNS query info)
    {type = "direct", source = "requestParameters.Host", target = "query.hostname"},
    {type = "direct", source = "requestParameters.bucketName", target = "query.hostname"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Resources
    {type = "direct", source = "resources.accountId", target = "resources.account_uid"},
    {type = "direct", source = "resources.type", target = "resources.type"},
    {type = "direct", source = "resources.ARN", target = "resources.uid"},
    
    -- Computed/constant fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "DNS Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "Google Cloud DNS"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Google"},
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
            if value == nil and mapping.source2 then 
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

    -- Determine DNS activity and set activity fields
    local activityId, activityName = getDNSActivity(event)
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId

    -- Set timestamp
    local eventTime = getNestedField(event, 'eventTime')
    if eventTime then
        result.time = parseTimestamp(eventTime)
    end
    if not result.time then
        result.time = os.time() * 1000
    end

    -- Set severity
    local severity = event.severity or event.level or event.priority
    result.severity_id = getSeverityId(severity)

    -- Set status based on error fields
    if event.errorCode or event.errorMessage then
        result.status = "Failure"
        result.status_id = 2
        if not result.status_detail and event.errorMessage then
            result.status_detail = event.errorMessage
        end
        if not result.status_code and event.errorCode then
            result.status_code = event.errorCode
        end
    else
        result.status = "Success"
        result.status_id = 1
    end

    -- Create observables for key DNS data
    local observables = {}
    if result.src_endpoint and result.src_endpoint.ip then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = result.src_endpoint.ip
        })
    end
    if result.query and result.query.hostname then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "query.hostname",
            value = result.query.hostname
        })
    end
    if #observables > 0 then
        result.observables = observables
    end

    -- Collect unmapped fields
    copyUnmappedFields(event, mappedPaths, result)

    return result
end