-- AWS GuardDuty Detection Finding Transformation to OCSF
-- Class: Detection Finding (2004), Category: Findings (2)

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

-- Convert ISO timestamp to milliseconds since epoch
function parseTimestamp(timestamp)
    if not timestamp or type(timestamp) ~= "string" then
        return os.time() * 1000
    end
    
    -- Parse ISO 8601 format: YYYY-MM-DDTHH:MM:SS.sssZ
    local year, month, day, hour, min, sec = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
        return os.time(timeTable) * 1000
    end
    
    return os.time() * 1000
end

-- Map severity to OCSF severity_id
function getSeverityId(severity)
    if not severity then return 0 end
    local severityMap = {
        ["LOW"] = 2,
        ["MEDIUM"] = 3,
        ["HIGH"] = 4,
        ["CRITICAL"] = 5,
        ["INFORMATIONAL"] = 1,
        ["INFO"] = 1
    }
    return severityMap[string.upper(tostring(severity))] or 0
end

-- GuardDuty field mappings
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Detection Finding"},
    {type = "computed", target = "category_name", value = "Findings"},
    
    -- Finding information
    {type = "direct", source = "eventID", target = "finding_info.uid"},
    {type = "direct", source = "message", target = "finding_info.title"},
    {type = "direct", source = "eventCategory", target = "finding_info.desc"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "Amazon GuardDuty"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Amazon Web Services"},
    {type = "direct", source = "eventVersion", target = "metadata.version"},
    
    -- Cloud information
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    
    -- Actor information
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.user.name"},
    
    -- Source endpoint
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    
    -- HTTP request info
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    
    -- Error information
    {type = "direct", source = "errorCode", target = "status_code"},
    {type = "direct", source = "errorMessage", target = "status_detail"},
    
    -- TLS information
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    
    -- VPC endpoint
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- API version
    {type = "direct", source = "apiVersion", target = "api.version"}
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
    
    -- Set OCSF required fields with defaults
    result.class_uid = result.class_uid or CLASS_UID
    result.category_uid = result.category_uid or CATEGORY_UID
    
    -- Activity ID and Type UID (default to 99 - Other)
    local activityId = 1 -- Create for Detection Finding
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.activity_name = "Create"
    
    -- Set time from eventTime
    local eventTime = getNestedField(event, "eventTime")
    result.time = parseTimestamp(eventTime)
    
    -- Set severity (default to Unknown)
    local severity = getNestedField(event, "severity")
    result.severity_id = getSeverityId(severity)
    
    -- Set finding creation and modification times
    if eventTime then
        local timeMs = parseTimestamp(eventTime)
        setNestedField(result, "finding_info.created_time", timeMs)
        setNestedField(result, "finding_info.modified_time", timeMs)
    end
    
    -- Set status based on error information
    if getNestedField(event, "errorCode") then
        result.status = "Failure"
        result.status_id = 2
    else
        result.status = "Success"
        result.status_id = 1
    end
    
    -- Build observables array
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
    
    local userId = getNestedField(event, "userIdentity.principalId")
    if userId then
        table.insert(observables, {
            type_id = 4,
            type = "User ID",
            name = "actor.user.uid",
            value = userId
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Handle resources array
    local resources = getNestedField(event, "resources")
    if resources and type(resources) == "table" then
        result.resources = {}
        for i, resource in ipairs(resources) do
            if type(resource) == "table" then
                local resourceObj = {
                    uid = resource.ARN,
                    type = resource.type,
                    cloud_account_uid = resource.accountId
                }
                table.insert(result.resources, resourceObj)
            end
        end
        mappedPaths["resources"] = true
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end