-- NGINX Error Logs to OCSF HTTP Activity Parser
-- Maps NGINX error log events to OCSF class_uid 4002 (HTTP Activity)

-- OCSF Constants
local CLASS_UID = 4002
local CATEGORY_UID = 4

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

-- Severity mapping for NGINX error levels
local function getSeverityId(errorCode, errorMessage)
    if errorCode then
        local code = tostring(errorCode)
        -- Map HTTP status codes to severity
        if code:match("^5%d%d$") then return 4 -- High (server errors)
        elseif code:match("^4%d%d$") then return 2 -- Low (client errors)
        elseif code:match("^3%d%d$") then return 1 -- Informational (redirects)
        elseif code:match("^2%d%d$") then return 1 -- Informational (success)
        end
    end
    
    if errorMessage then
        local msg = tostring(errorMessage):lower()
        if msg:match("critical") or msg:match("fatal") or msg:match("emergency") then return 5
        elseif msg:match("error") or msg:match("failed") then return 4
        elseif msg:match("warning") or msg:match("warn") then return 2
        elseif msg:match("info") or msg:match("notice") then return 1
        end
    end
    
    return 0 -- Unknown
end

-- Activity ID mapping based on error types
local function getActivityId(errorCode, errorMessage)
    if errorCode then
        local code = tostring(errorCode)
        if code:match("^4%d%d$") then return 1 -- Connect
        elseif code:match("^5%d%d$") then return 99 -- Other (server error)
        end
    end
    
    if errorMessage and tostring(errorMessage):lower():match("timeout") then
        return 5 -- Refuse
    end
    
    return 99 -- Other
end

-- Field mappings configuration
local fieldMappings = {
    -- Direct mappings
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    {type = "direct", source = "errorCode", target = "http_response.code"},
    {type = "direct", source = "errorMessage", target = "http_response.message"},
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "apiVersion", target = "http_request.version"},
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "direct", source = "vpcEndpointId", target = "cloud.vpc_uid"},
    
    -- User identity mappings
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "priority", source1 = "userIdentity.sessionContext.sessionIssuer.userName", source2 = "userIdentity.principalId", target = "actor.user.name"},
    
    -- Request parameters
    {type = "direct", source = "requestParameters.bucketName", target = "http_request.url.path"},
    {type = "direct", source = "requestParameters.Host", target = "http_request.url.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "dst_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "dst_endpoint.location.region"},
    
    -- TLS details
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Additional event data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "metadata.correlation_uid"},
    
    -- Resource information
    {type = "direct", source = "resources.ARN", target = "resources[0].uid"},
    {type = "direct", source = "resources.type", target = "resources[0].type"},
    {type = "direct", source = "resources.accountId", target = "resources[0].account_uid"},
    
    -- Response elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "http_response.headers.x-access-key-id"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "http_response.headers.x-credential-expiration"},
    
    -- Computed fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "HTTP Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.name", value = "NGINX"},
    {type = "computed", target = "metadata.product.vendor_name", value = "NGINX, Inc."},
    {type = "computed", target = "metadata.version", value = "1.0.0"}
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
            if mapping.source2 then
                mappedPaths[mapping.source2] = true
            end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end

    -- Set activity_id based on error analysis
    local errorCode = getNestedField(event, "errorCode")
    local errorMessage = getNestedField(event, "errorMessage") or getNestedField(event, "message")
    local activity_id = getActivityId(errorCode, errorMessage)
    result.activity_id = activity_id
    
    -- Set type_uid
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity_id based on error analysis
    result.severity_id = getSeverityId(errorCode, errorMessage)
    
    -- Set activity_name based on activity_id
    local activity_names = {
        [1] = "Connect",
        [2] = "Create",
        [3] = "Read",
        [4] = "Update",
        [5] = "Refuse",
        [6] = "Delete",
        [99] = "Other"
    }
    result.activity_name = activity_names[activity_id] or "Other"

    -- Handle time conversion
    local eventTime = getNestedField(event, "eventTime")
    if eventTime and type(eventTime) == "string" then
        -- Parse ISO 8601 timestamp
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
            result.time = os.time() * 1000
        end
    else
        result.time = os.time() * 1000
    end

    -- Set status information
    if errorCode then
        result.status_id = tonumber(errorCode)
        if result.status_id >= 400 then
            result.status = "Failure"
        elseif result.status_id >= 200 and result.status_id < 400 then
            result.status = "Success"
        else
            result.status = "Unknown"
        end
    else
        result.status = "Unknown"
        result.status_id = 0
    end
    
    -- Set status_detail from error message
    if errorMessage then
        result.status_detail = tostring(errorMessage)
    end

    -- Store raw event data
    if event.message then
        result.raw_data = tostring(event.message)
    end

    -- Create observables for key security indicators
    local observables = {}
    if getNestedField(result, "src_endpoint.ip") then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = result.src_endpoint.ip
        })
    end
    if getNestedField(result, "actor.user.name") then
        table.insert(observables, {
            type_id = 4,
            type = "User Name", 
            name = "actor.user.name",
            value = result.actor.user.name
        })
    end
    if #observables > 0 then
        result.observables = observables
    end

    -- Add unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)

    return result
end