-- Constants for OCSF DNS Activity
local CLASS_UID = 4003
local CATEGORY_UID = 4

-- DNS query type mappings
local DNS_TYPES = {
    ["1"] = "A", ["2"] = "NS", ["5"] = "CNAME", ["6"] = "SOA", 
    ["12"] = "PTR", ["15"] = "MX", ["16"] = "TXT", ["28"] = "AAAA",
    ["33"] = "SRV", ["255"] = "ANY"
}

-- DNS response code mappings
local RCODE_MAP = {
    ["0"] = "NOERROR", ["1"] = "FORMERR", ["2"] = "SERVFAIL", 
    ["3"] = "NXDOMAIN", ["4"] = "NOTIMP", ["5"] = "REFUSED"
}

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

-- Parse embedded payload from message/raw regardless of type.
local function parseEmbeddedPayload(payload)
    if type(payload) == "table" then
        return payload
    end
    local parsed = {}
    if type(payload) ~= "string" or payload == "" then
        return parsed
    end

    -- JSON-first strategy when payload looks like JSON.
    if payload:sub(1, 1) == "{" and json and json.decode then
        local ok, decoded = pcall(function() return json.decode(payload) end)
        if ok and type(decoded) == "table" then
            return decoded
        end
    end

    -- key="value with spaces"
    for k, v in payload:gmatch('([%w_%.%-]+)%s*=%s*"([^"]*)"') do
        parsed[k] = v
    end
    -- key=value (unquoted)
    for k, v in payload:gmatch('([%w_%.%-]+)%s*=%s*([^%s"]+)') do
        if parsed[k] == nil then
            parsed[k] = v
        end
    end
    return parsed
end

-- Normalize event with aliases so mapping works on embedded KV payloads.
local function normalizeEvent(event)
    local normalized = {}
    for k, v in pairs(event) do normalized[k] = v end

    local payload = event["message"]
    if payload == nil then payload = event["raw"] end
    local embedded = parseEmbeddedPayload(payload)
    for k, v in pairs(embedded) do
        if normalized[k] == nil then normalized[k] = v end
    end

    if normalized["recordType"] and not normalized["query_type"] then
        normalized["query_type"] = normalized["recordType"]
    end
    if normalized["responseCode"] and not normalized["rcode"] then
        normalized["rcode"] = normalized["responseCode"]
    end
    if normalized["cliIP"] and not normalized["client_ip"] then
        normalized["client_ip"] = normalized["cliIP"]
    end
    if normalized["resolverIP"] and not normalized["server_ip"] then
        normalized["server_ip"] = normalized["resolverIP"]
    end
    if normalized["domain"] and not normalized["query"] then
        normalized["query"] = normalized["domain"]
    end
    if normalized["answer"] and not normalized["answers"] then
        normalized["answers"] = normalized["answer"]
    end
    return normalized
end

-- Safe value access with default
function getValue(tbl, key, default)
    if type(tbl) ~= "table" then return default end
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

-- Parse timestamp to milliseconds
local function parseTimestamp(timestamp)
    if not timestamp then return nil end
    
    -- Handle various timestamp formats
    if type(timestamp) == "number" then
        -- Already in seconds or milliseconds
        if timestamp > 1000000000000 then return timestamp -- milliseconds
        else return timestamp * 1000 end -- seconds
    elseif type(timestamp) == "string" then
        -- Try ISO format: YYYY-MM-DDTHH:MM:SS
        local yr, mo, dy, hr, mn, sc = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        if yr then
            local okTime, ts = pcall(function()
                return os.time({
                    year = tonumber(yr), month = tonumber(mo), day = tonumber(dy),
                    hour = tonumber(hr), min = tonumber(mn), sec = tonumber(sc),
                    isdst = false
                })
            end)
            if okTime and ts then return ts * 1000 end
        end
        
        -- Try epoch timestamp as string
        local epochTime = tonumber(timestamp)
        if epochTime then
            if epochTime > 1000000000000 then return epochTime
            else return epochTime * 1000 end
        end
    end
    
    return nil
end

-- Get severity based on response code or other indicators
local function getSeverityId(event)
    local rcode = tostring(getValue(event, "rcode", "0"))
    local status = getValue(event, "status", "")
    local rcUpper = string.upper(rcode)
    
    -- Critical: DNS failures that indicate security issues
    if rcode == "5" or rcUpper == "REFUSED" or status:lower():find("refused") then return 5 end
    
    -- High: Server failures
    if rcode == "2" or rcUpper == "SERVFAIL" or status:lower():find("servfail") then return 4 end
    
    -- Medium: Domain not found or format errors
    if rcode == "3" or rcode == "1" or rcUpper == "NXDOMAIN" or rcUpper == "FORMERR" then return 3 end
    
    -- Low: Not implemented
    if rcode == "4" or rcUpper == "NOTIMP" then return 2 end
    
    -- Informational: Successful queries
    if rcode == "0" or rcUpper == "NOERROR" then return 1 end
    
    return 0 -- Unknown
end

-- Get activity ID based on DNS operation
local function getActivityId(event)
    local queryType = getValue(event, "query_type", "")
    local operation = getValue(event, "operation", "")
    
    -- Common DNS activities
    if operation:lower():find("query") or queryType ~= "" then return 1 end -- Query
    if operation:lower():find("response") then return 2 end -- Response
    if operation:lower():find("update") then return 3 end -- Update
    
    return 99 -- Other
end

-- Get activity name
local function getActivityName(event)
    local operation = getValue(event, "operation", "")
    local queryType = getValue(event, "query_type", "")
    
    if operation ~= "" then return operation end
    if queryType ~= "" then return "DNS " .. queryType .. " Query" end
    
    return "DNS Activity"
end

-- Field mappings for Akamai DNS logs
local fieldMappings = {
    -- Core DNS fields
    {type = "direct", source = "query", target = "query.hostname"},
    {type = "direct", source = "hostname", target = "query.hostname"},
    {type = "direct", source = "domain", target = "query.hostname"},
    {type = "direct", source = "query_type", target = "query.type"},
    {type = "direct", source = "qtype", target = "query.type"},
    {type = "direct", source = "query_class", target = "query.class"},
    {type = "direct", source = "qclass", target = "query.class"},
    {type = "direct", source = "rcode", target = "rcode_id"},
    {type = "direct", source = "response_code", target = "rcode_id"},
    {type = "direct", source = "answer", target = "answers"},
    {type = "direct", source = "answers", target = "answers"},
    
    -- Network endpoint fields
    {type = "direct", source = "client_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "src_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "source_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "server_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dst_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "destination_ip", target = "dst_endpoint.ip"},
    
    -- Metadata fields
    {type = "direct", source = "message", target = "message"},
    {type = "direct", source = "raw_data", target = "raw_data"},
    {type = "direct", source = "raw", target = "raw_data"},
    {type = "direct", source = "status", target = "status"},
    {type = "direct", source = "status_detail", target = "status_detail"},
    {type = "direct", source = "count", target = "count"},
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "response_time", target = "duration"},
    
    -- Timestamps
    {type = "direct", source = "start_time", target = "start_time"},
    {type = "direct", source = "end_time", target = "end_time"},
    {type = "direct", source = "timezone_offset", target = "timezone_offset"},
    
    -- Product metadata
    {type = "computed", target = "metadata.product.name", value = "Akamai DNS"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Akamai"},
    {type = "computed", target = "metadata.version", value = "1.0.0"},
    
    -- OCSF required fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "DNS Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
}

function processEvent(event)
    -- Input validation
    if type(event) ~= "table" then return nil end
    event = normalizeEvent(event)
    
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
    
    -- Set activity-specific fields
    local activityId = getActivityId(event)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    result.activity_name = getActivityName(event)
    result.severity_id = getSeverityId(event)
    
    -- Parse timestamp
    local timestamp = getNestedField(event, "timestamp") or getNestedField(event, "time") or 
                     getNestedField(event, "@timestamp") or getNestedField(event, "event_time")
    local parsedTime = parseTimestamp(timestamp)
    if parsedTime then
        result.time = parsedTime
    else
        local okNow, nowTs = pcall(function() return os.time() end)
        result.time = ((okNow and nowTs) and nowTs or 0) * 1000
    end
    
    -- Map DNS query type to string
    if result.query and result.query.type and DNS_TYPES[tostring(result.query.type)] then
        result.query.type = DNS_TYPES[tostring(result.query.type)]
    end
    
    -- Map response code to string
    if result.rcode_id then
        result.rcode = RCODE_MAP[tostring(result.rcode_id)] or tostring(result.rcode_id)
    end
    
    -- Set status based on response code
    if not result.status and result.rcode_id then
        if result.rcode_id == "0" then
            result.status = "Success"
            result.status_id = 1
        else
            result.status = "Failure"
            result.status_id = 2
        end
    end
    
    -- Create observables for key fields
    local observables = {}
    if result.query and result.query.hostname then
        table.insert(observables, {
            type_id = 1, 
            type = "Hostname",
            name = "query.hostname", 
            value = result.query.hostname
        })
    end
    if result.src_endpoint and result.src_endpoint.ip then
        table.insert(observables, {
            type_id = 2, 
            type = "IP Address",
            name = "src_endpoint.ip", 
            value = result.src_endpoint.ip
        })
    end
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end
