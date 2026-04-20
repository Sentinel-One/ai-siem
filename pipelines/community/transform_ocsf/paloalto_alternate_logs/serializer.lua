-- Constants for OCSF Network Activity class
local CLASS_UID = 4001
local CATEGORY_UID = 4

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

-- Severity mapping for Palo Alto logs
local function getSeverityId(severity)
    if severity == nil then return 0 end
    local severityStr = tostring(severity):lower()
    if severityStr == "critical" or severityStr == "5" then return 5
    elseif severityStr == "high" or severityStr == "4" then return 4
    elseif severityStr == "medium" or severityStr == "3" then return 3
    elseif severityStr == "low" or severityStr == "2" then return 2
    elseif severityStr == "informational" or severityStr == "info" or severityStr == "1" then return 1
    else return 0 end
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if not timestamp then return os.time() * 1000 end
    
    -- Try ISO 8601 format
    local year, month, day, hour, min, sec = timestamp:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
    if year then
        local time_table = {
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }
        return os.time(time_table) * 1000
    end
    
    -- Try epoch seconds
    local epoch = tonumber(timestamp)
    if epoch then
        -- If it looks like seconds (reasonable range), convert to milliseconds
        if epoch > 1000000000 and epoch < 9999999999 then
            return epoch * 1000
        elseif epoch > 1000000000000 then -- Already milliseconds
            return epoch
        end
    end
    
    return os.time() * 1000
end

-- Map protocol names to standard values
local function mapProtocol(proto)
    if not proto then return nil end
    local protoStr = tostring(proto):lower()
    if protoStr == "tcp" or protoStr == "6" then return "tcp"
    elseif protoStr == "udp" or protoStr == "17" then return "udp"
    elseif protoStr == "icmp" or protoStr == "1" then return "icmp"
    elseif protoStr == "http" then return "http"
    elseif protoStr == "https" then return "https"
    else return proto end
end

-- Determine activity based on Palo Alto log type and action
local function getActivityInfo(event)
    local logType = event.logtype or event.log_type or event.type
    local action = event.action or event.verdict
    local subtype = event.subtype
    
    -- Default activity
    local activity_id = 1 -- Other
    local activity_name = "Network Activity"
    
    if logType then
        local logTypeStr = tostring(logType):lower()
        if logTypeStr:find("traffic") then
            if action then
                local actionStr = tostring(action):lower()
                if actionStr == "allow" or actionStr == "permit" then
                    activity_id = 1 -- Allow
                    activity_name = "Traffic Allowed"
                elseif actionStr == "deny" or actionStr == "block" or actionStr == "drop" then
                    activity_id = 2 -- Deny
                    activity_name = "Traffic Denied"
                else
                    activity_id = 1
                    activity_name = "Traffic Activity"
                end
            end
        elseif logTypeStr:find("threat") then
            activity_id = 6 -- Malicious Activity
            activity_name = "Threat Detection"
        elseif logTypeStr:find("url") then
            activity_id = 5 -- URL Activity  
            activity_name = "URL Filtering"
        end
    end
    
    return activity_id, activity_name
end

-- Field mappings for Palo Alto logs
local fieldMappings = {
    -- Common timestamp fields
    {type = "priority", source1 = "receive_time", source2 = "generated_time", source3 = "time_generated", source4 = "timestamp", target = "_timestamp"},
    
    -- Source endpoint fields
    {type = "direct", source = "src", target = "src_endpoint.ip"},
    {type = "direct", source = "srcip", target = "src_endpoint.ip"},
    {type = "direct", source = "source_ip", target = "src_endpoint.ip"},
    {type = "direct", source = "sport", target = "src_endpoint.port"},
    {type = "direct", source = "srcport", target = "src_endpoint.port"},
    {type = "direct", source = "source_port", target = "src_endpoint.port"},
    {type = "direct", source = "srchost", target = "src_endpoint.hostname"},
    {type = "direct", source = "source_host", target = "src_endpoint.hostname"},
    
    -- Destination endpoint fields
    {type = "direct", source = "dst", target = "dst_endpoint.ip"},
    {type = "direct", source = "dstip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dest_ip", target = "dst_endpoint.ip"},
    {type = "direct", source = "dport", target = "dst_endpoint.port"},
    {type = "direct", source = "dstport", target = "dst_endpoint.port"},
    {type = "direct", source = "dest_port", target = "dst_endpoint.port"},
    {type = "direct", source = "dsthost", target = "dst_endpoint.hostname"},
    {type = "direct", source = "dest_host", target = "dst_endpoint.hostname"},
    
    -- Protocol and traffic info
    {type = "direct", source = "proto", target = "_protocol"},
    {type = "direct", source = "protocol", target = "_protocol"},
    {type = "direct", source = "ip_protocol", target = "_protocol"},
    {type = "direct", source = "bytes", target = "traffic.bytes"},
    {type = "direct", source = "bytes_sent", target = "traffic.bytes_out"},
    {type = "direct", source = "bytes_received", target = "traffic.bytes_in"},
    {type = "direct", source = "packets", target = "traffic.packets"},
    
    -- Security fields
    {type = "priority", source1 = "severity", source2 = "threat_severity", target = "_severity"},
    {type = "direct", source = "action", target = "_action"},
    {type = "direct", source = "verdict", target = "_verdict"},
    {type = "direct", source = "rule", target = "metadata.product.feature.name"},
    {type = "direct", source = "rule_name", target = "metadata.product.feature.name"},
    
    -- Application info
    {type = "direct", source = "app", target = "app_name"},
    {type = "direct", source = "application", target = "app_name"},
    {type = "direct", source = "url", target = "http_request.url.url_string"},
    {type = "direct", source = "category", target = "category_name"},
    
    -- Device info
    {type = "direct", source = "serial", target = "metadata.product.uid"},
    {type = "direct", source = "device_name", target = "metadata.product.name"},
    
    -- Message and raw data
    {type = "priority", source1 = "message", source2 = "threat_name", source3 = "misc", target = "message"},
    {type = "direct", source = "raw", target = "raw_data"},
    
    -- Fixed OCSF values
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    {type = "computed", target = "metadata.product.vendor_name", value = "Palo Alto Networks"},
}

function processEvent(event)
    if type(event) ~= "table" then return nil end

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
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if value == nil or value == "" then
                if mapping.source2 then value = getNestedField(event, mapping.source2) end
                if (value == nil or value == "") and mapping.source3 then value = getNestedField(event, mapping.source3) end
                if (value == nil or value == "") and mapping.source4 then value = getNestedField(event, mapping.source4) end
            end
            if value ~= nil and value ~= "" then 
                setNestedField(result, mapping.target, value)
            end
            mappedPaths[mapping.source1] = true
            if mapping.source2 then mappedPaths[mapping.source2] = true end
            if mapping.source3 then mappedPaths[mapping.source3] = true end
            if mapping.source4 then mappedPaths[mapping.source4] = true end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end

    -- Set timestamp
    local timestamp = getNestedField(result, "_timestamp")
    result.time = parseTimestamp(timestamp)
    result._timestamp = nil

    -- Set protocol
    local protocol = getNestedField(result, "_protocol")
    if protocol then
        result.protocol_name = mapProtocol(protocol)
    end
    result._protocol = nil

    -- Set severity
    local severity = getNestedField(result, "_severity")
    result.severity_id = getSeverityId(severity)
    result._severity = nil

    -- Determine activity
    local activity_id, activity_name = getActivityInfo(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id

    -- Set status based on action/verdict
    local action = getNestedField(result, "_action") or getNestedField(result, "_verdict")
    if action then
        local actionStr = tostring(action):lower()
        if actionStr == "allow" or actionStr == "permit" then
            result.status = "Success"
            result.status_id = 1
        elseif actionStr == "deny" or actionStr == "block" or actionStr == "drop" then
            result.status = "Failure" 
            result.status_id = 2
        else
            result.status = tostring(action)
            result.status_id = 99
        end
    end
    result._action = nil
    result._verdict = nil

    -- Set default message if not present
    if not result.message then
        result.message = result.activity_name or "Palo Alto Network Activity"
    end

    -- Set product metadata defaults
    if not getNestedField(result, "metadata.product.name") then
        setNestedField(result, "metadata.product.name", "PAN-OS")
    end

    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)

    -- Clean userdata nulls
    no_nulls(result, nil)

    return result
end