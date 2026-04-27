-- Cisco Meraki Network Activity Parser
-- Maps Cisco Meraki logs to OCSF Network Activity (class_uid=4001)

local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Common Meraki event types to activity mapping
local EVENT_TYPE_MAPPING = {
    ['flows'] = {activity_id = 5, activity_name = 'Traffic Flow'},
    ['urls'] = {activity_id = 6, activity_name = 'URL Request'},
    ['ids-alerts'] = {activity_id = 99, activity_name = 'IDS Alert'},
    ['security_event'] = {activity_id = 99, activity_name = 'Security Event'},
    ['vpn_connectivity_change'] = {activity_id = 1, activity_name = 'VPN Connection'},
    ['dhcp'] = {activity_id = 99, activity_name = 'DHCP Event'},
    ['firewall'] = {activity_id = 2, activity_name = 'Firewall Action'},
    ['content_filtering_block'] = {activity_id = 2, activity_name = 'Content Filter Block'},
    ['amp'] = {activity_id = 99, activity_name = 'AMP Event'},
    ['airmarshal_events'] = {activity_id = 99, activity_name = 'Air Marshal Event'}
}

-- Severity mapping for Meraki priorities/actions
local function getSeverityId(priority, action, type)
    if priority then
        local p = string.lower(tostring(priority))
        if p == "critical" or p == "high" then return 4
        elseif p == "medium" then return 3
        elseif p == "low" then return 2
        elseif p == "info" or p == "informational" then return 1
        end
    end
    
    if action then
        local a = string.lower(tostring(action))
        if a == "block" or a == "deny" or a == "drop" then return 4
        elseif a == "allow" or a == "permit" then return 1
        end
    end
    
    if type then
        local t = string.lower(tostring(type))
        if string.find(t, "alert") or string.find(t, "security") then return 4
        elseif string.find(t, "block") then return 4
        end
    end
    
    return 1  -- Default to Informational
end

-- Parse timestamp to milliseconds
local function parseTime(timestamp)
    if not timestamp then return os.time() * 1000 end
    
    -- Handle Unix timestamp
    local ts = tonumber(timestamp)
    if ts then
        if ts < 10000000000 then  -- Seconds
            return ts * 1000
        else  -- Already milliseconds
            return ts
        end
    end
    
    -- Handle ISO format: 2023-01-01T12:00:00Z or 2023-01-01T12:00:00.123Z
    local year, month, day, hour, min, sec, ms = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z?")
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
        local epoch_time = os.time(time_table) * 1000
        if ms and ms ~= "" then
            epoch_time = epoch_time + tonumber(ms)
        end
        return epoch_time
    end
    
    return os.time() * 1000
end

-- Helper functions from production patterns
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
    if type(tbl) ~= "table" then return default end
    local value = tbl[key]
    return value ~= nil and value or default
end

function copyUnmappedFields(event, mappedPaths, result)
    if type(event) ~= "table" then return end
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Main field mappings for Cisco Meraki
local fieldMappings = {
    -- OCSF Required Fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Network endpoints
    {type = "priority", source1 = "src_ip", source2 = "sip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "dst_ip", source2 = "dip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "sport", target = "src_endpoint.port"},
    {type = "priority", source1 = "dst_port", source2 = "dport", target = "dst_endpoint.port"},
    {type = "direct", source = "src_mac", target = "src_endpoint.mac"},
    {type = "direct", source = "dst_mac", target = "dst_endpoint.mac"},
    
    -- Protocol and network details
    {type = "priority", source1 = "protocol", source2 = "ip_protocol", target = "protocol_name"},
    {type = "direct", source = "protocol_num", target = "ip_protocol"},
    
    -- Traffic metrics
    {type = "direct", source = "sent_bytes", target = "traffic.bytes_out"},
    {type = "direct", source = "recv_bytes", target = "traffic.bytes_in"},
    {type = "direct", source = "sent_packets", target = "traffic.packets_out"},
    {type = "direct", source = "recv_packets", target = "traffic.packets_in"},
    
    -- Event details
    {type = "priority", source1 = "msg", source2 = "message", target = "message"},
    {type = "direct", source = "action", target = "disposition"},
    {type = "direct", source = "reason", target = "status_detail"},
    {type = "direct", source = "rule", target = "rule.name"},
    {type = "direct", source = "policy", target = "policy.name"},
    
    -- Device and metadata
    {type = "direct", source = "device_mac", target = "device.mac"},
    {type = "direct", source = "device_name", target = "device.name"},
    {type = "direct", source = "device_type", target = "device.type"},
    {type = "direct", source = "client_mac", target = "src_endpoint.mac"},
    {type = "direct", source = "client_ip", target = "src_endpoint.ip"},
    
    -- URL and web filtering
    {type = "direct", source = "url", target = "http_request.url.url_string"},
    {type = "direct", source = "request_disposition", target = "http_request.url.category_ids"},
    
    -- VPN specific
    {type = "direct", source = "vpn_type", target = "connection_info.protocol_name"},
    {type = "direct", source = "peer_identity", target = "dst_endpoint.name"},
    
    -- Security events
    {type = "direct", source = "signature", target = "malware.name"},
    {type = "direct", source = "priority", target = "severity"},
    {type = "direct", source = "classification", target = "class_name"}
}

function processEvent(event)
    -- Input validation
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
    
    -- Determine event type and activity
    local eventType = getValue(event, "type", "")
    local eventName = getValue(event, "event_type", eventType)
    local activity_mapping = EVENT_TYPE_MAPPING[eventType] or EVENT_TYPE_MAPPING[eventName]
    
    if activity_mapping then
        result.activity_id = activity_mapping.activity_id
        result.activity_name = activity_mapping.activity_name
    else
        result.activity_id = 99  -- Other
        result.activity_name = eventName ~= "" and eventName or "Network Activity"
    end
    
    -- Calculate type_uid
    result.type_uid = CLASS_UID * 100 + result.activity_id
    
    -- Set severity
    result.severity_id = getSeverityId(
        getValue(event, "priority", nil),
        getValue(event, "action", nil),
        getValue(event, "type", nil)
    )
    
    -- Parse timestamp
    local timestamp = getValue(event, "ts", getValue(event, "timestamp", nil))
    result.time = parseTime(timestamp)
    
    -- Set status based on action
    local action = getValue(event, "action", "")
    if action ~= "" then
        if string.lower(action) == "allow" or string.lower(action) == "permit" then
            result.status_id = 1  -- Success
            result.status = "Success"
        elseif string.lower(action) == "block" or string.lower(action) == "deny" then
            result.status_id = 2  -- Failure
            result.status = "Failure"
        else
            result.status_id = 99  -- Other
            result.status = action
        end
    end
    
    -- Metadata
    result.metadata = {
        product = {
            name = "Meraki",
            vendor_name = "Cisco"
        },
        version = "1.0"
    }
    
    -- Set raw_data if available
    local raw = getValue(event, "raw", getValue(event, "_raw", nil))
    if raw then
        result.raw_data = raw
    end
    
    -- Duration for flow events
    local duration = getValue(event, "duration", nil)
    if duration then
        result.duration = tonumber(duration)
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end