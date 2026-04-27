-- SonicWall Firewall Logs to OCSF Network Activity Transformation
-- Class: Network Activity (4001), Category: Network Activity (4)

local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Activity mapping for SonicWall firewall events
local ACTIVITY_MAP = {
    ["Connection Opened"] = {id = 1, name = "Open"},
    ["Connection Closed"] = {id = 2, name = "Close"},
    ["Connection Denied"] = {id = 3, name = "Refuse"},
    ["Traffic Allowed"] = {id = 1, name = "Allow"},
    ["Traffic Blocked"] = {id = 3, name = "Block"},
    ["Traffic Denied"] = {id = 3, name = "Deny"},
    ["Session Started"] = {id = 1, name = "Open"},
    ["Session Ended"] = {id = 2, name = "Close"},
    ["default"] = {id = 99, name = "Other"}
}

-- Protocol mapping
local PROTOCOL_MAP = {
    ["1"] = "ICMP", ["6"] = "TCP", ["17"] = "UDP", ["47"] = "GRE", ["50"] = "ESP", ["51"] = "AH"
}

-- Severity mapping for SonicWall priority levels
local function getSeverityId(priority)
    if priority == nil or priority == "" then return 0 end
    local prio = tostring(priority):lower()
    if prio:match("critical") or prio:match("emerg") then return 5
    elseif prio:match("high") or prio:match("alert") then return 4
    elseif prio:match("medium") or prio:match("warn") then return 3
    elseif prio:match("low") or prio:match("notice") then return 2
    elseif prio:match("info") then return 1
    else return 0 end
end

-- Parse SonicWall timestamp to epoch milliseconds
local function parseTimestamp(timestamp)
    if not timestamp or timestamp == "" then return os.time() * 1000 end
    
    -- Try various SonicWall timestamp formats
    -- Format: YYYY-MM-DD HH:MM:SS UTC
    local year, month, day, hour, min, sec = timestamp:match("(%d%d%d%d)%-(%d%d)%-(%d%d) (%d%d):(%d%d):(%d%d)")
    if year then
        local time_table = {
            year = tonumber(year), month = tonumber(month), day = tonumber(day),
            hour = tonumber(hour), min = tonumber(min), sec = tonumber(sec)
        }
        return os.time(time_table) * 1000
    end
    
    -- Format: MMM DD YYYY HH:MM:SS
    local mon, d, y, h, m, s = timestamp:match("(%a%a%a) (%d+) (%d%d%d%d) (%d+):(%d+):(%d+)")
    if mon then
        local months = {Jan=1,Feb=2,Mar=3,Apr=4,May=5,Jun=6,Jul=7,Aug=8,Sep=9,Oct=10,Nov=11,Dec=12}
        local time_table = {
            year = tonumber(y), month = months[mon], day = tonumber(d),
            hour = tonumber(h), min = tonumber(m), sec = tonumber(s)
        }
        return os.time(time_table) * 1000
    end
    
    return os.time() * 1000
end

-- Determine activity from SonicWall action and message
local function getActivity(action, message, msg)
    local text = (action or "") .. " " .. (message or "") .. " " .. (msg or "")
    text = text:lower()
    
    if text:match("open") or text:match("allow") or text:match("permit") then
        return ACTIVITY_MAP["Connection Opened"]
    elseif text:match("close") or text:match("end") or text:match("terminate") then
        return ACTIVITY_MAP["Connection Closed"]
    elseif text:match("block") or text:match("deny") or text:match("drop") or text:match("refuse") then
        return ACTIVITY_MAP["Connection Denied"]
    else
        return ACTIVITY_MAP["default"]
    end
end

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

function getValue(tbl, key, default)
    if type(tbl) ~= "table" then return default end
    local value = tbl[key]
    return value ~= nil and value or default
end

-- Collect unmapped fields
function copyUnmappedFields(event, mappedPaths, result)
    if type(event) ~= "table" then return end
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            if not result.unmapped then result.unmapped = {} end
            result.unmapped[k] = v
        end
    end
end

-- Main transformation function
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Set OCSF class information
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = "Network Activity"
    result.category_name = "Network Activity"
    
    -- Parse timestamp
    local timestamp = getValue(event, "time", "") or getValue(event, "timestamp", "") or getValue(event, "date", "")
    result.time = parseTimestamp(timestamp)
    mappedPaths["time"] = true
    mappedPaths["timestamp"] = true
    mappedPaths["date"] = true
    
    -- Determine activity
    local action = getValue(event, "action", "")
    local message = getValue(event, "message", "")
    local msg = getValue(event, "msg", "")
    local activity = getActivity(action, message, msg)
    result.activity_id = activity.id
    result.activity_name = activity.name
    result.type_uid = CLASS_UID * 100 + activity.id
    mappedPaths["action"] = true
    mappedPaths["message"] = true
    mappedPaths["msg"] = true
    
    -- Set severity
    local priority = getValue(event, "priority", "") or getValue(event, "pri", "") or getValue(event, "severity", "")
    result.severity_id = getSeverityId(priority)
    mappedPaths["priority"] = true
    mappedPaths["pri"] = true
    mappedPaths["severity"] = true
    
    -- Source endpoint information
    local src_ip = getValue(event, "src", "") or getValue(event, "srcip", "") or getValue(event, "source_ip", "")
    if src_ip and src_ip ~= "" then
        setNestedField(result, "src_endpoint.ip", src_ip)
        mappedPaths["src"] = true
        mappedPaths["srcip"] = true
        mappedPaths["source_ip"] = true
    end
    
    local src_port = getValue(event, "srcport", "") or getValue(event, "src_port", "") or getValue(event, "sport", "")
    if src_port and src_port ~= "" then
        setNestedField(result, "src_endpoint.port", tonumber(src_port) or src_port)
        mappedPaths["srcport"] = true
        mappedPaths["src_port"] = true
        mappedPaths["sport"] = true
    end
    
    -- Destination endpoint information
    local dst_ip = getValue(event, "dst", "") or getValue(event, "dstip", "") or getValue(event, "dest_ip", "")
    if dst_ip and dst_ip ~= "" then
        setNestedField(result, "dst_endpoint.ip", dst_ip)
        mappedPaths["dst"] = true
        mappedPaths["dstip"] = true
        mappedPaths["dest_ip"] = true
    end
    
    local dst_port = getValue(event, "dstport", "") or getValue(event, "dst_port", "") or getValue(event, "dport", "")
    if dst_port and dst_port ~= "" then
        setNestedField(result, "dst_endpoint.port", tonumber(dst_port) or dst_port)
        mappedPaths["dstport"] = true
        mappedPaths["dst_port"] = true
        mappedPaths["dport"] = true
    end
    
    -- Protocol information
    local protocol = getValue(event, "proto", "") or getValue(event, "protocol", "") or getValue(event, "ip_proto", "")
    if protocol and protocol ~= "" then
        -- Map numeric protocol to name
        local proto_name = PROTOCOL_MAP[tostring(protocol)] or protocol
        result.protocol_name = proto_name
        mappedPaths["proto"] = true
        mappedPaths["protocol"] = true
        mappedPaths["ip_proto"] = true
    end
    
    -- Traffic statistics
    local sent_bytes = getValue(event, "sent", "") or getValue(event, "bytes_sent", "")
    if sent_bytes and sent_bytes ~= "" then
        setNestedField(result, "traffic.bytes_out", tonumber(sent_bytes) or sent_bytes)
        mappedPaths["sent"] = true
        mappedPaths["bytes_sent"] = true
    end
    
    local rcvd_bytes = getValue(event, "rcvd", "") or getValue(event, "bytes_received", "")
    if rcvd_bytes and rcvd_bytes ~= "" then
        setNestedField(result, "traffic.bytes_in", tonumber(rcvd_bytes) or rcvd_bytes)
        mappedPaths["rcvd"] = true
        mappedPaths["bytes_received"] = true
    end
    
    -- Duration
    local duration = getValue(event, "duration", "") or getValue(event, "elapsed", "")
    if duration and duration ~= "" then
        result.duration = tonumber(duration) or duration
        mappedPaths["duration"] = true
        mappedPaths["elapsed"] = true
    end
    
    -- Device/interface information
    local interface = getValue(event, "interface", "") or getValue(event, "intf", "")
    if interface and interface ~= "" then
        setNestedField(result, "src_endpoint.interface_name", interface)
        mappedPaths["interface"] = true
        mappedPaths["intf"] = true
    end
    
    -- Zone information
    local src_zone = getValue(event, "srczone", "") or getValue(event, "src_zone", "")
    if src_zone and src_zone ~= "" then
        setNestedField(result, "src_endpoint.zone", src_zone)
        mappedPaths["srczone"] = true
        mappedPaths["src_zone"] = true
    end
    
    local dst_zone = getValue(event, "dstzone", "") or getValue(event, "dst_zone", "")
    if dst_zone and dst_zone ~= "" then
        setNestedField(result, "dst_endpoint.zone", dst_zone)
        mappedPaths["dstzone"] = true
        mappedPaths["dst_zone"] = true
    end
    
    -- Set metadata for SonicWall
    setNestedField(result, "metadata.product.name", "SonicWall Firewall")
    setNestedField(result, "metadata.product.vendor_name", "SonicWall")
    setNestedField(result, "metadata.version", "1.0.0")
    
    -- Preserve original message
    if message and message ~= "" then
        result.message = message
    elseif msg and msg ~= "" then
        result.message = msg
    end
    
    -- Store raw data if available
    local raw = getValue(event, "raw", "") or getValue(event, "raw_data", "")
    if raw and raw ~= "" then
        result.raw_data = raw
        mappedPaths["raw"] = true
        mappedPaths["raw_data"] = true
    end
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end