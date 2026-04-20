-- pfSense Firewall Logs to OCSF Network Activity transformation
-- Maps pfSense firewall log events to OCSF Network Activity class (4001)

local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Nested field access helper functions
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

-- Collect unmapped fields to preserve data
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Parse pfSense firewall log format (typically CSV-like or syslog format)
function parsePfSenseLog(logLine)
    if type(logLine) ~= "string" then return {} end
    
    -- Common pfSense log patterns - handle both CSV and space-separated formats
    local fields = {}
    
    -- Try to extract common pfSense firewall fields
    -- Pattern for: timestamp,action,interface,protocol,src_ip,src_port,dst_ip,dst_port,length
    local timestamp, action, interface, protocol, src_ip, src_port, dst_ip, dst_port, length = 
        logLine:match("([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)")
    
    if timestamp then
        fields.timestamp = timestamp
        fields.action = action
        fields.interface = interface
        fields.protocol = protocol
        fields.src_ip = src_ip
        fields.src_port = src_port
        fields.dst_ip = dst_ip
        fields.dst_port = dst_port
        fields.length = length
    else
        -- Try space-separated format common in syslog
        local parts = {}
        for part in logLine:gmatch("%S+") do
            table.insert(parts, part)
        end
        
        -- Extract IP addresses, ports, and protocol from parts
        for i, part in ipairs(parts) do
            if part:match("^%d+%.%d+%.%d+%.%d+$") then
                if not fields.src_ip then
                    fields.src_ip = part
                elseif not fields.dst_ip then
                    fields.dst_ip = part
                end
            elseif part:match("^%d+$") and tonumber(part) and tonumber(part) > 0 and tonumber(part) < 65536 then
                if not fields.src_port and fields.src_ip then
                    fields.src_port = part
                elseif not fields.dst_port and fields.dst_ip then
                    fields.dst_port = part
                end
            elseif part:lower():match("^(tcp|udp|icmp)$") then
                fields.protocol = part:upper()
            elseif part:lower():match("^(block|pass|reject|allow|deny)") then
                fields.action = part:lower()
            end
        end
    end
    
    return fields
end

-- Map pfSense action to OCSF activity_id
function getActivityId(action)
    if not action then return 99 end
    local actionLower = string.lower(action)
    
    if actionLower:find("block") or actionLower:find("deny") or actionLower:find("drop") then
        return 2  -- Deny
    elseif actionLower:find("pass") or actionLower:find("allow") or actionLower:find("accept") then
        return 1  -- Allow
    elseif actionLower:find("reject") then
        return 3  -- Reject
    else
        return 99 -- Other
    end
end

-- Get activity name from action
function getActivityName(action)
    if not action then return "Network Traffic" end
    local actionLower = string.lower(action)
    
    if actionLower:find("block") or actionLower:find("deny") or actionLower:find("drop") then
        return "Traffic Denied"
    elseif actionLower:find("pass") or actionLower:find("allow") or actionLower:find("accept") then
        return "Traffic Allowed"
    elseif actionLower:find("reject") then
        return "Traffic Rejected"
    else
        return "Network Traffic"
    end
end

-- Map action to severity
function getSeverityId(action)
    if not action then return 0 end
    local actionLower = string.lower(action)
    
    if actionLower:find("block") or actionLower:find("deny") or actionLower:find("drop") then
        return 3  -- Medium - blocked traffic could indicate attack attempts
    elseif actionLower:find("reject") then
        return 2  -- Low - rejected connections
    elseif actionLower:find("pass") or actionLower:find("allow") or actionLower:find("accept") then
        return 1  -- Informational - allowed traffic
    else
        return 0  -- Unknown
    end
end

-- Parse timestamp to milliseconds since epoch
function parseTimestamp(timestamp)
    if not timestamp then return os.time() * 1000 end
    
    -- Try various timestamp formats common in pfSense logs
    -- ISO format: 2023-12-01T10:30:45
    local yr, mo, dy, hr, mn, sc = timestamp:match("(%d%d%d%d)-(%d%d)-(%d%d)[T ](%d%d):(%d%d):(%d%d)")
    if yr then
        return os.time({year=tonumber(yr), month=tonumber(mo), day=tonumber(dy),
                       hour=tonumber(hr), min=tonumber(mn), sec=tonumber(sc), isdst=false}) * 1000
    end
    
    -- Syslog format: Dec  1 10:30:45
    local month_names = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6,
                        Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
    local mon, day, hour, min, sec = timestamp:match("(%a%a%a)%s+(%d+)%s+(%d+):(%d+):(%d+)")
    if mon and month_names[mon] then
        local current_year = os.date("*t").year
        return os.time({year=current_year, month=month_names[mon], day=tonumber(day),
                       hour=tonumber(hour), min=tonumber(min), sec=tonumber(sec), isdst=false}) * 1000
    end
    
    -- Unix timestamp
    local unix_ts = tonumber(timestamp)
    if unix_ts and unix_ts > 1000000000 then
        return unix_ts * 1000  -- Convert to milliseconds
    end
    
    -- Default to current time
    return os.time() * 1000
end

-- Clean empty tables and nil values
function cleanResult(tbl)
    if type(tbl) ~= "table" then return tbl end
    
    local cleaned = {}
    for k, v in pairs(tbl) do
        if type(v) == "table" then
            local cleanedSub = cleanResult(v)
            if next(cleanedSub) ~= nil then
                cleaned[k] = cleanedSub
            end
        elseif v ~= nil and v ~= "" then
            cleaned[k] = v
        end
    end
    return cleaned
end

-- Main processing function
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Parse log message if it's a string
    local parsedFields = {}
    if type(event.message) == "string" then
        parsedFields = parsePfSenseLog(event.message)
        mappedPaths.message = true
    elseif type(event.raw_data) == "string" then
        parsedFields = parsePfSenseLog(event.raw_data)
        mappedPaths.raw_data = true
    end
    
    -- Merge parsed fields with event data, prioritizing direct event fields
    for k, v in pairs(parsedFields) do
        if event[k] == nil then
            event[k] = v
        end
    end
    
    -- Set OCSF required fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = "Network Activity"
    result.category_name = "Network Activity"
    
    -- Determine activity based on action
    local action = event.action or event.verdict or event.disposition
    result.activity_id = getActivityId(action)
    result.activity_name = getActivityName(action)
    result.type_uid = CLASS_UID * 100 + result.activity_id
    result.severity_id = getSeverityId(action)
    
    -- Set timestamp
    local timestamp = event.timestamp or event.time or event.eventTime or event.datetime
    result.time = parseTimestamp(timestamp)
    
    -- Map network fields
    local src_ip = event.src_ip or event.sourceip or event.source_ip or event.srcip
    if src_ip then
        setNestedField(result, "src_endpoint.ip", src_ip)
        mappedPaths.src_ip = true
        mappedPaths.sourceip = true
        mappedPaths.source_ip = true
        mappedPaths.srcip = true
    end
    
    local src_port = event.src_port or event.sourceport or event.source_port or event.srcport
    if src_port then
        setNestedField(result, "src_endpoint.port", tonumber(src_port) or src_port)
        mappedPaths.src_port = true
        mappedPaths.sourceport = true
        mappedPaths.source_port = true
        mappedPaths.srcport = true
    end
    
    local dst_ip = event.dst_ip or event.destip or event.dest_ip or event.dstip or event.destination_ip
    if dst_ip then
        setNestedField(result, "dst_endpoint.ip", dst_ip)
        mappedPaths.dst_ip = true
        mappedPaths.destip = true
        mappedPaths.dest_ip = true
        mappedPaths.dstip = true
        mappedPaths.destination_ip = true
    end
    
    local dst_port = event.dst_port or event.destport or event.dest_port or event.dstport or event.destination_port
    if dst_port then
        setNestedField(result, "dst_endpoint.port", tonumber(dst_port) or dst_port)
        mappedPaths.dst_port = true
        mappedPaths.destport = true
        mappedPaths.dest_port = true
        mappedPaths.dstport = true
        mappedPaths.destination_port = true
    end
    
    -- Protocol
    local protocol = event.protocol or event.proto or event.ip_protocol
    if protocol then
        result.protocol_name = string.upper(protocol)
        mappedPaths.protocol = true
        mappedPaths.proto = true
        mappedPaths.ip_protocol = true
    end
    
    -- Additional fields
    if event.length or event.bytes then
        local bytes = tonumber(event.length) or tonumber(event.bytes)
        if bytes then
            setNestedField(result, "traffic.bytes", bytes)
            mappedPaths.length = true
            mappedPaths.bytes = true
        end
    end
    
    if event.interface or event.intf then
        setNestedField(result, "src_endpoint.interface_name", event.interface or event.intf)
        mappedPaths.interface = true
        mappedPaths.intf = true
    end
    
    -- Set message and raw_data
    if event.message then
        result.message = event.message
    end
    
    if event.raw_data then
        result.raw_data = event.raw_data
    end
    
    -- Metadata
    setNestedField(result, "metadata.product.name", "pfSense")
    setNestedField(result, "metadata.product.vendor_name", "Netgate")
    setNestedField(result, "metadata.version", "1.0.0")
    
    -- Mark commonly mapped fields
    mappedPaths.action = true
    mappedPaths.verdict = true
    mappedPaths.disposition = true
    mappedPaths.timestamp = true
    mappedPaths.time = true
    mappedPaths.eventTime = true
    mappedPaths.datetime = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean result
    result = cleanResult(result)
    
    return result
end