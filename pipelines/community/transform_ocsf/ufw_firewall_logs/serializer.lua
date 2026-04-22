-- UFW Firewall Logs OCSF Transformation
-- Maps UFW firewall log events to OCSF Network Activity class

-- Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4
local CLASS_NAME = "Network Activity"
local CATEGORY_NAME = "Network Activity"

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

-- Parse UFW log message format
function parseUfwMessage(message)
    if type(message) ~= "string" then return {} end
    
    local parsed = {}
    
    -- Extract action (ALLOW/BLOCK/DENY)
    local action = message:match("%[UFW ([A-Z]+)%]") or message:match("UFW: ([A-Z]+)")
    if action then parsed.action = action end
    
    -- Extract source IP and port
    local src_ip, src_port = message:match("SRC=([%d%.]+).-SPT=(%d+)")
    if src_ip then parsed.src_ip = src_ip end
    if src_port then parsed.src_port = tonumber(src_port) end
    
    -- Extract destination IP and port
    local dst_ip, dst_port = message:match("DST=([%d%.]+).-DPT=(%d+)")
    if dst_ip then parsed.dst_ip = dst_ip end
    if dst_port then parsed.dst_port = tonumber(dst_port) end
    
    -- Extract protocol
    local protocol = message:match("PROTO=([%w]+)")
    if protocol then parsed.protocol = protocol end
    
    -- Extract interface
    local interface = message:match("IN=([%w%-%.]+)")
    if interface and interface ~= "" then parsed.interface_in = interface end
    
    local out_interface = message:match("OUT=([%w%-%.]+)")
    if out_interface and out_interface ~= "" then parsed.interface_out = out_interface end
    
    -- Extract MAC addresses
    local mac = message:match("MAC=([%w%:]+)")
    if mac then parsed.mac = mac end
    
    -- Extract length
    local len = message:match("LEN=(%d+)")
    if len then parsed.length = tonumber(len) end
    
    -- Extract TTL
    local ttl = message:match("TTL=(%d+)")
    if ttl then parsed.ttl = tonumber(ttl) end
    
    return parsed
end

-- Map UFW action to OCSF activity_id
function getActivityId(action)
    if not action then return 99 end -- Other
    local actionMap = {
        ALLOW = 1,    -- Allow
        BLOCK = 2,    -- Deny  
        DENY = 2,     -- Deny
        DROP = 2,     -- Deny
        REJECT = 2    -- Deny
    }
    return actionMap[action:upper()] or 99
end

-- Map action to severity
function getSeverityFromAction(action)
    if not action then return 1 end -- Informational
    local severityMap = {
        ALLOW = 1,    -- Informational
        BLOCK = 3,    -- Medium
        DENY = 3,     -- Medium
        DROP = 3,     -- Medium
        REJECT = 3    -- Medium
    }
    return severityMap[action:upper()] or 1
end

-- Convert timestamp to milliseconds since epoch
function parseTimestamp(timestamp)
    if not timestamp then return os.time() * 1000 end
    
    -- Handle various timestamp formats
    if type(timestamp) == "number" then
        -- Already epoch time
        return timestamp < 1e12 and timestamp * 1000 or timestamp
    end
    
    if type(timestamp) == "string" then
        -- Try ISO format
        local year, month, day, hour, min, sec = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
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
        
        -- Try syslog format (Oct 15 14:30:25)
        local months = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6, Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
        local mon, day2, hour2, min2, sec2 = timestamp:match("(%a+)%s+(%d+)%s+(%d+):(%d+):(%d+)")
        if mon and months[mon] then
            local time_table = {
                year = os.date("%Y"),
                month = months[mon],
                day = tonumber(day2),
                hour = tonumber(hour2),
                min = tonumber(min2),
                sec = tonumber(sec2),
                isdst = false
            }
            return os.time(time_table) * 1000
        end
    end
    
    return os.time() * 1000
end

-- Main transformation function
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Set OCSF required fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = CLASS_NAME
    result.category_name = CATEGORY_NAME
    
    -- Parse message field or raw log
    local message = event.message or event.raw_data or event.log or event._raw or ""
    local parsed = parseUfwMessage(message)
    
    -- Map activity and type
    local activity_id = getActivityId(parsed.action)
    result.activity_id = activity_id
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set activity name
    if parsed.action then
        result.activity_name = "Firewall " .. parsed.action
        mappedPaths.action = true
    else
        result.activity_name = "Network Activity"
    end
    
    -- Set severity based on action
    result.severity_id = getSeverityFromAction(parsed.action)
    
    -- Map timestamp
    local timestamp = event.timestamp or event.time or event["@timestamp"] or event.eventTime
    result.time = parseTimestamp(timestamp)
    if event.timestamp then mappedPaths.timestamp = true end
    if event.time then mappedPaths.time = true end
    if event["@timestamp"] then mappedPaths["@timestamp"] = true end
    if event.eventTime then mappedPaths.eventTime = true end
    
    -- Map source endpoint
    if parsed.src_ip then
        setNestedField(result, "src_endpoint.ip", parsed.src_ip)
    end
    if parsed.src_port then
        setNestedField(result, "src_endpoint.port", parsed.src_port)
    end
    
    -- Map destination endpoint  
    if parsed.dst_ip then
        setNestedField(result, "dst_endpoint.ip", parsed.dst_ip)
    end
    if parsed.dst_port then
        setNestedField(result, "dst_endpoint.port", parsed.dst_port)
    end
    
    -- Map protocol
    if parsed.protocol then
        result.protocol_name = parsed.protocol
    end
    
    -- Set metadata
    setNestedField(result, "metadata.product.name", "UFW Firewall")
    setNestedField(result, "metadata.product.vendor_name", "Ubuntu")
    setNestedField(result, "metadata.version", "1.0.0")
    
    -- Set status based on action
    if parsed.action then
        if parsed.action == "ALLOW" then
            result.status = "Success"
            result.status_id = 1
        else
            result.status = "Failure" 
            result.status_id = 2
        end
    end
    
    -- Store original message
    if message and message ~= "" then
        result.message = message
        mappedPaths.message = true
        mappedPaths.raw_data = true
        mappedPaths.log = true
        mappedPaths["_raw"] = true
    end
    
    -- Add additional parsed fields to unmapped
    if parsed.interface_in then
        setNestedField(result, "unmapped.interface_in", parsed.interface_in)
    end
    if parsed.interface_out then  
        setNestedField(result, "unmapped.interface_out", parsed.interface_out)
    end
    if parsed.mac then
        setNestedField(result, "unmapped.mac", parsed.mac)
    end
    if parsed.length then
        setNestedField(result, "unmapped.packet_length", parsed.length)
    end
    if parsed.ttl then
        setNestedField(result, "unmapped.ttl", parsed.ttl)
    end
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up nulls
    result = no_nulls(result, nil)
    
    return result
end