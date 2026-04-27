-- Fortinet FortiGate Network Activity Transformation to OCSF 4001
-- Handles firewall, VPN, IPS, web filter, and other network events

-- OCSF Constants
local CLASS_UID = 4001
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

-- FortiGate specific severity mapping
local function getSeverityId(level)
    if level == nil then return 1 end
    local levelStr = tostring(level):lower()
    
    -- FortiGate uses numeric levels and text levels
    if levelStr == "critical" or levelStr == "5" then return 5
    elseif levelStr == "high" or levelStr == "4" then return 4
    elseif levelStr == "medium" or levelStr == "3" then return 3
    elseif levelStr == "low" or levelStr == "2" then return 2
    elseif levelStr == "information" or levelStr == "informational" or levelStr == "1" then return 1
    elseif levelStr == "warning" or levelStr == "warn" then return 2
    elseif levelStr == "error" then return 4
    else return 1 end
end

-- FortiGate activity mapping based on subtype and logid
local function getActivityId(subtype, logid, action)
    local subtypeStr = tostring(subtype or ""):lower()
    local actionStr = tostring(action or ""):lower()
    
    -- Traffic/Firewall logs
    if subtypeStr == "forward" or subtypeStr == "local" or subtypeStr == "multicast" then
        if actionStr == "accept" or actionStr == "allow" then return 1 -- Allow
        elseif actionStr == "deny" or actionStr == "block" then return 2 -- Deny
        else return 5 -- Traffic
        end
    -- VPN logs
    elseif subtypeStr == "vpn" then return 7 -- VPN Activity
    -- IPS/UTM logs
    elseif subtypeStr == "ips" or subtypeStr == "app-ctrl" or subtypeStr == "webfilter" then
        return 6 -- Security Event
    -- Authentication logs
    elseif subtypeStr == "auth" then return 3 -- Authentication
    -- System logs
    elseif subtypeStr == "system" then return 4 -- Configuration
    else return 99 -- Other
    end
end

-- Time parsing for FortiGate timestamp formats
local function parseFortiGateTime(timeStr)
    if not timeStr then return os.time() * 1000 end
    
    -- Try Unix timestamp first (common in FortiGate logs)
    local unixTime = tonumber(timeStr)
    if unixTime then
        return unixTime * 1000 -- Convert to milliseconds
    end
    
    -- Try ISO format: YYYY-MM-DDTHH:MM:SS
    local year, month, day, hour, min, sec = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if year then
        return os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec)
        }) * 1000
    end
    
    -- Try date format: YYYY-MM-DD HH:MM:SS
    year, month, day, hour, min, sec = timeStr:match("(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)")
    if year then
        return os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec)
        }) * 1000
    end
    
    -- Default to current time
    return os.time() * 1000
end

-- Main transformation function
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Field mappings for FortiGate logs
    local fieldMappings = {
        -- OCSF Required Fields
        {type = "computed", target = "class_uid", value = CLASS_UID},
        {type = "computed", target = "category_uid", value = CATEGORY_UID},
        {type = "computed", target = "class_name", value = "Network Activity"},
        {type = "computed", target = "category_name", value = "Network Activity"},
        
        -- Source endpoint
        {type = "direct", source = "srcip", target = "src_endpoint.ip"},
        {type = "direct", source = "srcport", target = "src_endpoint.port"},
        {type = "direct", source = "srcname", target = "src_endpoint.hostname"},
        {type = "direct", source = "srcintf", target = "src_endpoint.interface_name"},
        {type = "direct", source = "srcintfrole", target = "src_endpoint.interface_uid"},
        
        -- Destination endpoint
        {type = "direct", source = "dstip", target = "dst_endpoint.ip"},
        {type = "direct", source = "dstport", target = "dst_endpoint.port"},
        {type = "direct", source = "dstname", target = "dst_endpoint.hostname"},
        {type = "direct", source = "dstintf", target = "dst_endpoint.interface_name"},
        {type = "direct", source = "dstintfrole", target = "dst_endpoint.interface_uid"},
        
        -- Protocol and traffic
        {type = "direct", source = "proto", target = "connection_info.protocol_num"},
        {type = "direct", source = "service", target = "connection_info.protocol_name"},
        {type = "direct", source = "app", target = "app_name"},
        {type = "direct", source = "appcat", target = "app_category"},
        
        -- Traffic stats
        {type = "direct", source = "sentbyte", target = "traffic.bytes_out"},
        {type = "direct", source = "rcvdbyte", target = "traffic.bytes_in"},
        {type = "direct", source = "sentpkt", target = "traffic.packets_out"},
        {type = "direct", source = "rcvdpkt", target = "traffic.packets_in"},
        {type = "direct", source = "duration", target = "duration"},
        
        -- Security and policy
        {type = "direct", source = "policyid", target = "policy.uid"},
        {type = "direct", source = "policyname", target = "policy.name"},
        {type = "direct", source = "policytype", target = "policy.type"},
        {type = "direct", source = "action", target = "disposition"},
        {type = "direct", source = "status", target = "status"},
        
        -- User information
        {type = "direct", source = "user", target = "actor.user.name"},
        {type = "direct", source = "group", target = "actor.user.groups"},
        {type = "direct", source = "authserver", target = "actor.authorizations"},
        
        -- Device and metadata
        {type = "direct", source = "devname", target = "metadata.product.name"},
        {type = "direct", source = "devid", target = "device.uid"},
        {type = "direct", source = "vd", target = "device.vlan_uid"},
        {type = "direct", source = "logid", target = "metadata.log_name"},
        {type = "direct", source = "type", target = "metadata.log_provider"},
        {type = "direct", source = "subtype", target = "type_name"},
        
        -- Message and details
        {type = "direct", source = "msg", target = "message"},
        {type = "direct", source = "logdesc", target = "status_detail"},
        {type = "direct", source = "attack", target = "finding.title"},
        {type = "direct", source = "attackid", target = "finding.uid"},
        {type = "direct", source = "ref", target = "finding.src_url"},
        
        -- URL and web filtering
        {type = "direct", source = "url", target = "http_request.url.url_string"},
        {type = "direct", source = "hostname", target = "http_request.url.hostname"},
        {type = "direct", source = "urlcat", target = "http_request.url.category_ids"},
        {type = "direct", source = "method", target = "http_request.http_method"},
        {type = "direct", source = "httpmethod", target = "http_request.http_method"},
        {type = "direct", source = "agent", target = "http_request.user_agent"}
    }
    
    -- Process all field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getNestedField(event, mapping.source)
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
                mappedPaths[mapping.source] = true
            end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set activity_id based on FortiGate event characteristics
    local activityId = getActivityId(event.subtype, event.logid, event.action)
    result.activity_id = activityId
    result.type_uid = CLASS_UID * 100 + activityId
    mappedPaths.subtype = true
    mappedPaths.logid = true
    mappedPaths.action = true
    
    -- Set activity_name based on activity_id
    local activityNames = {
        [1] = "Allow",
        [2] = "Deny", 
        [3] = "Authentication",
        [4] = "Configuration",
        [5] = "Traffic",
        [6] = "Security Event",
        [7] = "VPN Activity",
        [99] = "Other"
    }
    result.activity_name = activityNames[activityId] or "Unknown"
    
    -- Set severity based on FortiGate level or priority
    local severity = event.level or event.priority or event.pri
    result.severity_id = getSeverityId(severity)
    if severity then mappedPaths.level = true; mappedPaths.priority = true; mappedPaths.pri = true end
    
    -- Parse timestamp
    local timeField = event.eventtime or event.timestamp or event.date or event.time
    result.time = parseFortiGateTime(timeField)
    if timeField then 
        mappedPaths.eventtime = true
        mappedPaths.timestamp = true
        mappedPaths.date = true
        mappedPaths.time = true
    end
    
    -- Set metadata
    setNestedField(result, "metadata.product.vendor_name", "Fortinet")
    if not getNestedField(result, "metadata.product.name") then
        setNestedField(result, "metadata.product.name", "FortiGate")
    end
    setNestedField(result, "metadata.version", "1.0.0")
    
    -- Set protocol name if we have protocol number
    local protoNum = tonumber(getNestedField(result, "connection_info.protocol_num"))
    if protoNum then
        local protoNames = {[1] = "ICMP", [6] = "TCP", [17] = "UDP", [47] = "GRE", [50] = "ESP", [51] = "AH"}
        if protoNames[protoNum] then
            setNestedField(result, "connection_info.protocol_name", protoNames[protoNum])
        end
    end
    
    -- Convert port numbers to integers
    if result.src_endpoint and result.src_endpoint.port then
        result.src_endpoint.port = tonumber(result.src_endpoint.port)
    end
    if result.dst_endpoint and result.dst_endpoint.port then
        result.dst_endpoint.port = tonumber(result.dst_endpoint.port)
    end
    
    -- Convert traffic stats to numbers
    if result.traffic then
        if result.traffic.bytes_in then result.traffic.bytes_in = tonumber(result.traffic.bytes_in) end
        if result.traffic.bytes_out then result.traffic.bytes_out = tonumber(result.traffic.bytes_out) end
        if result.traffic.packets_in then result.traffic.packets_in = tonumber(result.traffic.packets_in) end
        if result.traffic.packets_out then result.traffic.packets_out = tonumber(result.traffic.packets_out) end
    end
    if result.duration then result.duration = tonumber(result.duration) end
    
    -- Set disposition_id based on action
    local actionStr = tostring(result.disposition or ""):lower()
    if actionStr == "allow" or actionStr == "accept" then
        result.disposition_id = 1 -- Allowed
    elseif actionStr == "deny" or actionStr == "block" or actionStr == "close" then
        result.disposition_id = 2 -- Blocked
    elseif actionStr == "drop" then
        result.disposition_id = 3 -- Dropped
    else
        result.disposition_id = 99 -- Other
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end