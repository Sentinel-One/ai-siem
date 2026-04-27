-- Palo Alto VPN Logs to OCSF Network Activity transformation
-- OCSF Class: Network Activity (4001)

local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Helper functions for production-quality parsing
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

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return nil end
    
    -- Try ISO format first: 2023-01-15T10:30:45Z or 2023-01-15T10:30:45.123Z
    local year, month, day, hour, min, sec = timeStr:match("(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)")
    if year then
        return os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        }) * 1000
    end
    
    -- Try Palo Alto format: Jan 15 10:30:45 or 2023/01/15 10:30:45
    local mon, d, h, m, s = timeStr:match("(%a%a%a)%s+(%d+)%s+(%d%d):(%d%d):(%d%d)")
    if mon then
        local months = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6,
                       Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
        return os.time({
            year = os.date("%Y"),
            month = months[mon] or 1,
            day = tonumber(d),
            hour = tonumber(h),
            min = tonumber(m),
            sec = tonumber(s),
            isdst = false
        }) * 1000
    end
    
    return nil
end

-- Map severity levels to OCSF severity_id
local function getSeverityId(severity)
    if not severity then return 0 end
    local sev = tostring(severity):lower()
    
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        warning = 3,
        low = 2,
        info = 1,
        informational = 1,
        debug = 1,
        error = 4,
        alert = 4
    }
    
    return severityMap[sev] or 0
end

-- Determine VPN activity based on event data
local function getVpnActivity(event)
    local action = getValue(event, "action", "")
    local eventType = getValue(event, "event_type", "")
    local subtype = getValue(event, "subtype", "")
    
    if type(action) == "string" then
        action = action:lower()
        if action:match("connect") or action:match("login") or action:match("auth") then
            return 1, "Connect"
        elseif action:match("disconnect") or action:match("logout") or action:match("close") then
            return 2, "Disconnect"
        elseif action:match("tunnel") then
            return 3, "Tunnel Activity"
        elseif action:match("deny") or action:match("block") or action:match("drop") then
            return 4, "Deny"
        elseif action:match("allow") or action:match("permit") then
            return 5, "Allow"
        end
    end
    
    -- Default VPN activity
    return 99, "VPN Activity"
end

-- Field mappings for Palo Alto VPN logs
local fieldMappings = {
    -- Basic OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Network Activity"},
    {type = "computed", target = "category_name", value = "Network Activity"},
    
    -- Source endpoint mappings
    {type = "priority", source1 = "src_ip", source2 = "source_ip", source3 = "srcip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "src_port", source2 = "source_port", source3 = "srcport", target = "src_endpoint.port"},
    {type = "priority", source1 = "src_host", source2 = "source_host", source3 = "srchost", target = "src_endpoint.hostname"},
    
    -- Destination endpoint mappings  
    {type = "priority", source1 = "dst_ip", source2 = "dest_ip", source3 = "dstip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "dst_port", source2 = "dest_port", source3 = "dstport", target = "dst_endpoint.port"},
    {type = "priority", source1 = "dst_host", source2 = "dest_host", source3 = "dsthost", target = "dst_endpoint.hostname"},
    
    -- Protocol and network info
    {type = "priority", source1 = "protocol", source2 = "proto", target = "protocol_name"},
    {type = "priority", source1 = "bytes", source2 = "bytes_sent", target = "traffic.bytes"},
    {type = "priority", source1 = "packets", source2 = "packet_count", target = "traffic.packets"},
    
    -- User and device info
    {type = "priority", source1 = "user", source2 = "username", source3 = "usr", target = "actor.user.name"},
    {type = "priority", source1 = "domain", source2 = "user_domain", target = "actor.user.domain"},
    {type = "priority", source1 = "machine", source2 = "device", source3 = "hostname", target = "device.hostname"},
    
    -- VPN specific fields
    {type = "priority", source1 = "tunnel_id", source2 = "vpn_tunnel", target = "connection_info.uid"},
    {type = "priority", source1 = "gateway", source2 = "vpn_gateway", target = "proxy.ip"},
    {type = "priority", source1 = "client_ip", source2 = "vpn_client_ip", target = "src_endpoint.ip"},
    
    -- Status and error info
    {type = "priority", source1 = "status", source2 = "result", target = "status"},
    {type = "priority", source1 = "reason", source2 = "error_msg", source3 = "message", target = "status_detail"},
    {type = "direct", source = "duration", target = "duration"},
    {type = "direct", source = "session_id", target = "session.uid"},
    
    -- Raw message
    {type = "priority", source1 = "raw", source2 = "original", source3 = "_raw", target = "raw_data"},
    {type = "priority", source1 = "msg", source2 = "message", target = "message"}
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
            local value = nil
            local sources = {mapping.source1, mapping.source2, mapping.source3}
            for _, source in ipairs(sources) do
                if source then
                    value = getNestedField(event, source)
                    if value ~= nil and value ~= "" then break end
                    mappedPaths[source] = true
                end
            end
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
            end
            
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Set VPN activity
    local activity_id, activity_name = getVpnActivity(event)
    result.activity_id = activity_id
    result.activity_name = activity_name
    result.type_uid = CLASS_UID * 100 + activity_id
    
    -- Set severity
    local severity = getValue(event, "severity", getValue(event, "priority", getValue(event, "level", nil)))
    result.severity_id = getSeverityId(severity)
    
    -- Parse timestamp
    local timeFields = {"time", "timestamp", "_time", "event_time", "log_time", "generated_time"}
    local eventTime = nil
    for _, field in ipairs(timeFields) do
        eventTime = getNestedField(event, field)
        if eventTime then
            mappedPaths[field] = true
            break
        end
    end
    
    if eventTime then
        result.time = parseTimestamp(eventTime) or (os.time() * 1000)
    else
        result.time = os.time() * 1000
    end
    
    -- Set metadata
    setNestedField(result, "metadata.product.name", "PAN-OS")
    setNestedField(result, "metadata.product.vendor_name", "Palo Alto Networks")
    setNestedField(result, "metadata.version", "1.0.0")
    
    -- Set status_id based on status
    local status = getNestedField(result, "status")
    if status then
        if type(status) == "string" then
            local statusLower = status:lower()
            if statusLower:match("success") or statusLower:match("allow") or statusLower:match("permit") then
                result.status_id = 1  -- Success
            elseif statusLower:match("fail") or statusLower:match("deny") or statusLower:match("block") then
                result.status_id = 2  -- Failure
            else
                result.status_id = 99 -- Other
            end
        end
    end
    
    -- Add observables for key network indicators
    local observables = {}
    local srcIp = getNestedField(result, "src_endpoint.ip")
    if srcIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address", 
            name = "src_endpoint.ip",
            value = srcIp
        })
    end
    
    local dstIp = getNestedField(result, "dst_endpoint.ip")
    if dstIp then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "dst_endpoint.ip", 
            value = dstIp
        })
    end
    
    local username = getNestedField(result, "actor.user.name")
    if username then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.name",
            value = username
        })
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve data
    copyUnmappedFields(event, mappedPaths, result)
    
    return result
end