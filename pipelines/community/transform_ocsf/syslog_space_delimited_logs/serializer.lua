-- Constants
local CLASS_UID = 4001
local CATEGORY_UID = 4

-- Nested field access (production-proven from Observo scripts)
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
    if type(tbl) ~= "table" then return default end
    local value = tbl[key]
    return value ~= nil and value or default
end

-- Replace userdata nil values (Observo sandbox quirk)
function no_nulls(d, rn)
    if type(d) == "table" then
        for k, v in pairs(d) do
            if type(v) == "userdata" then d[k] = rn
            elseif type(v) == "table" then no_nulls(v, rn) end
        end
    end
    return d
end

-- Collect unmapped fields (preserves data not in field mappings)
function copyUnmappedFields(event, mappedPaths, result)
    for k, v in pairs(event) do
        if not mappedPaths[k] and k ~= "_ob" and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
end

-- Parse space-delimited log format and extract key-value pairs
function parseSpaceDelimitedLog(logString)
    if type(logString) ~= "string" then return {} end
    
    local fields = {}
    local i = 1
    local len = #logString
    
    while i <= len do
        -- Skip whitespace
        while i <= len and logString:sub(i, i):match("%s") do
            i = i + 1
        end
        
        if i > len then break end
        
        local key, value
        local keyStart = i
        
        -- Find key (until = or space)
        while i <= len and not logString:sub(i, i):match("[=%s]") do
            i = i + 1
        end
        
        key = logString:sub(keyStart, i - 1)
        
        if i <= len and logString:sub(i, i) == "=" then
            i = i + 1 -- skip =
            local valueStart = i
            
            -- Check if value is quoted
            if i <= len and logString:sub(i, i):match("['\"]") then
                local quote = logString:sub(i, i)
                i = i + 1 -- skip opening quote
                valueStart = i
                -- Find closing quote
                while i <= len and logString:sub(i, i) ~= quote do
                    i = i + 1
                end
                value = logString:sub(valueStart, i - 1)
                if i <= len then i = i + 1 end -- skip closing quote
            else
                -- Find end of unquoted value (space or end)
                while i <= len and not logString:sub(i, i):match("%s") do
                    i = i + 1
                end
                value = logString:sub(valueStart, i - 1)
            end
        else
            -- Key without value
            value = key
        end
        
        if key and key ~= "" then
            fields[key] = value
        end
    end
    
    return fields
end

-- Extract IP addresses from string
function extractIPs(str)
    if type(str) ~= "string" then return nil, nil end
    local srcIP, dstIP
    -- Look for patterns like src=ip dst=ip or from ip to ip
    srcIP = str:match("src[=%s]*([%d%.]+)")
    dstIP = str:match("dst[=%s]*([%d%.]+)")
    if not srcIP then srcIP = str:match("from[%s]+([%d%.]+)") end
    if not dstIP then dstIP = str:match("to[%s]+([%d%.]+)") end
    return srcIP, dstIP
end

-- Extract ports from string
function extractPorts(str)
    if type(str) ~= "string" then return nil, nil end
    local srcPort, dstPort
    srcPort = str:match("sport[=%s]*(%d+)")
    dstPort = str:match("dport[=%s]*(%d+)")
    if not srcPort then srcPort = str:match("from[%s]+[%d%.]+[:%s]+(%d+)") end
    if not dstPort then dstPort = str:match("to[%s]+[%d%.]+[:%s]+(%d+)") end
    return srcPort and tonumber(srcPort), dstPort and tonumber(dstPort)
end

-- Get severity ID from various severity indicators
function getSeverityId(event)
    -- Check various common severity fields
    local severityFields = {"severity", "priority", "level", "sev", "pri"}
    for _, field in ipairs(severityFields) do
        local value = event[field]
        if value then
            if type(value) == "string" then
                local lower = string.lower(value)
                if lower:match("crit") or lower:match("fatal") then return 5
                elseif lower:match("high") or lower:match("error") then return 4
                elseif lower:match("warn") or lower:match("medium") then return 3
                elseif lower:match("low") then return 2
                elseif lower:match("info") or lower:match("notice") then return 1
                end
            elseif type(value) == "number" then
                -- Assume 0-7 syslog severity scale
                if value <= 2 then return 5      -- critical/alert/emergency
                elseif value <= 3 then return 4  -- error
                elseif value <= 4 then return 3  -- warning
                elseif value <= 6 then return 2  -- notice/info
                else return 1                    -- debug
                end
            end
        end
    end
    return 0 -- Unknown
end

-- Parse timestamp to milliseconds
function parseTimestamp(timeStr)
    if not timeStr or type(timeStr) ~= "string" then return os.time() * 1000 end
    
    -- Try ISO format first
    local yr, mo, dy, hr, mn, sc = timeStr:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if yr then
        return os.time({year=tonumber(yr), month=tonumber(mo), day=tonumber(dy),
                       hour=tonumber(hr), min=tonumber(mn), sec=tonumber(sc)}) * 1000
    end
    
    -- Try syslog timestamp format
    local month, day, time = timeStr:match("(%a+)%s+(%d+)%s+([%d:]+)")
    if month and day and time then
        local monthMap = {Jan=1, Feb=2, Mar=3, Apr=4, May=5, Jun=6,
                         Jul=7, Aug=8, Sep=9, Oct=10, Nov=11, Dec=12}
        local hr2, mn2, sc2 = time:match("(%d+):(%d+):(%d+)")
        if monthMap[month] and hr2 then
            return os.time({year=os.date("%Y"), month=monthMap[month], day=tonumber(day),
                           hour=tonumber(hr2), min=tonumber(mn2), sec=tonumber(sc2) or 0}) * 1000
        end
    end
    
    return os.time() * 1000
end

-- Main processing function
function processEvent(event)
    if type(event) ~= "table" then return nil end
    
    local result = {}
    local mappedPaths = {}
    
    -- Extract fields from message or raw data if it's space-delimited
    local messageData = event.message or event.raw_data or event.data
    local parsedFields = {}
    if type(messageData) == "string" then
        parsedFields = parseSpaceDelimitedLog(messageData)
        -- Merge parsed fields with original event
        for k, v in pairs(parsedFields) do
            if not event[k] then
                event[k] = v
            end
        end
    end
    
    -- Set OCSF required fields
    result.class_uid = CLASS_UID
    result.category_uid = CATEGORY_UID
    result.class_name = "Network Activity"
    result.category_name = "Network Activity"
    
    -- Determine activity based on content
    local activityId = 99 -- Other by default
    local activityName = "Network Traffic"
    
    if messageData then
        local msgLower = string.lower(tostring(messageData))
        if msgLower:match("connect") then
            activityId = 1
            activityName = "Open"
        elseif msgLower:match("close") or msgLower:match("disconnect") then
            activityId = 2
            activityName = "Close"
        elseif msgLower:match("deny") or msgLower:match("block") or msgLower:match("drop") then
            activityId = 4
            activityName = "Refuse"
        elseif msgLower:match("accept") or msgLower:match("allow") then
            activityId = 1
            activityName = "Open"
        end
    end
    
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity
    result.severity_id = getSeverityId(event)
    
    -- Set time from various timestamp fields
    local timeFields = {"time", "timestamp", "@timestamp", "eventTime", "logTime"}
    for _, field in ipairs(timeFields) do
        local timeValue = event[field]
        if timeValue then
            result.time = parseTimestamp(tostring(timeValue))
            mappedPaths[field] = true
            break
        end
    end
    if not result.time then
        result.time = os.time() * 1000
    end
    
    -- Map network endpoints
    local srcIP, dstIP = extractIPs(messageData or "")
    if not srcIP then srcIP = event.src_ip or event.srcip or event.source_ip end
    if not dstIP then dstIP = event.dst_ip or event.dstip or event.dest_ip or event.destination_ip end
    
    local srcPort, dstPort = extractPorts(messageData or "")
    if not srcPort then srcPort = tonumber(event.src_port or event.srcport or event.source_port) end
    if not dstPort then dstPort = tonumber(event.dst_port or event.dstport or event.dest_port or event.destination_port) end
    
    if srcIP then
        setNestedField(result, "src_endpoint.ip", srcIP)
        mappedPaths["src_ip"] = true
        mappedPaths["srcip"] = true
        mappedPaths["source_ip"] = true
    end
    if dstIP then
        setNestedField(result, "dst_endpoint.ip", dstIP)
        mappedPaths["dst_ip"] = true
        mappedPaths["dstip"] = true
        mappedPaths["dest_ip"] = true
        mappedPaths["destination_ip"] = true
    end
    if srcPort then
        setNestedField(result, "src_endpoint.port", srcPort)
        mappedPaths["src_port"] = true
        mappedPaths["srcport"] = true
        mappedPaths["source_port"] = true
    end
    if dstPort then
        setNestedField(result, "dst_endpoint.port", dstPort)
        mappedPaths["dst_port"] = true
        mappedPaths["dstport"] = true
        mappedPaths["dest_port"] = true
        mappedPaths["destination_port"] = true
    end
    
    -- Map hostnames
    local srcHost = event.src_host or event.srchost or event.source_host
    local dstHost = event.dst_host or event.dsthost or event.dest_host or event.destination_host
    if srcHost then
        setNestedField(result, "src_endpoint.hostname", srcHost)
        mappedPaths["src_host"] = true
        mappedPaths["srchost"] = true
        mappedPaths["source_host"] = true
    end
    if dstHost then
        setNestedField(result, "dst_endpoint.hostname", dstHost)
        mappedPaths["dst_host"] = true
        mappedPaths["dsthost"] = true
        mappedPaths["dest_host"] = true
        mappedPaths["destination_host"] = true
    end
    
    -- Map protocol
    local protocol = event.protocol or event.proto
    if protocol then
        result.protocol_name = tostring(protocol):upper()
        mappedPaths["protocol"] = true
        mappedPaths["proto"] = true
    end
    
    -- Map message and raw data
    if event.message then
        result.message = event.message
        mappedPaths["message"] = true
    end
    if event.raw_data then
        result.raw_data = event.raw_data
        mappedPaths["raw_data"] = true
    end
    
    -- Map common status fields
    local statusFields = {"status", "action", "result"}
    for _, field in ipairs(statusFields) do
        if event[field] then
            result.status = event[field]
            mappedPaths[field] = true
            break
        end
    end
    
    -- Map metadata if available
    if event.product then
        setNestedField(result, "metadata.product.name", event.product)
        mappedPaths["product"] = true
    end
    if event.vendor then
        setNestedField(result, "metadata.product.vendor_name", event.vendor)
        mappedPaths["vendor"] = true
    end
    
    -- Map other common fields
    if event.count then
        result.count = tonumber(event.count)
        mappedPaths["count"] = true
    end
    if event.duration then
        result.duration = tonumber(event.duration)
        mappedPaths["duration"] = true
    end
    
    -- Mark parsed message fields as mapped
    for k, _ in pairs(parsedFields) do
        mappedPaths[k] = true
    end
    mappedPaths["data"] = true
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up and return
    return no_nulls(result, nil)
end