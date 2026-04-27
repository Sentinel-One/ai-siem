-- CrowdStrike Detection Finding Parser
-- Transforms CrowdStrike events to OCSF Detection Finding (class_uid=2004)

local CLASS_UID = 2004
local CATEGORY_UID = 2

-- Nested field access helpers
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

-- Safe value access
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

-- Map severity to OCSF severity_id
local function getSeverityId(severity)
    if severity == nil then return 0 end
    local severityStr = string.lower(tostring(severity))
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        low = 2,
        info = 1,
        informational = 1,
        warning = 3,
        error = 4,
        fatal = 6
    }
    return severityMap[severityStr] or 0
end

-- Convert timestamp to milliseconds since epoch
local function convertTimestamp(timestamp)
    if timestamp == nil then return os.time() * 1000 end
    
    -- Handle Unix timestamp (seconds or milliseconds)
    if type(timestamp) == "number" then
        return timestamp < 1e12 and timestamp * 1000 or timestamp
    end
    
    -- Handle ISO timestamp
    if type(timestamp) == "string" then
        local yr, mo, dy, hr, mn, sc = timestamp:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        if yr then
            return os.time({
                year = tonumber(yr),
                month = tonumber(mo),
                day = tonumber(dy),
                hour = tonumber(hr),
                min = tonumber(mn),
                sec = tonumber(sc),
                isdst = false
            }) * 1000
        end
    end
    
    return os.time() * 1000
end

-- Main field mappings for CrowdStrike
local fieldMappings = {
    -- Core OCSF fields
    {type = "computed", target = "class_uid", value = CLASS_UID},
    {type = "computed", target = "category_uid", value = CATEGORY_UID},
    {type = "computed", target = "class_name", value = "Detection Finding"},
    {type = "computed", target = "category_name", value = "Findings"},
    
    -- Detection/Event basic fields
    {type = "priority", source1 = "event_simpleName", source2 = "eventType", source3 = "detection_id", target = "finding_info.title"},
    {type = "priority", source1 = "detection_id", source2 = "event.DetectId", source3 = "DetectId", target = "finding_info.uid"},
    {type = "priority", source1 = "description", source2 = "DetectDescription", source3 = "event.DetectDescription", target = "finding_info.desc"},
    
    -- Timestamp handling
    {type = "priority", source1 = "timestamp", source2 = "ProcessStartTime", source3 = "_time", target = "_timestamp"},
    
    -- Severity and confidence
    {type = "priority", source1 = "severity", source2 = "SeverityName", source3 = "event.SeverityName", target = "_severity"},
    {type = "priority", source1 = "confidence", source2 = "Confidence", source3 = "event.Confidence", target = "_confidence"},
    
    -- Status information
    {type = "priority", source1 = "status", source2 = "PatternDispositionDescription", target = "status_detail"},
    
    -- Message and raw data
    {type = "priority", source1 = "message", source2 = "event_platform", target = "message"},
    {type = "direct", source = "_raw", target = "raw_data"},
    
    -- Metadata
    {type = "computed", target = "metadata.product.name", value = "CrowdStrike Falcon"},
    {type = "computed", target = "metadata.product.vendor_name", value = "CrowdStrike"},
    {type = "priority", source1 = "aid", source2 = "event.aid", target = "metadata.product.uid"},
    
    -- Host/Device information
    {type = "priority", source1 = "ComputerName", source2 = "device.hostname", source3 = "aip", target = "device.name"},
    {type = "priority", source1 = "device.local_ip", source2 = "LocalAddressIP4", target = "device.ip"},
    {type = "priority", source1 = "device.os_version", source2 = "event.platform", target = "device.os.name"},
    
    -- Actor/User information
    {type = "priority", source1 = "UserName", source2 = "user.name", source3 = "event.UserName", target = "actor.user.name"},
    {type = "priority", source1 = "UserSid", source2 = "event.UserSid", target = "actor.user.uid"},
    
    -- Process information
    {type = "priority", source1 = "FileName", source2 = "ImageFileName", source3 = "event.ImageFileName", target = "actor.process.name"},
    {type = "priority", source1 = "FilePath", source2 = "event.FilePath", target = "actor.process.file.path"},
    {type = "priority", source1 = "SHA256HashData", source2 = "event.SHA256HashData", target = "actor.process.file.hashes.sha256"},
    {type = "priority", source1 = "MD5HashData", source2 = "event.MD5HashData", target = "actor.process.file.hashes.md5"},
    {type = "priority", source1 = "ProcessId", source2 = "event.ProcessId", target = "actor.process.pid"},
    {type = "priority", source1 = "CommandLine", source2 = "event.CommandLine", target = "actor.process.cmd_line"},
    
    -- Network information
    {type = "priority", source1 = "RemoteAddressIP4", source2 = "dst_ip", target = "dst_endpoint.ip"},
    {type = "priority", source1 = "RemotePort", source2 = "dst_port", target = "dst_endpoint.port"},
    {type = "priority", source1 = "LocalAddressIP4", source2 = "src_ip", target = "src_endpoint.ip"},
    {type = "priority", source1 = "LocalPort", source2 = "src_port", target = "src_endpoint.port"},
    
    -- File information for file-based detections
    {type = "priority", source1 = "TargetFilename", source2 = "event.TargetFilename", target = "file.name"},
    {type = "priority", source1 = "event.ParentProcessId", source2 = "ParentProcessId", target = "actor.process.parent_process.pid"},
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
                mappedPaths[mapping.source] = true
            end
        elseif mapping.type == "priority" then
            local value = nil
            -- Try sources in priority order
            if mapping.source1 then
                value = getNestedField(event, mapping.source1)
                mappedPaths[mapping.source1] = true
            end
            if value == nil and mapping.source2 then
                value = getNestedField(event, mapping.source2)
                mappedPaths[mapping.source2] = true
            end
            if value == nil and mapping.source3 then
                value = getNestedField(event, mapping.source3)
                mappedPaths[mapping.source3] = true
            end
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
            end
        elseif mapping.type == "computed" then
            setNestedField(result, mapping.target, mapping.value)
        end
    end
    
    -- Handle special transformations
    local timestamp = getNestedField(result, "_timestamp")
    result.time = convertTimestamp(timestamp)
    result["_timestamp"] = nil
    
    -- Set severity_id based on severity
    local severityValue = getNestedField(result, "_severity")
    result.severity_id = getSeverityId(severityValue)
    result["_severity"] = nil
    
    -- Set confidence_id if confidence exists
    local confidenceValue = getNestedField(result, "_confidence")
    if confidenceValue then
        if type(confidenceValue) == "number" then
            result.confidence_id = confidenceValue > 80 and 3 or (confidenceValue > 50 and 2 or 1)
        end
    end
    result["_confidence"] = nil
    
    -- Set activity_id and activity_name based on event type
    local eventType = getValue(event, "event_simpleName", getValue(event, "eventType", "Unknown"))
    local activityMap = {
        ProcessRollup2 = {id = 1, name = "Process Activity"},
        NetworkConnectIP4 = {id = 2, name = "Network Connection"},
        DnsRequest = {id = 3, name = "DNS Query"},
        FileWritten = {id = 4, name = "File Write"},
        RegKeyActivity = {id = 5, name = "Registry Activity"},
        Detection = {id = 99, name = "Detection"},
    }
    
    local activity = activityMap[eventType] or {id = 99, name = tostring(eventType)}
    result.activity_id = activity.id
    result.activity_name = activity.name
    
    -- Set type_uid
    result.type_uid = CLASS_UID * 100 + result.activity_id
    
    -- Set default values for required fields
    if not result.finding_info then result.finding_info = {} end
    if not result.finding_info.title then
        result.finding_info.title = result.activity_name or "CrowdStrike Detection"
    end
    if not result.finding_info.uid then
        result.finding_info.uid = getValue(event, "cid", "unknown") .. "-" .. (os.time() * 1000)
    end
    
    -- Set default severity if not set
    if not result.severity_id or result.severity_id == 0 then
        result.severity_id = 3  -- Medium as default for detections
    end
    
    -- Set finding types if this is a detection
    if string.find(string.lower(eventType), "detect") then
        result.finding_info.types = {"Malware", "Behavioral Analysis"}
    end
    
    -- Set creation time
    result.finding_info.created_time = result.time
    result.finding_info.modified_time = result.time
    
    -- Copy unmapped fields
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up null values
    result = no_nulls(result, nil)
    
    return result
end