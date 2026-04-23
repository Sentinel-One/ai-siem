-- CrowdStrike Endpoint Detection Finding Parser
-- Maps CrowdStrike endpoint events to OCSF Detection Finding format

-- OCSF constants
local CLASS_UID = 2004
local CATEGORY_UID = 2

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

-- Map CrowdStrike severity to OCSF severity_id
local function getSeverityId(severity)
    if severity == nil then return 0 end
    local sev = tostring(severity):lower()
    local severityMap = {
        critical = 5,
        high = 4,
        medium = 3,
        low = 2,
        informational = 1,
        info = 1,
        ["1"] = 2,  -- Low
        ["2"] = 3,  -- Medium
        ["3"] = 4,  -- High
        ["4"] = 5   -- Critical
    }
    return severityMap[sev] or 0
end

-- Map confidence level to OCSF confidence_id
local function getConfidenceId(confidence)
    if confidence == nil then return nil end
    local conf = tostring(confidence):lower()
    local confidenceMap = {
        high = 3,
        medium = 2,
        low = 1,
        unknown = 0
    }
    return confidenceMap[conf] or nil
end

-- Parse timestamp to milliseconds since epoch
local function parseTimestamp(timestamp)
    if timestamp == nil then return os.time() * 1000 end
    
    -- Handle Unix timestamp (seconds)
    if type(timestamp) == "number" then
        return timestamp * 1000
    end
    
    -- Handle ISO 8601 format
    local ts = tostring(timestamp)
    local year, month, day, hour, min, sec = ts:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if year then
        local time = os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec),
            isdst = false
        })
        return time * 1000
    end
    
    return os.time() * 1000
end

-- Clean empty tables recursively
local function cleanEmptyTables(tbl)
    if type(tbl) ~= "table" then return tbl end
    
    local cleaned = {}
    for k, v in pairs(tbl) do
        if type(v) == "table" then
            local cleanedValue = cleanEmptyTables(v)
            if next(cleanedValue) ~= nil then
                cleaned[k] = cleanedValue
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
    
    -- CrowdStrike field mappings
    local fieldMappings = {
        -- Detection/finding basic info
        {type = "direct", source = "DetectId", target = "finding_info.uid"},
        {type = "direct", source = "DetectName", target = "finding_info.title"},
        {type = "direct", source = "DetectDescription", target = "finding_info.desc"},
        {type = "priority", source1 = "event_simpleName", source2 = "EventType", target = "finding_info.title"},
        
        -- Alternative finding info fields
        {type = "priority", source1 = "FalconHostLink", source2 = "ProcessId", target = "finding_info.uid"},
        {type = "priority", source1 = "ThreatName", source2 = "MalwareName", target = "finding_info.title"},
        {type = "priority", source1 = "ThreatDescription", source2 = "Description", target = "finding_info.desc"},
        
        -- Timing
        {type = "direct", source = "ProcessStartTime", target = "start_time"},
        {type = "direct", source = "ProcessEndTime", target = "end_time"},
        {type = "direct", source = "timestamp", target = "time"},
        {type = "direct", source = "_time", target = "time"},
        
        -- Device/endpoint info
        {type = "direct", source = "ComputerName", target = "device.hostname"},
        {type = "direct", source = "MachineDomain", target = "device.domain"},
        {type = "direct", source = "aid", target = "device.uid"},
        {type = "direct", source = "cid", target = "device.owner.uid"},
        
        -- Process info
        {type = "direct", source = "ImageFileName", target = "process.file.name"},
        {type = "direct", source = "CommandLine", target = "process.cmd_line"},
        {type = "direct", source = "ProcessId", target = "process.pid"},
        {type = "direct", source = "ParentProcessId", target = "process.parent_process.pid"},
        {type = "direct", source = "SHA256HashData", target = "process.file.hashes.sha256"},
        {type = "direct", source = "MD5HashData", target = "process.file.hashes.md5"},
        
        -- User info
        {type = "direct", source = "UserName", target = "actor.user.name"},
        {type = "direct", source = "UserSid", target = "actor.user.uid"},
        
        -- Network info
        {type = "direct", source = "LocalIP", target = "src_endpoint.ip"},
        {type = "direct", source = "RemoteIP", target = "dst_endpoint.ip"},
        {type = "direct", source = "LocalPort", target = "src_endpoint.port"},
        {type = "direct", source = "RemotePort", target = "dst_endpoint.port"},
        
        -- Metadata
        {type = "computed", target = "metadata.product.name", value = "CrowdStrike Falcon"},
        {type = "computed", target = "metadata.product.vendor_name", value = "CrowdStrike"},
        {type = "direct", source = "ConfigBuild", target = "metadata.version"},
        
        -- Status and severity
        {type = "direct", source = "Severity", target = "severity"},
        {type = "direct", source = "MaxSeverity", target = "severity"},
        {type = "direct", source = "Confidence", target = "confidence"},
        {type = "direct", source = "Status", target = "status"},
        
        -- Raw message
        {type = "priority", source1 = "RawProcessId", source2 = "event_platform", target = "raw_data"},
        
        -- OCSF required fields
        {type = "computed", target = "class_uid", value = CLASS_UID},
        {type = "computed", target = "category_uid", value = CATEGORY_UID},
        {type = "computed", target = "class_name", value = "Detection Finding"},
        {type = "computed", target = "category_name", value = "Findings"}
    }
    
    -- Process field mappings
    for _, mapping in ipairs(fieldMappings) do
        if mapping.type == "direct" then
            local value = getNestedField(event, mapping.source)
            if value ~= nil and value ~= "" then
                setNestedField(result, mapping.target, value)
                mappedPaths[mapping.source] = true
            end
        elseif mapping.type == "priority" then
            local value = getNestedField(event, mapping.source1)
            if (value == nil or value == "") and mapping.source2 then
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
    
    -- Set activity based on event type
    local activityId = 1  -- Create
    local activityName = "Create"
    
    local eventType = getNestedField(event, "event_simpleName") or getNestedField(event, "EventType")
    if eventType then
        local evtType = tostring(eventType):lower()
        if evtType:match("update") then
            activityId = 2
            activityName = "Update"
        elseif evtType:match("delete") or evtType:match("remove") then
            activityId = 3
            activityName = "Delete"
        end
    end
    
    result.activity_id = activityId
    result.activity_name = activityName
    result.type_uid = CLASS_UID * 100 + activityId
    
    -- Set severity_id from various severity fields
    local severity = getNestedField(result, "severity") or 
                    getNestedField(event, "Severity") or 
                    getNestedField(event, "MaxSeverity")
    result.severity_id = getSeverityId(severity)
    
    -- Set confidence_id
    local confidence = getNestedField(result, "confidence") or getNestedField(event, "Confidence")
    result.confidence_id = getConfidenceId(confidence)
    
    -- Parse timestamp
    local timestamp = getNestedField(result, "time") or 
                     getNestedField(event, "timestamp") or 
                     getNestedField(event, "_time") or
                     getNestedField(event, "ProcessStartTime")
    result.time = parseTimestamp(timestamp)
    
    -- Set finding types based on detection category
    local findingTypes = {}
    local detectName = getNestedField(result, "finding_info.title") or ""
    if detectName:lower():match("malware") then
        table.insert(findingTypes, "Malware")
    elseif detectName:lower():match("suspicious") then
        table.insert(findingTypes, "Suspicious Activity")
    elseif detectName:lower():match("behavior") then
        table.insert(findingTypes, "Behavioral Analysis")
    end
    
    if #findingTypes > 0 then
        setNestedField(result, "finding_info.types", findingTypes)
    end
    
    -- Set default finding_info.uid if missing
    if not getNestedField(result, "finding_info.uid") then
        local uid = getNestedField(event, "ProcessId") or 
                   getNestedField(event, "aid") or 
                   ("cs_" .. tostring(result.time))
        setNestedField(result, "finding_info.uid", uid)
    end
    
    -- Set default finding_info.title if missing
    if not getNestedField(result, "finding_info.title") then
        setNestedField(result, "finding_info.title", "CrowdStrike Detection")
    end
    
    -- Set message from various sources
    if not result.message then
        result.message = getNestedField(result, "finding_info.desc") or 
                        getNestedField(result, "finding_info.title") or
                        "CrowdStrike endpoint detection event"
    end
    
    -- Set finding creation/modification times
    setNestedField(result, "finding_info.created_time", result.time)
    setNestedField(result, "finding_info.modified_time", result.time)
    
    -- Create observables for key indicators
    local observables = {}
    
    -- IP addresses
    local srcIp = getNestedField(result, "src_endpoint.ip")
    local dstIp = getNestedField(result, "dst_endpoint.ip")
    if srcIp then
        table.insert(observables, {type_id = 2, type = "IP Address", name = "src_endpoint.ip", value = srcIp})
    end
    if dstIp then
        table.insert(observables, {type_id = 2, type = "IP Address", name = "dst_endpoint.ip", value = dstIp})
    end
    
    -- File hashes
    local sha256 = getNestedField(result, "process.file.hashes.sha256")
    local md5 = getNestedField(result, "process.file.hashes.md5")
    if sha256 then
        table.insert(observables, {type_id = 13, type = "File Hash", name = "process.file.hashes.sha256", value = sha256})
    end
    if md5 then
        table.insert(observables, {type_id = 13, type = "File Hash", name = "process.file.hashes.md5", value = md5})
    end
    
    -- Process name
    local processName = getNestedField(result, "process.file.name")
    if processName then
        table.insert(observables, {type_id = 8, type = "Process Name", name = "process.file.name", value = processName})
    end
    
    if #observables > 0 then
        result.observables = observables
    end
    
    -- Copy unmapped fields to preserve original data
    copyUnmappedFields(event, mappedPaths, result)
    
    -- Clean up the result
    result = no_nulls(result, nil)
    result = cleanEmptyTables(result)
    
    return result
end