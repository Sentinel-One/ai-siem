--------------------------------------------------------------------------------
-- CrowdStrike Detections → OCSF 1.3.0 Detection Finding (class_uid = 2004)
-- Observo processEvent(event) contract
-- Author: Observo AI  |  Schema: OCSF 1.3.0  |  Class: Detection Finding (2004)
-- Strict rules enforced:
--   (1) No "Unknown"/"unknown" string defaults — nil or source fallbacks only
--   (2) tostring(x or "") guard before every :match/:gsub/:gmatch/:lower/:upper
--   (3) table.concat for all loop-based string building — no .. inside loops
--   (4) Every helper is `local function` declared ABOVE processEvent
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- FEATURES: Runtime feature flags
--------------------------------------------------------------------------------
local FEATURES = {
    PRESERVE_RAW         = true,   -- attach raw_data (json-encoded source event)
    ENRICH_DEVICE        = true,   -- build device object from host/agent fields
    ENRICH_PROCESS       = true,   -- build process object from file/cmd fields
    ENRICH_ATTACKS       = true,   -- build attacks[] from MITRE tactic/technique
    ENRICH_EVIDENCES     = true,   -- build evidences[] from process + file hashes
    ENRICH_RESOURCES     = true,   -- build resources[] from device/file targets
    ENRICH_OBSERVABLES   = true,   -- build observables[] from IPs, hashes, users
    STRIP_EMPTY          = true,   -- recursively remove nil/"" values before return
}

--------------------------------------------------------------------------------
-- FIELD_ORDERS: Canonical top-level key ordering for downstream consumers
--------------------------------------------------------------------------------
local FIELD_ORDERS = {
    "class_uid",
    "class_name",
    "category_uid",
    "category_name",
    "activity_id",
    "activity_name",
    "type_uid",
    "type_name",
    "time",
    "start_time",
    "end_time",
    "severity_id",
    "severity",
    "status",
    "status_id",
    "status_code",
    "status_detail",
    "action",
    "action_id",
    "disposition",
    "disposition_id",
    "confidence",
    "confidence_id",
    "confidence_score",
    "risk_score",
    "risk_level",
    "risk_level_id",
    "message",
    "comment",
    "metadata",
    "finding_info",
    "actor",
    "device",
    "attacks",
    "malware",
    "evidences",
    "resources",
    "observables",
    "osint",
    "cloud",
    "raw_data",
    "unmapped",
}

--------------------------------------------------------------------------------
-- SEVERITY_MAP: CrowdStrike severity string/integer → OCSF {id, label}
-- CrowdStrike: 0=None/Info, 1=Low, 2=Medium, 3=High, 4=Critical
-- OCSF:        1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical
--------------------------------------------------------------------------------
local SEVERITY_MAP = {
    ["0"]          = { id = 1, label = "Informational" },
    ["1"]          = { id = 2, label = "Low" },
    ["2"]          = { id = 3, label = "Medium" },
    ["3"]          = { id = 4, label = "High" },
    ["4"]          = { id = 5, label = "Critical" },
    informational  = { id = 1, label = "Informational" },
    info           = { id = 1, label = "Informational" },
    none           = { id = 1, label = "Informational" },
    low            = { id = 2, label = "Low" },
    medium         = { id = 3, label = "Medium" },
    high           = { id = 4, label = "High" },
    critical       = { id = 5, label = "Critical" },
    fatal          = { id = 6, label = "Fatal" },
}

--------------------------------------------------------------------------------
-- STATUS_MAP: CrowdStrike detection status → OCSF {id, label}
-- OCSF status_id: 0=Unknown, 1=New, 2=In Progress, 3=Suppressed, 4=Resolved, 99=Other
--------------------------------------------------------------------------------
local STATUS_MAP = {
    new             = { id = 1,  label = "New" },
    ["in_progress"] = { id = 2,  label = "In Progress" },
    inprogress      = { id = 2,  label = "In Progress" },
    ["in progress"] = { id = 2,  label = "In Progress" },
    reopened        = { id = 2,  label = "In Progress" },
    suppressed      = { id = 3,  label = "Suppressed" },
    ignored         = { id = 3,  label = "Suppressed" },
    closed          = { id = 4,  label = "Resolved" },
    resolved        = { id = 4,  label = "Resolved" },
    true_positive   = { id = 4,  label = "Resolved" },
    false_positive  = { id = 3,  label = "Suppressed" },
}

--------------------------------------------------------------------------------
-- DISPOSITION_MAP: CrowdStrike PatternDispositionDescription → OCSF {id, label, action_id}
-- OCSF disposition_id notable values: 2=Blocked, 3=Quarantined, 15=Detected,
--   16=No Action, 17=Logged, 5=Deleted, 4=Isolated
-- OCSF action_id: 0=Unknown, 1=Allowed, 2=Denied, 99=Other
--------------------------------------------------------------------------------
local DISPOSITION_MAP = {
    ["detect"]                  = { id = 15, label = "Detected",    action_id = 1 },
    ["detection"]               = { id = 15, label = "Detected",    action_id = 1 },
    ["detected"]                = { id = 15, label = "Detected",    action_id = 1 },
    ["prevent"]                 = { id = 2,  label = "Blocked",     action_id = 2 },
    ["prevention"]              = { id = 2,  label = "Blocked",     action_id = 2 },
    ["prevented"]               = { id = 2,  label = "Blocked",     action_id = 2 },
    ["kill_process"]            = { id = 2,  label = "Blocked",     action_id = 2 },
    ["kill process"]            = { id = 2,  label = "Blocked",     action_id = 2 },
    ["quarantine"]              = { id = 3,  label = "Quarantined", action_id = 2 },
    ["quarantined"]             = { id = 3,  label = "Quarantined", action_id = 2 },
    ["quarantine_file"]         = { id = 3,  label = "Quarantined", action_id = 2 },
    ["quarantine file"]         = { id = 3,  label = "Quarantined", action_id = 2 },
    ["block"]                   = { id = 2,  label = "Blocked",     action_id = 2 },
    ["blocked"]                 = { id = 2,  label = "Blocked",     action_id = 2 },
    ["allow"]                   = { id = 1,  label = "Allowed",     action_id = 1 },
    ["allowed"]                 = { id = 1,  label = "Allowed",     action_id = 1 },
    ["no_action"]               = { id = 16, label = "No Action",   action_id = 1 },
    ["no action"]               = { id = 16, label = "No Action",   action_id = 1 },
    ["monitor"]                 = { id = 17, label = "Logged",      action_id = 1 },
    ["monitored"]               = { id = 17, label = "Logged",      action_id = 1 },
    ["log"]                     = { id = 17, label = "Logged",      action_id = 1 },
    ["logged"]                  = { id = 17, label = "Logged",      action_id = 1 },
    ["isolate"]                 = { id = 4,  label = "Isolated",    action_id = 2 },
    ["isolated"]                = { id = 4,  label = "Isolated",    action_id = 2 },
    ["delete"]                  = { id = 5,  label = "Deleted",     action_id = 2 },
    ["deleted"]                 = { id = 5,  label = "Deleted",     action_id = 2 },
    ["kill_and_quarantine"]     = { id = 3,  label = "Quarantined", action_id = 2 },
    ["kill and quarantine"]     = { id = 3,  label = "Quarantined", action_id = 2 },
}

--------------------------------------------------------------------------------
-- CONFIDENCE_MAP: CrowdStrike confidence string/int → OCSF {id, label}
-- OCSF confidence_id: 0=Unknown, 1=Low, 2=Medium, 3=High, 99=Other
--------------------------------------------------------------------------------
local CONFIDENCE_MAP = {
    ["0"]   = { id = 1, label = "Low" },
    ["1"]   = { id = 1, label = "Low" },
    ["25"]  = { id = 1, label = "Low" },
    ["50"]  = { id = 2, label = "Medium" },
    ["75"]  = { id = 3, label = "High" },
    ["100"] = { id = 3, label = "High" },
    low     = { id = 1, label = "Low" },
    medium  = { id = 2, label = "Medium" },
    high    = { id = 3, label = "High" },
}

--------------------------------------------------------------------------------
-- ACTIVITY_MAP: CrowdStrike status/event context → OCSF activity_id
-- OCSF activity_id: 0=Unknown, 1=Create, 2=Update, 3=Close, 99=Other
--------------------------------------------------------------------------------
local ACTIVITY_MAP = {
    new             = 1,
    created         = 1,
    ["in_progress"] = 2,
    inprogress      = 2,
    reopened        = 2,
    updated         = 2,
    update          = 2,
    closed          = 3,
    resolved        = 3,
    suppressed      = 3,
}

--------------------------------------------------------------------------------
-- ACTIVITY_NAMES: activity_id → caption
--------------------------------------------------------------------------------
local ACTIVITY_NAMES = {
    [0]  = "Create",   -- maps 0 to Create per OCSF 2004 enum (Unknown → Create default)
    [1]  = "Create",
    [2]  = "Update",
    [3]  = "Close",
    [99] = "Other",
}

--------------------------------------------------------------------------------
-- FIELD_MAP: CrowdStrike source field → OCSF destination dot-path
-- Only scalar/direct mappings; complex objects handled by builder helpers.
--------------------------------------------------------------------------------
local FIELD_MAP = {
    -- Timing
    ["timestamp"]               = "time",
    ["created_timestamp"]       = "time",
    ["_time"]                   = "time",
    ["ProcessStartTime"]        = "start_time",
    ["start_timestamp"]         = "start_time",
    ["end_timestamp"]           = "end_time",

    -- Metadata / correlation
    ["cid"]                     = "cloud.account.uid",
    ["customer_id"]             = "cloud.account.uid",
    ["ExternalApiType"]         = "metadata.product.feature.name",
    ["event_type"]              = "metadata.product.feature.name",
    ["DetectId"]                = "finding_info.uid",
    ["detection_id"]            = "finding_info.uid",
    ["composite_id"]            = "finding_info.uid",
    ["DetectName"]              = "finding_info.title",
    ["detect_name"]             = "finding_info.title",
    ["Description"]             = "finding_info.desc",
    ["description"]             = "finding_info.desc",
    ["FalconHostLink"]          = "finding_info.src_url",
    ["falcon_host_link"]        = "finding_info.src_url",
    ["ShowInUi"]                = "finding_info.is_alert",

    -- Device / host
    ["ComputerName"]            = "device.name",
    ["hostname"]                = "device.name",
    ["Hostname"]                = "device.name",
    ["aid"]                     = "device.uid",
    ["device_id"]               = "device.uid",
    ["LocalIP"]                 = "device.ip",
    ["local_ip"]                = "device.ip",
    ["MacAddress"]              = "device.mac",
    ["mac_address"]             = "device.mac",
    ["OSVersion"]               = "device.os.version",
    ["os_version"]              = "device.os.version",
    ["AgentVersion"]            = "device.agent_list.version",
    ["agent_version"]           = "device.agent_list.version",
    ["SensorId"]                = "device.uid",

    -- Actor / user
    ["UserName"]                = "actor.user.name",
    ["user_name"]               = "actor.user.name",
    ["UserId"]                  = "actor.user.uid",
    ["user_id"]                 = "actor.user.uid",
    ["LogonType"]               = "actor.session.logon_type",
    ["logon_type"]              = "actor.session.logon_type",

    -- Process
    ["ProcessId"]               = "process.pid",
    ["pid"]                     = "process.pid",
    ["FileName"]                = "process.file.name",
    ["filename"]                = "process.file.name",
    ["FilePath"]                = "process.file.path",
    ["filepath"]                = "process.file.path",
    ["CommandLine"]             = "process.cmd_line",
    ["cmdline"]                 = "process.cmd_line",
    ["command_line"]            = "process.cmd_line",
    ["SHA256HashData"]          = "process.file.hashes.value",
    ["sha256"]                  = "process.file.hashes.value",
    ["MD5HashData"]             = "process.file.fingerprint.value",
    ["md5"]                     = "process.file.fingerprint.value",
    ["ParentProcessId"]         = "process.parent_process.pid",
    ["parent_pid"]              = "process.parent_process.pid",
    ["ParentCommandLine"]       = "process.parent_process.cmd_line",
    ["parent_cmdline"]          = "process.parent_process.cmd_line",
    ["ImageFileName"]           = "process.file.path",

    -- Network
    ["RemoteIP"]                = "device.network_interfaces.ip",
    ["remote_ip"]               = "device.network_interfaces.ip",
    ["RemotePort"]              = "device.network_interfaces.port",
    ["remote_port"]             = "device.network_interfaces.port",

    -- Risk / score
    ["MaxSeverityDisplayName"]  = "risk_details",
    ["risk_score"]              = "risk_score",
    ["RiskScore"]               = "risk_score",
}

--------------------------------------------------------------------------------
-- local function deepGet
-- Safely retrieves a value from a nested table using dot-notation path.
-- Supports array index syntax: "key[N]"
--------------------------------------------------------------------------------
local function deepGet(obj, path)
    if obj == nil or path == nil then return nil end
    local current = obj
    for part in tostring(path or ""):gmatch("[^%.]+") do
        if current == nil then return nil end
        local key, idx = tostring(part or ""):match("^(.-)%[(%d+)%]$")
        if key and idx then
            local tbl = current[key]
            if type(tbl) == "table" then
                current = tbl[tonumber(idx)]
            else
                return nil
            end
        else
            current = current[part]
        end
    end
    return current
end

--------------------------------------------------------------------------------
-- local function deepSet
-- Safely sets a value in a nested table using dot-notation path.
-- Creates intermediate tables as needed.
-- Skips nil and empty-string values.
-- Auto-coerces numeric strings for known numeric destination paths.
--------------------------------------------------------------------------------
local function deepSet(obj, path, value)
    if value == nil then return end
    if value == "" then return end

    local path_s = tostring(path or "")

    -- Numeric coercion hints
    local numeric_hints = {
        "pid", "port", "uid", "lat", "long",
        "bytes", "packets", "score", "offset",
        "severity_id", "status_id", "activity_id",
        "class_uid", "category_uid", "type_uid",
        "confidence_id", "disposition_id", "action_id",
        "risk_score", "impact_score", "confidence_score",
        "risk_level_id", "impact_id",
    }
    for _, hint in ipairs(numeric_hints) do
        if path_s:find(hint, 1, true) then
            local n = tonumber(value)
            if n then value = n end
            break
        end
    end

    local keys = {}
    for k in path_s:gmatch("[^%.]+") do
        table.insert(keys, k)
    end
    if #keys == 0 then return end

    local current = obj
    for i = 1, #keys - 1 do
        local k = keys[i]
        if type(current[k]) ~= "table" then
            current[k] = {}
        end
        current = current[k]
    end
    current[keys[#keys]] = value
end

--------------------------------------------------------------------------------
-- local function stripEmpty
-- Recursively removes nil and empty-string values; prunes empty tables.
--------------------------------------------------------------------------------
local function stripEmpty(t)
    if type(t) ~= "table" then return end
    local to_remove = {}
    for k, v in pairs(t) do
        if v == nil or v == "" then
            table.insert(to_remove, k)
        elseif type(v) == "table" then
            stripEmpty(v)
            if next(v) == nil then
                table.insert(to_remove, k)
            end
        end
    end
    for _, k in ipairs(to_remove) do
        t[k] = nil
    end
end

--------------------------------------------------------------------------------
-- local function toEpochMs
-- Normalises CrowdStrike timestamp variants to epoch milliseconds (integer).
-- Handles: Unix ms (>1e12), Unix seconds, ISO-8601 strings, numeric strings.
--------------------------------------------------------------------------------
local function toEpochMs(val)
    if val == nil then return nil end

    if type(val) == "number" then
        if val > 1e12 then return math.floor(val) end
        return math.floor(val * 1000)
    end

    if type(val) == "string" then
        local n = tonumber(val)
        if n then
            if n > 1e12 then return math.floor(n) end
            return math.floor(n * 1000)
        end
        -- ISO-8601: "2024-06-15T12:34:56Z" or "2024-06-15T12:34:56.000Z"
        local y, mo, d, h, mi, s =
            tostring(val or ""):match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
        if y then
            local ok, ts = pcall(function()
                return os.time({
                    year  = tonumber(y),
                    month = tonumber(mo),
                    day   = tonumber(d),
                    hour  = tonumber(h),
                    min   = tonumber(mi),
                    sec   = tonumber(s),
                })
            end)
            if ok and ts then return ts * 1000 end
        end
    end

    return nil
end

--------------------------------------------------------------------------------
-- local function normSeverity
-- Maps CrowdStrike severity (string name or integer 0-4) → OCSF {id, label}.
-- Returns nil, nil when input is absent — never defaults to "Unknown".
--------------------------------------------------------------------------------
local function normSeverity(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower()
    local entry = SEVERITY_MAP[key]
    if entry then return entry.id, entry.label end
    -- Numeric fallback: CrowdStrike integer severity
    local n = tonumber(val)
    if n then
        local nkey = tostring(math.floor(n))
        local nentry = SEVERITY_MAP[nkey]
        if nentry then return nentry.id, nentry.label end
    end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normStatus
-- Maps CrowdStrike detection status string → OCSF {id, label}.
-- Returns nil, nil when input is absent — never defaults to "Unknown".
--------------------------------------------------------------------------------
local function normStatus(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower()
    -- Normalise spaces/underscores for lookup
    local key_norm = key:gsub("[ _%-]+", "_")
    local entry = STATUS_MAP[key] or STATUS_MAP[key_norm]
    if entry then return entry.id, entry.label end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normDisposition
-- Maps CrowdStrike PatternDispositionDescription → OCSF {disp_id, disp_label, action_id}.
-- Returns nil, nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normDisposition(val)
    if val == nil then return nil, nil, nil end
    local key = tostring(val or ""):lower()
    local key_norm = key:gsub("[ _%-]+", "_")
    local entry = DISPOSITION_MAP[key] or DISPOSITION_MAP[key_norm]
    if entry then return entry.id, entry.label, entry.action_id end
    -- Substring scan for partial matches
    for pattern, e2 in pairs(DISPOSITION_MAP) do
        if key:find(tostring(pattern or ""), 1, true) then
            return e2.id, e2.label, e2.action_id
        end
    end
    return nil, nil, nil
end

--------------------------------------------------------------------------------
-- local function normConfidence
-- Maps CrowdStrike confidence value → OCSF {id, label}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normConfidence(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower()
    local entry = CONFIDENCE_MAP[key]
    if entry then return entry.id, entry.label end
    -- Numeric range bucketing (0-100 scale)
    local n = tonumber(val)
    if n then
        if n <= 33  then return 1, "Low"    end
        if n <= 66  then return 2, "Medium" end
        if n <= 100 then return 3, "High"   end
    end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normActivityId
-- Derives OCSF activity_id from CrowdStrike status string.
-- Returns 1 (Create) as safe default when status is absent.
--------------------------------------------------------------------------------
local function normActivityId(status_val)
    if status_val == nil then return 1 end
    local key = tostring(status_val or ""):lower()
    local key_norm = key:gsub("[ _%-]+", "_")
    local id = ACTIVITY_MAP[key] or ACTIVITY_MAP[key_norm]
    if id then return id end
    return 1
end

--------------------------------------------------------------------------------
-- local function buildAttacks
-- Constructs OCSF attacks[] (MITRE ATT&CK) from CrowdStrike tactic/technique fields.
-- Handles both single-value and pipe-delimited multi-value strings.
-- Uses table.concat for all loop-based string assembly.
--------------------------------------------------------------------------------
local function buildAttacks(e)
    -- Collect tactic/technique pairs; CrowdStrike may send pipe-delimited lists
    local tactics    = {}
    local techniques = {}
    local tactic_ids = {}
    local tech_ids   = {}

    -- Split helper (no .. inside loop)
    local function splitPipe(s)
        local parts = {}
        for part in tostring(s or ""):gmatch("[^|]+") do
            local trimmed = part:match("^%s*(.-)%s*$")
            if trimmed and trimmed ~= "" then
                table.insert(parts, trimmed)
            end
        end
        return parts
    end

    local tactic_src    = e["Tactic"]      or e["tactic"]      or e["tactic_name"]
    local technique_src = e["Technique"]   or e["technique"]   or e["technique_name"]
    local tactic_id_src = e["TacticId"]    or e["tactic_id"]
    local tech_id_src   = e["TechniqueId"] or e["technique_id"]

    if tactic_src    then tactics    = splitPipe(tactic_src)    end
    if technique_src then techniques = splitPipe(technique_src) end
    if tactic_id_src then tactic_ids = splitPipe(tactic_id_src) end
    if tech_id_src   then tech_ids   = splitPipe(tech_id_src)   end

    if #tactics == 0 and #techniques == 0 then return nil end

    local attacks = {}
    local max_len = math.max(#tactics, #techniques)

    for i = 1, max_len do
        local entry = {}

        local tac_name = tactics[i]
        local tac_id   = tactic_ids[i]
        if tac_name or tac_id then
            entry.tactic = {}
            if tac_name then entry.tactic.name = tac_name end
            if tac_id   then entry.tactic.uid  = tac_id   end
        end

        local tech_name = techniques[i]
        local tech_id   = tech_ids[i]
        if tech_name or tech_id then
            entry.technique = {}
            if tech_name then entry.technique.name = tech_name end
            if tech_id   then entry.technique.uid  = tech_id   end
        end

        if next(entry) ~= nil then
            table.insert(attacks, entry)
        end
    end

    if #attacks == 0 then return nil end
    return attacks
end

--------------------------------------------------------------------------------
-- local function buildDevice
-- Constructs OCSF device object from CrowdStrike host/agent/OS fields.
--------------------------------------------------------------------------------
local function buildDevice(e)
    local dev = {}

    local name = e["ComputerName"] or e["hostname"] or e["Hostname"]
    if name then dev.name = name end

    local uid = e["aid"] or e["device_id"] or e["SensorId"]
    if uid then dev.uid = tostring(uid or "") end

    local ip = e["LocalIP"] or e["local_ip"]
    if ip then dev.ip = ip end

    local mac = e["MacAddress"] or e["mac_address"]
    if mac then dev.mac = mac end

    -- OS object
    local os_ver  = e["OSVersion"]  or e["os_version"]
    local os_name = e["OSName"]     or e["os_name"]     or e["platform_name"]
    local os_type = e["OSType"]     or e["os_type"]     or e["platform_type"]
    if os_ver or os_name or os_type then
        dev.os = {}
        if os_name then dev.os.name    = os_name end
        if os_ver  then dev.os.version = os_ver  end
        if os_type then dev.os.type    = os_type end
    end

    -- Agent list (CrowdStrike Falcon sensor)
    local agent_ver = e["AgentVersion"] or e["agent_version"]
    if agent_ver then
        dev.agent_list = {
            {
                name    = "CrowdStrike Falcon",
                version = tostring(agent_ver or ""),
                type    = "EDR",
                type_id = 3,
            }
        }
    end

    if next(dev) == nil then return nil end
    return dev
end

--------------------------------------------------------------------------------
-- local function buildProcess
-- Constructs OCSF process object from CrowdStrike process/file fields.
--------------------------------------------------------------------------------
local function buildProcess(e)
    local proc = {}

    local pid = e["ProcessId"] or e["pid"]
    if pid then proc.pid = tonumber(pid) or pid end

    local cmd = e["CommandLine"] or e["cmdline"] or e["command_line"]
    if cmd then proc.cmd_line = cmd end

    -- File object
    local fname = e["FileName"] or e["filename"]
    local fpath = e["FilePath"] or e["filepath"] or e["ImageFileName"]
    local sha256 = e["SHA256HashData"] or e["sha256"] or e["SHA256"]
    local md5    = e["MD5HashData"]    or e["md5"]    or e["MD5"]

    if fname or fpath or sha256 or md5 then
        proc.file = {}
        if fname then proc.file.name = fname end
        if fpath then proc.file.path = fpath end

        -- Hashes array
        local hashes = {}
        if sha256 and sha256 ~= "" then
            table.insert(hashes, {
                algorithm    = "SHA-256",
                algorithm_id = 3,
                value        = tostring(sha256 or ""),
            })
        end
        if md5 and md5 ~= "" then
            table.insert(hashes, {
                algorithm    = "MD5",
                algorithm_id = 1,
                value        = tostring(md5 or ""),
            })
        end
        if #hashes > 0 then proc.file.hashes = hashes end
    end

    -- Parent process
    local ppid     = e["ParentProcessId"]   or e["parent_pid"]
    local pcmd     = e["ParentCommandLine"] or e["parent_cmdline"]
    local pname    = e["ParentImageFileName"]
    if ppid or pcmd or pname then
        proc.parent_process = {}
        if ppid  then proc.parent_process.pid      = tonumber(ppid) or ppid end
        if pcmd  then proc.parent_process.cmd_line = pcmd  end
        if pname then
            proc.parent_process.file = { name = pname }
        end
    end

    -- User context on process
    local uname = e["UserName"] or e["user_name"]
    local uid   = e["UserId"]   or e["user_id"]
    if uname or uid then
        proc.user = {}
        if uname then proc.user.name = uname end
        if uid   then proc.user.uid  = tostring(uid or "") end
    end

    if next(proc) == nil then return nil end
    return proc
end

--------------------------------------------------------------------------------
-- local function buildFindingInfo
-- Constructs OCSF finding_info object (required).
-- Uses table.concat for multi-part title assembly.
--------------------------------------------------------------------------------
local function buildFindingInfo(e)
    local fi = {}

    local uid = e["DetectId"] or e["detection_id"] or e["composite_id"]
    if uid then fi.uid = tostring(uid or "") end

    local title = e["DetectName"] or e["detect_name"] or e["Name"] or e["name"]
    if title then
        fi.title = tostring(title or "")
    else
        -- Build title from tactic + technique without .. in a loop
        local parts = {}
        local tac = e["Tactic"] or e["tactic"]
        local tec = e["Technique"] or e["technique"]
        if tac then table.insert(parts, tostring(tac or "")) end
        if tec then table.insert(parts, tostring(tec or "")) end
        if #parts > 0 then
            fi.title = table.concat(parts, " / ")
        end
    end

    local desc = e["Description"] or e["description"]
    if desc then fi.desc = tostring(desc or "") end

    local src_url = e["FalconHostLink"] or e["falcon_host_link"]
    if src_url then fi.src_url = tostring(src_url or "") end

    -- created_time mirrors the event time
    local ts = e["created_timestamp"] or e["timestamp"] or e["_time"]
    local ts_ms = toEpochMs(ts)
    if ts_ms then fi.created_time = ts_ms end

    -- Product UID (detection rule / pattern ID)
    local pattern_id = e["PatternId"] or e["pattern_id"] or e["DetectId"]
    if pattern_id then fi.product_uid = tostring(pattern_id or "") end

    -- Types array (detection category)
    local detect_type = e["DetectionType"] or e["detection_type"] or e["ExternalApiType"]
    if detect_type then
        fi.types = { tostring(detect_type or "") }
    end

    if next(fi) == nil then return nil end
    return fi
end

--------------------------------------------------------------------------------
-- local function buildObservables
-- Constructs OCSF observables[] from key indicator fields.
-- type_id: 1=Hostname, 2=IP Address, 5=Process Name, 7=Hash, 20=User Name, 99=Other
--------------------------------------------------------------------------------
local function buildObservables(e)
    local obs = {}

    local function addObs(name, type_id, value)
        if value and value ~= "" then
            table.insert(obs, {
                name    = name,
                type_id = type_id,
                value   = tostring(value or ""),
            })
        end
    end

    addObs("device.name",  1,  e["ComputerName"]   or e["hostname"])
    addObs("device.ip",    2,  e["LocalIP"]         or e["local_ip"])
    addObs("remote_ip",    2,  e["RemoteIP"]         or e["remote_ip"])
    addObs("actor.user",   20, e["UserName"]         or e["user_name"])
    addObs("process.name", 5,  e["FileName"]         or e["filename"])
    addObs("sha256",       7,  e["SHA256HashData"]   or e["sha256"])
    addObs("md5",          7,  e["MD5HashData"]      or e["md5"])
    addObs("device.uid",   99, e["aid"]              or e["device_id"])

    if #obs == 0 then return nil end
    return obs
end

--------------------------------------------------------------------------------
-- local function buildEvidences
-- Constructs OCSF evidences[] from process + file artefacts.
--------------------------------------------------------------------------------
local function buildEvidences(e)
    local evid = {}

    local sha256 = e["SHA256HashData"] or e["sha256"] or e["SHA256"]
    local md5    = e["MD5HashData"]    or e["md5"]    or e["MD5"]
    local fname  = e["FileName"]       or e["filename"]
    local fpath  = e["FilePath"]       or e["filepath"]
    local cmd    = e["CommandLine"]    or e["cmdline"] or e["command_line"]

    if sha256 or md5 or fname or fpath or cmd then
        local ev = {}

        if cmd then ev.cmd_line = tostring(cmd or "") end

        if fname or fpath or sha256 or md5 then
            ev.file = {}
            if fname then ev.file.name = tostring(fname or "") end
            if fpath then ev.file.path = tostring(fpath or "") end

            local hashes = {}
            if sha256 and sha256 ~= "" then
                table.insert(hashes, {
                    algorithm    = "SHA-256",
                    algorithm_id = 3,
                    value        = tostring(sha256 or ""),
                })
            end
            if md5 and md5 ~= "" then
                table.insert(hashes, {
                    algorithm    = "MD5",
                    algorithm_id = 1,
                    value        = tostring(md5 or ""),
                })
            end
            if #hashes > 0 then ev.file.hashes = hashes end
        end

        if next(ev) ~= nil then
            table.insert(evid, ev)
        end
    end

    if #evid == 0 then return nil end
    return evid
end

--------------------------------------------------------------------------------
-- local function buildResources
-- Constructs OCSF resources[] from device and file targets.
--------------------------------------------------------------------------------
local function buildResources(e)
    local resources = {}

    local function addResource(name, rtype, uid)
        if name or uid then
            local r = { type = rtype }
            if name then r.name = tostring(name or "") end
            if uid  then r.uid  = tostring(uid  or "") end
            table.insert(resources, r)
        end
    end

    addResource(
        e["ComputerName"] or e["hostname"],
        "Device",
        e["aid"] or e["device_id"]
    )

    local fname = e["FileName"] or e["filename"]
    local fpath = e["FilePath"] or e["filepath"]
    if fname or fpath then
        local file_name = fname or fpath
        addResource(file_name, "File", nil)
    end

    if #resources == 0 then return nil end
    return resources
end

--------------------------------------------------------------------------------
-- local function buildMalware
-- Constructs OCSF malware[] from CrowdStrike IOC / malware classification fields.
--------------------------------------------------------------------------------
local function buildMalware(e)
    local mal_name  = e["MalwareName"]  or e["malware_name"]  or e["ioc_value"]
    local mal_class = e["MalwareClass"] or e["malware_class"] or e["ioc_type"]
    local sha256    = e["SHA256HashData"] or e["sha256"]

    if not mal_name and not mal_class and not sha256 then return nil end

    local entry = {}
    if mal_name  then entry.name           = tostring(mal_name  or "") end
    if mal_class then entry.classification = tostring(mal_class or "") end

    if sha256 then
        entry.hashes = {
            {
                algorithm    = "SHA-256",
                algorithm_id = 3,
                value        = tostring(sha256 or ""),
            }
        }
    end

    return { entry }
end

--------------------------------------------------------------------------------
-- MAIN: processEvent
-- Entry point required by the Observo Lua transform runtime.
-- All helpers are declared as local functions ABOVE this function.
--------------------------------------------------------------------------------
function processEvent(event)

    --------------------------------------------------------------------------
    -- INNER: core transform — wrapped in pcall for pipeline safety
    --------------------------------------------------------------------------
    local function execute(e)

        -- Track consumed source keys to populate unmapped correctly
        local consumed = {}

        -----------------------------------------------------------------------
        -- 1. Seed OCSF skeleton with required constant fields
        -----------------------------------------------------------------------
        local ocsf = {
            class_uid     = 2004,
            class_name    = "Detection Finding",
            category_uid  = 2,
            category_name = "Findings",
            metadata = {
                version = "1.3.0",
                product = {
                    vendor_name = "CrowdStrike",
                    name        = "Falcon",
                    feature     = { name = "Detections" },
                },
            },
            osint    = {},
            unmapped = {},
        }

        -----------------------------------------------------------------------
        -- 2. Apply FIELD_MAP: scalar source field → OCSF destination path
        -----------------------------------------------------------------------
        for src_field, dest_path in pairs(FIELD_MAP) do
            local val = deepGet(e, src_field)
            if val ~= nil and val ~= "" then
                if dest_path == "time" or dest_path == "start_time" or dest_path == "end_time" then
                    val = toEpochMs(val)
                end
                if val ~= nil then
                    deepSet(ocsf, dest_path, val)
                    consumed[src_field] = true
                end
            end
        end

        -----------------------------------------------------------------------
        -- 3. Resolve time with fallback chain
        -----------------------------------------------------------------------
        if ocsf.time == nil then
            local fallbacks = {
                "created_timestamp", "timestamp", "_time",
                "ProcessStartTime", "start_timestamp",
            }
            for _, fb in ipairs(fallbacks) do
                local ts = toEpochMs(e[fb])
                if ts then
                    ocsf.time = ts
                    consumed[fb] = true
                    break
                end
            end
        end
        if ocsf.time == nil then
            local ok, ts = pcall(os.time)
            ocsf.time = ok and (ts * 1000) or 0
        end

        -----------------------------------------------------------------------
        -- 4. Severity
        -----------------------------------------------------------------------
        local sev_raw = e["Severity"] or e["severity"] or e["SeverityName"] or e["severity_name"]
        local sev_id, sev_label = normSeverity(sev_raw)
        if sev_id then
            ocsf.severity_id = sev_id
            ocsf.severity    = sev_label
        else
            -- Required field: safe numeric default (Informational) when absent
            ocsf.severity_id = 1
            ocsf.severity    = "Informational"
        end
        consumed["Severity"]      = true
        consumed["severity"]      = true
        consumed["SeverityName"]  = true
        consumed["severity_name"] = true

        -----------------------------------------------------------------------
        -- 5. Status
        -----------------------------------------------------------------------
        local status_raw = e["Status"] or e["status"]
        local st_id, st_label = normStatus(status_raw)
        if st_id then
            ocsf.status_id = st_id
            ocsf.status    = st_label
        end
        consumed["Status"] = true
        consumed["status"] = true

        -----------------------------------------------------------------------
        -- 6. Disposition + action_id
        -----------------------------------------------------------------------
        local disp_raw = e["PatternDispositionDescription"]
                      or e["disposition"]
                      or e["Disposition"]
                      or e["action"]
                      or e["Action"]
        local disp_id, disp_label, act_id = normDisposition(disp_raw)
        if disp_id then
            ocsf.disposition_id = disp_id
            ocsf.disposition    = disp_label
        end
        -- action_id is required; derive from disposition or default to 0
        ocsf.action_id = act_id or 0
        if act_id and act_id == 1 then
            ocsf.action = "Allowed"
        elseif act_id and act_id == 2 then
            ocsf.action = "Denied"
        end
        consumed["PatternDispositionDescription"] = true
        consumed["disposition"]                   = true
        consumed["Disposition"]                   = true
        consumed["action"]                        = true
        consumed["Action"]                        = true

        -----------------------------------------------------------------------
        -- 7. Confidence
        -----------------------------------------------------------------------
        local conf_raw = e["Confidence"] or e["confidence"] or e["ConfidenceScore"]
        local conf_id, conf_label = normConfidence(conf_raw)
        if conf_id then
            ocsf.confidence_id    = conf_id
            ocsf.confidence       = conf_label
        end
        local conf_score = tonumber(e["Confidence"] or e["confidence"] or e["ConfidenceScore"])
        if conf_score then ocsf.confidence_score = conf_score end
        consumed["Confidence"]      = true
        consumed["confidence"]      = true
        consumed["ConfidenceScore"] = true

        -----------------------------------------------------------------------
        -- 8. Risk score / level
        -----------------------------------------------------------------------
        local rs = tonumber(e["RiskScore"] or e["risk_score"] or e["MaxSeverity"])
        if rs then ocsf.risk_score = rs end
        consumed["RiskScore"]   = true
        consumed["risk_score"]  = true
        consumed["MaxSeverity"] = true

        -----------------------------------------------------------------------
        -- 9. activity_id, type_uid, activity_name
        -----------------------------------------------------------------------
        local activity_id = normActivityId(status_raw)
        ocsf.activity_id   = activity_id
        ocsf.activity_name = ACTIVITY_NAMES[activity_id] or "Create"
        ocsf.type_uid      = 2004 * 100 + activity_id
        ocsf.type_name     = "Detection Finding: " .. (ACTIVITY_NAMES[activity_id] or "Create")

        -----------------------------------------------------------------------
        -- 10. finding_info (required)
        -----------------------------------------------------------------------
        local fi = buildFindingInfo(e)
        if fi then
            ocsf.finding_info = fi
            consumed["DetectId"]          = true
            consumed["detection_id"]      = true
            consumed["composite_id"]      = true
            consumed["DetectName"]        = true
            consumed["detect_name"]       = true
            consumed["Description"]       = true
            consumed["description"]       = true
            consumed["FalconHostLink"]    = true
            consumed["falcon_host_link"]  = true
            consumed["PatternId"]         = true
            consumed["pattern_id"]        = true
            consumed["DetectionType"]     = true
            consumed["detection_type"]    = true
        end

        -----------------------------------------------------------------------
        -- 11. cloud (required)
        -----------------------------------------------------------------------
        if not ocsf.cloud then ocsf.cloud = {} end
        ocsf.cloud.provider = "CrowdStrike"
        local cid = e["cid"] or e["customer_id"]
        if cid then
            ocsf.cloud.account = { uid = tostring(cid or "") }
            consumed["cid"]         = true
            consumed["customer_id"] = true
        end

        -----------------------------------------------------------------------
        -- 12. device (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_DEVICE then
            local dev = buildDevice(e)
            if dev then
                ocsf.device = dev
                consumed["ComputerName"]  = true
                consumed["hostname"]      = true
                consumed["Hostname"]      = true
                consumed["aid"]           = true
                consumed["device_id"]     = true
                consumed["SensorId"]      = true
                consumed["LocalIP"]       = true
                consumed["local_ip"]      = true
                consumed["MacAddress"]    = true
                consumed["mac_address"]   = true
                consumed["OSVersion"]     = true
                consumed["os_version"]    = true
                consumed["OSName"]        = true
                consumed["os_name"]       = true
                consumed["platform_name"] = true
                consumed["OSType"]        = true
                consumed["os_type"]       = true
                consumed["platform_type"] = true
                consumed["AgentVersion"]  = true
                consumed["agent_version"] = true
            end
        end

        -----------------------------------------------------------------------
        -- 13. actor (optional but populated when user context present)
        -----------------------------------------------------------------------
        local uname = e["UserName"] or e["user_name"]
        local uid   = e["UserId"]   or e["user_id"]
        if uname or uid then
            ocsf.actor = { user = { type_id = 1, type = "User" } }
            if uname then ocsf.actor.user.name = tostring(uname or "") end
            if uid   then ocsf.actor.user.uid  = tostring(uid   or "") end
            consumed["UserName"] = true
            consumed["user_name"] = true
            consumed["UserId"]   = true
            consumed["user_id"]  = true
        end

        -----------------------------------------------------------------------
        -- 14. attacks[] (MITRE ATT&CK)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_ATTACKS then
            local attacks = buildAttacks(e)
            if attacks then
                ocsf.attacks = attacks
                consumed["Tactic"]       = true
                consumed["tactic"]       = true
                consumed["tactic_name"]  = true
                consumed["Technique"]    = true
                consumed["technique"]    = true
                consumed["technique_name"] = true
                consumed["TacticId"]     = true
                consumed["tactic_id"]    = true
                consumed["TechniqueId"]  = true
                consumed["technique_id"] = true
            end
        end

        -----------------------------------------------------------------------
        -- 15. malware[]
        -----------------------------------------------------------------------
        local malware = buildMalware(e)
        if malware then
            ocsf.malware = malware
            consumed["MalwareName"]  = true
            consumed["malware_name"] = true
            consumed["MalwareClass"] = true
            consumed["malware_class"] = true
            consumed["ioc_value"]    = true
            consumed["ioc_type"]     = true
        end

        -----------------------------------------------------------------------
        -- 16. evidences[]
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_EVIDENCES then
            local evid = buildEvidences(e)
            if evid then
                ocsf.evidences = evid
                consumed["SHA256HashData"] = true
                consumed["sha256"]         = true
                consumed["SHA256"]         = true
                consumed["MD5HashData"]    = true
                consumed["md5"]            = true
                consumed["MD5"]            = true
                consumed["FileName"]       = true
                consumed["filename"]       = true
                consumed["FilePath"]       = true
                consumed["filepath"]       = true
                consumed["ImageFileName"]  = true
                consumed["CommandLine"]    = true
                consumed["cmdline"]        = true
                consumed["command_line"]   = true
            end
        end

        -----------------------------------------------------------------------
        -- 17. resources[]
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_RESOURCES then
            local res = buildResources(e)
            if res then
                ocsf.resources = res
            end
        end

        -----------------------------------------------------------------------
        -- 18. observables[]
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_OBSERVABLES then
            local obs = buildObservables(e)
            if obs then ocsf.observables = obs end
        end

        -----------------------------------------------------------------------
        -- 19. status_code / status_detail from raw disposition description
        -----------------------------------------------------------------------
        if disp_raw then
            ocsf.status_code = tostring(disp_raw or "")
        end
        local explain = e["PatternDispositionFlags"] or e["disposition_flags"]
        if explain then
            ocsf.status_detail = tostring(explain or "")
            consumed["PatternDispositionFlags"] = true
            consumed["disposition_flags"]       = true
        end

        -----------------------------------------------------------------------
        -- 20. comment from analyst notes
        -----------------------------------------------------------------------
        local comment = e["Comment"] or e["comment"] or e["analyst_notes"]
        if comment then
            ocsf.comment = tostring(comment or "")
            consumed["Comment"]       = true
            consumed["comment"]       = true
            consumed["analyst_notes"] = true
        end

        -----------------------------------------------------------------------
        -- 21. raw_data
        -----------------------------------------------------------------------
        if FEATURES.PRESERVE_RAW then
            local ok_enc, raw_str = pcall(json.encode, e)
            if ok_enc and raw_str then
                ocsf.raw_data = raw_str
            end
        end

        -----------------------------------------------------------------------
        -- 22. Collect unmapped fields
        -----------------------------------------------------------------------
        -- Build a set of all top-level keys handled by FIELD_MAP or consumed
        local handled = {}
        for k in pairs(FIELD_MAP) do handled[k] = true end
        for k in pairs(consumed)  do handled[k] = true end

        for k, v in pairs(e) do
            if not handled[k] then
                ocsf.unmapped[k] = v
            end
        end
        if next(ocsf.unmapped) == nil then
            ocsf.unmapped = nil
        end

        -----------------------------------------------------------------------
        -- 23. Strip empty strings / empty tables
        -----------------------------------------------------------------------
        if FEATURES.STRIP_EMPTY then
            stripEmpty(ocsf)
        end

        -----------------------------------------------------------------------
        -- 24. Compose message string (table.concat, no .. in loop)
        -----------------------------------------------------------------------
        local msg_parts = {}
        local actor_name = deepGet(ocsf, "actor.user.name")
        local dev_name   = deepGet(ocsf, "device.name")
        local fi_title   = deepGet(ocsf, "finding_info.title")
        local sev_lbl    = ocsf.severity
        local disp_lbl   = ocsf.disposition

        table.insert(msg_parts, "CrowdStrike Detection:")
        if fi_title  then table.insert(msg_parts, "title="   .. tostring(fi_title  or "")) end
        if sev_lbl   then table.insert(msg_parts, "severity=" .. tostring(sev_lbl  or "")) end
        if disp_lbl  then table.insert(msg_parts, "disposition=" .. tostring(disp_lbl or "")) end
        if dev_name  then table.insert(msg_parts, "device="  .. tostring(dev_name  or "")) end
        if actor_name then table.insert(msg_parts, "user="   .. tostring(actor_name or "")) end

        ocsf.message = table.concat(msg_parts, " ")

        -----------------------------------------------------------------------
        -- 25. Encode final OCSF event as raw JSON into message field
        -----------------------------------------------------------------------
        local ok_msg, json_str = pcall(json.encode, ocsf)
        if ok_msg and json_str then
            ocsf.message = json_str
        end

        return ocsf
    end -- end execute()

    --------------------------------------------------------------------------
    -- Safety wrapper: pcall prevents pipeline crashes on malformed events
    --------------------------------------------------------------------------
    local ok, result = pcall(execute, event)
    if ok then
        return result
    else
        event["_ocsf_error"]        = tostring(result or "")
        event["_ocsf_serializer"]   = "crowdstrike_detection_finding"
        event["_ocsf_parse_failed"] = "true"
        return event
    end

end -- end processEvent()
