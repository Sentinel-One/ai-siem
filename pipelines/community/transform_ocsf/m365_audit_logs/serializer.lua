--------------------------------------------------------------------------------
-- Microsoft 365 Audit Logs → OCSF 1.3.0 API Activity (class_uid = 6003)
-- Observo processEvent(event) contract
-- Author: Observo AI  |  Schema: OCSF 1.3.0  |  Class: API Activity (6003)
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
    PRESERVE_RAW          = true,   -- attach raw_data (json-encoded source event)
    ENRICH_HTTP_REQUEST   = true,   -- build http_request from UserAgent / ClientIP
    ENRICH_RESOURCES      = true,   -- build resources[] from ObjectId / file fields
    ENRICH_CLOUD          = true,   -- build cloud from OrganizationId / Workload
    ENRICH_SRC_ENDPOINT   = true,   -- build src_endpoint from ClientIP / DeviceProperties
    ENRICH_OBSERVABLES    = true,   -- build observables[] from IPs / users / objects
    ENRICH_ACTOR          = true,   -- build actor from UserId / ApplicationId / session
    FLATTEN_EXT_PROPS     = true,   -- flatten ExtendedProperties KV list into api.request.data
    FLATTEN_PARAMETERS    = true,   -- flatten Parameters KV list into api.request.data
    STRIP_EMPTY           = true,   -- recursively remove nil/"" values before return
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
    "message",
    "metadata",
    "actor",
    "api",
    "http_request",
    "src_endpoint",
    "dst_endpoint",
    "cloud",
    "resources",
    "observables",
    "osint",
    "raw_data",
    "unmapped",
}

--------------------------------------------------------------------------------
-- OPERATION_VERB_MAP: M365 Operation verb prefix → OCSF activity_id
-- activity_id: 1=Create, 2=Read, 3=Update, 4=Delete, 99=Other
-- Keys are lowercase verb prefixes matched against the start of Operation.
--------------------------------------------------------------------------------
local OPERATION_VERB_MAP = {
    -- Create
    create      = 1,
    add         = 1,
    new         = 1,
    upload      = 1,
    send        = 1,
    post        = 1,
    publish     = 1,
    invite      = 1,
    register    = 1,
    generate    = 1,
    insert      = 1,
    submit      = 1,
    install     = 1,
    deploy      = 1,
    grant       = 1,
    assign      = 1,
    -- Read
    get         = 2,
    view        = 2,
    open        = 2,
    download    = 2,
    search      = 2,
    list        = 2,
    access      = 2,
    read        = 2,
    fetch       = 2,
    export      = 2,
    preview     = 2,
    show        = 2,
    -- Update
    update      = 3,
    set         = 3,
    modify      = 3,
    edit        = 3,
    change      = 3,
    enable      = 3,
    disable     = 3,
    rename      = 3,
    move        = 3,
    copy        = 3,
    restore     = 3,
    reset       = 3,
    rotate      = 3,
    sync        = 3,
    merge       = 3,
    approve     = 3,
    convert     = 3,
    -- Delete
    delete      = 4,
    remove      = 4,
    purge       = 4,
    revoke      = 4,
    expire      = 4,
    uninstall   = 4,
    unassign    = 4,
    reject      = 4,
    block       = 4,
    archive     = 4,
    trash       = 4,
}

--------------------------------------------------------------------------------
-- ACTIVITY_NAMES: activity_id → caption
--------------------------------------------------------------------------------
local ACTIVITY_NAMES = {
    [1]  = "Create",
    [2]  = "Read",
    [3]  = "Update",
    [4]  = "Delete",
    [99] = "Other",
}

--------------------------------------------------------------------------------
-- STATUS_MAP: M365 ResultStatus values → OCSF {id, label}
-- OCSF status_id: 1=Success, 2=Failure, 99=Other
--------------------------------------------------------------------------------
local STATUS_MAP = {
    succeeded           = { id = 1, label = "Success" },
    success             = { id = 1, label = "Success" },
    ["true"]            = { id = 1, label = "Success" },
    passed              = { id = 1, label = "Success" },
    allowed             = { id = 1, label = "Success" },
    failed              = { id = 2, label = "Failure" },
    failure             = { id = 2, label = "Failure" },
    ["false"]           = { id = 2, label = "Failure" },
    error               = { id = 2, label = "Failure" },
    denied              = { id = 2, label = "Failure" },
    blocked             = { id = 2, label = "Failure" },
    partiallysucceeded  = { id = 99, label = "Other" },
    partial             = { id = 99, label = "Other" },
    pending             = { id = 99, label = "Other" },
}

--------------------------------------------------------------------------------
-- USER_TYPE_MAP: M365 UserType integer → OCSF {type_id, type_label}
-- M365: 0=Regular, 1=Reserved, 2=Admin, 3=DcAdmin, 4=System,
--       5=Application, 6=ServicePrincipal, 7=CustomPolicy, 8=SystemPolicy
-- OCSF user type_id: 1=User, 2=Admin, 3=System, 4=Application, 99=Other
--------------------------------------------------------------------------------
local USER_TYPE_MAP = {
    ["0"] = { type_id = 1,  type_label = "User" },
    ["1"] = { type_id = 99, type_label = "Other" },
    ["2"] = { type_id = 2,  type_label = "Admin" },
    ["3"] = { type_id = 2,  type_label = "Admin" },
    ["4"] = { type_id = 3,  type_label = "System" },
    ["5"] = { type_id = 4,  type_label = "Application" },
    ["6"] = { type_id = 4,  type_label = "Application" },
    ["7"] = { type_id = 99, type_label = "Other" },
    ["8"] = { type_id = 3,  type_label = "System" },
}

--------------------------------------------------------------------------------
-- WORKLOAD_MAP: M365 Workload string → canonical service name
--------------------------------------------------------------------------------
local WORKLOAD_MAP = {
    exchange            = "Microsoft Exchange Online",
    sharepoint          = "Microsoft SharePoint Online",
    onedrive            = "Microsoft OneDrive for Business",
    azureactivedirectory = "Microsoft Entra ID",
    azuread             = "Microsoft Entra ID",
    teams               = "Microsoft Teams",
    microsoftteams      = "Microsoft Teams",
    securitycompliancecenter = "Microsoft Purview",
    compliance          = "Microsoft Purview",
    powerbi             = "Microsoft Power BI",
    dynamics365         = "Microsoft Dynamics 365",
    yammer              = "Microsoft Viva Engage",
    sway                = "Microsoft Sway",
    forms               = "Microsoft Forms",
    stream              = "Microsoft Stream",
    planner             = "Microsoft Planner",
    project             = "Microsoft Project",
    intune              = "Microsoft Intune",
    defender            = "Microsoft Defender",
    mip                 = "Microsoft Information Protection",
}

--------------------------------------------------------------------------------
-- FIELD_MAP: M365 source field → OCSF destination dot-path (scalar mappings)
-- Complex / nested objects are handled by dedicated builder helpers.
--------------------------------------------------------------------------------
local FIELD_MAP = {
    -- Timing
    ["CreationTime"]            = "time",
    ["CreationDate"]            = "time",
    ["_time"]                   = "time",
    ["timestamp"]               = "time",

    -- Metadata / correlation
    ["Id"]                      = "metadata.uid",
    ["AuditLogRecordId"]        = "metadata.uid",
    ["CorrelationId"]           = "metadata.correlation_uid",
    ["RecordType"]              = "metadata.product.feature.uid",
    ["RecordTypeName"]          = "metadata.product.feature.name",

    -- Actor / user (scalar; full object built by buildActor)
    ["UserId"]                  = "actor.user.name",
    ["UserKey"]                 = "actor.user.uid",
    ["SessionId"]               = "actor.session.uid",
    ["ApplicationId"]           = "actor.app.uid",
    ["ApplicationDisplayName"]  = "actor.app.name",
    ["ServicePrincipalName"]    = "actor.app.name",

    -- Source endpoint (scalar; full object built by buildSrcEndpoint)
    ["ClientIP"]                = "src_endpoint.ip",
    ["ClientIPAddress"]         = "src_endpoint.ip",
    ["ActorIpAddress"]          = "src_endpoint.ip",

    -- API / operation (scalar; full object built by buildApi)
    ["Operation"]               = "api.operation",
    ["SiteUrl"]                 = "api.request.url",
    ["ObjectId"]                = "api.request.data.object_id",
    ["MessageId"]               = "api.request.uid",
    ["MailboxOwnerUPN"]         = "api.request.data.mailbox_owner",
    ["FolderPath"]              = "api.request.data.folder_path",
    ["TargetUserOrGroupName"]   = "api.request.data.target_user",
    ["TargetUserOrGroupType"]   = "api.request.data.target_type",
    ["TeamName"]                = "api.request.data.team_name",
    ["ChannelName"]             = "api.request.data.channel_name",
    ["CommunicationType"]       = "api.request.data.communication_type",
    ["AddOnName"]               = "api.service.name",

    -- Cloud (scalar; full object built by buildCloud)
    ["OrganizationId"]          = "cloud.account.uid",
    ["OrganizationName"]        = "cloud.account.name",
    ["Workload"]                = "cloud.region",   -- overridden by buildCloud

    -- HTTP request (scalar; full object built by buildHttpRequest)
    ["UserAgent"]               = "http_request.user_agent",
    ["RequestId"]               = "http_request.uid",

    -- Status (scalar; normalised in main logic)
    ["ResultStatus"]            = "status",
    ["ErrorNumber"]             = "status_code",
    ["LogonError"]              = "status_detail",
    ["ExtendedInfoUrl"]         = "status_detail",

    -- File / resource (scalar; resources[] built by buildResources)
    ["SourceFileName"]          = "api.request.data.source_file_name",
    ["SourceFileExtension"]     = "api.request.data.source_file_ext",
    ["DestinationFileName"]     = "api.request.data.dest_file_name",
    ["DestinationFolderPath"]   = "api.request.data.dest_folder_path",
    ["FileSizeBytes"]           = "api.request.data.file_size_bytes",

    -- Policy / label
    ["PolicyName"]              = "api.request.data.policy_name",
    ["LabelName"]               = "api.request.data.label_name",
    ["SensitivityLabelId"]      = "api.request.data.sensitivity_label_id",
}

--------------------------------------------------------------------------------
-- local function deepGet
-- Safely retrieves a value from a nested table using dot-notation path.
-- Supports array index syntax: "key[N]"
-- Supports Microsoft KV-list scan: [{key=K, value=V}, ...]
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
            local next_val = current[part]
            -- Microsoft KV-list scan: [{key=K, value=V}]
            if next_val == nil and type(current) == "table" and #current > 0 then
                for _, item in ipairs(current) do
                    if type(item) == "table" then
                        if item.key == part then
                            next_val = item.value
                            break
                        elseif item.Name == part then
                            next_val = item.Value
                            break
                        end
                    end
                end
            end
            current = next_val
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

    local numeric_hints = {
        "uid", "port", "pid", "lat", "long",
        "bytes", "packets", "score", "offset",
        "severity_id", "status_id", "activity_id",
        "class_uid", "category_uid", "type_uid",
        "type_id", "record_type", "file_size",
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
-- Normalises M365 timestamp variants to epoch milliseconds (integer).
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
-- local function normStatus
-- Maps M365 ResultStatus string → OCSF {id, label}.
-- Returns nil, nil when input is absent — never defaults to a string literal.
--------------------------------------------------------------------------------
local function normStatus(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower()
    local key_norm = key:gsub("%s+", "")
    local entry = STATUS_MAP[key] or STATUS_MAP[key_norm]
    if entry then return entry.id, entry.label end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normActivityId
-- Derives OCSF activity_id from M365 Operation string.
-- Strategy:
--   1. Extract leading verb (camelCase or underscore-separated)
--   2. Exact match in OPERATION_VERB_MAP
--   3. Substring scan for partial matches
--   4. Default to 99 (Other)
--------------------------------------------------------------------------------
local function normActivityId(operation)
    if operation == nil then return 99 end
    local op = tostring(operation or ""):lower()

    -- Extract leading verb: split on camelCase boundary or underscore/hyphen/space
    -- e.g. "FileDownloaded" → "file", "Set-Mailbox" → "set", "UserLoggedIn" → "user"
    -- Try underscore/hyphen/space split first
    local verb = tostring(op or ""):match("^([a-z]+)[%-%_%s]")
    if not verb then
        -- camelCase: take lowercase prefix up to first uppercase transition
        -- Since op is already lowercased, take first word of original casing
        verb = tostring(operation or ""):match("^([A-Z][a-z]+)")
        if verb then verb = tostring(verb or ""):lower() end
    end
    if not verb then
        verb = tostring(op or ""):match("^([a-z]+)")
    end

    if verb and OPERATION_VERB_MAP[verb] then
        return OPERATION_VERB_MAP[verb]
    end

    -- Substring scan across full lowercased operation
    for pattern, id in pairs(OPERATION_VERB_MAP) do
        if tostring(op or ""):find(tostring(pattern or ""), 1, true) then
            return id
        end
    end

    return 99
end

--------------------------------------------------------------------------------
-- local function normUserType
-- Maps M365 UserType integer → OCSF {type_id, type_label}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normUserType(val)
    if val == nil then return nil, nil end
    local key = tostring(val or "")
    local entry = USER_TYPE_MAP[key]
    if entry then return entry.type_id, entry.type_label end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function resolveWorkload
-- Maps M365 Workload string → canonical Microsoft service name.
-- Returns nil when input is absent.
--------------------------------------------------------------------------------
local function resolveWorkload(val)
    if val == nil then return nil end
    local key = tostring(val or ""):lower():gsub("%s+", "")
    return WORKLOAD_MAP[key] or tostring(val or "")
end

--------------------------------------------------------------------------------
-- local function extractKvList
-- Flattens a Microsoft KV-list array into a plain Lua table.
-- Supports [{key=K, value=V}], [{Name=K, Value=V}], [{Key=K, Value=V}] shapes.
-- Uses table.concat for any multi-value assembly inside loops.
--------------------------------------------------------------------------------
local function extractKvList(arr)
    if type(arr) ~= "table" then return nil end
    local result = {}
    local found  = false
    for _, item in ipairs(arr) do
        if type(item) == "table" then
            local k = item.key   or item.Key   or item.Name   or item.name
            local v = item.value or item.Value or item.NewValue or item.newValue
            if k and v ~= nil then
                result[tostring(k or "")] = v
                found = true
            end
        end
    end
    if not found then return nil end
    return result
end

--------------------------------------------------------------------------------
-- local function buildActor
-- Constructs OCSF actor object from M365 user / application / session fields.
--------------------------------------------------------------------------------
local function buildActor(e)
    local actor = {}

    -- User sub-object
    local uname = e["UserId"]
    local ukey  = e["UserKey"]
    local utype = e["UserType"]

    if uname or ukey or utype then
        actor.user = {}
        if uname then actor.user.name = tostring(uname or "") end
        if ukey  then actor.user.uid  = tostring(ukey  or "") end

        local type_id, type_label = normUserType(utype)
        if type_id    then actor.user.type_id = type_id    end
        if type_label then actor.user.type    = type_label end
    end

    -- Application / service principal sub-object
    local app_id   = e["ApplicationId"]
    local app_name = e["ApplicationDisplayName"] or e["ServicePrincipalName"]
    if app_id or app_name then
        actor.app = {}
        if app_id   then actor.app.uid  = tostring(app_id   or "") end
        if app_name then actor.app.name = tostring(app_name or "") end
    end

    -- Session sub-object
    local session_id = e["SessionId"]
    if session_id then
        actor.session = { uid = tostring(session_id or "") }
    end

    -- Invoked-by (for delegated / app-only tokens)
    local invoked_by = e["InvocationInfo"] or e["InvokedBy"]
    if invoked_by then
        actor.invoked_by = { name = tostring(invoked_by or "") }
    end

    if next(actor) == nil then return nil end
    return actor
end

--------------------------------------------------------------------------------
-- local function buildSrcEndpoint
-- Constructs OCSF src_endpoint from M365 ClientIP / DeviceProperties.
--------------------------------------------------------------------------------
local function buildSrcEndpoint(e)
    local ep = {}

    local ip = e["ClientIP"] or e["ClientIPAddress"] or e["ActorIpAddress"]
    if ip then
        -- Strip IPv6 brackets: [::1]:port → ::1
        local clean_ip = tostring(ip or ""):match("^%[(.+)%]:%d+$")
                      or tostring(ip or ""):match("^%[(.+)%]$")
                      or tostring(ip or ""):match("^([^:]+):%d+$")
                      or ip
        ep.ip = tostring(clean_ip or "")
    end

    -- DeviceProperties is a KV-list in some M365 schemas
    local dev_props = e["DeviceProperties"]
    if type(dev_props) == "table" then
        local flat = extractKvList(dev_props)
        if flat then
            if flat["OS"]          then ep.os = { name = tostring(flat["OS"] or "") } end
            if flat["BrowserType"] then ep.agent_list = { { name = tostring(flat["BrowserType"] or ""), type = "Browser", type_id = 99 } } end
            if flat["DeviceId"]    then ep.uid = tostring(flat["DeviceId"] or "") end
            if flat["DisplayName"] then ep.name = tostring(flat["DisplayName"] or "") end
        end
    end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildHttpRequest
-- Constructs OCSF http_request from M365 UserAgent / RequestId / SiteUrl.
--------------------------------------------------------------------------------
local function buildHttpRequest(e)
    local req = {}

    local ua = e["UserAgent"]
    if ua then req.user_agent = tostring(ua or "") end

    local req_id = e["RequestId"] or e["CorrelationId"]
    if req_id then req.uid = tostring(req_id or "") end

    local site_url = e["SiteUrl"]
    if site_url then req.url = { text = tostring(site_url or "") } end

    -- HTTP method inference from Operation
    local op = tostring(e["Operation"] or ""):lower()
    if op ~= "" then
        local method
        if tostring(op or ""):find("get", 1, true)      or
           tostring(op or ""):find("list", 1, true)     or
           tostring(op or ""):find("view", 1, true)     or
           tostring(op or ""):find("search", 1, true)   or
           tostring(op or ""):find("download", 1, true) then
            method = "GET"
        elseif tostring(op or ""):find("delete", 1, true) or
               tostring(op or ""):find("remove", 1, true) or
               tostring(op or ""):find("purge", 1, true)  then
            method = "DELETE"
        elseif tostring(op or ""):find("update", 1, true) or
               tostring(op or ""):find("set", 1, true)    or
               tostring(op or ""):find("modify", 1, true) or
               tostring(op or ""):find("edit", 1, true)   or
               tostring(op or ""):find("enable", 1, true) or
               tostring(op or ""):find("disable", 1, true) then
            method = "PATCH"
        elseif tostring(op or ""):find("create", 1, true) or
               tostring(op or ""):find("add", 1, true)    or
               tostring(op or ""):find("new", 1, true)    or
               tostring(op or ""):find("upload", 1, true) or
               tostring(op or ""):find("send", 1, true)   or
               tostring(op or ""):find("post", 1, true)   then
            method = "POST"
        end
        if method then req.http_method = method end
    end

    if next(req) == nil then return nil end
    return req
end

--------------------------------------------------------------------------------
-- local function buildApi
-- Constructs OCSF api object from M365 Operation / service / request fields.
-- Flattens ExtendedProperties and Parameters KV-lists into api.request.data.
--------------------------------------------------------------------------------
local function buildApi(e)
    local api = {}

    local op = e["Operation"]
    if op then api.operation = tostring(op or "") end

    -- Service
    local svc_name = e["AddOnName"] or resolveWorkload(e["Workload"])
    if svc_name then
        api.service = { name = tostring(svc_name or "") }
    end

    -- Request sub-object
    local req_data = {}

    local obj_id = e["ObjectId"]
    if obj_id then req_data.object_id = tostring(obj_id or "") end

    local site_url = e["SiteUrl"]
    if site_url then req_data.site_url = tostring(site_url or "") end

    local mailbox = e["MailboxOwnerUPN"]
    if mailbox then req_data.mailbox_owner = tostring(mailbox or "") end

    local folder = e["FolderPath"]
    if folder then req_data.folder_path = tostring(folder or "") end

    local target_user = e["TargetUserOrGroupName"]
    if target_user then req_data.target_user = tostring(target_user or "") end

    local target_type = e["TargetUserOrGroupType"]
    if target_type then req_data.target_type = tostring(target_type or "") end

    local team = e["TeamName"]
    if team then req_data.team_name = tostring(team or "") end

    local channel = e["ChannelName"]
    if channel then req_data.channel_name = tostring(channel or "") end

    local comm_type = e["CommunicationType"]
    if comm_type then req_data.communication_type = tostring(comm_type or "") end

    local src_file = e["SourceFileName"]
    if src_file then req_data.source_file_name = tostring(src_file or "") end

    local src_ext = e["SourceFileExtension"]
    if src_ext then req_data.source_file_ext = tostring(src_ext or "") end

    local dest_file = e["DestinationFileName"]
    if dest_file then req_data.dest_file_name = tostring(dest_file or "") end

    local dest_folder = e["DestinationFolderPath"]
    if dest_folder then req_data.dest_folder_path = tostring(dest_folder or "") end

    local file_size = tonumber(e["FileSizeBytes"])
    if file_size then req_data.file_size_bytes = file_size end

    local policy = e["PolicyName"]
    if policy then req_data.policy_name = tostring(policy or "") end

    local label = e["LabelName"]
    if label then req_data.label_name = tostring(label or "") end

    -- Flatten ExtendedProperties KV-list
    if FEATURES.FLATTEN_EXT_PROPS then
        local ext = e["ExtendedProperties"]
        if type(ext) == "table" then
            local flat = extractKvList(ext)
            if flat then
                for k, v in pairs(flat) do
                    req_data[tostring(k or "")] = v
                end
            end
        end
    end

    -- Flatten Parameters KV-list
    if FEATURES.FLATTEN_PARAMETERS then
        local params = e["Parameters"]
        if type(params) == "table" then
            local flat = extractKvList(params)
            if flat then
                for k, v in pairs(flat) do
                    req_data[tostring(k or "")] = v
                end
            end
        end
    end

    if next(req_data) ~= nil then
        api.request = { data = req_data }
    end

    -- Request UID from MessageId
    local msg_id = e["MessageId"]
    if msg_id then
        if not api.request then api.request = {} end
        api.request.uid = tostring(msg_id or "")
    end

    if next(api) == nil then return nil end
    return api
end

--------------------------------------------------------------------------------
-- local function buildCloud
-- Constructs OCSF cloud object from M365 OrganizationId / Workload / TenantId.
--------------------------------------------------------------------------------
local function buildCloud(e)
    local cloud = { provider = "Microsoft" }

    local org_id   = e["OrganizationId"] or e["TenantId"]
    local org_name = e["OrganizationName"]
    if org_id or org_name then
        cloud.account = {}
        if org_id   then cloud.account.uid  = tostring(org_id   or "") end
        if org_name then cloud.account.name = tostring(org_name or "") end
        cloud.account.type = "Tenant"
    end

    local workload = e["Workload"]
    if workload then
        local svc = resolveWorkload(workload)
        if svc then cloud.region = tostring(workload or "") end
    end

    return cloud
end

--------------------------------------------------------------------------------
-- local function buildResources
-- Constructs OCSF resources[] from M365 ObjectId / file / SharePoint fields.
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

    -- Primary object
    local obj_id = e["ObjectId"]
    if obj_id then
        addResource(tostring(obj_id or ""), "Object", nil)
    end

    -- File resource
    local fname = e["SourceFileName"]
    local fext  = e["SourceFileExtension"]
    if fname then
        local full_name
        if fext and fext ~= "" then
            full_name = tostring(fname or "") .. "." .. tostring(fext or "")
        else
            full_name = tostring(fname or "")
        end
        addResource(full_name, "File", nil)
    end

    -- Destination file
    local dest_file = e["DestinationFileName"]
    if dest_file then
        addResource(tostring(dest_file or ""), "File", nil)
    end

    -- SharePoint site
    local site_url = e["SiteUrl"]
    if site_url then
        addResource(tostring(site_url or ""), "SharePoint Site", nil)
    end

    -- Target user / group
    local target = e["TargetUserOrGroupName"]
    local ttype  = e["TargetUserOrGroupType"]
    if target then
        addResource(tostring(target or ""), ttype or "User", nil)
    end

    -- AffectedItems array
    local affected = e["AffectedItems"]
    if type(affected) == "table" then
        for _, item in ipairs(affected) do
            if type(item) == "table" then
                local item_name = item.Name or item.name or item.Subject or item.subject
                local item_id   = item.Id   or item.id
                if item_name or item_id then
                    addResource(
                        item_name and tostring(item_name or "") or nil,
                        "Item",
                        item_id  and tostring(item_id   or "") or nil
                    )
                end
            end
        end
    end

    if #resources == 0 then return nil end
    return resources
end

--------------------------------------------------------------------------------
-- local function buildObservables
-- Constructs OCSF observables[] from key indicator fields.
-- type_id: 1=Hostname, 2=IP Address, 3=URL, 20=User Name, 99=Other
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

    addObs("actor.user",    20, e["UserId"])
    addObs("src_endpoint",   2, e["ClientIP"] or e["ClientIPAddress"])
    addObs("object_id",     99, e["ObjectId"])
    addObs("site_url",       3, e["SiteUrl"])
    addObs("target_user",   20, e["TargetUserOrGroupName"])
    addObs("app.name",      99, e["ApplicationDisplayName"] or e["ServicePrincipalName"])
    addObs("correlation_id", 99, e["CorrelationId"])

    if #obs == 0 then return nil end
    return obs
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
            class_uid     = 6003,
            class_name    = "API Activity",
            category_uid  = 6,
            category_name = "Application Activity",
            severity_id   = 1,
            severity      = "Informational",
            metadata = {
                version = "1.3.0",
                product = {
                    vendor_name = "Microsoft",
                    name        = "Microsoft 365",
                    feature     = { name = "Audit" },
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
            local fallbacks = { "CreationTime", "CreationDate", "timestamp", "_time" }
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
        -- 4. Workload → metadata.product.feature.name (override RecordTypeName)
        -----------------------------------------------------------------------
        local workload = e["Workload"]
        if workload then
            local svc = resolveWorkload(workload)
            if svc then
                deepSet(ocsf, "metadata.product.feature.name", svc)
            end
            consumed["Workload"] = true
        end

        -----------------------------------------------------------------------
        -- 5. activity_id, type_uid, activity_name
        -----------------------------------------------------------------------
        local operation   = e["Operation"]
        local activity_id = normActivityId(operation)

        ocsf.activity_id   = activity_id
        ocsf.activity_name = ACTIVITY_NAMES[activity_id] or "Other"
        ocsf.type_uid      = 6003 * 100 + activity_id
        ocsf.type_name     = "API Activity: " .. (ACTIVITY_NAMES[activity_id] or "Other")
        consumed["Operation"] = true

        -----------------------------------------------------------------------
        -- 6. Status
        -----------------------------------------------------------------------
        local status_raw = e["ResultStatus"]
        local st_id, st_label = normStatus(status_raw)
        if st_id then
            ocsf.status_id = st_id
            ocsf.status    = st_label
        end
        consumed["ResultStatus"] = true

        local err_num = e["ErrorNumber"]
        if err_num then
            ocsf.status_code = tostring(err_num or "")
            consumed["ErrorNumber"] = true
        end

        local logon_err = e["LogonError"]
        if logon_err then
            ocsf.status_detail = tostring(logon_err or "")
            consumed["LogonError"] = true
        end

        -----------------------------------------------------------------------
        -- 7. Severity: elevate on failure
        -----------------------------------------------------------------------
        if ocsf.status_id == 2 then
            ocsf.severity_id = 2
            ocsf.severity    = "Low"
        end

        -----------------------------------------------------------------------
        -- 8. actor (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_ACTOR then
            local actor = buildActor(e)
            if actor then
                ocsf.actor = actor
            else
                -- Ensure required field exists even when empty
                ocsf.actor = {}
            end
            consumed["UserId"]                 = true
            consumed["UserKey"]                = true
            consumed["UserType"]               = true
            consumed["SessionId"]              = true
            consumed["ApplicationId"]          = true
            consumed["ApplicationDisplayName"] = true
            consumed["ServicePrincipalName"]   = true
            consumed["InvocationInfo"]         = true
            consumed["InvokedBy"]              = true
        end

        -----------------------------------------------------------------------
        -- 9. src_endpoint (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SRC_ENDPOINT then
            local ep = buildSrcEndpoint(e)
            if ep then
                ocsf.src_endpoint = ep
            else
                ocsf.src_endpoint = {}
            end
            consumed["ClientIP"]          = true
            consumed["ClientIPAddress"]   = true
            consumed["ActorIpAddress"]    = true
            consumed["DeviceProperties"]  = true
        end

        -----------------------------------------------------------------------
        -- 10. api (required)
        -----------------------------------------------------------------------
        local api_obj = buildApi(e)
        if api_obj then
            ocsf.api = api_obj
        else
            ocsf.api = {}
        end
        consumed["Operation"]               = true
        consumed["AddOnName"]               = true
        consumed["ObjectId"]                = true
        consumed["SiteUrl"]                 = true
        consumed["MailboxOwnerUPN"]         = true
        consumed["FolderPath"]              = true
        consumed["TargetUserOrGroupName"]   = true
        consumed["TargetUserOrGroupType"]   = true
        consumed["TeamName"]                = true
        consumed["ChannelName"]             = true
        consumed["CommunicationType"]       = true
        consumed["SourceFileName"]          = true
        consumed["SourceFileExtension"]     = true
        consumed["DestinationFileName"]     = true
        consumed["DestinationFolderPath"]   = true
        consumed["FileSizeBytes"]           = true
        consumed["PolicyName"]              = true
        consumed["LabelName"]               = true
        consumed["SensitivityLabelId"]      = true
        consumed["MessageId"]               = true
        consumed["ExtendedProperties"]      = true
        consumed["Parameters"]              = true

        -----------------------------------------------------------------------
        -- 11. cloud (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CLOUD then
            ocsf.cloud = buildCloud(e)
            consumed["OrganizationId"]   = true
            consumed["OrganizationName"] = true
            consumed["TenantId"]         = true
            consumed["Workload"]         = true
        end

        -----------------------------------------------------------------------
        -- 12. http_request (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_HTTP_REQUEST then
            local hr = buildHttpRequest(e)
            if hr then
                ocsf.http_request = hr
            end
            consumed["UserAgent"]    = true
            consumed["RequestId"]    = true
            consumed["CorrelationId"] = true
        end

        -----------------------------------------------------------------------
        -- 13. resources (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_RESOURCES then
            local res = buildResources(e)
            if res then
                ocsf.resources = res
            end
            consumed["AffectedItems"] = true
        end

        -----------------------------------------------------------------------
        -- 14. observables (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_OBSERVABLES then
            local obs = buildObservables(e)
            if obs then ocsf.observables = obs end
        end

        -----------------------------------------------------------------------
        -- 15. ModifiedProperties → unmapped (complex nested array)
        -----------------------------------------------------------------------
        local mod_props = e["ModifiedProperties"]
        if type(mod_props) == "table" then
            ocsf.unmapped["ModifiedProperties"] = mod_props
            consumed["ModifiedProperties"] = true
        end

        -----------------------------------------------------------------------
        -- 16. PolicyDetails → unmapped
        -----------------------------------------------------------------------
        local policy_details = e["PolicyDetails"]
        if policy_details ~= nil then
            ocsf.unmapped["PolicyDetails"] = policy_details
            consumed["PolicyDetails"] = true
        end

        -----------------------------------------------------------------------
        -- 17. SharePointMetaData → unmapped
        -----------------------------------------------------------------------
        local sp_meta = e["SharePointMetaData"]
        if sp_meta ~= nil then
            ocsf.unmapped["SharePointMetaData"] = sp_meta
            consumed["SharePointMetaData"] = true
        end

        -----------------------------------------------------------------------
        -- 18. ExchangeMetaData → unmapped
        -----------------------------------------------------------------------
        local ex_meta = e["ExchangeMetaData"]
        if ex_meta ~= nil then
            ocsf.unmapped["ExchangeMetaData"] = ex_meta
            consumed["ExchangeMetaData"] = true
        end

        -----------------------------------------------------------------------
        -- 19. raw_data
        -----------------------------------------------------------------------
        if FEATURES.PRESERVE_RAW then
            local ok_enc, raw_str = pcall(json.encode, e)
            if ok_enc and raw_str then
                ocsf.raw_data = raw_str
            end
        end

        -----------------------------------------------------------------------
        -- 20. Collect remaining unmapped fields
        -----------------------------------------------------------------------
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
        -- 21. Strip empty strings / empty tables
        -----------------------------------------------------------------------
        if FEATURES.STRIP_EMPTY then
            stripEmpty(ocsf)
        end

        -----------------------------------------------------------------------
        -- 22. Compose human-readable message (table.concat, no .. in loop)
        -----------------------------------------------------------------------
        local msg_parts = {}
        local actor_name  = deepGet(ocsf, "actor.user.name")
        local api_op      = deepGet(ocsf, "api.operation")
        local workload_lbl = e["Workload"]
        local obj_id_lbl  = deepGet(ocsf, "api.request.data.object_id")
        local status_lbl  = ocsf.status

        table.insert(msg_parts, "M365 Audit:")
        if api_op      then table.insert(msg_parts, "operation=" .. tostring(api_op      or "")) end
        if actor_name  then table.insert(msg_parts, "user="      .. tostring(actor_name  or "")) end
        if workload_lbl then table.insert(msg_parts, "workload=" .. tostring(workload_lbl or "")) end
        if status_lbl  then table.insert(msg_parts, "status="   .. tostring(status_lbl  or "")) end
        if obj_id_lbl  then table.insert(msg_parts, "object="   .. tostring(obj_id_lbl  or "")) end

        ocsf.message = table.concat(msg_parts, " ")

        -----------------------------------------------------------------------
        -- 23. Encode final OCSF event as raw JSON into message field
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
        event["_ocsf_serializer"]   = "m365_audit_api_activity"
        event["_ocsf_parse_failed"] = "true"
        return event
    end

end -- end processEvent()
