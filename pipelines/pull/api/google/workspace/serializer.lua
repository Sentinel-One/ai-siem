--------------------------------------------------------------------------------
-- Google Workspace Admin & Login Activity Logs
-- → OCSF 1.3.0 Authentication (class_uid = 3002)
-- Observo processEvent(event) contract
-- Author: Observo AI  |  Schema: OCSF 1.3.0  |  Class: Authentication (3002)
-- Covers: login, admin, token, groups, drive, meet, chat applicationNames
-- Handles: nested GWS Reports API JSON + pre-parsed flat records
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
    ENRICH_USER           = true,   -- build user from actor.email / profileId
    ENRICH_SRC_ENDPOINT   = true,   -- build src_endpoint from ipAddress
    ENRICH_DST_ENDPOINT   = true,   -- build dst_endpoint from service / app
    ENRICH_SERVICE        = true,   -- build service from applicationName
    ENRICH_DEVICE         = true,   -- build device from device_id / device_type params
    ENRICH_SESSION        = true,   -- build session from uniqueQualifier
    ENRICH_CLOUD          = true,   -- build cloud from customerId / domain
    ENRICH_OBSERVABLES    = true,   -- build observables[] from IPs / users
    PARSE_NESTED_GWS      = true,   -- parse raw nested GWS Reports API structure
    FLATTEN_PARAMS        = true,   -- flatten events[].parameters[] KV list
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
    "duration",
    "severity_id",
    "severity",
    "status",
    "status_id",
    "status_code",
    "status_detail",
    "is_mfa",
    "is_remote",
    "is_new_logon",
    "auth_protocol",
    "auth_protocol_id",
    "logon_type",
    "logon_type_id",
    "message",
    "metadata",
    "user",
    "actor",
    "src_endpoint",
    "dst_endpoint",
    "service",
    "session",
    "device",
    "cloud",
    "observables",
    "osint",
    "raw_data",
    "unmapped",
}

--------------------------------------------------------------------------------
-- EVENT_NAME_MAP: GWS login event name → {activity_id, status_id, status_label}
-- activity_id: 1=Logon, 2=Logoff, 6=Preauth, 99=Other
-- status_id:   1=Success, 2=Failure
--------------------------------------------------------------------------------
local EVENT_NAME_MAP = {
    login_success                       = { activity_id = 1, status_id = 1, status_label = "Success" },
    login_failure                       = { activity_id = 1, status_id = 2, status_label = "Failure" },
    login_verification                  = { activity_id = 6, status_id = 1, status_label = "Success" },
    login_challenge                     = { activity_id = 6, status_id = 1, status_label = "Success" },
    login_challenge_passed              = { activity_id = 6, status_id = 1, status_label = "Success" },
    login_challenge_failed              = { activity_id = 6, status_id = 2, status_label = "Failure" },
    logout                              = { activity_id = 2, status_id = 1, status_label = "Success" },
    risky_sensitive_action_allowed      = { activity_id = 1, status_id = 1, status_label = "Success" },
    risky_sensitive_action_blocked      = { activity_id = 1, status_id = 2, status_label = "Failure" },
    suspicious_login                    = { activity_id = 1, status_id = 1, status_label = "Success" },
    suspicious_login_less_secure_app    = { activity_id = 1, status_id = 1, status_label = "Success" },
    gov_attack_warning                  = { activity_id = 1, status_id = 1, status_label = "Success" },
    account_disabled_spamming           = { activity_id = 99, status_id = 2, status_label = "Failure" },
    account_disabled_hijacked           = { activity_id = 99, status_id = 2, status_label = "Failure" },
    ["2sv_enroll"]                      = { activity_id = 99, status_id = 1, status_label = "Success" },
    ["2sv_disable"]                     = { activity_id = 99, status_id = 1, status_label = "Success" },
    ["2sv_change"]                      = { activity_id = 99, status_id = 1, status_label = "Success" },
    titanium_enroll                     = { activity_id = 99, status_id = 1, status_label = "Success" },
    titanium_unenroll                   = { activity_id = 99, status_id = 1, status_label = "Success" },
    passkey_enroll                      = { activity_id = 99, status_id = 1, status_label = "Success" },
    passkey_unenroll                    = { activity_id = 99, status_id = 1, status_label = "Success" },
}

--------------------------------------------------------------------------------
-- ADMIN_VERB_MAP: GWS admin event name verb prefix → OCSF activity_id
-- activity_id: 1=Logon(Create), 2=Logoff(Delete), 99=Other
-- Reusing Logon/Logoff as Create/Delete proxies for admin IAM events
--------------------------------------------------------------------------------
local ADMIN_VERB_MAP = {
    create      = 1,
    add         = 1,
    insert      = 1,
    grant       = 1,
    assign      = 1,
    enable      = 1,
    unsuspend   = 1,
    restore     = 1,
    invite      = 1,
    approve     = 1,
    delete      = 2,
    remove      = 2,
    revoke      = 2,
    suspend     = 2,
    disable     = 2,
    reject      = 2,
    change      = 99,
    update      = 99,
    modify      = 99,
    reset       = 99,
    rename      = 99,
    move        = 99,
    transfer    = 99,
    download    = 99,
    upload      = 99,
    view        = 99,
    list        = 99,
}

--------------------------------------------------------------------------------
-- ACTIVITY_NAMES: activity_id → caption
--------------------------------------------------------------------------------
local ACTIVITY_NAMES = {
    [1]  = "Logon",
    [2]  = "Logoff",
    [3]  = "Authentication Ticket",
    [4]  = "Service Ticket Request",
    [5]  = "Service Ticket Renew",
    [6]  = "Preauth",
    [99] = "Other",
}

--------------------------------------------------------------------------------
-- LOGIN_TYPE_MAP: GWS login_type → OCSF {auth_protocol_id, auth_protocol}
-- auth_protocol_id: 4=OpenID, 5=SAML, 6=OAUTH 2.0, 99=Other
--------------------------------------------------------------------------------
local LOGIN_TYPE_MAP = {
    google_password             = { id = 99, label = "Google Password" },
    google_password_with_2sv    = { id = 99, label = "Google Password with 2SV" },
    reauth                      = { id = 99, label = "Reauthentication" },
    saml                        = { id = 5,  label = "SAML" },
    oauth2                      = { id = 6,  label = "OAUTH 2.0" },
    oidc                        = { id = 4,  label = "OpenID" },
    exchange                    = { id = 99, label = "Exchange" },
    unknown_login_type          = { id = 99, label = nil },
    less_secure_app             = { id = 99, label = "Less Secure App" },
    passkey                     = { id = 99, label = "Passkey" },
    titanium                    = { id = 99, label = "Security Key" },
}

--------------------------------------------------------------------------------
-- MFA_CHALLENGE_METHODS: GWS challenge method values that indicate MFA
--------------------------------------------------------------------------------
local MFA_CHALLENGE_METHODS = {
    idv_preregistered_phone     = true,
    idv_totp                    = true,
    security_key                = true,
    backup_code                 = true,
    google_authenticator        = true,
    recovery_phone              = true,
    recovery_email              = true,
    titanium_key                = true,
    passkey                     = true,
    phone_prompt                = true,
    totp                        = true,
    sms                         = true,
    voice                       = true,
    push                        = true,
}

--------------------------------------------------------------------------------
-- SUSPICIOUS_EVENTS: GWS event names that warrant elevated severity
--------------------------------------------------------------------------------
local SUSPICIOUS_EVENTS = {
    suspicious_login                    = true,
    suspicious_login_less_secure_app    = true,
    gov_attack_warning                  = true,
    account_disabled_hijacked           = true,
    risky_sensitive_action_blocked      = true,
    login_failure                       = true,
    login_challenge_failed              = true,
}

--------------------------------------------------------------------------------
-- FIELD_MAP: flat/pre-parsed GWS source field → OCSF destination dot-path
--------------------------------------------------------------------------------
local FIELD_MAP = {
    -- Timing
    ["time"]                    = "time",
    ["timestamp"]               = "time",
    ["_time"]                   = "time",
    ["eventTime"]               = "time",
    ["event_time"]              = "time",

    -- Metadata
    ["uniqueQualifier"]         = "metadata.uid",
    ["unique_qualifier"]        = "metadata.uid",
    ["etag"]                    = "metadata.uid",
    ["customerId"]              = "cloud.account.uid",
    ["customer_id"]             = "cloud.account.uid",
    ["applicationName"]         = "metadata.product.feature.name",
    ["application_name"]        = "metadata.product.feature.name",

    -- Actor / user (flat)
    ["email"]                   = "user.email_addr",
    ["actor_email"]             = "user.email_addr",
    ["userEmail"]               = "user.email_addr",
    ["user_email"]              = "user.email_addr",
    ["profileId"]               = "user.uid",
    ["profile_id"]              = "user.uid",
    ["userId"]                  = "user.uid",
    ["user_id"]                 = "user.uid",
    ["callerType"]              = "user.type",
    ["caller_type"]             = "user.type",

    -- Source endpoint (flat)
    ["ipAddress"]               = "src_endpoint.ip",
    ["ip_address"]              = "src_endpoint.ip",
    ["sourceIp"]                = "src_endpoint.ip",
    ["source_ip"]               = "src_endpoint.ip",

    -- Event name / operation (flat)
    ["eventName"]               = "api.operation",
    ["event_name"]              = "api.operation",
    ["name"]                    = "api.operation",

    -- Status (flat)
    ["result"]                  = "status",
    ["loginResult"]             = "status",
    ["login_result"]            = "status",

    -- Auth (flat)
    ["loginType"]               = "auth_protocol",
    ["login_type"]              = "auth_protocol",
    ["authMethod"]              = "auth_protocol",
    ["auth_method"]             = "auth_protocol",

    -- Device (flat)
    ["deviceId"]                = "device.uid",
    ["device_id"]               = "device.uid",
    ["deviceType"]              = "device.type",
    ["device_type"]             = "device.type",
    ["deviceOsType"]            = "device.os.name",
    ["device_os_type"]          = "device.os.name",
    ["deviceOsVersion"]         = "device.os.version",
    ["device_os_version"]       = "device.os.version",

    -- Session (flat)
    ["sessionId"]               = "session.uid",
    ["session_id"]              = "session.uid",
}

--------------------------------------------------------------------------------
-- local function deepGet
-- Safely retrieves a value from a nested table using dot-notation path.
-- Supports array index syntax: "key[N]"
-- Supports GWS parameters KV-list scan: [{name=K, value=V}]
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
            -- GWS parameters KV-list scan: [{name=K, value=V}]
            if next_val == nil and type(current) == "table" and #current > 0 then
                for _, item in ipairs(current) do
                    if type(item) == "table" then
                        if item.name == part then
                            next_val = item.value or item.boolValue or item.intValue
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
        "auth_protocol_id", "logon_type_id", "type_id",
        "timezone_offset", "duration",
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
-- Normalises GWS timestamp variants to epoch milliseconds (integer).
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
        -- ISO-8601: "2024-06-15T12:34:56.000Z" or "2024-06-15T12:34:56Z"
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
-- local function extractParams
-- Flattens a GWS events[].parameters[] array into a plain Lua table.
-- Supports: {name=K, value=V}, {name=K, boolValue=V}, {name=K, intValue=V},
--           {name=K, multiValue=[...]}, {name=K, multiBoolValue=[...]}
--------------------------------------------------------------------------------
local function extractParams(params_arr)
    if type(params_arr) ~= "table" then return {} end
    local result = {}
    for _, item in ipairs(params_arr) do
        if type(item) == "table" then
            local k = item.name
            if k then
                local v = item.value
                       or item.boolValue
                       or item.intValue
                if v ~= nil then
                    result[tostring(k or "")] = v
                end
                -- multiValue: store as comma-joined string
                local mv = item.multiValue
                if type(mv) == "table" and #mv > 0 then
                    local parts = {}
                    for _, mval in ipairs(mv) do
                        table.insert(parts, tostring(mval or ""))
                    end
                    result[tostring(k or "")] = table.concat(parts, ",")
                end
                -- multiBoolValue
                local mbv = item.multiBoolValue
                if type(mbv) == "table" and #mbv > 0 then
                    local parts = {}
                    for _, bval in ipairs(mbv) do
                        table.insert(parts, tostring(bval or ""))
                    end
                    result[tostring(k or "")] = table.concat(parts, ",")
                end
            end
        end
    end
    return result
end

--------------------------------------------------------------------------------
-- local function extractFirstEvent
-- Walks the raw nested GWS Reports API structure to find the first event entry.
-- Returns: event_name (string), event_type (string), params (table)
--          or nil, nil, {} if not found.
-- Structure: events[].name, events[].type, events[].parameters[]
--------------------------------------------------------------------------------
local function extractFirstEvent(e)
    local events_arr = e["events"]
    if type(events_arr) ~= "table" or #events_arr == 0 then
        return nil, nil, {}
    end
    local first = events_arr[1]
    if type(first) ~= "table" then return nil, nil, {} end

    local ev_name   = first["name"]
    local ev_type   = first["type"]
    local ev_params = extractParams(first["parameters"])

    return ev_name, ev_type, ev_params
end

--------------------------------------------------------------------------------
-- local function detectAppName
-- Resolves the GWS applicationName from nested id.applicationName or flat fields.
--------------------------------------------------------------------------------
local function detectAppName(e)
    -- Nested GWS structure: id.applicationName
    local id_obj = e["id"]
    if type(id_obj) == "table" then
        local app = id_obj["applicationName"]
        if app then return tostring(app or "") end
    end
    -- Flat fields
    return e["applicationName"] or e["application_name"] or e["appName"] or nil
end

--------------------------------------------------------------------------------
-- local function normEventActivity
-- Derives OCSF activity_id from GWS event name and applicationName.
-- For login app: uses EVENT_NAME_MAP.
-- For admin app: parses verb prefix from event name using ADMIN_VERB_MAP.
-- Returns activity_id integer.
--------------------------------------------------------------------------------
local function normEventActivity(event_name, app_name)
    if event_name == nil then return 99 end
    local en_lower = tostring(event_name or ""):lower()

    -- Direct lookup in login event map
    local entry = EVENT_NAME_MAP[en_lower]
    if entry then return entry.activity_id end

    -- Admin / other apps: extract leading verb
    local app_lower = tostring(app_name or ""):lower()
    if app_lower == "admin" or app_lower == "groups_enterprise" then
        -- Split on underscore, take first token
        local verb = tostring(en_lower or ""):match("^([a-z]+)_")
                  or tostring(en_lower or ""):match("^([a-z]+)$")
        if verb then
            local id = ADMIN_VERB_MAP[verb]
            if id then return id end
        end
    end

    -- Substring scan for login-related names
    if tostring(en_lower or ""):find("login", 1, true) or
       tostring(en_lower or ""):find("logon", 1, true) or
       tostring(en_lower or ""):find("signin", 1, true) then
        return 1
    end
    if tostring(en_lower or ""):find("logout", 1, true) or
       tostring(en_lower or ""):find("logoff", 1, true) or
       tostring(en_lower or ""):find("signout", 1, true) then
        return 2
    end
    if tostring(en_lower or ""):find("challenge", 1, true) or
       tostring(en_lower or ""):find("verification", 1, true) or
       tostring(en_lower or ""):find("preauth", 1, true) then
        return 6
    end

    return 99
end

--------------------------------------------------------------------------------
-- local function normEventStatus
-- Derives OCSF {status_id, status_label} from GWS event name.
-- Returns nil, nil when no mapping found.
--------------------------------------------------------------------------------
local function normEventStatus(event_name)
    if event_name == nil then return nil, nil end
    local en_lower = tostring(event_name or ""):lower()

    local entry = EVENT_NAME_MAP[en_lower]
    if entry then return entry.status_id, entry.status_label end

    -- Substring heuristics
    if tostring(en_lower or ""):find("success", 1, true) or
       tostring(en_lower or ""):find("allowed", 1, true) or
       tostring(en_lower or ""):find("passed", 1, true)  then
        return 1, "Success"
    end
    if tostring(en_lower or ""):find("failure", 1, true) or
       tostring(en_lower or ""):find("failed", 1, true)  or
       tostring(en_lower or ""):find("blocked", 1, true) or
       tostring(en_lower or ""):find("disabled", 1, true) then
        return 2, "Failure"
    end

    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normLoginType
-- Maps GWS login_type parameter → OCSF {auth_protocol_id, auth_protocol}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normLoginType(login_type)
    if login_type == nil then return nil, nil end
    local key = tostring(login_type or ""):lower()
    local entry = LOGIN_TYPE_MAP[key]
    if entry then return entry.id, entry.label end
    -- Pass through unrecognised values as-is with id=99
    return 99, tostring(login_type or "")
end

--------------------------------------------------------------------------------
-- local function normLogonType
-- Derives OCSF {logon_type_id, logon_type} from GWS login context.
-- OCSF logon_type_id: 2=Interactive, 3=Network, 10=Remote Interactive, 99=Other
--------------------------------------------------------------------------------
local function normLogonType(login_type, is_remote)
    if login_type == nil and is_remote == nil then return nil, nil end

    local lt = tostring(login_type or ""):lower()

    if lt == "saml" or lt == "oauth2" or lt == "oidc" then
        return 3, "Network"
    end
    if lt == "less_secure_app" or lt == "exchange" then
        return 3, "Network"
    end
    if is_remote == true then
        return 10, "Remote Interactive"
    end
    if lt == "google_password" or lt == "google_password_with_2sv" or lt == "passkey" then
        return 2, "Interactive"
    end
    if lt == "reauth" then
        return 2, "Interactive"
    end

    return nil, nil
end

--------------------------------------------------------------------------------
-- local function isMfaMethod
-- Returns true if the given challenge method string indicates MFA was used.
-- Handles comma-separated multiValue strings.
--------------------------------------------------------------------------------
local function isMfaMethod(method_val)
    if method_val == nil then return nil end
    local val_s = tostring(method_val or "")
    if val_s == "" then return nil end

    -- Scan comma-separated values
    local found_mfa    = false
    local found_any    = false
    for part in val_s:gmatch("[^,]+") do
        local trimmed = tostring(part or ""):match("^%s*(.-)%s*$")
        if trimmed and trimmed ~= "" then
            found_any = true
            local key = tostring(trimmed or ""):lower()
            if MFA_CHALLENGE_METHODS[key] then
                found_mfa = true
            end
        end
    end

    if not found_any then return nil end
    return found_mfa
end

--------------------------------------------------------------------------------
-- local function normSeverity
-- Derives OCSF {severity_id, severity_label} from GWS risk signals.
-- Returns {1, "Informational"} as safe default.
--------------------------------------------------------------------------------
local function normSeverity(is_suspicious, event_name, status_id)
    -- Explicit suspicious flag
    if is_suspicious == true or is_suspicious == "true" then
        return 4, "High"
    end

    -- Government-sponsored attack warning
    if event_name then
        local en = tostring(event_name or ""):lower()
        if en == "gov_attack_warning" then
            return 5, "Critical"
        end
        if SUSPICIOUS_EVENTS[en] then
            if status_id == 2 then
                return 3, "Medium"
            end
            return 2, "Low"
        end
    end

    -- Failure → Low
    if status_id == 2 then
        return 2, "Low"
    end

    return 1, "Informational"
end

--------------------------------------------------------------------------------
-- local function buildUser
-- Constructs OCSF user object (required) from GWS actor fields.
-- Handles nested actor object and flat fields.
--------------------------------------------------------------------------------
local function buildUser(e, params)
    local user = {}

    -- Nested GWS actor object
    local actor_obj = e["actor"]
    if type(actor_obj) == "table" then
        local email      = actor_obj["email"]
        local profile_id = actor_obj["profileId"]
        local caller_type = actor_obj["callerType"]

        if email then
            user.email_addr = tostring(email or "")
            -- Derive name from email (part before @)
            local name_part = tostring(email or ""):match("^([^@]+)@")
            if name_part then user.name = name_part end
            -- Full email as uid fallback
            user.uid = tostring(email or "")
        end
        if profile_id then user.uid = tostring(profile_id or "") end

        if caller_type then
            local ct = tostring(caller_type or ""):lower()
            if ct == "user" then
                user.type_id = 1
                user.type    = "User"
            elseif ct == "service_account" or ct == "serviceaccount" then
                user.type_id = 4
                user.type    = "Application"
            end
        end
    end

    -- Flat field fallbacks
    if not user.email_addr then
        local flat_email = e["email"] or e["actor_email"] or e["userEmail"] or e["user_email"]
        if flat_email then
            user.email_addr = tostring(flat_email or "")
            if not user.name then
                local name_part = tostring(flat_email or ""):match("^([^@]+)@")
                if name_part then user.name = name_part end
            end
        end
    end
    if not user.uid then
        local flat_uid = e["profileId"] or e["profile_id"] or e["userId"] or e["user_id"]
        if flat_uid then user.uid = tostring(flat_uid or "") end
    end

    -- Affected email from params (may differ from actor for admin events)
    local affected_email = params["affected_email_address"]
    if affected_email and affected_email ~= "" then
        user.email_addr = tostring(affected_email or "")
    end

    -- Domain from email
    if user.email_addr then
        local domain = tostring(user.email_addr or ""):match("@(.+)$")
        if domain then user.domain = domain end
    end

    -- Org unit from params
    local org_unit = params["org_unit"] or params["org_unit_name"]
    if org_unit then user.org_unit_uid = tostring(org_unit or "") end

    if next(user) == nil then return nil end
    return user
end

--------------------------------------------------------------------------------
-- local function buildSrcEndpoint
-- Constructs OCSF src_endpoint from GWS ipAddress field.
--------------------------------------------------------------------------------
local function buildSrcEndpoint(e)
    local ep = {}

    local ip = e["ipAddress"] or e["ip_address"] or e["sourceIp"] or e["source_ip"]
    if ip then
        -- Strip IPv6 brackets
        local clean = tostring(ip or ""):match("^%[(.+)%]:%d+$")
                   or tostring(ip or ""):match("^%[(.+)%]$")
                   or ip
        ep.ip = tostring(clean or "")
    end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildDstEndpoint
-- Constructs OCSF dst_endpoint from GWS service / application context.
--------------------------------------------------------------------------------
local function buildDstEndpoint(e, params, app_name)
    local ep = {}

    -- Service URL from params
    local svc_url = params["service_url"] or params["resource_url"]
    if svc_url then ep.hostname = tostring(svc_url or "") end

    -- Application name as hostname fallback
    if not ep.hostname and app_name then
        local app_lower = tostring(app_name or ""):lower()
        local hostname_map = {
            login       = "accounts.google.com",
            admin       = "admin.google.com",
            drive       = "drive.google.com",
            gmail       = "mail.google.com",
            calendar    = "calendar.google.com",
            meet        = "meet.google.com",
            chat        = "chat.google.com",
            groups      = "groups.google.com",
            token       = "oauth2.googleapis.com",
        }
        local h = hostname_map[app_lower]
        if h then ep.hostname = h end
    end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildService
-- Constructs OCSF service object from GWS applicationName / resource context.
--------------------------------------------------------------------------------
local function buildService(e, params, app_name)
    local svc = {}

    if app_name then svc.name = tostring(app_name or "") end

    -- Resource / target service from params
    local resource = params["resource_name"] or params["target_resource"]
    if resource then svc.uid = tostring(resource or "") end

    -- Application name from params (OAuth token events)
    local app_param = params["app_name"] or params["client_id"]
    if app_param then svc.name = svc.name or tostring(app_param or "") end

    if next(svc) == nil then return nil end
    return svc
end

--------------------------------------------------------------------------------
-- local function buildDevice
-- Constructs OCSF device object from GWS device_id / device_type parameters.
--------------------------------------------------------------------------------
local function buildDevice(e, params)
    local dev = {}

    local dev_id = params["device_id"] or e["deviceId"] or e["device_id"]
    if dev_id then dev.uid = tostring(dev_id or "") end

    local dev_type = params["device_type"] or e["deviceType"] or e["device_type"]
    if dev_type then dev.type = tostring(dev_type or "") end

    local os_name = params["device_os_type"] or e["deviceOsType"] or e["device_os_type"]
    if os_name then
        dev.os = { name = tostring(os_name or "") }
        local os_ver = params["device_os_version"] or e["deviceOsVersion"] or e["device_os_version"]
        if os_ver then dev.os.version = tostring(os_ver or "") end
    end

    local dev_name = params["device_name"] or params["device_hostname"]
    if dev_name then dev.name = tostring(dev_name or "") end

    -- Browser as agent
    local browser = params["browser"] or params["user_agent"]
    if browser then
        dev.agent_list = {
            { name = tostring(browser or ""), type = "Browser", type_id = 99 }
        }
    end

    if next(dev) == nil then return nil end
    return dev
end

--------------------------------------------------------------------------------
-- local function buildSession
-- Constructs OCSF session object from GWS uniqueQualifier / sessionId.
--------------------------------------------------------------------------------
local function buildSession(e, params)
    local sess = {}

    -- Nested GWS id.uniqueQualifier
    local id_obj = e["id"]
    if type(id_obj) == "table" then
        local uq = id_obj["uniqueQualifier"]
        if uq then sess.uid = tostring(uq or "") end
    end

    -- Flat fallbacks
    if not sess.uid then
        local flat_uid = e["uniqueQualifier"] or e["unique_qualifier"]
                      or e["sessionId"]       or e["session_id"]
                      or params["session_id"]
        if flat_uid then sess.uid = tostring(flat_uid or "") end
    end

    if next(sess) == nil then return nil end
    return sess
end

--------------------------------------------------------------------------------
-- local function buildCloud
-- Constructs OCSF cloud object from GWS customerId / domain.
--------------------------------------------------------------------------------
local function buildCloud(e)
    local cloud = { provider = "Google" }

    -- Nested GWS id.customerId
    local id_obj = e["id"]
    if type(id_obj) == "table" then
        local cid = id_obj["customerId"]
        if cid then
            cloud.account = {
                uid  = tostring(cid or ""),
                type = "Workspace",
            }
        end
    end

    -- Flat fallback
    if not cloud.account then
        local flat_cid = e["customerId"] or e["customer_id"]
        if flat_cid then
            cloud.account = {
                uid  = tostring(flat_cid or ""),
                type = "Workspace",
            }
        end
    end

    -- Domain from actor email
    local actor_obj = e["actor"]
    if type(actor_obj) == "table" then
        local email = actor_obj["email"]
        if email then
            local domain = tostring(email or ""):match("@(.+)$")
            if domain then cloud.region = domain end
        end
    end

    return cloud
end

--------------------------------------------------------------------------------
-- local function buildObservables
-- Constructs OCSF observables[] from key indicator fields.
-- type_id: 2=IP Address, 20=User Name, 99=Other
--------------------------------------------------------------------------------
local function buildObservables(e, params)
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

    -- IP address
    local ip = e["ipAddress"] or e["ip_address"] or e["sourceIp"]
    addObs("src_endpoint.ip", 2, ip)

    -- User email
    local actor_obj = e["actor"]
    local email
    if type(actor_obj) == "table" then
        email = actor_obj["email"]
    end
    email = email or e["email"] or e["actor_email"] or e["userEmail"]
    addObs("user.email_addr", 20, email)

    -- Affected email (may differ from actor)
    local affected = params["affected_email_address"]
    if affected and affected ~= email then
        addObs("affected_email", 20, affected)
    end

    -- Device ID
    local dev_id = params["device_id"] or e["deviceId"]
    addObs("device.uid", 99, dev_id)

    if #obs == 0 then return nil end
    return obs
end

--------------------------------------------------------------------------------
-- MAIN: processEvent
-- Entry point required by the Observo Lua transform runtime.
-- All helpers are declared as local functions ABOVE this function.
-- Handles both:
--   (A) Raw nested GWS Reports API JSON (id{}, actor{}, events[]{parameters[]})
--   (B) Pre-parsed flat records (individual fields already extracted)
--------------------------------------------------------------------------------
function processEvent(event)

    --------------------------------------------------------------------------
    -- INNER: core transform — wrapped in pcall for pipeline safety
    --------------------------------------------------------------------------
    local function execute(e)

        -- Track consumed source keys to populate unmapped correctly
        local consumed = {}

        -----------------------------------------------------------------------
        -- 1. Extract nested GWS structure if present
        -----------------------------------------------------------------------
        local event_name  = nil
        local event_type  = nil
        local params      = {}
        local app_name    = detectAppName(e)

        if FEATURES.PARSE_NESTED_GWS then
            -- Extract id.* fields
            local id_obj = e["id"]
            if type(id_obj) == "table" then
                local id_time = id_obj["time"]
                if id_time and e["time"] == nil then
                    e["_gws_id_time"] = id_time
                end
                if not app_name then
                    app_name = id_obj["applicationName"]
                end
                consumed["id"] = true
            end

            -- Extract first event entry
            if type(e["events"]) == "table" then
                event_name, event_type, params = extractFirstEvent(e)
                consumed["events"] = true
            end
        end

        -- Flat field fallbacks for event name
        if event_name == nil then
            event_name = e["eventName"] or e["event_name"] or e["name"]
        end

        -- Merge flat params into params table
        if FEATURES.FLATTEN_PARAMS then
            local flat_params = e["parameters"]
            if type(flat_params) == "table" then
                local flat = extractParams(flat_params)
                for k, v in pairs(flat) do
                    if params[k] == nil then params[k] = v end
                end
                consumed["parameters"] = true
            end
        end

        -----------------------------------------------------------------------
        -- 2. Resolve activity_id and event status
        -----------------------------------------------------------------------
        local activity_id = normEventActivity(event_name, app_name)
        local st_id, st_label = normEventStatus(event_name)

        -- Override status from flat result field
        local flat_result = e["result"] or e["loginResult"] or e["login_result"]
        if flat_result and st_id == nil then
            local fr_lower = tostring(flat_result or ""):lower()
            if fr_lower == "success" or fr_lower == "succeeded" then
                st_id    = 1
                st_label = "Success"
            elseif fr_lower == "failure" or fr_lower == "failed" then
                st_id    = 2
                st_label = "Failure"
            end
        end

        -----------------------------------------------------------------------
        -- 3. Resolve is_suspicious from params
        -----------------------------------------------------------------------
        local is_suspicious = params["is_suspicious"]
        if is_suspicious == nil then
            is_suspicious = e["isSuspicious"] or e["is_suspicious"]
        end

        -----------------------------------------------------------------------
        -- 4. Resolve severity
        -----------------------------------------------------------------------
        local sev_id, sev_label = normSeverity(is_suspicious, event_name, st_id)

        -----------------------------------------------------------------------
        -- 5. Seed OCSF skeleton with required constant fields
        -----------------------------------------------------------------------
        local ocsf = {
            class_uid     = 3002,
            class_name    = "Authentication",
            category_uid  = 3,
            category_name = "Identity & Access Management",
            activity_id   = activity_id,
            activity_name = ACTIVITY_NAMES[activity_id] or "Other",
            type_uid      = 3002 * 100 + activity_id,
            type_name     = "Authentication: " .. (ACTIVITY_NAMES[activity_id] or "Other"),
            severity_id   = sev_id,
            severity      = sev_label,
            metadata = {
                version = "1.3.0",
                product = {
                    vendor_name = "Google",
                    name        = "Google Workspace",
                    feature     = {
                        name = app_name and tostring(app_name or "") or nil,
                    },
                },
            },
            osint    = {},
            unmapped = {},
        }

        -----------------------------------------------------------------------
        -- 6. Apply FIELD_MAP: scalar source field → OCSF destination path
        -----------------------------------------------------------------------
        for src_field, dest_path in pairs(FIELD_MAP) do
            local val = e[src_field]
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
        -- 7. Resolve time with fallback chain
        -----------------------------------------------------------------------
        if ocsf.time == nil then
            local fallbacks = {
                "_gws_id_time", "time", "timestamp", "_time", "eventTime", "event_time",
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
        consumed["_gws_id_time"] = true

        -----------------------------------------------------------------------
        -- 8. Status
        -----------------------------------------------------------------------
        if st_id    then ocsf.status_id = st_id    end
        if st_label then ocsf.status    = st_label end

        -- status_code from event name
        if event_name then
            ocsf.status_code = tostring(event_name or "")
        end

        -- status_detail from challenge status param
        local challenge_status = params["login_challenge_status"]
                              or params["login_challenge_reason"]
        if challenge_status then
            ocsf.status_detail = tostring(challenge_status or "")
        end

        consumed["result"]       = true
        consumed["loginResult"]  = true
        consumed["login_result"] = true

        -----------------------------------------------------------------------
        -- 9. Auth protocol from login_type parameter
        -----------------------------------------------------------------------
        local login_type_raw = params["login_type"]
                            or e["loginType"] or e["login_type"]
                            or e["authMethod"] or e["auth_method"]
        local ap_id, ap_label = normLoginType(login_type_raw)
        if ap_id    then ocsf.auth_protocol_id = ap_id    end
        if ap_label then ocsf.auth_protocol    = ap_label end

        consumed["loginType"]   = true
        consumed["login_type"]  = true
        consumed["authMethod"]  = true
        consumed["auth_method"] = true

        -----------------------------------------------------------------------
        -- 10. Logon type
        -----------------------------------------------------------------------
        local lt_id, lt_label = normLogonType(login_type_raw, nil)
        if lt_id    then ocsf.logon_type_id = lt_id    end
        if lt_label then ocsf.logon_type    = lt_label end

        -----------------------------------------------------------------------
        -- 11. is_mfa from login_challenge_method parameter
        -----------------------------------------------------------------------
        local challenge_method = params["login_challenge_method"]
                              or e["loginChallengeMethod"] or e["login_challenge_method"]
        local mfa_result = isMfaMethod(challenge_method)
        if mfa_result ~= nil then ocsf.is_mfa = mfa_result end

        consumed["loginChallengeMethod"]  = true
        consumed["login_challenge_method"] = true

        -----------------------------------------------------------------------
        -- 12. is_remote: GWS logins are inherently remote
        -----------------------------------------------------------------------
        ocsf.is_remote = true

        -----------------------------------------------------------------------
        -- 13. api.operation from event name
        -----------------------------------------------------------------------
        if event_name then
            ocsf.api = { operation = tostring(event_name or "") }
        end
        consumed["eventName"]  = true
        consumed["event_name"] = true
        consumed["name"]       = true

        -----------------------------------------------------------------------
        -- 14. user (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_USER then
            local user_obj = buildUser(e, params)
            if user_obj then
                ocsf.user = user_obj
            else
                ocsf.user = {}
            end
            consumed["actor"]       = true
            consumed["email"]       = true
            consumed["actor_email"] = true
            consumed["userEmail"]   = true
            consumed["user_email"]  = true
            consumed["profileId"]   = true
            consumed["profile_id"]  = true
            consumed["userId"]      = true
            consumed["user_id"]     = true
            consumed["callerType"]  = true
            consumed["caller_type"] = true
        end

        -----------------------------------------------------------------------
        -- 15. src_endpoint (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SRC_ENDPOINT then
            local ep = buildSrcEndpoint(e)
            if ep then ocsf.src_endpoint = ep end
            consumed["ipAddress"]  = true
            consumed["ip_address"] = true
            consumed["sourceIp"]   = true
            consumed["source_ip"]  = true
        end

        -----------------------------------------------------------------------
        -- 16. dst_endpoint (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_DST_ENDPOINT then
            local ep = buildDstEndpoint(e, params, app_name)
            if ep then ocsf.dst_endpoint = ep end
        end

        -----------------------------------------------------------------------
        -- 17. service (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SERVICE then
            local svc = buildService(e, params, app_name)
            if svc then ocsf.service = svc end
            consumed["applicationName"]  = true
            consumed["application_name"] = true
            consumed["appName"]          = true
        end

        -----------------------------------------------------------------------
        -- 18. device (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_DEVICE then
            local dev = buildDevice(e, params)
            if dev then ocsf.device = dev end
            consumed["deviceId"]         = true
            consumed["device_id"]        = true
            consumed["deviceType"]       = true
            consumed["device_type"]      = true
            consumed["deviceOsType"]     = true
            consumed["device_os_type"]   = true
            consumed["deviceOsVersion"]  = true
            consumed["device_os_version"] = true
        end

        -----------------------------------------------------------------------
        -- 19. session (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SESSION then
            local sess = buildSession(e, params)
            if sess then ocsf.session = sess end
            consumed["uniqueQualifier"]  = true
            consumed["unique_qualifier"] = true
            consumed["sessionId"]        = true
            consumed["session_id"]       = true
        end

        -----------------------------------------------------------------------
        -- 20. cloud (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CLOUD then
            ocsf.cloud = buildCloud(e)
            consumed["customerId"]   = true
            consumed["customer_id"]  = true
        end

        -----------------------------------------------------------------------
        -- 21. observables (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_OBSERVABLES then
            local obs = buildObservables(e, params)
            if obs then ocsf.observables = obs end
        end

        -----------------------------------------------------------------------
        -- 22. Carry over remaining params into unmapped
        -----------------------------------------------------------------------
        local handled_params = {
            login_type              = true,
            login_challenge_method  = true,
            login_challenge_status  = true,
            login_challenge_reason  = true,
            is_suspicious           = true,
            affected_email_address  = true,
            device_id               = true,
            device_type             = true,
            device_os_type          = true,
            device_os_version       = true,
            device_name             = true,
            device_hostname         = true,
            browser                 = true,
            user_agent              = true,
            org_unit                = true,
            org_unit_name           = true,
            session_id              = true,
            app_name                = true,
            client_id               = true,
            resource_name           = true,
            target_resource         = true,
            service_url             = true,
            resource_url            = true,
        }
        for k, v in pairs(params) do
            if not handled_params[k] then
                ocsf.unmapped["param_" .. tostring(k or "")] = v
            end
        end

        -----------------------------------------------------------------------
        -- 23. raw_data
        -----------------------------------------------------------------------
        if FEATURES.PRESERVE_RAW then
            local ok_enc, raw_str = pcall(json.encode, e)
            if ok_enc and raw_str then
                ocsf.raw_data = raw_str
            end
        end

        -----------------------------------------------------------------------
        -- 24. Collect remaining unmapped source fields
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
        -- 25. Strip empty strings / empty tables
        -----------------------------------------------------------------------
        if FEATURES.STRIP_EMPTY then
            stripEmpty(ocsf)
        end

        -----------------------------------------------------------------------
        -- 26. Compose human-readable message (table.concat, no .. in loop)
        -----------------------------------------------------------------------
        local msg_parts = {}

        local user_email  = deepGet(ocsf, "user.email_addr")
        local api_op      = deepGet(ocsf, "api.operation")
        local src_ip      = deepGet(ocsf, "src_endpoint.ip")
        local svc_name    = deepGet(ocsf, "service.name")
        local status_lbl  = ocsf.status
        local sev_lbl     = ocsf.severity

        table.insert(msg_parts, "GWS Auth:")
        if api_op     then table.insert(msg_parts, "event="    .. tostring(api_op     or "")) end
        if user_email then table.insert(msg_parts, "user="     .. tostring(user_email or "")) end
        if src_ip     then table.insert(msg_parts, "ip="       .. tostring(src_ip     or "")) end
        if svc_name   then table.insert(msg_parts, "app="      .. tostring(svc_name   or "")) end
        if status_lbl then table.insert(msg_parts, "status="   .. tostring(status_lbl or "")) end
        if sev_lbl and sev_lbl ~= "Informational" then
            table.insert(msg_parts, "severity=" .. tostring(sev_lbl or ""))
        end

        ocsf.message = table.concat(msg_parts, " ")

        -----------------------------------------------------------------------
        -- 27. Encode final OCSF event as raw JSON into message field
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
        event["_ocsf_serializer"]   = "gws_auth_authentication"
        event["_ocsf_parse_failed"] = "true"
        return event
    end

end -- end processEvent()
