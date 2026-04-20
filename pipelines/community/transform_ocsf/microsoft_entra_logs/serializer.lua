--------------------------------------------------------------------------------
-- Microsoft Entra (Azure AD) Sign-in & Audit Logs
-- → OCSF 1.3.0 API Activity (class_uid = 6003)
-- Observo processEvent(event) contract
-- Author: Observo AI  |  Schema: OCSF 1.3.0  |  Class: API Activity (6003)
-- Covers: SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs,
--         ManagedIdentitySignInLogs, AuditLogs, DirectoryAuditLogs
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
    PRESERVE_RAW            = true,   -- attach raw_data (json-encoded source event)
    ENRICH_ACTOR            = true,   -- build actor from initiatedBy / user fields
    ENRICH_SRC_ENDPOINT     = true,   -- build src_endpoint from ipAddress / deviceDetail / location
    ENRICH_HTTP_REQUEST     = true,   -- build http_request from browser / userAgent
    ENRICH_API              = true,   -- build api from operation / resource / additionalDetails
    ENRICH_CLOUD            = true,   -- build cloud from tenantId / homeTenantId
    ENRICH_RESOURCES        = true,   -- build resources[] from targetResources
    ENRICH_OBSERVABLES      = true,   -- build observables[] from IPs / users / apps
    FLATTEN_ADDITIONAL      = true,   -- flatten additionalDetails KV list into api.request.data
    STRIP_EMPTY             = true,   -- recursively remove nil/"" values before return
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
-- OPERATION_VERB_MAP: Entra operation verb → OCSF activity_id
-- activity_id: 1=Create, 2=Read, 3=Update, 4=Delete, 99=Other
-- Keys are lowercase; matched against leading verb of activityDisplayName /
-- operationType after camelCase / space / hyphen splitting.
--------------------------------------------------------------------------------
local OPERATION_VERB_MAP = {
    -- Create
    add         = 1,
    create      = 1,
    invite      = 1,
    register    = 1,
    provision   = 1,
    generate    = 1,
    issue       = 1,
    grant       = 1,
    assign      = 1,
    new         = 1,
    upload      = 1,
    publish     = 1,
    -- Read / Sign-in (accessing a resource)
    get         = 2,
    list        = 2,
    read        = 2,
    view        = 2,
    search      = 2,
    access      = 2,
    signin      = 2,
    ["sign-in"] = 2,
    login       = 2,
    authenticate = 2,
    validate    = 2,
    check       = 2,
    -- Update
    update      = 3,
    set         = 3,
    modify      = 3,
    edit        = 3,
    change      = 3,
    enable      = 3,
    disable     = 3,
    reset       = 3,
    restore     = 3,
    rotate      = 3,
    renew       = 3,
    extend      = 3,
    sync        = 3,
    convert     = 3,
    move        = 3,
    rename      = 3,
    approve     = 3,
    -- Delete
    delete      = 4,
    remove      = 4,
    revoke      = 4,
    expire      = 4,
    purge       = 4,
    block       = 4,
    unassign    = 4,
    deregister  = 4,
    deprovision = 4,
    reject      = 4,
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
-- STATUS_MAP: Entra result / ResultType strings → OCSF {id, label}
-- OCSF status_id: 1=Success, 2=Failure, 99=Other
--------------------------------------------------------------------------------
local STATUS_MAP = {
    success             = { id = 1,  label = "Success" },
    succeeded           = { id = 1,  label = "Success" },
    ["0"]               = { id = 1,  label = "Success" },   -- errorCode 0 = success
    failure             = { id = 2,  label = "Failure" },
    failed              = { id = 2,  label = "Failure" },
    error               = { id = 2,  label = "Failure" },
    interrupted         = { id = 2,  label = "Failure" },
    timeout             = { id = 99, label = "Other" },
    notapplicable       = { id = 99, label = "Other" },
    unknownfuturevalue  = { id = 99, label = "Other" },
    pending             = { id = 99, label = "Other" },
}

--------------------------------------------------------------------------------
-- RISK_SEVERITY_MAP: Entra riskLevel strings → OCSF {severity_id, severity}
-- OCSF: 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical
--------------------------------------------------------------------------------
local RISK_SEVERITY_MAP = {
    none    = { id = 1, label = "Informational" },
    low     = { id = 2, label = "Low" },
    medium  = { id = 3, label = "Medium" },
    high    = { id = 4, label = "High" },
    hidden  = { id = 1, label = "Informational" },
}

--------------------------------------------------------------------------------
-- USER_TYPE_MAP: Entra userType string → OCSF {type_id, type_label}
-- OCSF user type_id: 1=User, 2=Admin, 3=System, 4=Application, 99=Other
--------------------------------------------------------------------------------
local USER_TYPE_MAP = {
    member          = { type_id = 1,  type_label = "User" },
    guest           = { type_id = 1,  type_label = "User" },
    external        = { type_id = 1,  type_label = "User" },
    serviceprincipal = { type_id = 4, type_label = "Application" },
    application     = { type_id = 4,  type_label = "Application" },
    managedidentity = { type_id = 4,  type_label = "Application" },
    system          = { type_id = 3,  type_label = "System" },
    admin           = { type_id = 2,  type_label = "Admin" },
}

--------------------------------------------------------------------------------
-- LOG_TYPE: Entra log type discriminator constants
--------------------------------------------------------------------------------
local LOG_TYPE = {
    SIGNIN  = "signin",
    AUDIT   = "audit",
}

--------------------------------------------------------------------------------
-- FIELD_MAP: Entra source field → OCSF destination dot-path (scalar mappings)
-- Complex / nested objects are handled by dedicated builder helpers.
--------------------------------------------------------------------------------
local FIELD_MAP = {
    -- Timing (sign-in)
    ["createdDateTime"]                 = "time",
    ["activityDateTime"]                = "time",
    ["_time"]                           = "time",
    ["timestamp"]                       = "time",
    ["processingTimeInMilliseconds"]    = "duration",

    -- Metadata / correlation
    ["id"]                              = "metadata.uid",
    ["correlationId"]                   = "metadata.correlation_uid",
    ["tenantId"]                        = "cloud.account.uid",
    ["homeTenantId"]                    = "cloud.account.uid",
    ["category"]                        = "metadata.product.feature.name",
    ["loggedByService"]                 = "metadata.product.feature.name",
    ["operationType"]                   = "api.operation",
    ["activityDisplayName"]             = "api.operation",

    -- Actor (sign-in — flat fields; nested handled by buildActor)
    ["userDisplayName"]                 = "actor.user.name",
    ["userPrincipalName"]               = "actor.user.name",
    ["userId"]                          = "actor.user.uid",
    ["userType"]                        = "actor.user.type",
    ["appDisplayName"]                  = "actor.app.name",
    ["appId"]                           = "actor.app.uid",
    ["servicePrincipalName"]            = "actor.app.name",
    ["servicePrincipalId"]              = "actor.app.uid",
    ["managedIdentityType"]             = "actor.app.type",

    -- Source endpoint (sign-in — flat; nested handled by buildSrcEndpoint)
    ["ipAddress"]                       = "src_endpoint.ip",

    -- HTTP / browser (sign-in)
    ["userAgent"]                       = "http_request.user_agent",

    -- API / resource (sign-in)
    ["resourceDisplayName"]             = "api.request.data.resource_name",
    ["resourceId"]                      = "api.request.data.resource_id",
    ["resourceTenantId"]                = "api.request.data.resource_tenant_id",
    ["clientAppUsed"]                   = "api.request.data.client_app",
    ["authenticationRequirement"]       = "api.request.data.auth_requirement",
    ["conditionalAccessStatus"]         = "api.request.data.conditional_access_status",
    ["tokenIssuerType"]                 = "api.request.data.token_issuer_type",
    ["tokenIssuerName"]                 = "api.request.data.token_issuer_name",
    ["isInteractive"]                   = "api.request.data.is_interactive",
    ["flaggedForReview"]                = "api.request.data.flagged_for_review",
    ["riskState"]                       = "api.request.data.risk_state",
    ["riskDetail"]                      = "api.request.data.risk_detail",
    ["riskEventTypes"]                  = "api.request.data.risk_event_types",
    ["authenticationProtocol"]          = "api.request.data.auth_protocol",
    ["incomingTokenType"]               = "api.request.data.incoming_token_type",
    ["uniqueTokenIdentifier"]           = "api.request.uid",
    ["originalRequestId"]               = "api.request.uid",

    -- Status (sign-in — normalised in main logic)
    ["resultType"]                      = "status_code",
    ["resultDescription"]               = "status_detail",
    ["result"]                          = "status",
    ["resultReason"]                    = "status_detail",
}

--------------------------------------------------------------------------------
-- local function deepGet
-- Safely retrieves a value from a nested table using dot-notation path.
-- Supports array index syntax: "key[N]"
-- Supports Microsoft KV-list scan: [{key=K, value=V}, {displayName=K, newValue=V}]
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
            -- Microsoft KV-list scan
            if next_val == nil and type(current) == "table" and #current > 0 then
                for _, item in ipairs(current) do
                    if type(item) == "table" then
                        if item.key == part then
                            next_val = item.value
                            break
                        elseif item.displayName == part then
                            next_val = item.newValue
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
        "type_id", "duration", "error_code",
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
-- Normalises Entra timestamp variants to epoch milliseconds (integer).
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
-- Maps Entra result / ResultType / errorCode → OCSF {id, label}.
-- Returns nil, nil when input is absent — never defaults to a string literal.
--------------------------------------------------------------------------------
local function normStatus(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower():gsub("%s+", "")
    local entry = STATUS_MAP[key]
    if entry then return entry.id, entry.label end
    -- Non-zero numeric errorCode → Failure
    local n = tonumber(val)
    if n and n ~= 0 then return 2, "Failure" end
    if n and n == 0 then return 1, "Success" end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normActivityId
-- Derives OCSF activity_id from Entra activityDisplayName / operationType.
-- Strategy:
--   1. Exact lowercase match in OPERATION_VERB_MAP
--   2. Extract leading verb (camelCase / space / hyphen split) → map
--   3. Substring scan
--   4. Default to 99 (Other)
--------------------------------------------------------------------------------
local function normActivityId(operation)
    if operation == nil then return 99 end
    local op_lower = tostring(operation or ""):lower()

    -- Exact match (handles "sign-in", "signin", etc.)
    if OPERATION_VERB_MAP[op_lower] then
        return OPERATION_VERB_MAP[op_lower]
    end

    -- Extract leading verb: space / hyphen / underscore split
    local verb = tostring(op_lower or ""):match("^([a-z%-]+)[%s%-%_]")
              or tostring(op_lower or ""):match("^([a-z%-]+)$")

    if verb and OPERATION_VERB_MAP[verb] then
        return OPERATION_VERB_MAP[verb]
    end

    -- camelCase split: take first lowercase word from original
    local camel_verb = tostring(operation or ""):match("^([A-Z][a-z]+)")
    if camel_verb then
        local cv_lower = tostring(camel_verb or ""):lower()
        if OPERATION_VERB_MAP[cv_lower] then
            return OPERATION_VERB_MAP[cv_lower]
        end
    end

    -- Substring scan
    for pattern, id in pairs(OPERATION_VERB_MAP) do
        if tostring(op_lower or ""):find(tostring(pattern or ""), 1, true) then
            return id
        end
    end

    return 99
end

--------------------------------------------------------------------------------
-- local function normRiskSeverity
-- Maps Entra riskLevel string → OCSF {severity_id, severity_label}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normRiskSeverity(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower()
    local entry = RISK_SEVERITY_MAP[key]
    if entry then return entry.id, entry.label end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normUserType
-- Maps Entra userType string → OCSF {type_id, type_label}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normUserType(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower():gsub("%s+", "")
    local entry = USER_TYPE_MAP[key]
    if entry then return entry.type_id, entry.type_label end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function detectLogType
-- Heuristically determines whether the event is a sign-in log or an audit log.
-- Returns LOG_TYPE.SIGNIN or LOG_TYPE.AUDIT.
--------------------------------------------------------------------------------
local function detectLogType(e)
    -- Explicit log type fields
    local log_type_field = e["Type"] or e["type"] or e["LogType"] or e["log_type"]
    if log_type_field then
        local lt = tostring(log_type_field or ""):lower()
        if tostring(lt or ""):find("signin", 1, true) or
           tostring(lt or ""):find("sign_in", 1, true) or
           tostring(lt or ""):find("sign-in", 1, true) then
            return LOG_TYPE.SIGNIN
        end
        if tostring(lt or ""):find("audit", 1, true) then
            return LOG_TYPE.AUDIT
        end
    end

    -- Category-based detection
    local cat = tostring(e["category"] or e["Category"] or ""):lower()
    if tostring(cat or ""):find("signin", 1, true) or
       tostring(cat or ""):find("sign_in", 1, true) or
       tostring(cat or ""):find("noninteractive", 1, true) or
       tostring(cat or ""):find("serviceprincipal", 1, true) or
       tostring(cat or ""):find("managedidentity", 1, true) then
        return LOG_TYPE.SIGNIN
    end
    if tostring(cat or ""):find("audit", 1, true) or
       tostring(cat or ""):find("directory", 1, true) then
        return LOG_TYPE.AUDIT
    end

    -- Field presence heuristics
    if e["status"] and type(e["status"]) == "table" then
        return LOG_TYPE.SIGNIN   -- sign-in has status as nested object
    end
    if e["initiatedBy"] then
        return LOG_TYPE.AUDIT
    end
    if e["ipAddress"] or e["deviceDetail"] or e["location"] then
        return LOG_TYPE.SIGNIN
    end
    if e["targetResources"] or e["activityDisplayName"] then
        return LOG_TYPE.AUDIT
    end

    -- Default to sign-in (most common Entra log type)
    return LOG_TYPE.SIGNIN
end

--------------------------------------------------------------------------------
-- local function extractKvList
-- Flattens a Microsoft KV-list array into a plain Lua table.
-- Supports [{key=K, value=V}], [{displayName=K, newValue=V}], [{Name=K, Value=V}]
--------------------------------------------------------------------------------
local function extractKvList(arr)
    if type(arr) ~= "table" then return nil end
    local result = {}
    local found  = false
    for _, item in ipairs(arr) do
        if type(item) == "table" then
            local k = item.key         or item.Key         or item.Name
                   or item.displayName or item.name
            local v = item.value       or item.Value       or item.newValue
                   or item.NewValue
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
-- Constructs OCSF actor object.
-- Sign-in: userPrincipalName / userId / appDisplayName / appId
-- Audit:   initiatedBy.user.* / initiatedBy.app.*
--------------------------------------------------------------------------------
local function buildActor(e, log_type)
    local actor = {}

    if log_type == LOG_TYPE.AUDIT then
        -- Audit log: initiatedBy nested object
        local ib = e["initiatedBy"]
        if type(ib) == "table" then
            local ib_user = ib["user"]
            local ib_app  = ib["app"]

            if type(ib_user) == "table" then
                actor.user = {}
                local upn = ib_user["userPrincipalName"] or ib_user["displayName"]
                if upn then actor.user.name = tostring(upn or "") end
                local uid = ib_user["id"]
                if uid then actor.user.uid = tostring(uid or "") end
                local ip  = ib_user["ipAddress"]
                if ip  then actor.user.endpoint = { ip = tostring(ip or "") } end
                actor.user.type_id = 1
                actor.user.type    = "User"
            end

            if type(ib_app) == "table" then
                actor.app = {}
                local aname = ib_app["displayName"]
                if aname then actor.app.name = tostring(aname or "") end
                local auid = ib_app["appId"] or ib_app["servicePrincipalId"]
                if auid then actor.app.uid = tostring(auid or "") end
                local spname = ib_app["servicePrincipalName"]
                if spname then actor.app.name = actor.app.name or tostring(spname or "") end
            end
        end
    else
        -- Sign-in log: flat user fields
        local uname = e["userDisplayName"] or e["userPrincipalName"]
        local uid   = e["userId"]
        local utype = e["userType"]

        if uname or uid then
            actor.user = {}
            if uname then actor.user.name = tostring(uname or "") end
            if uid   then actor.user.uid  = tostring(uid   or "") end

            local type_id, type_label = normUserType(utype)
            if type_id    then actor.user.type_id = type_id    end
            if type_label then actor.user.type    = type_label end
        end

        -- Application / service principal
        local app_name = e["appDisplayName"] or e["servicePrincipalName"]
        local app_id   = e["appId"]          or e["servicePrincipalId"]
        if app_name or app_id then
            actor.app = {}
            if app_name then actor.app.name = tostring(app_name or "") end
            if app_id   then actor.app.uid  = tostring(app_id   or "") end
        end
    end

    -- Session (both log types)
    local session_id = e["sessionId"] or e["correlationId"]
    if session_id then
        actor.session = { uid = tostring(session_id or "") }
    end

    if next(actor) == nil then return nil end
    return actor
end

--------------------------------------------------------------------------------
-- local function buildSrcEndpoint
-- Constructs OCSF src_endpoint.
-- Sign-in: ipAddress + location + deviceDetail
-- Audit:   initiatedBy.user.ipAddress
--------------------------------------------------------------------------------
local function buildSrcEndpoint(e, log_type)
    local ep = {}

    -- IP address
    local ip
    if log_type == LOG_TYPE.AUDIT then
        local ib = e["initiatedBy"]
        if type(ib) == "table" and type(ib["user"]) == "table" then
            ip = ib["user"]["ipAddress"]
        end
    end
    ip = ip or e["ipAddress"]

    if ip then
        -- Strip IPv6 brackets: [::1]:port → ::1
        local clean = tostring(ip or ""):match("^%[(.+)%]:%d+$")
                   or tostring(ip or ""):match("^%[(.+)%]$")
                   or tostring(ip or ""):match("^([^:]+):%d+$")
                   or ip
        ep.ip = tostring(clean or "")
    end

    -- Location (sign-in only)
    local loc = e["location"]
    if type(loc) == "table" then
        ep.location = {}
        local city    = loc["city"]
        local state   = loc["state"]
        local country = loc["countryOrRegion"]
        if city    then ep.location.city    = tostring(city    or "") end
        if state   then ep.location.region  = tostring(state   or "") end
        if country then ep.location.country = tostring(country or "") end

        local geo = loc["geoCoordinates"]
        if type(geo) == "table" then
            local lat = tonumber(geo["latitude"])
            local lng = tonumber(geo["longitude"])
            if lat then ep.location.lat  = lat end
            if lng then ep.location.long = lng end
        end
    end

    -- Device detail (sign-in only)
    local dd = e["deviceDetail"]
    if type(dd) == "table" then
        local dev_id   = dd["deviceId"]
        local dev_name = dd["displayName"]
        local os_name  = dd["operatingSystem"]
        local trust    = dd["trustType"]
        local is_comp  = dd["isCompliant"]
        local is_mgd   = dd["isManaged"]

        if dev_id   then ep.uid  = tostring(dev_id   or "") end
        if dev_name then ep.name = tostring(dev_name or "") end
        if trust    then ep.type = tostring(trust    or "") end

        if os_name then
            ep.os = { name = tostring(os_name or "") }
        end

        if is_comp ~= nil or is_mgd ~= nil then
            ep.data = {}
            if is_comp ~= nil then ep.data.is_compliant = is_comp end
            if is_mgd  ~= nil then ep.data.is_managed   = is_mgd  end
        end
    end

    -- networkLocationDetails (sign-in)
    local nld = e["networkLocationDetails"]
    if type(nld) == "table" and #nld > 0 then
        local first = nld[1]
        if type(first) == "table" then
            local net_type = first["networkType"]
            if net_type then
                if not ep.data then ep.data = {} end
                ep.data.network_type = tostring(net_type or "")
            end
        end
    end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildHttpRequest
-- Constructs OCSF http_request from deviceDetail.browser / userAgent.
--------------------------------------------------------------------------------
local function buildHttpRequest(e)
    local req = {}

    -- Browser from deviceDetail
    local dd = e["deviceDetail"]
    if type(dd) == "table" then
        local browser = dd["browser"]
        if browser and browser ~= "" then
            req.user_agent = tostring(browser or "")
        end
    end

    -- Fallback: explicit userAgent field
    if not req.user_agent then
        local ua = e["userAgent"]
        if ua then req.user_agent = tostring(ua or "") end
    end

    -- Request UID
    local req_uid = e["uniqueTokenIdentifier"] or e["originalRequestId"]
    if req_uid then req.uid = tostring(req_uid or "") end

    -- HTTP method inference from operation
    local op = tostring(e["activityDisplayName"] or e["operationType"] or ""):lower()
    if op ~= "" then
        local method
        if tostring(op or ""):find("get", 1, true)    or
           tostring(op or ""):find("list", 1, true)   or
           tostring(op or ""):find("read", 1, true)   or
           tostring(op or ""):find("signin", 1, true) or
           tostring(op or ""):find("sign-in", 1, true) then
            method = "GET"
        elseif tostring(op or ""):find("delete", 1, true) or
               tostring(op or ""):find("remove", 1, true) or
               tostring(op or ""):find("revoke", 1, true) then
            method = "DELETE"
        elseif tostring(op or ""):find("update", 1, true) or
               tostring(op or ""):find("set", 1, true)    or
               tostring(op or ""):find("modify", 1, true) or
               tostring(op or ""):find("enable", 1, true) or
               tostring(op or ""):find("disable", 1, true) or
               tostring(op or ""):find("reset", 1, true)  then
            method = "PATCH"
        elseif tostring(op or ""):find("add", 1, true)    or
               tostring(op or ""):find("create", 1, true) or
               tostring(op or ""):find("invite", 1, true) or
               tostring(op or ""):find("register", 1, true) then
            method = "POST"
        end
        if method then req.http_method = method end
    end

    if next(req) == nil then return nil end
    return req
end

--------------------------------------------------------------------------------
-- local function buildApi
-- Constructs OCSF api object.
-- Sign-in: resourceDisplayName / resourceId / clientAppUsed / authDetails
-- Audit:   activityDisplayName / additionalDetails KV list
--------------------------------------------------------------------------------
local function buildApi(e, log_type)
    local api = {}

    -- Operation
    local op = e["activityDisplayName"] or e["operationType"]
    if op then api.operation = tostring(op or "") end

    -- Service
    local svc_name = e["loggedByService"] or e["resourceDisplayName"]
    if svc_name then
        api.service = { name = tostring(svc_name or "") }
    end

    -- Request data
    local req_data = {}

    if log_type == LOG_TYPE.SIGNIN then
        local res_name = e["resourceDisplayName"]
        if res_name then req_data.resource_name = tostring(res_name or "") end

        local res_id = e["resourceId"]
        if res_id then req_data.resource_id = tostring(res_id or "") end

        local res_tenant = e["resourceTenantId"]
        if res_tenant then req_data.resource_tenant_id = tostring(res_tenant or "") end

        local client_app = e["clientAppUsed"]
        if client_app then req_data.client_app = tostring(client_app or "") end

        local auth_req = e["authenticationRequirement"]
        if auth_req then req_data.auth_requirement = tostring(auth_req or "") end

        local ca_status = e["conditionalAccessStatus"]
        if ca_status then req_data.conditional_access_status = tostring(ca_status or "") end

        local token_type = e["tokenIssuerType"]
        if token_type then req_data.token_issuer_type = tostring(token_type or "") end

        local token_name = e["tokenIssuerName"]
        if token_name then req_data.token_issuer_name = tostring(token_name or "") end

        local is_interactive = e["isInteractive"]
        if is_interactive ~= nil then req_data.is_interactive = is_interactive end

        local flagged = e["flaggedForReview"]
        if flagged ~= nil then req_data.flagged_for_review = flagged end

        local risk_state = e["riskState"]
        if risk_state then req_data.risk_state = tostring(risk_state or "") end

        local risk_detail = e["riskDetail"]
        if risk_detail then req_data.risk_detail = tostring(risk_detail or "") end

        local auth_proto = e["authenticationProtocol"]
        if auth_proto then req_data.auth_protocol = tostring(auth_proto or "") end

        local incoming_token = e["incomingTokenType"]
        if incoming_token then req_data.incoming_token_type = tostring(incoming_token or "") end

        -- mfaDetail
        local mfa = e["mfaDetail"]
        if type(mfa) == "table" then
            local mfa_method = mfa["authMethod"]
            local mfa_detail = mfa["authDetail"]
            if mfa_method then req_data.mfa_method = tostring(mfa_method or "") end
            if mfa_detail  then req_data.mfa_detail = tostring(mfa_detail or "") end
        end

        -- authenticationDetails (array of auth steps)
        local auth_details = e["authenticationDetails"]
        if type(auth_details) == "table" and #auth_details > 0 then
            local methods = {}
            for _, step in ipairs(auth_details) do
                if type(step) == "table" then
                    local method = step["authenticationMethod"]
                    if method and method ~= "" then
                        table.insert(methods, tostring(method or ""))
                    end
                end
            end
            if #methods > 0 then
                req_data.auth_methods = table.concat(methods, ",")
            end
        end

        -- appliedConditionalAccessPolicies (array → names)
        local ca_policies = e["appliedConditionalAccessPolicies"]
        if type(ca_policies) == "table" and #ca_policies > 0 then
            local policy_names = {}
            for _, pol in ipairs(ca_policies) do
                if type(pol) == "table" then
                    local pname = pol["displayName"] or pol["id"]
                    if pname and pname ~= "" then
                        table.insert(policy_names, tostring(pname or ""))
                    end
                end
            end
            if #policy_names > 0 then
                req_data.ca_policies = table.concat(policy_names, ",")
            end
        end

    else
        -- Audit log: flatten additionalDetails KV list
        if FEATURES.FLATTEN_ADDITIONAL then
            local add_details = e["additionalDetails"]
            if type(add_details) == "table" then
                local flat = extractKvList(add_details)
                if flat then
                    for k, v in pairs(flat) do
                        req_data[tostring(k or "")] = v
                    end
                end
            end
        end
    end

    if next(req_data) ~= nil then
        if not api.request then api.request = {} end
        api.request.data = req_data
    end

    -- Request UID
    local req_uid = e["uniqueTokenIdentifier"] or e["originalRequestId"]
    if req_uid then
        if not api.request then api.request = {} end
        api.request.uid = tostring(req_uid or "")
    end

    if next(api) == nil then return nil end
    return api
end

--------------------------------------------------------------------------------
-- local function buildCloud
-- Constructs OCSF cloud object from Entra tenantId / homeTenantId.
--------------------------------------------------------------------------------
local function buildCloud(e)
    local cloud = { provider = "Microsoft" }

    local tenant_id   = e["tenantId"]     or e["homeTenantId"]
    local tenant_name = e["tenantName"]
    if tenant_id or tenant_name then
        cloud.account = { type = "Tenant" }
        if tenant_id   then cloud.account.uid  = tostring(tenant_id   or "") end
        if tenant_name then cloud.account.name = tostring(tenant_name or "") end
    end

    -- Cross-tenant: resource tenant
    local res_tenant = e["resourceTenantId"]
    if res_tenant and res_tenant ~= (e["tenantId"] or "") then
        cloud.data = { resource_tenant_id = tostring(res_tenant or "") }
    end

    return cloud
end

--------------------------------------------------------------------------------
-- local function buildResources
-- Constructs OCSF resources[] from Entra targetResources (audit logs).
--------------------------------------------------------------------------------
local function buildResources(e, log_type)
    if log_type ~= LOG_TYPE.AUDIT then return nil end

    local tr = e["targetResources"]
    if type(tr) ~= "table" or #tr == 0 then return nil end

    local resources = {}

    for _, res in ipairs(tr) do
        if type(res) == "table" then
            local r = {}

            local rname = res["displayName"]
            if rname then r.name = tostring(rname or "") end

            local rtype = res["type"]
            if rtype then r.type = tostring(rtype or "") end

            local rid = res["id"]
            if rid then r.uid = tostring(rid or "") end

            -- Modified properties → data
            local mod_props = res["modifiedProperties"]
            if type(mod_props) == "table" and #mod_props > 0 then
                local props = {}
                for _, prop in ipairs(mod_props) do
                    if type(prop) == "table" then
                        local pname = prop["displayName"]
                        local pnew  = prop["newValue"]
                        local pold  = prop["oldValue"]
                        if pname then
                            props[tostring(pname or "")] = {
                                new_value = pnew,
                                old_value = pold,
                            }
                        end
                    end
                end
                if next(props) ~= nil then r.data = props end
            end

            if next(r) ~= nil then
                table.insert(resources, r)
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

    -- User
    addObs("actor.user",    20, e["userPrincipalName"] or e["userDisplayName"])

    -- IP
    local ip = e["ipAddress"]
    if not ip then
        local ib = e["initiatedBy"]
        if type(ib) == "table" and type(ib["user"]) == "table" then
            ip = ib["user"]["ipAddress"]
        end
    end
    addObs("src_endpoint.ip", 2, ip)

    -- App
    addObs("actor.app",     99, e["appDisplayName"] or e["servicePrincipalName"])

    -- Resource
    addObs("resource",      99, e["resourceDisplayName"])

    -- Correlation
    addObs("correlation_id", 99, e["correlationId"])

    -- Tenant
    addObs("tenant_id",     99, e["tenantId"] or e["homeTenantId"])

    if #obs == 0 then return nil end
    return obs
end

--------------------------------------------------------------------------------
-- local function resolveSignInStatus
-- Resolves sign-in status from the nested status object (errorCode + failureReason)
-- or from flat result / resultType fields.
-- Returns: status_id, status_label, status_code_str, status_detail_str
--------------------------------------------------------------------------------
local function resolveSignInStatus(e)
    -- Nested status object (sign-in logs)
    local status_obj = e["status"]
    if type(status_obj) == "table" then
        local err_code = status_obj["errorCode"]
        local failure  = status_obj["failureReason"]
        local add_det  = status_obj["additionalDetails"]

        local st_id, st_label = normStatus(err_code)
        local st_code   = err_code ~= nil and tostring(err_code or "") or nil
        local st_detail = failure or add_det

        return st_id, st_label,
               st_code,
               st_detail and tostring(st_detail or "") or nil
    end

    -- Flat result fields (audit logs)
    local result = e["result"] or e["resultType"]
    local reason = e["resultReason"] or e["resultDescription"]
    local st_id, st_label = normStatus(result)
    return st_id, st_label,
           result and tostring(result or "") or nil,
           reason and tostring(reason or "") or nil
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
        -- 1. Detect log type: sign-in vs audit
        -----------------------------------------------------------------------
        local log_type = detectLogType(e)

        -----------------------------------------------------------------------
        -- 2. Seed OCSF skeleton with required constant fields
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
                    name        = "Microsoft Entra ID",
                    feature     = {
                        name = log_type == LOG_TYPE.SIGNIN and "Sign-in Logs" or "Audit Logs",
                    },
                },
            },
            osint    = {},
            unmapped = {},
        }

        -----------------------------------------------------------------------
        -- 3. Apply FIELD_MAP: scalar source field → OCSF destination path
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
        -- 4. Resolve time with fallback chain
        -----------------------------------------------------------------------
        if ocsf.time == nil then
            local fallbacks = {
                "createdDateTime", "activityDateTime",
                "timestamp", "_time",
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
        -- 5. Resolve operation and activity_id
        -----------------------------------------------------------------------
        local operation
        if log_type == LOG_TYPE.SIGNIN then
            operation = "Sign-in"
        else
            operation = e["activityDisplayName"] or e["operationType"]
        end

        local activity_id = normActivityId(operation)
        ocsf.activity_id   = activity_id
        ocsf.activity_name = ACTIVITY_NAMES[activity_id] or "Other"
        ocsf.type_uid      = 6003 * 100 + activity_id
        ocsf.type_name     = "API Activity: " .. (ACTIVITY_NAMES[activity_id] or "Other")

        consumed["activityDisplayName"] = true
        consumed["operationType"]       = true

        -----------------------------------------------------------------------
        -- 6. Resolve status
        -----------------------------------------------------------------------
        local st_id, st_label, st_code, st_detail = resolveSignInStatus(e)
        if st_id    then ocsf.status_id    = st_id    end
        if st_label then ocsf.status       = st_label end
        if st_code  then ocsf.status_code  = st_code  end
        if st_detail then ocsf.status_detail = st_detail end

        consumed["status"]            = true
        consumed["result"]            = true
        consumed["resultType"]        = true
        consumed["resultReason"]      = true
        consumed["resultDescription"] = true

        -----------------------------------------------------------------------
        -- 7. Severity: risk-based elevation
        -----------------------------------------------------------------------
        local risk_raw = e["riskLevelAggregated"]
                      or e["riskLevelDuringSignIn"]
                      or e["riskLevel"]
        local risk_sev_id, risk_sev_label = normRiskSeverity(risk_raw)
        if risk_sev_id and risk_sev_id > ocsf.severity_id then
            ocsf.severity_id = risk_sev_id
            ocsf.severity    = risk_sev_label
        end
        -- Failure always at least Low
        if ocsf.status_id == 2 and ocsf.severity_id < 2 then
            ocsf.severity_id = 2
            ocsf.severity    = "Low"
        end
        consumed["riskLevelAggregated"]    = true
        consumed["riskLevelDuringSignIn"]  = true
        consumed["riskLevel"]              = true

        -----------------------------------------------------------------------
        -- 8. actor (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_ACTOR then
            local actor = buildActor(e, log_type)
            if actor then
                ocsf.actor = actor
            else
                ocsf.actor = {}
            end
            consumed["userDisplayName"]         = true
            consumed["userPrincipalName"]        = true
            consumed["userId"]                   = true
            consumed["userType"]                 = true
            consumed["appDisplayName"]           = true
            consumed["appId"]                    = true
            consumed["servicePrincipalName"]     = true
            consumed["servicePrincipalId"]       = true
            consumed["managedIdentityType"]      = true
            consumed["sessionId"]                = true
            consumed["initiatedBy"]              = true
        end

        -----------------------------------------------------------------------
        -- 9. src_endpoint (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SRC_ENDPOINT then
            local ep = buildSrcEndpoint(e, log_type)
            if ep then
                ocsf.src_endpoint = ep
            else
                ocsf.src_endpoint = {}
            end
            consumed["ipAddress"]              = true
            consumed["location"]               = true
            consumed["deviceDetail"]           = true
            consumed["networkLocationDetails"] = true
        end

        -----------------------------------------------------------------------
        -- 10. api (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_API then
            local api_obj = buildApi(e, log_type)
            if api_obj then
                ocsf.api = api_obj
            else
                ocsf.api = {}
            end
            consumed["resourceDisplayName"]                 = true
            consumed["resourceId"]                          = true
            consumed["resourceTenantId"]                    = true
            consumed["clientAppUsed"]                       = true
            consumed["authenticationRequirement"]           = true
            consumed["conditionalAccessStatus"]             = true
            consumed["tokenIssuerType"]                     = true
            consumed["tokenIssuerName"]                     = true
            consumed["isInteractive"]                       = true
            consumed["flaggedForReview"]                    = true
            consumed["riskState"]                           = true
            consumed["riskDetail"]                          = true
            consumed["authenticationProtocol"]              = true
            consumed["incomingTokenType"]                   = true
            consumed["mfaDetail"]                           = true
            consumed["authenticationDetails"]               = true
            consumed["appliedConditionalAccessPolicies"]    = true
            consumed["additionalDetails"]                   = true
            consumed["loggedByService"]                     = true
            consumed["uniqueTokenIdentifier"]               = true
            consumed["originalRequestId"]                   = true
        end

        -----------------------------------------------------------------------
        -- 11. cloud (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CLOUD then
            ocsf.cloud = buildCloud(e)
            consumed["tenantId"]         = true
            consumed["homeTenantId"]     = true
            consumed["tenantName"]       = true
            consumed["resourceTenantId"] = true
        end

        -----------------------------------------------------------------------
        -- 12. http_request (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_HTTP_REQUEST then
            local hr = buildHttpRequest(e)
            if hr then ocsf.http_request = hr end
            consumed["userAgent"] = true
        end

        -----------------------------------------------------------------------
        -- 13. resources (recommended — audit logs only)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_RESOURCES then
            local res = buildResources(e, log_type)
            if res then ocsf.resources = res end
            consumed["targetResources"] = true
        end

        -----------------------------------------------------------------------
        -- 14. observables (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_OBSERVABLES then
            local obs = buildObservables(e)
            if obs then ocsf.observables = obs end
        end

        -----------------------------------------------------------------------
        -- 15. duration (sign-in processing time)
        -----------------------------------------------------------------------
        local proc_ms = tonumber(e["processingTimeInMilliseconds"])
        if proc_ms then
            ocsf.duration = proc_ms
            consumed["processingTimeInMilliseconds"] = true
        end

        -----------------------------------------------------------------------
        -- 16. metadata enrichment: category / correlationId
        -----------------------------------------------------------------------
        local cat = e["category"] or e["Category"]
        if cat then
            deepSet(ocsf, "metadata.product.feature.name", tostring(cat or ""))
            consumed["category"]  = true
            consumed["Category"]  = true
        end

        local corr = e["correlationId"]
        if corr then
            deepSet(ocsf, "metadata.correlation_uid", tostring(corr or ""))
            consumed["correlationId"] = true
        end

        local log_id = e["id"]
        if log_id then
            deepSet(ocsf, "metadata.uid", tostring(log_id or ""))
            consumed["id"] = true
        end

        -----------------------------------------------------------------------
        -- 17. raw_data
        -----------------------------------------------------------------------
        if FEATURES.PRESERVE_RAW then
            local ok_enc, raw_str = pcall(json.encode, e)
            if ok_enc and raw_str then
                ocsf.raw_data = raw_str
            end
        end

        -----------------------------------------------------------------------
        -- 18. Collect remaining unmapped fields
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
        -- 19. Strip empty strings / empty tables
        -----------------------------------------------------------------------
        if FEATURES.STRIP_EMPTY then
            stripEmpty(ocsf)
        end

        -----------------------------------------------------------------------
        -- 20. Compose human-readable message (table.concat, no .. in loop)
        -----------------------------------------------------------------------
        local msg_parts = {}
        local actor_name  = deepGet(ocsf, "actor.user.name")
        local app_name    = deepGet(ocsf, "actor.app.name")
        local api_op      = deepGet(ocsf, "api.operation")
        local src_ip      = deepGet(ocsf, "src_endpoint.ip")
        local status_lbl  = ocsf.status
        local sev_lbl     = ocsf.severity

        local log_prefix = log_type == LOG_TYPE.SIGNIN and "Entra Sign-in:" or "Entra Audit:"
        table.insert(msg_parts, log_prefix)
        if api_op     then table.insert(msg_parts, "operation=" .. tostring(api_op    or "")) end
        if actor_name then table.insert(msg_parts, "user="      .. tostring(actor_name or "")) end
        if app_name   then table.insert(msg_parts, "app="       .. tostring(app_name  or "")) end
        if src_ip     then table.insert(msg_parts, "ip="        .. tostring(src_ip    or "")) end
        if status_lbl then table.insert(msg_parts, "status="    .. tostring(status_lbl or "")) end
        if sev_lbl and sev_lbl ~= "Informational" then
            table.insert(msg_parts, "severity=" .. tostring(sev_lbl or ""))
        end

        ocsf.message = table.concat(msg_parts, " ")

        -----------------------------------------------------------------------
        -- 21. Encode final OCSF event as raw JSON into message field
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
        event["_ocsf_serializer"]   = "entra_signin_audit_api_activity"
        event["_ocsf_parse_failed"] = "true"
        return event
    end

end -- end processEvent()
