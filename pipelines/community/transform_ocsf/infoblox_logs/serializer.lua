--------------------------------------------------------------------------------
-- Infoblox DNS Query Logs → OCSF 1.3.0 DNS Activity (class_uid = 4003)
-- Observo processEvent(event) contract
-- Author: Observo AI  |  Schema: OCSF 1.3.0  |  Class: DNS Activity (4003)
-- Covers: Infoblox NIOS syslog (named), RPZ/Threat Intelligence, pre-parsed flat
-- Raw syslog patterns handled:
--   Query:    client <ip>#<port> (<qname>): query: <qname> <class> <type> <flags> (<srv>)
--   Response: ... query: ... -> <rcode>
--   RPZ:      client <ip>#<port>: rpz <action> rewrite <qname>/<type>/<class> via <zone>
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
    PARSE_RAW_SYSLOG      = true,   -- attempt to parse raw Infoblox syslog message
    ENRICH_QUERY          = true,   -- build query object from qname/qtype/qclass
    ENRICH_ANSWERS        = true,   -- build answers[] from response IP / rdata fields
    ENRICH_SRC_ENDPOINT   = true,   -- build src_endpoint from client_ip / src_ip
    ENRICH_DST_ENDPOINT   = true,   -- build dst_endpoint from server_ip / dst_ip
    ENRICH_CONNECTION     = true,   -- build connection_info from protocol / flags
    ENRICH_DEVICE         = true,   -- build device from hostname / mac fields
    ENRICH_FIREWALL_RULE  = true,   -- build firewall_rule from RPZ rule / policy
    ENRICH_CLOUD          = true,   -- build cloud from grid / member fields
    ENRICH_OBSERVABLES    = true,   -- build observables[] from IPs / domain
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
    "query_time",
    "response_time",
    "duration",
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
    "rcode",
    "rcode_id",
    "message",
    "metadata",
    "query",
    "answers",
    "src_endpoint",
    "dst_endpoint",
    "connection_info",
    "firewall_rule",
    "device",
    "cloud",
    "observables",
    "osint",
    "raw_data",
    "unmapped",
}

--------------------------------------------------------------------------------
-- RCODE_MAP: DNS response code string → OCSF {rcode_id, rcode_label,
--            status_id, status_label}
-- OCSF rcode_id follows RFC 1035 / IANA DNS RCODEs
--------------------------------------------------------------------------------
local RCODE_MAP = {
    noerror     = { rcode_id = 0,  rcode_label = "NoError",   status_id = 1, status_label = "Success" },
    noerr       = { rcode_id = 0,  rcode_label = "NoError",   status_id = 1, status_label = "Success" },
    ["0"]       = { rcode_id = 0,  rcode_label = "NoError",   status_id = 1, status_label = "Success" },
    formerr     = { rcode_id = 1,  rcode_label = "FormError", status_id = 2, status_label = "Failure" },
    ["1"]       = { rcode_id = 1,  rcode_label = "FormError", status_id = 2, status_label = "Failure" },
    servfail    = { rcode_id = 2,  rcode_label = "ServError", status_id = 2, status_label = "Failure" },
    ["2"]       = { rcode_id = 2,  rcode_label = "ServError", status_id = 2, status_label = "Failure" },
    nxdomain    = { rcode_id = 3,  rcode_label = "NXDomain",  status_id = 2, status_label = "Failure" },
    ["3"]       = { rcode_id = 3,  rcode_label = "NXDomain",  status_id = 2, status_label = "Failure" },
    notimp      = { rcode_id = 4,  rcode_label = "NotImp",    status_id = 2, status_label = "Failure" },
    ["4"]       = { rcode_id = 4,  rcode_label = "NotImp",    status_id = 2, status_label = "Failure" },
    refused     = { rcode_id = 5,  rcode_label = "Refused",   status_id = 2, status_label = "Failure" },
    ["5"]       = { rcode_id = 5,  rcode_label = "Refused",   status_id = 2, status_label = "Failure" },
    yxdomain    = { rcode_id = 6,  rcode_label = "YXDomain",  status_id = 2, status_label = "Failure" },
    ["6"]       = { rcode_id = 6,  rcode_label = "YXDomain",  status_id = 2, status_label = "Failure" },
    yxrrset     = { rcode_id = 7,  rcode_label = "YXRRSet",   status_id = 2, status_label = "Failure" },
    ["7"]       = { rcode_id = 7,  rcode_label = "YXRRSet",   status_id = 2, status_label = "Failure" },
    nxrrset     = { rcode_id = 8,  rcode_label = "NXRRSet",   status_id = 2, status_label = "Failure" },
    ["8"]       = { rcode_id = 8,  rcode_label = "NXRRSet",   status_id = 2, status_label = "Failure" },
    notauth     = { rcode_id = 9,  rcode_label = "NotAuth",   status_id = 2, status_label = "Failure" },
    ["9"]       = { rcode_id = 9,  rcode_label = "NotAuth",   status_id = 2, status_label = "Failure" },
    notzone     = { rcode_id = 10, rcode_label = "NotZone",   status_id = 2, status_label = "Failure" },
    ["10"]      = { rcode_id = 10, rcode_label = "NotZone",   status_id = 2, status_label = "Failure" },
    badvers     = { rcode_id = 16, rcode_label = "BADSIG_VERS", status_id = 2, status_label = "Failure" },
    badsig      = { rcode_id = 16, rcode_label = "BADSIG_VERS", status_id = 2, status_label = "Failure" },
    badkey      = { rcode_id = 17, rcode_label = "BADKEY",    status_id = 2, status_label = "Failure" },
    badtime     = { rcode_id = 18, rcode_label = "BADTIME",   status_id = 2, status_label = "Failure" },
    badcookie   = { rcode_id = 23, rcode_label = "BADCOOKIE", status_id = 2, status_label = "Failure" },
}

--------------------------------------------------------------------------------
-- QTYPE_MAP: DNS query type string → OCSF {type_id, type_label}
-- Based on IANA DNS Parameters
--------------------------------------------------------------------------------
local QTYPE_MAP = {
    a       = { id = 1,   label = "A" },
    ns      = { id = 2,   label = "NS" },
    cname   = { id = 5,   label = "CNAME" },
    soa     = { id = 6,   label = "SOA" },
    ptr     = { id = 12,  label = "PTR" },
    mx      = { id = 15,  label = "MX" },
    txt     = { id = 16,  label = "TXT" },
    aaaa    = { id = 28,  label = "AAAA" },
    srv     = { id = 33,  label = "SRV" },
    naptr   = { id = 35,  label = "NAPTR" },
    ds      = { id = 43,  label = "DS" },
    rrsig   = { id = 46,  label = "RRSIG" },
    nsec    = { id = 47,  label = "NSEC" },
    dnskey  = { id = 48,  label = "DNSKEY" },
    nsec3   = { id = 50,  label = "NSEC3" },
    tlsa    = { id = 52,  label = "TLSA" },
    https   = { id = 65,  label = "HTTPS" },
    svcb    = { id = 64,  label = "SVCB" },
    caa     = { id = 257, label = "CAA" },
    any     = { id = 255, label = "ANY" },
    ["*"]   = { id = 255, label = "ANY" },
}

--------------------------------------------------------------------------------
-- QCLASS_MAP: DNS query class string → OCSF {class_id, class_label}
--------------------------------------------------------------------------------
local QCLASS_MAP = {
    ["in"]  = { id = 1,   label = "IN" },
    ["1"]   = { id = 1,   label = "IN" },
    ch      = { id = 3,   label = "CH" },
    ["3"]   = { id = 3,   label = "CH" },
    hs      = { id = 4,   label = "HS" },
    ["4"]   = { id = 4,   label = "HS" },
    any     = { id = 255, label = "ANY" },
    ["255"] = { id = 255, label = "ANY" },
    ["*"]   = { id = 255, label = "ANY" },
}

--------------------------------------------------------------------------------
-- RPZ_ACTION_MAP: Infoblox RPZ action → OCSF {disposition_id, action_id,
--                disposition_label, action_label}
-- OCSF disposition_id: 1=Allowed, 2=Blocked, 6=Dropped, 7=Custom Action
-- OCSF action_id: 1=Allowed, 2=Denied
--------------------------------------------------------------------------------
local RPZ_ACTION_MAP = {
    passthru    = { disposition_id = 1,  action_id = 1, disposition_label = "Allowed",       action_label = "Allowed" },
    pass        = { disposition_id = 1,  action_id = 1, disposition_label = "Allowed",       action_label = "Allowed" },
    allow       = { disposition_id = 1,  action_id = 1, disposition_label = "Allowed",       action_label = "Allowed" },
    allowed     = { disposition_id = 1,  action_id = 1, disposition_label = "Allowed",       action_label = "Allowed" },
    block       = { disposition_id = 2,  action_id = 2, disposition_label = "Blocked",       action_label = "Denied" },
    blocked     = { disposition_id = 2,  action_id = 2, disposition_label = "Blocked",       action_label = "Denied" },
    nxdomain    = { disposition_id = 2,  action_id = 2, disposition_label = "Blocked",       action_label = "Denied" },
    nodata      = { disposition_id = 2,  action_id = 2, disposition_label = "Blocked",       action_label = "Denied" },
    deny        = { disposition_id = 2,  action_id = 2, disposition_label = "Blocked",       action_label = "Denied" },
    denied      = { disposition_id = 2,  action_id = 2, disposition_label = "Blocked",       action_label = "Denied" },
    drop        = { disposition_id = 6,  action_id = 2, disposition_label = "Dropped",       action_label = "Denied" },
    dropped     = { disposition_id = 6,  action_id = 2, disposition_label = "Dropped",       action_label = "Denied" },
    redirect    = { disposition_id = 7,  action_id = 1, disposition_label = "Custom Action", action_label = "Allowed" },
    redirected  = { disposition_id = 7,  action_id = 1, disposition_label = "Custom Action", action_label = "Allowed" },
    substitute  = { disposition_id = 7,  action_id = 1, disposition_label = "Custom Action", action_label = "Allowed" },
    truncate    = { disposition_id = 7,  action_id = 1, disposition_label = "Custom Action", action_label = "Allowed" },
    log         = { disposition_id = 17, action_id = 1, disposition_label = "Logged",        action_label = "Allowed" },
    logged      = { disposition_id = 17, action_id = 1, disposition_label = "Logged",        action_label = "Allowed" },
}

--------------------------------------------------------------------------------
-- THREAT_SEVERITY_MAP: Infoblox threat level string/int → OCSF {id, label}
--------------------------------------------------------------------------------
local THREAT_SEVERITY_MAP = {
    ["0"]           = { id = 1, label = "Informational" },
    none            = { id = 1, label = "Informational" },
    info            = { id = 1, label = "Informational" },
    informational   = { id = 1, label = "Informational" },
    ["1"]           = { id = 2, label = "Low" },
    low             = { id = 2, label = "Low" },
    ["2"]           = { id = 3, label = "Medium" },
    medium          = { id = 3, label = "Medium" },
    ["3"]           = { id = 4, label = "High" },
    high            = { id = 4, label = "High" },
    ["4"]           = { id = 5, label = "Critical" },
    critical        = { id = 5, label = "Critical" },
    ["5"]           = { id = 5, label = "Critical" },
}

--------------------------------------------------------------------------------
-- ACTIVITY_NAMES: activity_id → caption
--------------------------------------------------------------------------------
local ACTIVITY_NAMES = {
    [0]  = "Query",     -- safe default
    [1]  = "Query",
    [2]  = "Response",
    [6]  = "Traffic",
    [99] = "Other",
}

--------------------------------------------------------------------------------
-- FIELD_MAP: flat/pre-parsed Infoblox source field → OCSF destination dot-path
--------------------------------------------------------------------------------
local FIELD_MAP = {
    -- Timing
    ["time"]                    = "time",
    ["timestamp"]               = "time",
    ["_time"]                   = "time",
    ["event_time"]              = "time",
    ["query_time"]              = "query_time",
    ["response_time"]           = "response_time",
    ["latency"]                 = "duration",
    ["response_time_ms"]        = "duration",
    ["duration"]                = "duration",

    -- Metadata
    ["grid_name"]               = "metadata.product.feature.name",
    ["member"]                  = "metadata.product.feature.name",
    ["dns_view"]                = "metadata.product.feature.name",
    ["view"]                    = "metadata.product.feature.name",
    ["process_id"]              = "metadata.uid",
    ["pid"]                     = "metadata.uid",

    -- Source endpoint (flat)
    ["client_ip"]               = "src_endpoint.ip",
    ["src_ip"]                  = "src_endpoint.ip",
    ["source_ip"]               = "src_endpoint.ip",
    ["client_address"]          = "src_endpoint.ip",
    ["client_port"]             = "src_endpoint.port",
    ["src_port"]                = "src_endpoint.port",
    ["source_port"]             = "src_endpoint.port",

    -- Destination endpoint (flat)
    ["server_ip"]               = "dst_endpoint.ip",
    ["dst_ip"]                  = "dst_endpoint.ip",
    ["destination_ip"]          = "dst_endpoint.ip",
    ["resolver_ip"]             = "dst_endpoint.ip",
    ["server_port"]             = "dst_endpoint.port",
    ["dst_port"]                = "dst_endpoint.port",

    -- Query (flat)
    ["qname"]                   = "query.hostname",
    ["query_name"]              = "query.hostname",
    ["domain"]                  = "query.hostname",
    ["domain_name"]             = "query.hostname",
    ["fqdn"]                    = "query.hostname",
    ["qtype"]                   = "query.type",
    ["query_type"]              = "query.type",
    ["record_type"]             = "query.type",
    ["qclass"]                  = "query.class",
    ["query_class"]             = "query.class",

    -- Response / rcode (flat)
    ["rcode"]                   = "rcode",
    ["response_code"]           = "rcode",
    ["result_code"]             = "rcode",
    ["dns_rcode"]               = "rcode",

    -- Answer (flat)
    ["response_ip"]             = "answers.rdata",
    ["answer_ip"]               = "answers.rdata",
    ["answer_data"]             = "answers.rdata",
    ["rdata"]                   = "answers.rdata",
    ["ttl"]                     = "answers.ttl",
    ["answer_ttl"]              = "answers.ttl",

    -- Protocol / transport
    ["protocol"]                = "connection_info.protocol_name",
    ["transport"]               = "connection_info.protocol_name",
    ["dns_transport"]           = "connection_info.protocol_name",

    -- Device / host
    ["hostname"]                = "device.name",
    ["host"]                    = "device.name",
    ["device_name"]             = "device.name",
    ["mac_address"]             = "device.mac",
    ["mac"]                     = "device.mac",

    -- Cloud / grid
    ["grid_member"]             = "cloud.account.name",
    ["site"]                    = "cloud.region",
    ["location"]                = "cloud.region",

    -- Firewall / RPZ
    ["rpz_rule"]                = "firewall_rule.name",
    ["policy_name"]             = "firewall_rule.name",
    ["rpz_zone"]                = "firewall_rule.name",
    ["feed_name"]               = "firewall_rule.uid",
    ["threat_rule"]             = "firewall_rule.name",

    -- Threat intelligence
    ["threat_class"]            = "status_detail",
    ["threat_property"]         = "status_detail",
    ["threat_indicator"]        = "status_detail",
    ["category"]                = "status_detail",
    ["threat_category"]         = "status_detail",
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

    local numeric_hints = {
        "port", "pid", "uid", "lat", "long",
        "bytes", "packets", "score", "offset",
        "severity_id", "status_id", "activity_id",
        "class_uid", "category_uid", "type_uid",
        "rcode_id", "type_id", "class_id",
        "action_id", "disposition_id", "duration",
        "ttl", "query_time", "response_time",
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
-- Normalises Infoblox timestamp variants to epoch milliseconds (integer).
-- Handles: Unix ms (>1e12), Unix seconds, ISO-8601, syslog date strings.
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
        -- Syslog: "Jan 15 12:34:56" (no year — use current year)
        local mon_str, day_s, h2, mi2, s2 =
            tostring(val or ""):match("^(%a+)%s+(%d+)%s+(%d%d):(%d%d):(%d%d)")
        if mon_str then
            local mon_map = {
                jan=1, feb=2, mar=3, apr=4, may=5, jun=6,
                jul=7, aug=8, sep=9, oct=10, nov=11, dec=12,
            }
            local mo2 = mon_map[tostring(mon_str or ""):lower()]
            if mo2 then
                local ok2, ts2 = pcall(function()
                    local now = os.time()
                    local yr  = tonumber(os.date("%Y", now))
                    return os.time({
                        year  = yr,
                        month = mo2,
                        day   = tonumber(day_s),
                        hour  = tonumber(h2),
                        min   = tonumber(mi2),
                        sec   = tonumber(s2),
                    })
                end)
                if ok2 and ts2 then return ts2 * 1000 end
            end
        end
    end

    return nil
end

--------------------------------------------------------------------------------
-- local function normRcode
-- Maps DNS rcode string/int → OCSF {rcode_id, rcode_label, status_id, status_label}.
-- Returns nil fields when input is absent.
--------------------------------------------------------------------------------
local function normRcode(val)
    if val == nil then return nil, nil, nil, nil end
    local key = tostring(val or ""):lower()
    local entry = RCODE_MAP[key]
    if entry then
        return entry.rcode_id, entry.rcode_label, entry.status_id, entry.status_label
    end
    -- Numeric fallback
    local n = tonumber(val)
    if n then
        local nkey = tostring(math.floor(n))
        local nentry = RCODE_MAP[nkey]
        if nentry then
            return nentry.rcode_id, nentry.rcode_label, nentry.status_id, nentry.status_label
        end
        -- Non-zero numeric → failure
        if n ~= 0 then return n, nil, 2, "Failure" end
    end
    return nil, nil, nil, nil
end

--------------------------------------------------------------------------------
-- local function normQtype
-- Maps DNS query type string → OCSF {type_id, type_label}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normQtype(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower()
    local entry = QTYPE_MAP[key]
    if entry then return entry.id, entry.label end
    -- Numeric type
    local n = tonumber(val)
    if n then return n, tostring(val or "") end
    -- Pass through as-is with id=99
    return 99, tostring(val or ""):upper()
end

--------------------------------------------------------------------------------
-- local function normQclass
-- Maps DNS query class string → OCSF {class_id, class_label}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normQclass(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower()
    local entry = QCLASS_MAP[key]
    if entry then return entry.id, entry.label end
    local n = tonumber(val)
    if n then return n, tostring(val or "") end
    return 99, tostring(val or ""):upper()
end

--------------------------------------------------------------------------------
-- local function normRpzAction
-- Maps Infoblox RPZ action string → OCSF {disposition_id, action_id,
--                                         disposition_label, action_label}.
-- Returns nil fields when input is absent.
--------------------------------------------------------------------------------
local function normRpzAction(val)
    if val == nil then return nil, nil, nil, nil end
    local key = tostring(val or ""):lower()
    local entry = RPZ_ACTION_MAP[key]
    if entry then
        return entry.disposition_id, entry.action_id,
               entry.disposition_label, entry.action_label
    end
    -- Substring scan
    for pattern, e2 in pairs(RPZ_ACTION_MAP) do
        if tostring(key or ""):find(tostring(pattern or ""), 1, true) then
            return e2.disposition_id, e2.action_id,
                   e2.disposition_label, e2.action_label
        end
    end
    return nil, nil, nil, nil
end

--------------------------------------------------------------------------------
-- local function normThreatSeverity
-- Maps Infoblox threat level string/int → OCSF {severity_id, severity_label}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normThreatSeverity(val)
    if val == nil then return nil, nil end
    local key = tostring(val or ""):lower()
    local entry = THREAT_SEVERITY_MAP[key]
    if entry then return entry.id, entry.label end
    local n = tonumber(val)
    if n then
        local nkey = tostring(math.floor(n))
        local nentry = THREAT_SEVERITY_MAP[nkey]
        if nentry then return nentry.id, nentry.label end
        if n >= 4 then return 5, "Critical" end
        if n >= 3 then return 4, "High" end
        if n >= 2 then return 3, "Medium" end
        if n >= 1 then return 2, "Low" end
    end
    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normActivityId
-- Derives OCSF activity_id from Infoblox log context.
-- 1=Query, 2=Response, 6=Traffic, 99=Other
--------------------------------------------------------------------------------
local function normActivityId(e, parsed)
    -- Explicit activity field
    local act_raw = e["activity"] or e["activity_id"] or e["dns_activity"]
    if act_raw then
        local a = tostring(act_raw or ""):lower()
        if a == "query"    or a == "1" then return 1 end
        if a == "response" or a == "2" then return 2 end
        if a == "traffic"  or a == "6" then return 6 end
    end

    -- Infer from parsed syslog fields
    if parsed then
        -- Has rcode → Response
        if parsed.rcode and parsed.rcode ~= "" then return 2 end
        -- Has query keyword → Query
        if parsed.is_query then return 1 end
        -- RPZ event → Query (with policy action)
        if parsed.is_rpz then return 1 end
    end

    -- Flat field heuristics
    local rcode_raw = e["rcode"] or e["response_code"] or e["dns_rcode"]
    if rcode_raw then return 2 end

    local msg_raw = e["message"] or e["raw"] or e["_raw"] or e["log_message"]
    if msg_raw then
        local m = tostring(msg_raw or ""):lower()
        if tostring(m or ""):find("query:", 1, true) then return 1 end
        if tostring(m or ""):find("response", 1, true) then return 2 end
        if tostring(m or ""):find("rpz", 1, true) then return 1 end
    end

    -- Default: Query (most common Infoblox DNS log type)
    return 1
end

--------------------------------------------------------------------------------
-- local function parseDnsFlags
-- Parses Infoblox DNS flag string into a structured table.
-- Infoblox flag chars: + (RD), - (no RD), D (DNSSEC), T (TCP), E (EDNS),
--                      C (CD), A (AA), S (signed)
-- Returns a table of boolean flags.
--------------------------------------------------------------------------------
local function parseDnsFlags(flags_str)
    if flags_str == nil then return {} end
    local f = tostring(flags_str or "")
    local flags = {}

    -- Recursion desired: + present
    if f:find("+", 1, true) then flags.is_recursive = true end
    -- No recursion: - present (without +)
    if f:find("-", 1, true) and not f:find("+", 1, true) then
        flags.is_recursive = false
    end
    -- DNSSEC OK
    if f:find("D", 1, true) then flags.is_dnssec = true end
    -- TCP
    if f:find("T", 1, true) then flags.is_tcp = true end
    -- EDNS
    if f:find("E", 1, true) then flags.is_edns = true end
    -- Checking Disabled
    if f:find("C", 1, true) then flags.is_cd = true end
    -- Authoritative Answer
    if f:find("A", 1, true) then flags.is_aa = true end

    return flags
end

--------------------------------------------------------------------------------
-- local function parseRawSyslog
-- Parses raw Infoblox NIOS named syslog message into structured fields.
-- Handles three primary patterns:
--   (1) Query:    client <ip>#<port> (<qname>): query: <qname> <class> <type> <flags> (<srv>)
--   (2) Response: ... query: ... -> <rcode>
--   (3) RPZ:      client <ip>#<port>: rpz <action> rewrite <qname>/<type>/<class> via <zone>
-- Returns a table of extracted fields, or empty table if no match.
--------------------------------------------------------------------------------
local function parseRawSyslog(raw)
    if raw == nil then return {} end
    local s = tostring(raw or "")
    if s == "" then return {} end

    local parsed = {}

    -- Extract client IP and port: "client <ip>#<port>"
    local cip, cport = s:match("client%s+([%d%.%:a-fA-F]+)#(%d+)")
    if cip   then parsed.client_ip   = cip   end
    if cport then parsed.client_port = cport end

    -- IPv6 bracket form: "client [::1]#port"
    if not cip then
        local cip6, cport6 = s:match("client%s+%[([%d%:a-fA-F]+)%]#(%d+)")
        if cip6   then parsed.client_ip   = cip6   end
        if cport6 then parsed.client_port = cport6 end
    end

    -- Check for RPZ pattern
    local rpz_action, rpz_qname, rpz_type, rpz_class, rpz_zone =
        s:match("rpz%s+%S+%s+(%S+)%s+rewrite%s+([^/]+)/([^/]+)/([^%s]+)%s+via%s+(%S+)")
    if rpz_action then
        parsed.is_rpz    = true
        parsed.rpz_action = rpz_action
        parsed.qname     = rpz_qname
        parsed.qtype     = rpz_type
        parsed.qclass    = rpz_class
        parsed.rpz_zone  = rpz_zone
        return parsed
    end

    -- Simpler RPZ pattern: "rpz QNAME <action> rewrite <domain>/..."
    local rpz_type2, rpz_action2, rpz_rest =
        s:match("rpz%s+(%S+)%s+(%S+)%s+rewrite%s+(%S+)")
    if rpz_type2 and rpz_action2 then
        parsed.is_rpz     = true
        parsed.rpz_action = rpz_action2
        local rqname, rqtype, rqclass = rpz_rest:match("^([^/]+)/([^/]+)/([^%s]+)")
        if rqname  then parsed.qname  = rqname  end
        if rqtype  then parsed.qtype  = rqtype  end
        if rqclass then parsed.qclass = rqclass end
        return parsed
    end

    -- Query pattern: "query: <qname> <class> <type> <flags> (<server_ip>)"
    local qname, qclass, qtype, flags, server_ip =
        s:match("query:%s+(%S+)%s+(%S+)%s+(%S+)%s+([%+%-%a%d]*)%s*%(([%d%.%:a-fA-F%[%]]+)%)")
    if qname then
        parsed.is_query  = true
        parsed.qname     = qname
        parsed.qclass    = qclass
        parsed.qtype     = qtype
        parsed.flags     = flags
        parsed.server_ip = server_ip and server_ip:match("^%[(.+)%]$") or server_ip
    end

    -- Response code after "->": "... -> NOERROR"
    local rcode = s:match("%->%s*(%S+)%s*$")
    if rcode then
        parsed.rcode = rcode
    end

    -- Fallback: extract qname from parenthetical hint "(<qname>):"
    if not parsed.qname then
        local hint_qname = s:match("%(([^%)]+)%):")
        if hint_qname then parsed.qname = hint_qname end
    end

    -- Extract server IP from trailing "(ip)" if not already found
    if not parsed.server_ip then
        local trail_ip = s:match("%(([%d%.]+)%)%s*$")
        if trail_ip then parsed.server_ip = trail_ip end
    end

    return parsed
end

--------------------------------------------------------------------------------
-- local function buildQuery
-- Constructs OCSF query object from parsed syslog fields or flat source fields.
--------------------------------------------------------------------------------
local function buildQuery(e, parsed)
    local q = {}

    local qname = (parsed and parsed.qname)
               or e["qname"] or e["query_name"] or e["domain"]
               or e["domain_name"] or e["fqdn"]
    if qname then q.hostname = tostring(qname or "") end

    local qtype_raw = (parsed and parsed.qtype)
                   or e["qtype"] or e["query_type"] or e["record_type"]
    if qtype_raw then
        local tid, tlabel = normQtype(qtype_raw)
        if tlabel then q.type    = tlabel end
        if tid    then q.type_id = tid    end
    end

    local qclass_raw = (parsed and parsed.qclass)
                    or e["qclass"] or e["query_class"]
    if qclass_raw then
        local cid, clabel = normQclass(qclass_raw)
        if clabel then q.class    = clabel end
        if cid    then q.class_id = cid    end
    end

    -- DNS flags
    local flags_raw = (parsed and parsed.flags) or e["flags"] or e["dns_flags"]
    if flags_raw then
        q.flags = tostring(flags_raw or "")
        local flag_info = parseDnsFlags(flags_raw)
        if flag_info.is_recursive ~= nil then
            q.is_recursive = flag_info.is_recursive
        end
    end

    -- Opcode (default QUERY=0)
    local opcode_raw = e["opcode"] or e["dns_opcode"]
    if opcode_raw then
        q.opcode = tostring(opcode_raw or "")
        local op_lower = tostring(opcode_raw or ""):lower()
        if op_lower == "query"  or op_lower == "0" then q.opcode_id = 0 end
        if op_lower == "iquery" or op_lower == "1" then q.opcode_id = 1 end
        if op_lower == "status" or op_lower == "2" then q.opcode_id = 2 end
        if op_lower == "notify" or op_lower == "4" then q.opcode_id = 4 end
        if op_lower == "update" or op_lower == "5" then q.opcode_id = 5 end
    end

    if next(q) == nil then return nil end
    return q
end

--------------------------------------------------------------------------------
-- local function buildAnswers
-- Constructs OCSF answers[] from response IP / rdata fields.
-- Handles comma-separated multi-answer strings.
--------------------------------------------------------------------------------
local function buildAnswers(e, parsed)
    local answers = {}

    -- Collect rdata values
    local rdata_raw = e["response_ip"] or e["answer_ip"] or e["answer_data"]
                   or e["rdata"] or e["answers"]
    if rdata_raw == nil then return nil end

    local ttl_raw = e["ttl"] or e["answer_ttl"]
    local ttl_val = tonumber(ttl_raw)

    -- Infer answer type from query type
    local qtype_raw = (parsed and parsed.qtype) or e["qtype"] or e["query_type"]
    local _, type_label = normQtype(qtype_raw)
    local type_id
    if qtype_raw then
        type_id, type_label = normQtype(qtype_raw)
    end

    -- Class defaults to IN
    local class_id    = 1
    local class_label = "IN"

    -- Split comma-separated rdata
    local rdata_s = tostring(rdata_raw or "")
    local rdata_parts = {}
    for part in rdata_s:gmatch("[^,;%s]+") do
        local trimmed = tostring(part or ""):match("^%s*(.-)%s*$")
        if trimmed and trimmed ~= "" then
            table.insert(rdata_parts, trimmed)
        end
    end

    for _, rdata_val in ipairs(rdata_parts) do
        local ans = {
            rdata    = rdata_val,
            class_id = class_id,
            class    = class_label,
        }
        if type_label then ans.type    = type_label end
        if type_id    then ans.type_id = type_id    end
        if ttl_val    then ans.ttl     = ttl_val    end
        table.insert(answers, ans)
    end

    if #answers == 0 then return nil end
    return answers
end

--------------------------------------------------------------------------------
-- local function buildSrcEndpoint
-- Constructs OCSF src_endpoint from client IP / port fields.
--------------------------------------------------------------------------------
local function buildSrcEndpoint(e, parsed)
    local ep = {}

    local ip = (parsed and parsed.client_ip)
            or e["client_ip"] or e["src_ip"] or e["source_ip"] or e["client_address"]
    if ip then
        local clean = tostring(ip or ""):match("^%[(.+)%]$") or ip
        ep.ip = tostring(clean or "")
    end

    local port = (parsed and parsed.client_port)
              or e["client_port"] or e["src_port"] or e["source_port"]
    if port then
        local p = tonumber(port)
        if p then ep.port = p end
    end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildDstEndpoint
-- Constructs OCSF dst_endpoint from server IP / DNS resolver fields.
--------------------------------------------------------------------------------
local function buildDstEndpoint(e, parsed)
    local ep = {}

    local ip = (parsed and parsed.server_ip)
            or e["server_ip"] or e["dst_ip"] or e["destination_ip"] or e["resolver_ip"]
    if ip then
        local clean = tostring(ip or ""):match("^%[(.+)%]$") or ip
        ep.ip = tostring(clean or "")
    end

    local port = e["server_port"] or e["dst_port"]
    if port then
        local p = tonumber(port)
        if p then ep.port = p end
    end

    -- Default DNS port
    if not ep.port and ep.ip then ep.port = 53 end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildConnectionInfo
-- Constructs OCSF connection_info from protocol / flag fields.
--------------------------------------------------------------------------------
local function buildConnectionInfo(e, parsed)
    local ci = {}

    local proto_raw = e["protocol"] or e["transport"] or e["dns_transport"]
    if proto_raw then
        local p = tostring(proto_raw or ""):upper()
        if p == "TCP" or p == "T" then
            ci.protocol_name = "TCP"
        elseif p == "UDP" or p == "U" then
            ci.protocol_name = "UDP"
        else
            ci.protocol_name = p
        end
    end

    -- Infer TCP from flags
    if not ci.protocol_name and parsed and parsed.flags then
        local flag_info = parseDnsFlags(parsed.flags)
        if flag_info.is_tcp then
            ci.protocol_name = "TCP"
        end
    end

    -- Default DNS transport: UDP
    if not ci.protocol_name then ci.protocol_name = "UDP" end

    -- Protocol number
    if ci.protocol_name == "UDP" then ci.protocol_num = 17 end
    if ci.protocol_name == "TCP" then ci.protocol_num = 6  end

    if next(ci) == nil then return nil end
    return ci
end

--------------------------------------------------------------------------------
-- local function buildDevice
-- Constructs OCSF device object from Infoblox grid member / hostname fields.
--------------------------------------------------------------------------------
local function buildDevice(e)
    local dev = {}

    local name = e["hostname"] or e["host"] or e["device_name"] or e["grid_member"]
    if name then dev.name = tostring(name or "") end

    local mac = e["mac_address"] or e["mac"]
    if mac then dev.mac = tostring(mac or "") end

    local uid = e["device_id"] or e["member_id"]
    if uid then dev.uid = tostring(uid or "") end

    local os_name = e["os_name"] or e["os_type"]
    if os_name then dev.os = { name = tostring(os_name or "") } end

    if next(dev) == nil then return nil end
    return dev
end

--------------------------------------------------------------------------------
-- local function buildFirewallRule
-- Constructs OCSF firewall_rule from Infoblox RPZ rule / policy fields.
--------------------------------------------------------------------------------
local function buildFirewallRule(e, parsed)
    local fr = {}

    local rule_name = (parsed and parsed.rpz_zone)
                   or e["rpz_rule"] or e["policy_name"] or e["rpz_zone"]
                   or e["threat_rule"] or e["rule_name"]
    if rule_name then fr.name = tostring(rule_name or "") end

    local feed_uid = e["feed_name"] or e["feed_id"] or e["threat_feed"]
    if feed_uid then fr.uid = tostring(feed_uid or "") end

    local rule_type = e["rule_type"] or e["policy_type"]
    if rule_type then fr.type = tostring(rule_type or "") end

    if next(fr) == nil then return nil end
    return fr
end

--------------------------------------------------------------------------------
-- local function buildCloud
-- Constructs OCSF cloud object from Infoblox grid / site fields.
--------------------------------------------------------------------------------
local function buildCloud(e)
    local cloud = { provider = "Infoblox" }

    local grid = e["grid_name"] or e["grid"] or e["infoblox_grid"]
    if grid then
        cloud.account = { name = tostring(grid or "") }
    end

    local member = e["grid_member"] or e["member"]
    if member then
        if not cloud.account then cloud.account = {} end
        cloud.account.uid = tostring(member or "")
    end

    local site = e["site"] or e["location"] or e["region"]
    if site then cloud.region = tostring(site or "") end

    return cloud
end

--------------------------------------------------------------------------------
-- local function buildObservables
-- Constructs OCSF observables[] from key DNS indicator fields.
-- type_id: 1=Hostname, 2=IP Address, 99=Other
--------------------------------------------------------------------------------
local function buildObservables(e, parsed)
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

    -- Queried domain
    local qname = (parsed and parsed.qname)
               or e["qname"] or e["query_name"] or e["domain"]
    addObs("query.hostname", 1, qname)

    -- Client IP
    local cip = (parsed and parsed.client_ip)
             or e["client_ip"] or e["src_ip"] or e["source_ip"]
    addObs("src_endpoint.ip", 2, cip)

    -- Server IP
    local sip = (parsed and parsed.server_ip)
             or e["server_ip"] or e["dst_ip"]
    addObs("dst_endpoint.ip", 2, sip)

    -- Answer IP
    local aip = e["response_ip"] or e["answer_ip"] or e["rdata"]
    addObs("answers.rdata", 2, aip)

    -- RPZ zone
    local rpz = (parsed and parsed.rpz_zone) or e["rpz_zone"] or e["rpz_rule"]
    addObs("firewall_rule.name", 99, rpz)

    if #obs == 0 then return nil end
    return obs
end

--------------------------------------------------------------------------------
-- MAIN: processEvent
-- Entry point required by the Observo Lua transform runtime.
-- All helpers are declared as local functions ABOVE this function.
-- Handles both:
--   (A) Raw Infoblox NIOS syslog messages (named log format)
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
        -- 1. Attempt raw syslog parsing
        -----------------------------------------------------------------------
        local parsed = {}
        if FEATURES.PARSE_RAW_SYSLOG then
            local raw_msg = e["message"] or e["raw"] or e["_raw"]
                         or e["log_message"] or e["msg"] or e["syslog_message"]
            if raw_msg then
                parsed = parseRawSyslog(raw_msg)
                consumed["message"]        = true
                consumed["raw"]            = true
                consumed["_raw"]           = true
                consumed["log_message"]    = true
                consumed["msg"]            = true
                consumed["syslog_message"] = true
            end
        end

        -----------------------------------------------------------------------
        -- 2. Resolve RPZ action (from parsed or flat fields)
        -----------------------------------------------------------------------
        local rpz_action_raw = (parsed.rpz_action)
                            or e["rpz_action"] or e["action"] or e["decision"]
                            or e["dns_action"] or e["policy_action"]
        local disp_id, act_id, disp_label, act_label = normRpzAction(rpz_action_raw)

        consumed["rpz_action"]    = true
        consumed["action"]        = true
        consumed["decision"]      = true
        consumed["dns_action"]    = true
        consumed["policy_action"] = true

        -----------------------------------------------------------------------
        -- 3. Resolve rcode
        -----------------------------------------------------------------------
        local rcode_raw = (parsed.rcode)
                       or e["rcode"] or e["response_code"]
                       or e["result_code"] or e["dns_rcode"]
        local rc_id, rc_label, st_id, st_label = normRcode(rcode_raw)

        consumed["rcode"]         = true
        consumed["response_code"] = true
        consumed["result_code"]   = true
        consumed["dns_rcode"]     = true

        -----------------------------------------------------------------------
        -- 4. Resolve threat severity
        -----------------------------------------------------------------------
        local threat_raw = e["threat_level"] or e["threat_score"]
                        or e["severity"] or e["risk_level"]
        local threat_sev_id, threat_sev_label = normThreatSeverity(threat_raw)

        consumed["threat_level"] = true
        consumed["threat_score"] = true
        consumed["severity"]     = true
        consumed["risk_level"]   = true

        -----------------------------------------------------------------------
        -- 5. Resolve activity_id
        -----------------------------------------------------------------------
        local activity_id = normActivityId(e, parsed)

        -----------------------------------------------------------------------
        -- 6. Resolve final severity
        --    Priority: threat intelligence > rcode failure > default
        -----------------------------------------------------------------------
        local final_sev_id, final_sev_label
        if threat_sev_id and threat_sev_id > 1 then
            final_sev_id    = threat_sev_id
            final_sev_label = threat_sev_label
        elseif st_id == 2 then
            -- NXDOMAIN / REFUSED → Low
            if rc_id == 3 or rc_id == 5 then
                final_sev_id    = 2
                final_sev_label = "Low"
            else
                final_sev_id    = 1
                final_sev_label = "Informational"
            end
        else
            final_sev_id    = 1
            final_sev_label = "Informational"
        end

        -----------------------------------------------------------------------
        -- 7. Seed OCSF skeleton with required constant fields
        -----------------------------------------------------------------------
        local ocsf = {
            class_uid     = 4003,
            class_name    = "DNS Activity",
            category_uid  = 4,
            category_name = "Network Activity",
            activity_id   = activity_id,
            activity_name = ACTIVITY_NAMES[activity_id] or "Query",
            type_uid      = 4003 * 100 + activity_id,
            type_name     = "DNS Activity: " .. (ACTIVITY_NAMES[activity_id] or "Query"),
            severity_id   = final_sev_id,
            severity      = final_sev_label,
            -- Required: action_id defaults to 1 (Allowed) for DNS queries
            action_id     = act_id or 1,
            action        = act_label or "Allowed",
            metadata = {
                version = "1.3.0",
                product = {
                    vendor_name = "Infoblox",
                    name        = "NIOS",
                    feature     = { name = "DNS" },
                },
            },
            osint    = {},
            unmapped = {},
        }

        -----------------------------------------------------------------------
        -- 8. Apply FIELD_MAP: scalar source field → OCSF destination path
        -----------------------------------------------------------------------
        for src_field, dest_path in pairs(FIELD_MAP) do
            local val = e[src_field]
            if val ~= nil and val ~= "" then
                if dest_path == "time"          or
                   dest_path == "query_time"    or
                   dest_path == "response_time" then
                    val = toEpochMs(val)
                end
                if val ~= nil then
                    deepSet(ocsf, dest_path, val)
                    consumed[src_field] = true
                end
            end
        end

        -----------------------------------------------------------------------
        -- 9. Resolve time with fallback chain
        -----------------------------------------------------------------------
        if ocsf.time == nil then
            local fallbacks = { "time", "timestamp", "_time", "event_time" }
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
        -- 10. Apply rcode fields
        -----------------------------------------------------------------------
        if rc_id    then ocsf.rcode_id = rc_id    end
        if rc_label then ocsf.rcode    = rc_label  end
        if st_id    then ocsf.status_id = st_id    end
        if st_label then ocsf.status    = st_label  end

        -- status_code from raw rcode string
        if rcode_raw then
            ocsf.status_code = tostring(rcode_raw or "")
        end

        -----------------------------------------------------------------------
        -- 11. Apply disposition from RPZ action
        -----------------------------------------------------------------------
        if disp_id    then ocsf.disposition_id = disp_id    end
        if disp_label then ocsf.disposition    = disp_label  end

        -----------------------------------------------------------------------
        -- 12. status_detail from threat intelligence fields
        -----------------------------------------------------------------------
        local threat_class = e["threat_class"] or e["threat_property"]
                          or e["threat_indicator"] or e["category"]
                          or e["threat_category"]
        if threat_class then
            ocsf.status_detail = tostring(threat_class or "")
            consumed["threat_class"]     = true
            consumed["threat_property"]  = true
            consumed["threat_indicator"] = true
            consumed["category"]         = true
            consumed["threat_category"]  = true
        end

        -----------------------------------------------------------------------
        -- 13. query object (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_QUERY then
            local q = buildQuery(e, parsed)
            if q then
                ocsf.query = q
            end
            consumed["qname"]        = true
            consumed["query_name"]   = true
            consumed["domain"]       = true
            consumed["domain_name"]  = true
            consumed["fqdn"]         = true
            consumed["qtype"]        = true
            consumed["query_type"]   = true
            consumed["record_type"]  = true
            consumed["qclass"]       = true
            consumed["query_class"]  = true
            consumed["flags"]        = true
            consumed["dns_flags"]    = true
            consumed["opcode"]       = true
            consumed["dns_opcode"]   = true
        end

        -----------------------------------------------------------------------
        -- 14. answers[] (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_ANSWERS then
            local ans = buildAnswers(e, parsed)
            if ans then ocsf.answers = ans end
            consumed["response_ip"]  = true
            consumed["answer_ip"]    = true
            consumed["answer_data"]  = true
            consumed["rdata"]        = true
            consumed["answers"]      = true
            consumed["ttl"]          = true
            consumed["answer_ttl"]   = true
        end

        -----------------------------------------------------------------------
        -- 15. src_endpoint (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SRC_ENDPOINT then
            local ep = buildSrcEndpoint(e, parsed)
            if ep then ocsf.src_endpoint = ep end
            consumed["client_ip"]      = true
            consumed["src_ip"]         = true
            consumed["source_ip"]      = true
            consumed["client_address"] = true
            consumed["client_port"]    = true
            consumed["src_port"]       = true
            consumed["source_port"]    = true
        end

        -----------------------------------------------------------------------
        -- 16. dst_endpoint (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_DST_ENDPOINT then
            local ep = buildDstEndpoint(e, parsed)
            if ep then ocsf.dst_endpoint = ep end
            consumed["server_ip"]      = true
            consumed["dst_ip"]         = true
            consumed["destination_ip"] = true
            consumed["resolver_ip"]    = true
            consumed["server_port"]    = true
            consumed["dst_port"]       = true
        end

        -----------------------------------------------------------------------
        -- 17. connection_info (optional)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CONNECTION then
            local ci = buildConnectionInfo(e, parsed)
            if ci then ocsf.connection_info = ci end
            consumed["protocol"]     = true
            consumed["transport"]    = true
            consumed["dns_transport"] = true
        end

        -----------------------------------------------------------------------
        -- 18. device (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_DEVICE then
            local dev = buildDevice(e)
            if dev then ocsf.device = dev end
            consumed["hostname"]    = true
            consumed["host"]        = true
            consumed["device_name"] = true
            consumed["mac_address"] = true
            consumed["mac"]         = true
            consumed["device_id"]   = true
            consumed["member_id"]   = true
            consumed["os_name"]     = true
            consumed["os_type"]     = true
        end

        -----------------------------------------------------------------------
        -- 19. firewall_rule (optional)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_FIREWALL_RULE then
            local fr = buildFirewallRule(e, parsed)
            if fr then ocsf.firewall_rule = fr end
            consumed["rpz_rule"]    = true
            consumed["policy_name"] = true
            consumed["rpz_zone"]    = true
            consumed["feed_name"]   = true
            consumed["threat_rule"] = true
            consumed["rule_name"]   = true
            consumed["feed_id"]     = true
            consumed["threat_feed"] = true
            consumed["rule_type"]   = true
            consumed["policy_type"] = true
        end

        -----------------------------------------------------------------------
        -- 20. cloud (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CLOUD then
            ocsf.cloud = buildCloud(e)
            consumed["grid_name"]   = true
            consumed["grid"]        = true
            consumed["grid_member"] = true
            consumed["member"]      = true
            consumed["site"]        = true
            consumed["location"]    = true
            consumed["region"]      = true
        end

        -----------------------------------------------------------------------
        -- 21. observables (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_OBSERVABLES then
            local obs = buildObservables(e, parsed)
            if obs then ocsf.observables = obs end
        end

        -----------------------------------------------------------------------
        -- 22. duration / latency
        -----------------------------------------------------------------------
        local lat = tonumber(e["latency"] or e["response_time_ms"] or e["duration"])
        if lat then
            ocsf.duration = lat
            consumed["latency"]           = true
            consumed["response_time_ms"]  = true
            consumed["duration"]          = true
        end

        -----------------------------------------------------------------------
        -- 23. metadata enrichment: dns_view / process_id
        -----------------------------------------------------------------------
        local dns_view = e["dns_view"] or e["view"]
        if dns_view then
            deepSet(ocsf, "metadata.product.feature.name", tostring(dns_view or ""))
            consumed["dns_view"] = true
            consumed["view"]     = true
        end

        local pid = e["process_id"] or e["pid"]
        if pid then
            deepSet(ocsf, "metadata.uid", tostring(pid or ""))
            consumed["process_id"] = true
            consumed["pid"]        = true
        end

        -----------------------------------------------------------------------
        -- 24. raw_data
        -----------------------------------------------------------------------
        if FEATURES.PRESERVE_RAW then
            local ok_enc, raw_str = pcall(json.encode, e)
            if ok_enc and raw_str then
                ocsf.raw_data = raw_str
            end
        end

        -----------------------------------------------------------------------
        -- 25. Collect remaining unmapped fields
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
        -- 26. Strip empty strings / empty tables
        -----------------------------------------------------------------------
        if FEATURES.STRIP_EMPTY then
            stripEmpty(ocsf)
        end

        -----------------------------------------------------------------------
        -- 27. Compose human-readable message (table.concat, no .. in loop)
        -----------------------------------------------------------------------
        local msg_parts = {}

        local qname_lbl   = deepGet(ocsf, "query.hostname")
        local qtype_lbl   = deepGet(ocsf, "query.type")
        local src_ip_lbl  = deepGet(ocsf, "src_endpoint.ip")
        local rcode_lbl   = ocsf.rcode
        local action_lbl  = ocsf.action
        local disp_lbl    = ocsf.disposition
        local sev_lbl     = ocsf.severity

        table.insert(msg_parts, "Infoblox DNS:")
        if qname_lbl  then table.insert(msg_parts, "query="  .. tostring(qname_lbl  or "")) end
        if qtype_lbl  then table.insert(msg_parts, "type="   .. tostring(qtype_lbl  or "")) end
        if src_ip_lbl then table.insert(msg_parts, "client=" .. tostring(src_ip_lbl or "")) end
        if rcode_lbl  then table.insert(msg_parts, "rcode="  .. tostring(rcode_lbl  or "")) end
        if disp_lbl   then table.insert(msg_parts, "disp="   .. tostring(disp_lbl   or "")) end
        if action_lbl then table.insert(msg_parts, "action=" .. tostring(action_lbl or "")) end
        if sev_lbl and sev_lbl ~= "Informational" then
            table.insert(msg_parts, "severity=" .. tostring(sev_lbl or ""))
        end

        ocsf.message = table.concat(msg_parts, " ")

        -----------------------------------------------------------------------
        -- 28. Encode final OCSF event as raw JSON into message field
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
        event["_ocsf_serializer"]   = "infoblox_dns_activity"
        event["_ocsf_parse_failed"] = "true"
        return event
    end

end -- end processEvent()
