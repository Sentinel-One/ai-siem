--------------------------------------------------------------------------------
-- Azure NSG Flow Logs → OCSF 1.3.0 Network Activity (class_uid = 4001)
-- Observo processEvent(event) contract
-- Author: Observo AI  |  Schema: OCSF 1.3.0  |  Class: Network Activity (4001)
-- Covers: NSG Flow Log v1 & v2 (nested JSON) + pre-parsed flat records
-- Flow Tuple v2: ts,src_ip,dst_ip,src_port,dst_port,proto,dir,action,
--                flow_state,pkts_sent,bytes_sent,pkts_recv,bytes_recv
-- Flow Tuple v1: ts,src_ip,dst_ip,src_port,dst_port,proto,dir,action
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
    ENRICH_SRC_ENDPOINT   = true,   -- build src_endpoint from tuple / flat fields
    ENRICH_DST_ENDPOINT   = true,   -- build dst_endpoint from tuple / flat fields
    ENRICH_CONNECTION     = true,   -- build connection_info from protocol / direction
    ENRICH_TRAFFIC        = true,   -- build traffic from byte/packet counters
    ENRICH_CLOUD          = true,   -- build cloud from resourceId / subscriptionId
    ENRICH_DEVICE         = true,   -- build device from macAddress / NSG resource
    ENRICH_FIREWALL_RULE  = true,   -- build firewall_rule from rule name
    ENRICH_OBSERVABLES    = true,   -- build observables[] from IPs / ports
    PARSE_NESTED_NSG      = true,   -- attempt to parse raw nested NSG JSON structure
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
    "action",
    "action_id",
    "disposition",
    "disposition_id",
    "message",
    "metadata",
    "src_endpoint",
    "dst_endpoint",
    "connection_info",
    "traffic",
    "firewall_rule",
    "device",
    "cloud",
    "observables",
    "osint",
    "raw_data",
    "unmapped",
}

--------------------------------------------------------------------------------
-- PROTOCOL_MAP: NSG protocol code → OCSF protocol name
-- NSG codes: T=TCP, U=UDP, *=Any/Other
--------------------------------------------------------------------------------
local PROTOCOL_MAP = {
    ["T"]   = "TCP",
    ["t"]   = "TCP",
    ["tcp"] = "TCP",
    ["U"]   = "UDP",
    ["u"]   = "UDP",
    ["udp"] = "UDP",
    ["I"]   = "ICMP",
    ["i"]   = "ICMP",
    ["icmp"] = "ICMP",
    ["6"]   = "TCP",
    ["17"]  = "UDP",
    ["1"]   = "ICMP",
}

--------------------------------------------------------------------------------
-- ACTION_MAP: NSG action code → OCSF {action_id, disposition_id, status_id,
--             status_label, action_label, severity_id, severity_label}
-- NSG: A=Allow, D=Deny
-- OCSF action_id: 1=Allowed, 2=Denied
-- OCSF disposition_id: 1=Allowed, 2=Blocked
-- OCSF status_id: 1=Success, 2=Failure
--------------------------------------------------------------------------------
local ACTION_MAP = {
    ["A"]      = { action_id = 1, disposition_id = 1, status_id = 1,
                   status_label = "Success", action_label = "Allowed",
                   disposition_label = "Allowed",
                   severity_id = 1, severity_label = "Informational" },
    ["a"]      = { action_id = 1, disposition_id = 1, status_id = 1,
                   status_label = "Success", action_label = "Allowed",
                   disposition_label = "Allowed",
                   severity_id = 1, severity_label = "Informational" },
    allow      = { action_id = 1, disposition_id = 1, status_id = 1,
                   status_label = "Success", action_label = "Allowed",
                   disposition_label = "Allowed",
                   severity_id = 1, severity_label = "Informational" },
    allowed    = { action_id = 1, disposition_id = 1, status_id = 1,
                   status_label = "Success", action_label = "Allowed",
                   disposition_label = "Allowed",
                   severity_id = 1, severity_label = "Informational" },
    permit     = { action_id = 1, disposition_id = 1, status_id = 1,
                   status_label = "Success", action_label = "Allowed",
                   disposition_label = "Allowed",
                   severity_id = 1, severity_label = "Informational" },
    ["D"]      = { action_id = 2, disposition_id = 2, status_id = 2,
                   status_label = "Failure", action_label = "Denied",
                   disposition_label = "Blocked",
                   severity_id = 2, severity_label = "Low" },
    ["d"]      = { action_id = 2, disposition_id = 2, status_id = 2,
                   status_label = "Failure", action_label = "Denied",
                   disposition_label = "Blocked",
                   severity_id = 2, severity_label = "Low" },
    deny       = { action_id = 2, disposition_id = 2, status_id = 2,
                   status_label = "Failure", action_label = "Denied",
                   disposition_label = "Blocked",
                   severity_id = 2, severity_label = "Low" },
    denied     = { action_id = 2, disposition_id = 2, status_id = 2,
                   status_label = "Failure", action_label = "Denied",
                   disposition_label = "Blocked",
                   severity_id = 2, severity_label = "Low" },
    block      = { action_id = 2, disposition_id = 2, status_id = 2,
                   status_label = "Failure", action_label = "Denied",
                   disposition_label = "Blocked",
                   severity_id = 2, severity_label = "Low" },
    blocked    = { action_id = 2, disposition_id = 2, status_id = 2,
                   status_label = "Failure", action_label = "Denied",
                   disposition_label = "Blocked",
                   severity_id = 2, severity_label = "Low" },
    drop       = { action_id = 2, disposition_id = 2, status_id = 2,
                   status_label = "Failure", action_label = "Denied",
                   disposition_label = "Blocked",
                   severity_id = 2, severity_label = "Low" },
}

--------------------------------------------------------------------------------
-- FLOW_STATE_MAP: NSG flow state code → OCSF activity_id
-- NSG v2: B=Begin, C=Continue, E=End
-- OCSF activity_id: 1=Open, 2=Close, 6=Traffic
--------------------------------------------------------------------------------
local FLOW_STATE_MAP = {
    ["B"] = 1,   -- Begin  → Open
    ["b"] = 1,
    begin  = 1,
    start  = 1,
    ["C"] = 6,   -- Continue → Traffic
    ["c"] = 6,
    continue = 6,
    ["E"] = 2,   -- End → Close
    ["e"] = 2,
    ["end"] = 2,
    finish  = 2,
    close   = 2,
}

--------------------------------------------------------------------------------
-- DIRECTION_ACTIVITY_MAP: NSG direction + action → OCSF activity_id
-- OCSF: 1=Open, 2=Close, 3=Reset, 4=Fail, 5=Refuse, 6=Traffic, 7=Listen
--------------------------------------------------------------------------------
local DIRECTION_ACTIVITY_MAP = {
    I_A = 1,   -- Inbound  + Allow → Open
    I_D = 5,   -- Inbound  + Deny  → Refuse
    O_A = 6,   -- Outbound + Allow → Traffic
    O_D = 4,   -- Outbound + Deny  → Fail
}

--------------------------------------------------------------------------------
-- ACTIVITY_NAMES: activity_id → caption
--------------------------------------------------------------------------------
local ACTIVITY_NAMES = {
    [0]  = "Open",      -- maps 0 to Open as safe default
    [1]  = "Open",
    [2]  = "Close",
    [3]  = "Reset",
    [4]  = "Fail",
    [5]  = "Refuse",
    [6]  = "Traffic",
    [7]  = "Listen",
    [99] = "Other",
}

--------------------------------------------------------------------------------
-- FIELD_MAP: flat/pre-parsed NSG source field → OCSF destination dot-path
-- Used when the pipeline has already extracted individual flow tuple fields.
--------------------------------------------------------------------------------
local FIELD_MAP = {
    -- Timing
    ["time"]                    = "time",
    ["timestamp"]               = "time",
    ["_time"]                   = "time",
    ["flowTimestamp"]           = "time",
    ["flow_timestamp"]          = "time",

    -- Metadata
    ["systemId"]                = "metadata.uid",
    ["system_id"]               = "metadata.uid",
    ["operationName"]           = "metadata.product.feature.name",
    ["operation_name"]          = "metadata.product.feature.name",
    ["category"]                = "metadata.product.feature.name",

    -- Source endpoint (flat)
    ["src_ip"]                  = "src_endpoint.ip",
    ["sourceAddress"]           = "src_endpoint.ip",
    ["SourceAddress"]           = "src_endpoint.ip",
    ["source_ip"]               = "src_endpoint.ip",
    ["src_port"]                = "src_endpoint.port",
    ["sourcePort"]              = "src_endpoint.port",
    ["SourcePort"]              = "src_endpoint.port",
    ["source_port"]             = "src_endpoint.port",

    -- Destination endpoint (flat)
    ["dst_ip"]                  = "dst_endpoint.ip",
    ["destinationAddress"]      = "dst_endpoint.ip",
    ["DestinationAddress"]      = "dst_endpoint.ip",
    ["destination_ip"]          = "dst_endpoint.ip",
    ["dst_port"]                = "dst_endpoint.port",
    ["destinationPort"]         = "dst_endpoint.port",
    ["DestinationPort"]         = "dst_endpoint.port",
    ["destination_port"]        = "dst_endpoint.port",

    -- Traffic counters (flat)
    ["packetsSent"]             = "traffic.packets_out",
    ["packets_sent"]            = "traffic.packets_out",
    ["bytesSent"]               = "traffic.bytes_out",
    ["bytes_sent"]              = "traffic.bytes_out",
    ["packetsReceived"]         = "traffic.packets_in",
    ["packets_received"]        = "traffic.packets_in",
    ["bytesReceived"]           = "traffic.bytes_in",
    ["bytes_received"]          = "traffic.bytes_in",

    -- Cloud / subscription
    ["subscriptionId"]          = "cloud.account.uid",
    ["subscription_id"]         = "cloud.account.uid",
    ["resourceGroup"]           = "cloud.region",
    ["resource_group"]          = "cloud.region",
    ["location"]                = "cloud.zone",

    -- Device / NSG
    ["macAddress"]              = "device.mac",
    ["mac_address"]             = "device.mac",
    ["mac"]                     = "device.mac",
    ["nsgName"]                 = "device.name",
    ["nsg_name"]                = "device.name",
    ["nsgId"]                   = "device.uid",
    ["nsg_id"]                  = "device.uid",

    -- Firewall rule
    ["ruleName"]                = "firewall_rule.name",
    ["rule_name"]               = "firewall_rule.name",
    ["rule"]                    = "firewall_rule.name",
    ["nsgRuleName"]             = "firewall_rule.name",
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
        "action_id", "disposition_id", "duration",
        "packets_in", "packets_out", "bytes_in", "bytes_out",
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
-- Normalises Azure timestamp variants to epoch milliseconds (integer).
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
-- local function parseResourceId
-- Parses an Azure resourceId string into component parts.
-- Format: /SUBSCRIPTIONS/{sub}/RESOURCEGROUPS/{rg}/PROVIDERS/.../{nsgName}
-- Returns: { subscription_id, resource_group, nsg_name, full_id }
--------------------------------------------------------------------------------
local function parseResourceId(resource_id)
    if resource_id == nil then return nil end
    local rid = tostring(resource_id or ""):upper()

    local sub_id = tostring(resource_id or ""):match("[Ss][Uu][Bb][Ss][Cc][Rr][Ii][Pp][Tt][Ii][Oo][Nn][Ss]/([^/]+)")
    local rg     = tostring(resource_id or ""):match("[Rr][Ee][Ss][Oo][Uu][Rr][Cc][Ee][Gg][Rr][Oo][Uu][Pp][Ss]/([^/]+)")
    local nsg    = tostring(resource_id or ""):match("[Nn][Ee][Tt][Ww][Oo][Rr][Kk][Ss][Ee][Cc][Uu][Rr][Ii][Tt][Yy][Gg][Rr][Oo][Uu][Pp][Ss]/([^/]+)")

    return {
        subscription_id = sub_id,
        resource_group  = rg,
        nsg_name        = nsg,
        full_id         = resource_id,
    }
end

--------------------------------------------------------------------------------
-- local function normProtocol
-- Maps NSG protocol code → OCSF protocol name string.
-- Returns nil when input is absent.
--------------------------------------------------------------------------------
local function normProtocol(val)
    if val == nil then return nil end
    local key = tostring(val or ""):lower()
    -- Direct lookup (handles T, U, tcp, udp, etc.)
    local mapped = PROTOCOL_MAP[tostring(val or "")]
                or PROTOCOL_MAP[key]
    if mapped then return mapped end
    -- Pass through if already a recognisable name
    if key == "tcp" or key == "udp" or key == "icmp" then
        return tostring(val or ""):upper()
    end
    return nil
end

--------------------------------------------------------------------------------
-- local function normAction
-- Maps NSG action code → OCSF action entry table.
-- Returns nil when input is absent.
--------------------------------------------------------------------------------
local function normAction(val)
    if val == nil then return nil end
    local key_raw = tostring(val or "")
    local key_low = tostring(val or ""):lower()
    return ACTION_MAP[key_raw] or ACTION_MAP[key_low]
end

--------------------------------------------------------------------------------
-- local function normActivityId
-- Derives OCSF activity_id from NSG direction, action, and flow_state.
-- Priority: flow_state (most specific) > direction+action > default Traffic
--------------------------------------------------------------------------------
local function normActivityId(direction, action, flow_state)
    -- Flow state takes priority (v2 logs)
    if flow_state ~= nil then
        local fs_key = tostring(flow_state or ""):lower()
        local fs_id  = FLOW_STATE_MAP[tostring(flow_state or "")]
                    or FLOW_STATE_MAP[fs_key]
        if fs_id then return fs_id end
    end

    -- Direction + action composite key
    if direction ~= nil and action ~= nil then
        local dir_up  = tostring(direction or ""):upper()
        local act_up  = tostring(action    or ""):upper()
        -- Normalise direction: Inbound→I, Outbound→O
        local dir_code
        if dir_up == "I" or dir_up == "INBOUND" or dir_up == "IN" then
            dir_code = "I"
        elseif dir_up == "O" or dir_up == "OUTBOUND" or dir_up == "OUT" then
            dir_code = "O"
        end
        -- Normalise action: Allow→A, Deny→D
        local act_code
        if act_up == "A" or act_up == "ALLOW" or act_up == "ALLOWED" or act_up == "PERMIT" then
            act_code = "A"
        elseif act_up == "D" or act_up == "DENY" or act_up == "DENIED" or act_up == "BLOCK" or act_up == "BLOCKED" then
            act_code = "D"
        end
        if dir_code and act_code then
            local composite = dir_code .. "_" .. act_code
            local id = DIRECTION_ACTIVITY_MAP[composite]
            if id then return id end
        end
    end

    -- Default: Traffic (most common NSG flow state)
    return 6
end

--------------------------------------------------------------------------------
-- local function parseFlowTuple
-- Parses a comma-separated NSG flow tuple string into a structured table.
-- v1 (8 fields):  ts,src_ip,dst_ip,src_port,dst_port,proto,dir,action
-- v2 (13 fields): ts,src_ip,dst_ip,src_port,dst_port,proto,dir,action,
--                 flow_state,pkts_sent,bytes_sent,pkts_recv,bytes_recv
-- Returns nil if the string is malformed.
--------------------------------------------------------------------------------
local function parseFlowTuple(tuple_str)
    if tuple_str == nil then return nil end
    local s = tostring(tuple_str or "")
    if s == "" then return nil end

    local fields = {}
    for field in s:gmatch("[^,]+") do
        table.insert(fields, field)
    end

    if #fields < 8 then return nil end

    local t = {
        ts           = fields[1],
        src_ip       = fields[2],
        dst_ip       = fields[3],
        src_port     = fields[4],
        dst_port     = fields[5],
        protocol     = fields[6],
        direction    = fields[7],
        action       = fields[8],
        -- v2 fields
        flow_state   = fields[9],
        pkts_sent    = fields[10],
        bytes_sent   = fields[11],
        pkts_recv    = fields[12],
        bytes_recv   = fields[13],
        version      = (#fields >= 13) and 2 or 1,
    }

    return t
end

--------------------------------------------------------------------------------
-- local function extractFirstTuple
-- Walks the raw nested NSG JSON structure to find the first flow tuple.
-- Returns: rule_name (string), mac (string), tuple_str (string)
--          or nil, nil, nil if not found.
-- Structure: properties.flows[].rule
--            properties.flows[].flows[].mac
--            properties.flows[].flows[].flowTuples[]
--------------------------------------------------------------------------------
local function extractFirstTuple(e)
    local props = e["properties"]
    if type(props) ~= "table" then return nil, nil, nil end

    local flows_outer = props["flows"]
    if type(flows_outer) ~= "table" or #flows_outer == 0 then return nil, nil, nil end

    for _, rule_block in ipairs(flows_outer) do
        if type(rule_block) == "table" then
            local rule_name  = rule_block["rule"]
            local flows_inner = rule_block["flows"]
            if type(flows_inner) == "table" then
                for _, mac_block in ipairs(flows_inner) do
                    if type(mac_block) == "table" then
                        local mac         = mac_block["mac"]
                        local flow_tuples = mac_block["flowTuples"]
                        if type(flow_tuples) == "table" and #flow_tuples > 0 then
                            return rule_name, mac, flow_tuples[1]
                        end
                    end
                end
            end
        end
    end

    return nil, nil, nil
end

--------------------------------------------------------------------------------
-- local function countAllTuples
-- Counts total flow tuples across all rule/mac blocks in the nested structure.
--------------------------------------------------------------------------------
local function countAllTuples(e)
    local props = e["properties"]
    if type(props) ~= "table" then return 0 end
    local flows_outer = props["flows"]
    if type(flows_outer) ~= "table" then return 0 end

    local count = 0
    for _, rule_block in ipairs(flows_outer) do
        if type(rule_block) == "table" then
            local flows_inner = rule_block["flows"]
            if type(flows_inner) == "table" then
                for _, mac_block in ipairs(flows_inner) do
                    if type(mac_block) == "table" then
                        local ft = mac_block["flowTuples"]
                        if type(ft) == "table" then
                            count = count + #ft
                        end
                    end
                end
            end
        end
    end
    return count
end

--------------------------------------------------------------------------------
-- local function buildSrcEndpoint
-- Constructs OCSF src_endpoint from tuple fields or flat source fields.
--------------------------------------------------------------------------------
local function buildSrcEndpoint(e, tuple)
    local ep = {}

    local ip   = (tuple and tuple.src_ip)
              or e["src_ip"] or e["sourceAddress"] or e["SourceAddress"] or e["source_ip"]
    local port = (tuple and tuple.src_port)
              or e["src_port"] or e["sourcePort"] or e["SourcePort"] or e["source_port"]

    if ip   then ep.ip   = tostring(ip   or "") end
    if port then
        local p = tonumber(port)
        if p then ep.port = p end
    end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildDstEndpoint
-- Constructs OCSF dst_endpoint from tuple fields or flat destination fields.
--------------------------------------------------------------------------------
local function buildDstEndpoint(e, tuple)
    local ep = {}

    local ip   = (tuple and tuple.dst_ip)
              or e["dst_ip"] or e["destinationAddress"] or e["DestinationAddress"] or e["destination_ip"]
    local port = (tuple and tuple.dst_port)
              or e["dst_port"] or e["destinationPort"] or e["DestinationPort"] or e["destination_port"]

    if ip   then ep.ip   = tostring(ip   or "") end
    if port then
        local p = tonumber(port)
        if p then ep.port = p end
    end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildConnectionInfo
-- Constructs OCSF connection_info from protocol and direction fields.
--------------------------------------------------------------------------------
local function buildConnectionInfo(e, tuple)
    local ci = {}

    local proto_raw = (tuple and tuple.protocol)
                   or e["protocol"] or e["Protocol"] or e["transport"]
    local proto = normProtocol(proto_raw)
    if proto then ci.protocol_name = proto end

    -- Direction label
    local dir_raw = (tuple and tuple.direction)
                 or e["direction"] or e["Direction"] or e["flowDirection"]
    if dir_raw then
        local dir_up = tostring(dir_raw or ""):upper()
        if dir_up == "I" or dir_up == "INBOUND" or dir_up == "IN" then
            ci.direction    = "Inbound"
            ci.direction_id = 1
        elseif dir_up == "O" or dir_up == "OUTBOUND" or dir_up == "OUT" then
            ci.direction    = "Outbound"
            ci.direction_id = 2
        end
    end

    if next(ci) == nil then return nil end
    return ci
end

--------------------------------------------------------------------------------
-- local function buildTraffic
-- Constructs OCSF traffic object from byte/packet counters.
-- v2 tuple: pkts_sent=packets_out, bytes_sent=bytes_out,
--           pkts_recv=packets_in,  bytes_recv=bytes_in
--------------------------------------------------------------------------------
local function buildTraffic(e, tuple)
    local tr = {}

    local function setNum(field, val)
        local n = tonumber(val)
        if n then tr[field] = n end
    end

    if tuple and tuple.version == 2 then
        setNum("packets_out", tuple.pkts_sent)
        setNum("bytes_out",   tuple.bytes_sent)
        setNum("packets_in",  tuple.pkts_recv)
        setNum("bytes_in",    tuple.bytes_recv)
    end

    -- Flat field fallbacks
    if not tr.packets_out then setNum("packets_out", e["packetsSent"]    or e["packets_sent"])    end
    if not tr.bytes_out   then setNum("bytes_out",   e["bytesSent"]      or e["bytes_sent"])      end
    if not tr.packets_in  then setNum("packets_in",  e["packetsReceived"] or e["packets_received"]) end
    if not tr.bytes_in    then setNum("bytes_in",    e["bytesReceived"]  or e["bytes_received"])  end

    -- Totals
    if tr.bytes_out and tr.bytes_in then
        tr.bytes = tr.bytes_out + tr.bytes_in
    end
    if tr.packets_out and tr.packets_in then
        tr.packets = tr.packets_out + tr.packets_in
    end

    if next(tr) == nil then return nil end
    return tr
end

--------------------------------------------------------------------------------
-- local function buildCloud
-- Constructs OCSF cloud object from Azure resourceId / subscriptionId.
--------------------------------------------------------------------------------
local function buildCloud(e, resource_parts)
    local cloud = { provider = "Azure" }

    local sub_id = (resource_parts and resource_parts.subscription_id)
                or e["subscriptionId"] or e["subscription_id"]
    if sub_id then
        cloud.account = {
            uid  = tostring(sub_id or ""),
            type = "Subscription",
        }
    end

    local rg = (resource_parts and resource_parts.resource_group)
            or e["resourceGroup"] or e["resource_group"]
    if rg then cloud.region = tostring(rg or "") end

    local loc = e["location"] or e["Location"]
    if loc then cloud.zone = tostring(loc or "") end

    return cloud
end

--------------------------------------------------------------------------------
-- local function buildDevice
-- Constructs OCSF device object from NSG MAC address and resource info.
--------------------------------------------------------------------------------
local function buildDevice(e, resource_parts, mac_override)
    local dev = {}

    local mac = mac_override
             or e["macAddress"] or e["mac_address"] or e["mac"]
    if mac then dev.mac = tostring(mac or "") end

    local nsg_name = (resource_parts and resource_parts.nsg_name)
                  or e["nsgName"] or e["nsg_name"]
    if nsg_name then dev.name = tostring(nsg_name or "") end

    local nsg_id = (resource_parts and resource_parts.full_id)
                or e["nsgId"] or e["nsg_id"] or e["resourceId"] or e["resource_id"]
    if nsg_id then dev.uid = tostring(nsg_id or "") end

    -- Device type: Network Security Group (virtual appliance)
    dev.type    = "Virtual"
    dev.type_id = 9

    if next(dev) == nil then return nil end
    return dev
end

--------------------------------------------------------------------------------
-- local function buildFirewallRule
-- Constructs OCSF firewall_rule object from NSG rule name.
--------------------------------------------------------------------------------
local function buildFirewallRule(e, rule_name_override)
    local rule_name = rule_name_override
                   or e["ruleName"] or e["rule_name"] or e["rule"]
                   or e["nsgRuleName"]
    if rule_name == nil then return nil end

    local fr = { name = tostring(rule_name or "") }

    -- Infer rule type from name prefix (DefaultRule_ vs custom)
    local rn = tostring(rule_name or "")
    if rn:find("DefaultRule_", 1, true) then
        fr.type    = "Default"
        fr.type_id = 1
    elseif rn:find("UserRule_", 1, true) then
        fr.type    = "Custom"
        fr.type_id = 2
    end

    return fr
end

--------------------------------------------------------------------------------
-- local function buildObservables
-- Constructs OCSF observables[] from key network indicator fields.
-- type_id: 2=IP Address, 99=Other
--------------------------------------------------------------------------------
local function buildObservables(e, tuple)
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

    local src_ip = (tuple and tuple.src_ip)
                or e["src_ip"] or e["sourceAddress"] or e["source_ip"]
    local dst_ip = (tuple and tuple.dst_ip)
                or e["dst_ip"] or e["destinationAddress"] or e["destination_ip"]
    local src_port = (tuple and tuple.src_port)
                  or e["src_port"] or e["sourcePort"] or e["source_port"]
    local dst_port = (tuple and tuple.dst_port)
                  or e["dst_port"] or e["destinationPort"] or e["destination_port"]

    addObs("src_endpoint.ip",   2,  src_ip)
    addObs("dst_endpoint.ip",   2,  dst_ip)
    addObs("src_endpoint.port", 99, src_port)
    addObs("dst_endpoint.port", 99, dst_port)

    if #obs == 0 then return nil end
    return obs
end

--------------------------------------------------------------------------------
-- MAIN: processEvent
-- Entry point required by the Observo Lua transform runtime.
-- All helpers are declared as local functions ABOVE this function.
-- Handles both:
--   (A) Pre-parsed flat NSG flow records (individual tuple fields already extracted)
--   (B) Raw nested NSG JSON (properties.flows[].flows[].flowTuples[])
--------------------------------------------------------------------------------
function processEvent(event)

    --------------------------------------------------------------------------
    -- INNER: core transform — wrapped in pcall for pipeline safety
    --------------------------------------------------------------------------
    local function execute(e)

        -- Track consumed source keys to populate unmapped correctly
        local consumed = {}

        -----------------------------------------------------------------------
        -- 1. Detect record type and extract tuple data
        -----------------------------------------------------------------------
        local tuple        = nil
        local rule_name    = nil
        local mac_override = nil
        local is_nested    = false
        local total_tuples = 0

        -- Check for raw nested NSG structure
        if FEATURES.PARSE_NESTED_NSG and type(e["properties"]) == "table" then
            is_nested   = true
            total_tuples = countAllTuples(e)
            rule_name, mac_override, local_tuple_str = extractFirstTuple(e)
            if local_tuple_str then
                tuple = parseFlowTuple(local_tuple_str)
            end
            consumed["properties"] = true
        end

        -- Check for pre-parsed flat tuple string
        if tuple == nil then
            local tuple_str = e["flowTuple"] or e["flow_tuple"] or e["tuple"]
            if tuple_str then
                tuple = parseFlowTuple(tostring(tuple_str or ""))
                consumed["flowTuple"]  = true
                consumed["flow_tuple"] = true
                consumed["tuple"]      = true
            end
        end

        -- Rule name from flat field if not from nested
        if rule_name == nil then
            rule_name = e["ruleName"] or e["rule_name"] or e["rule"] or e["nsgRuleName"]
        end

        -----------------------------------------------------------------------
        -- 2. Resolve action from tuple or flat fields
        -----------------------------------------------------------------------
        local action_raw = (tuple and tuple.action)
                        or e["action"] or e["Action"] or e["Decision"]
                        or e["decision"] or e["flowAction"]
        local action_entry = normAction(action_raw)

        -----------------------------------------------------------------------
        -- 3. Resolve direction and flow_state
        -----------------------------------------------------------------------
        local direction_raw = (tuple and tuple.direction)
                           or e["direction"] or e["Direction"] or e["flowDirection"]
        local flow_state_raw = (tuple and tuple.flow_state)
                            or e["flowState"] or e["flow_state"] or e["FlowState"]

        -----------------------------------------------------------------------
        -- 4. Resolve activity_id
        -----------------------------------------------------------------------
        local activity_id = normActivityId(direction_raw, action_raw, flow_state_raw)

        -----------------------------------------------------------------------
        -- 5. Seed OCSF skeleton with required constant fields
        -----------------------------------------------------------------------
        local ocsf = {
            class_uid     = 4001,
            class_name    = "Network Activity",
            category_uid  = 4,
            category_name = "Network Activity",
            activity_id   = activity_id,
            activity_name = ACTIVITY_NAMES[activity_id] or "Traffic",
            type_uid      = 4001 * 100 + activity_id,
            type_name     = "Network Activity: " .. (ACTIVITY_NAMES[activity_id] or "Traffic"),
            severity_id   = 1,
            severity      = "Informational",
            -- Required: action_id defaults to 0 (resolved below)
            action_id     = 0,
            metadata = {
                version = "1.3.0",
                product = {
                    vendor_name = "Microsoft",
                    name        = "Azure Network Security Group",
                    feature     = { name = "NSG Flow Logs" },
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
        -- 7. Resolve time: tuple timestamp (most precise) → outer event time
        -----------------------------------------------------------------------
        if tuple and tuple.ts then
            local ts_ms = toEpochMs(tuple.ts)
            if ts_ms then ocsf.time = ts_ms end
        end
        if ocsf.time == nil then
            local fallbacks = { "time", "timestamp", "_time" }
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
        -- 8. Apply action entry: action_id, disposition_id, status, severity
        -----------------------------------------------------------------------
        if action_entry then
            ocsf.action_id      = action_entry.action_id
            ocsf.action         = action_entry.action_label
            ocsf.disposition_id = action_entry.disposition_id
            ocsf.disposition    = action_entry.disposition_label
            ocsf.status_id      = action_entry.status_id
            ocsf.status         = action_entry.status_label
            ocsf.severity_id    = action_entry.severity_id
            ocsf.severity       = action_entry.severity_label
        end

        consumed["action"]      = true
        consumed["Action"]      = true
        consumed["Decision"]    = true
        consumed["decision"]    = true
        consumed["flowAction"]  = true
        consumed["direction"]   = true
        consumed["Direction"]   = true
        consumed["flowDirection"] = true
        consumed["flowState"]   = true
        consumed["flow_state"]  = true
        consumed["FlowState"]   = true

        -----------------------------------------------------------------------
        -- 9. src_endpoint (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SRC_ENDPOINT then
            local ep = buildSrcEndpoint(e, tuple)
            if ep then ocsf.src_endpoint = ep end
            consumed["src_ip"]        = true
            consumed["sourceAddress"] = true
            consumed["SourceAddress"] = true
            consumed["source_ip"]     = true
            consumed["src_port"]      = true
            consumed["sourcePort"]    = true
            consumed["SourcePort"]    = true
            consumed["source_port"]   = true
        end

        -----------------------------------------------------------------------
        -- 10. dst_endpoint (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_DST_ENDPOINT then
            local ep = buildDstEndpoint(e, tuple)
            if ep then
                ocsf.dst_endpoint = ep
            else
                ocsf.dst_endpoint = {}
            end
            consumed["dst_ip"]             = true
            consumed["destinationAddress"] = true
            consumed["DestinationAddress"] = true
            consumed["destination_ip"]     = true
            consumed["dst_port"]           = true
            consumed["destinationPort"]    = true
            consumed["DestinationPort"]    = true
            consumed["destination_port"]   = true
        end

        -----------------------------------------------------------------------
        -- 11. connection_info (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CONNECTION then
            local ci = buildConnectionInfo(e, tuple)
            if ci then ocsf.connection_info = ci end
            consumed["protocol"]      = true
            consumed["Protocol"]      = true
            consumed["transport"]     = true
        end

        -----------------------------------------------------------------------
        -- 12. traffic (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_TRAFFIC then
            local tr = buildTraffic(e, tuple)
            if tr then ocsf.traffic = tr end
            consumed["packetsSent"]      = true
            consumed["packets_sent"]     = true
            consumed["bytesSent"]        = true
            consumed["bytes_sent"]       = true
            consumed["packetsReceived"]  = true
            consumed["packets_received"] = true
            consumed["bytesReceived"]    = true
            consumed["bytes_received"]   = true
        end

        -----------------------------------------------------------------------
        -- 13. cloud (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CLOUD then
            local resource_id  = e["resourceId"] or e["resource_id"]
            local res_parts    = parseResourceId(resource_id)
            ocsf.cloud         = buildCloud(e, res_parts)
            consumed["resourceId"]      = true
            consumed["resource_id"]     = true
            consumed["subscriptionId"]  = true
            consumed["subscription_id"] = true
            consumed["resourceGroup"]   = true
            consumed["resource_group"]  = true
            consumed["location"]        = true
            consumed["Location"]        = true

            -----------------------------------------------------------------------
            -- 14. device (recommended) — shares resource_parts
            -----------------------------------------------------------------------
            if FEATURES.ENRICH_DEVICE then
                local dev = buildDevice(e, res_parts, mac_override)
                if dev then ocsf.device = dev end
                consumed["macAddress"]  = true
                consumed["mac_address"] = true
                consumed["mac"]         = true
                consumed["nsgName"]     = true
                consumed["nsg_name"]    = true
                consumed["nsgId"]       = true
                consumed["nsg_id"]      = true
            end
        end

        -----------------------------------------------------------------------
        -- 15. firewall_rule (optional)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_FIREWALL_RULE then
            local fr = buildFirewallRule(e, rule_name)
            if fr then ocsf.firewall_rule = fr end
            consumed["ruleName"]    = true
            consumed["rule_name"]   = true
            consumed["rule"]        = true
            consumed["nsgRuleName"] = true
        end

        -----------------------------------------------------------------------
        -- 16. observables (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_OBSERVABLES then
            local obs = buildObservables(e, tuple)
            if obs then ocsf.observables = obs end
        end

        -----------------------------------------------------------------------
        -- 17. NSG version from properties
        -----------------------------------------------------------------------
        if is_nested then
            local props = e["properties"]
            if type(props) == "table" then
                local ver = props["Version"]
                if ver then
                    deepSet(ocsf, "metadata.product.version", tostring(ver or ""))
                end
            end
        end

        -----------------------------------------------------------------------
        -- 18. Annotate if multiple tuples were present in raw nested log
        -----------------------------------------------------------------------
        if is_nested and total_tuples > 1 then
            ocsf.unmapped["_nsg_total_tuples"]    = total_tuples
            ocsf.unmapped["_nsg_tuples_note"]     = "Only first tuple serialized; remaining tuples require pipeline fan-out"
        end

        -----------------------------------------------------------------------
        -- 19. systemId → metadata.uid
        -----------------------------------------------------------------------
        local sys_id = e["systemId"] or e["system_id"]
        if sys_id then
            deepSet(ocsf, "metadata.uid", tostring(sys_id or ""))
            consumed["systemId"]   = true
            consumed["system_id"]  = true
        end

        -----------------------------------------------------------------------
        -- 20. operationName / category → metadata.product.feature.name
        -----------------------------------------------------------------------
        local op_name = e["operationName"] or e["operation_name"]
        if op_name then
            deepSet(ocsf, "metadata.product.feature.name", tostring(op_name or ""))
            consumed["operationName"]  = true
            consumed["operation_name"] = true
        end
        local cat = e["category"]
        if cat then
            consumed["category"] = true
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
        -- 22. Collect remaining unmapped fields
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
        -- 23. Strip empty strings / empty tables
        -----------------------------------------------------------------------
        if FEATURES.STRIP_EMPTY then
            stripEmpty(ocsf)
        end

        -----------------------------------------------------------------------
        -- 24. Compose human-readable message (table.concat, no .. in loop)
        -----------------------------------------------------------------------
        local msg_parts = {}

        local src_ip_lbl  = deepGet(ocsf, "src_endpoint.ip")
        local dst_ip_lbl  = deepGet(ocsf, "dst_endpoint.ip")
        local src_prt_lbl = deepGet(ocsf, "src_endpoint.port")
        local dst_prt_lbl = deepGet(ocsf, "dst_endpoint.port")
        local proto_lbl   = deepGet(ocsf, "connection_info.protocol_name")
        local dir_lbl     = deepGet(ocsf, "connection_info.direction")
        local action_lbl  = ocsf.action
        local rule_lbl    = deepGet(ocsf, "firewall_rule.name")

        table.insert(msg_parts, "Azure NSG Flow:")
        if proto_lbl  then table.insert(msg_parts, "proto="  .. tostring(proto_lbl  or "")) end
        if dir_lbl    then table.insert(msg_parts, "dir="    .. tostring(dir_lbl    or "")) end
        if src_ip_lbl then table.insert(msg_parts, "src="    .. tostring(src_ip_lbl or "")) end
        if src_prt_lbl then table.insert(msg_parts, "sport=" .. tostring(src_prt_lbl or "")) end
        if dst_ip_lbl then table.insert(msg_parts, "dst="    .. tostring(dst_ip_lbl or "")) end
        if dst_prt_lbl then table.insert(msg_parts, "dport=" .. tostring(dst_prt_lbl or "")) end
        if action_lbl then table.insert(msg_parts, "action=" .. tostring(action_lbl or "")) end
        if rule_lbl   then table.insert(msg_parts, "rule="   .. tostring(rule_lbl   or "")) end

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
        event["_ocsf_serializer"]   = "azure_nsg_flow_network_activity"
        event["_ocsf_parse_failed"] = "true"
        return event
    end

end -- end processEvent()
