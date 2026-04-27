--------------------------------------------------------------------------------
-- GCP VPC Flow Logs → OCSF 1.3.0 Network Activity (class_uid = 4001)
-- Observo processEvent(event) contract
-- Author: Observo AI  |  Schema: OCSF 1.3.0  |  Class: Network Activity (4001)
-- Covers: Cloud Logging nested JSON (jsonPayload + resource.labels) and
--         pre-parsed flat records exported via Pub/Sub or Log Sink
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
    PARSE_NESTED_GCP      = true,   -- unwrap jsonPayload + resource.labels
    ENRICH_SRC_ENDPOINT   = true,   -- build src_endpoint from connection + src_instance
    ENRICH_DST_ENDPOINT   = true,   -- build dst_endpoint from connection + dest_instance
    ENRICH_CONNECTION     = true,   -- build connection_info from protocol + reporter
    ENRICH_TRAFFIC        = true,   -- build traffic from bytes/packets counters
    ENRICH_CLOUD          = true,   -- build cloud from resource.labels project/zone/subnet
    ENRICH_DEVICE         = true,   -- build device from reporting VM instance
    ENRICH_OBSERVABLES    = true,   -- build observables[] from IPs / ports / ASNs
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
    "device",
    "cloud",
    "observables",
    "osint",
    "raw_data",
    "unmapped",
}

--------------------------------------------------------------------------------
-- PROTOCOL_MAP: IANA protocol number (int or string) → {name, num}
-- Covers all protocols commonly seen in GCP VPC Flow Logs
--------------------------------------------------------------------------------
local PROTOCOL_MAP = {
    ["1"]   = { name = "ICMP",    num = 1   },
    ["6"]   = { name = "TCP",     num = 6   },
    ["17"]  = { name = "UDP",     num = 17  },
    ["41"]  = { name = "IPv6",    num = 41  },
    ["47"]  = { name = "GRE",     num = 47  },
    ["50"]  = { name = "ESP",     num = 50  },
    ["51"]  = { name = "AH",      num = 51  },
    ["58"]  = { name = "ICMPv6",  num = 58  },
    ["89"]  = { name = "OSPF",    num = 89  },
    ["132"] = { name = "SCTP",    num = 132 },
    icmp    = { name = "ICMP",    num = 1   },
    tcp     = { name = "TCP",     num = 6   },
    udp     = { name = "UDP",     num = 17  },
    ipv6    = { name = "IPv6",    num = 41  },
    gre     = { name = "GRE",     num = 47  },
    esp     = { name = "ESP",     num = 50  },
    ah      = { name = "AH",      num = 51  },
    icmpv6  = { name = "ICMPv6",  num = 58  },
    ospf    = { name = "OSPF",    num = 89  },
    sctp    = { name = "SCTP",    num = 132 },
}

--------------------------------------------------------------------------------
-- ACTIVITY_NAMES: activity_id → caption
--------------------------------------------------------------------------------
local ACTIVITY_NAMES = {
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
-- FIELD_MAP: flat/pre-parsed GCP source field → OCSF destination dot-path
-- Used when jsonPayload fields have been promoted to the top level.
--------------------------------------------------------------------------------
local FIELD_MAP = {
    -- Timing
    ["timestamp"]               = "time",
    ["receiveTimestamp"]        = "time",
    ["_time"]                   = "time",
    ["start_time"]              = "start_time",
    ["end_time"]                = "end_time",
    ["rtt_msec"]                = "duration",
    ["latency_ms"]              = "duration",

    -- Metadata
    ["insertId"]                = "metadata.uid",
    ["insert_id"]               = "metadata.uid",
    ["logName"]                 = "metadata.product.feature.name",
    ["log_name"]                = "metadata.product.feature.name",

    -- Source endpoint (flat)
    ["src_ip"]                  = "src_endpoint.ip",
    ["source_ip"]               = "src_endpoint.ip",
    ["src_port"]                = "src_endpoint.port",
    ["source_port"]             = "src_endpoint.port",

    -- Destination endpoint (flat)
    ["dest_ip"]                 = "dst_endpoint.ip",
    ["destination_ip"]          = "dst_endpoint.ip",
    ["dst_ip"]                  = "dst_endpoint.ip",
    ["dest_port"]               = "dst_endpoint.port",
    ["destination_port"]        = "dst_endpoint.port",
    ["dst_port"]                = "dst_endpoint.port",

    -- Traffic counters (flat)
    ["bytes_sent"]              = "traffic.bytes_out",
    ["packets_sent"]            = "traffic.packets_out",
    ["bytes_received"]          = "traffic.bytes_in",
    ["packets_received"]        = "traffic.packets_in",

    -- Cloud / project (flat)
    ["project_id"]              = "cloud.account.uid",
    ["zone"]                    = "cloud.zone",
    ["region"]                  = "cloud.region",
    ["subnetwork_name"]         = "cloud.subnet_uid",
    ["vpc_name"]                = "cloud.vpc_uid",
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
        "protocol_num", "asn", "start_time", "end_time",
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
-- Normalises GCP timestamp variants to epoch milliseconds (integer).
-- Handles: Unix ms (>1e12), Unix seconds, ISO-8601 with nanoseconds,
--          ISO-8601 standard, numeric strings.
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
        -- ISO-8601 with optional fractional seconds and Z/offset
        -- "2024-06-15T12:34:56.123456789Z"
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
            if ok and ts then
                -- Extract sub-second fractional part (ms precision)
                local frac = tostring(val or ""):match("%.(%d+)")
                local ms_offset = 0
                if frac then
                    -- Normalise to milliseconds (take first 3 digits)
                    local frac3 = tostring(frac or ""):sub(1, 3)
                    while #frac3 < 3 do frac3 = frac3 .. "0" end
                    ms_offset = tonumber(frac3) or 0
                end
                return ts * 1000 + ms_offset
            end
        end
    end

    return nil
end

--------------------------------------------------------------------------------
-- local function normProtocol
-- Maps IANA protocol number (int/string) or name → {name, num}.
-- Returns nil, nil when input is absent.
--------------------------------------------------------------------------------
local function normProtocol(val)
    if val == nil then return nil, nil end
    local key_s = tostring(val or "")
    local key_l = tostring(val or ""):lower()

    local entry = PROTOCOL_MAP[key_s] or PROTOCOL_MAP[key_l]
    if entry then return entry.name, entry.num end

    -- Numeric fallback: return number as-is with nil name
    local n = tonumber(val)
    if n then return nil, n end

    return nil, nil
end

--------------------------------------------------------------------------------
-- local function normActivityId
-- Derives OCSF activity_id from GCP VPC flow context.
-- GCP flow logs represent observed traffic → default Traffic (6).
-- Refines to Open (1) when only start_time present,
-- Close (2) when end_time present and flow is complete.
--------------------------------------------------------------------------------
local function normActivityId(payload, e)
    -- Explicit override from flat field
    local act_raw = e["activity_id"] or e["activity"]
    if act_raw then
        local n = tonumber(act_raw)
        if n then return n end
        local a = tostring(act_raw or ""):lower()
        if a == "open"    then return 1 end
        if a == "close"   then return 2 end
        if a == "traffic" then return 6 end
    end

    -- Infer from start/end time presence
    local has_start = (payload and payload["start_time"]) or e["start_time"]
    local has_end   = (payload and payload["end_time"])   or e["end_time"]

    if has_start and has_end then return 2 end   -- complete flow → Close
    if has_start              then return 1 end   -- flow beginning → Open

    -- Default: Traffic (most representative for VPC flow logs)
    return 6
end

--------------------------------------------------------------------------------
-- local function parseResourceLabels
-- Extracts resource.labels fields from the nested GCP Cloud Logging structure.
-- Returns a flat table of label key→value pairs, or empty table.
--------------------------------------------------------------------------------
local function parseResourceLabels(e)
    local labels = {}
    local res = e["resource"]
    if type(res) ~= "table" then return labels end
    local lbl = res["labels"]
    if type(lbl) ~= "table" then return labels end
    for k, v in pairs(lbl) do
        labels[tostring(k or "")] = v
    end
    return labels
end

--------------------------------------------------------------------------------
-- local function extractPayload
-- Extracts jsonPayload from the nested GCP Cloud Logging structure.
-- Falls back to the top-level event if jsonPayload is absent (pre-parsed).
-- Returns the payload table and a boolean indicating if it was nested.
--------------------------------------------------------------------------------
local function extractPayload(e)
    local jp = e["jsonPayload"]
    if type(jp) == "table" then
        return jp, true
    end
    -- textPayload or protoPayload: return empty table, use flat fields
    return {}, false
end

--------------------------------------------------------------------------------
-- local function buildNetworkEndpoint
-- Reusable helper that constructs a single OCSF network endpoint object
-- from GCP instance, location, vpc, ip, and port data.
--------------------------------------------------------------------------------
local function buildNetworkEndpoint(instance_obj, location_obj, vpc_obj, ip, port)
    local ep = {}

    if ip then
        local clean = tostring(ip or ""):match("^%[(.+)%]$") or ip
        ep.ip = tostring(clean or "")
    end

    if port then
        local p = tonumber(port)
        if p then ep.port = p end
    end

    -- Instance metadata
    if type(instance_obj) == "table" then
        local vm_name = instance_obj["vm_name"]
        local zone    = instance_obj["zone"]
        local region  = instance_obj["region"]
        local proj    = instance_obj["project_id"]

        if vm_name then ep.name       = tostring(vm_name or "") end
        if zone    then ep.zone       = tostring(zone    or "") end
        if region  then ep.region     = tostring(region  or "") end
        if proj    then ep.project_id = tostring(proj    or "") end
    end

    -- Geo location
    if type(location_obj) == "table" then
        local country   = location_obj["country"]
        local region    = location_obj["region"]
        local continent = location_obj["continent"]
        local asn       = location_obj["asn"]

        if country or region or continent or asn then
            ep.location = {}
            if country   then ep.location.country   = tostring(country   or "") end
            if region    then ep.location.region     = tostring(region    or "") end
            if continent then ep.location.continent  = tostring(continent or "") end
            if asn       then ep.location.asn        = tonumber(asn) or asn      end
        end
    end

    -- VPC metadata
    if type(vpc_obj) == "table" then
        local vpc_name    = vpc_obj["vpc_name"]
        local subnet_name = vpc_obj["subnetwork_name"]
        local proj        = vpc_obj["project_id"]

        if vpc_name    then ep.vpc_uid    = tostring(vpc_name    or "") end
        if subnet_name then ep.subnet_uid = tostring(subnet_name or "") end
        if proj and not ep.project_id then
            ep.project_id = tostring(proj or "")
        end
    end

    if next(ep) == nil then return nil end
    return ep
end

--------------------------------------------------------------------------------
-- local function buildSrcEndpoint
-- Constructs OCSF src_endpoint from GCP connection + src_instance + src_location.
--------------------------------------------------------------------------------
local function buildSrcEndpoint(payload, e)
    local conn = type(payload["connection"]) == "table" and payload["connection"] or {}

    local ip   = conn["src_ip"]   or e["src_ip"]   or e["source_ip"]
    local port = conn["src_port"] or e["src_port"] or e["source_port"]

    local instance_obj = payload["src_instance"]
    local location_obj = payload["src_location"]
    local vpc_obj      = payload["src_vpc"]

    return buildNetworkEndpoint(instance_obj, location_obj, vpc_obj, ip, port)
end

--------------------------------------------------------------------------------
-- local function buildDstEndpoint
-- Constructs OCSF dst_endpoint from GCP connection + dest_instance + dest_location.
--------------------------------------------------------------------------------
local function buildDstEndpoint(payload, e)
    local conn = type(payload["connection"]) == "table" and payload["connection"] or {}

    local ip   = conn["dest_ip"]   or e["dest_ip"]   or e["destination_ip"] or e["dst_ip"]
    local port = conn["dest_port"] or e["dest_port"] or e["destination_port"] or e["dst_port"]

    local instance_obj = payload["dest_instance"]
    local location_obj = payload["dest_location"]
    local vpc_obj      = payload["dest_vpc"]

    return buildNetworkEndpoint(instance_obj, location_obj, vpc_obj, ip, port)
end

--------------------------------------------------------------------------------
-- local function buildConnectionInfo
-- Constructs OCSF connection_info from GCP protocol number and reporter field.
--------------------------------------------------------------------------------
local function buildConnectionInfo(payload, e)
    local ci = {}

    local conn = type(payload["connection"]) == "table" and payload["connection"] or {}

    local proto_raw = conn["protocol"]
                   or e["protocol"] or e["transport"] or e["ip_protocol"]
    if proto_raw ~= nil then
        local proto_name, proto_num = normProtocol(proto_raw)
        if proto_name then ci.protocol_name = proto_name end
        if proto_num  then ci.protocol_num  = proto_num  end
    end

    -- Direction from reporter field
    local reporter = payload["reporter"] or e["reporter"]
    if reporter then
        local r = tostring(reporter or ""):upper()
        if r == "SRC" then
            ci.direction    = "Outbound"
            ci.direction_id = 2
        elseif r == "DEST" then
            ci.direction    = "Inbound"
            ci.direction_id = 1
        end
    end

    -- RTT as connection quality indicator
    local rtt = tonumber(payload["rtt_msec"] or e["rtt_msec"])
    if rtt then ci.tcp_rtt = rtt end

    if next(ci) == nil then return nil end
    return ci
end

--------------------------------------------------------------------------------
-- local function buildTraffic
-- Constructs OCSF traffic object from GCP bytes/packets counters.
-- GCP reports from the reporter's perspective: bytes_sent = bytes_out for SRC.
--------------------------------------------------------------------------------
local function buildTraffic(payload, e)
    local tr = {}

    local function setNum(field, val)
        local n = tonumber(val)
        if n then tr[field] = n end
    end

    local reporter = tostring(payload["reporter"] or e["reporter"] or ""):upper()

    local bytes_sent   = payload["bytes_sent"]    or e["bytes_sent"]
    local packets_sent = payload["packets_sent"]  or e["packets_sent"]
    local bytes_recv   = payload["bytes_received"] or e["bytes_received"]
    local pkts_recv    = payload["packets_received"] or e["packets_received"]

    -- reporter=SRC: sent = outbound from src perspective
    -- reporter=DEST: sent = inbound to dest perspective
    if reporter == "DEST" then
        setNum("bytes_in",    bytes_sent)
        setNum("packets_in",  packets_sent)
        setNum("bytes_out",   bytes_recv)
        setNum("packets_out", pkts_recv)
    else
        -- SRC or unspecified: treat sent as outbound
        setNum("bytes_out",   bytes_sent)
        setNum("packets_out", packets_sent)
        setNum("bytes_in",    bytes_recv)
        setNum("packets_in",  pkts_recv)
    end

    -- Totals
    if tr.bytes_out and tr.bytes_in then
        tr.bytes = tr.bytes_out + tr.bytes_in
    elseif tr.bytes_out then
        tr.bytes = tr.bytes_out
    elseif tr.bytes_in then
        tr.bytes = tr.bytes_in
    end

    if tr.packets_out and tr.packets_in then
        tr.packets = tr.packets_out + tr.packets_in
    elseif tr.packets_out then
        tr.packets = tr.packets_out
    elseif tr.packets_in then
        tr.packets = tr.packets_in
    end

    if next(tr) == nil then return nil end
    return tr
end

--------------------------------------------------------------------------------
-- local function buildCloud
-- Constructs OCSF cloud object from GCP resource.labels and payload VPC fields.
--------------------------------------------------------------------------------
local function buildCloud(resource_labels, payload, e)
    local cloud = { provider = "GCP" }

    -- Project ID
    local proj = resource_labels["project_id"]
              or e["project_id"]
    if proj then
        cloud.account = {
            uid  = tostring(proj or ""),
            type = "Project",
        }
    end

    -- Zone from resource labels
    local zone = resource_labels["location"] or resource_labels["zone"] or e["zone"]
    if zone then cloud.zone = tostring(zone or "") end

    -- Region: derive from zone (strip trailing -[a-z])
    local region = resource_labels["region"] or e["region"]
    if not region and zone then
        region = tostring(zone or ""):match("^(.+)%-[a-z]$")
    end
    if region then cloud.region = tostring(region or "") end

    -- Subnetwork
    local subnet = resource_labels["subnetwork_name"] or e["subnetwork_name"]
    if subnet then cloud.subnet_uid = tostring(subnet or "") end

    -- VPC from src_vpc or dest_vpc
    local src_vpc  = type(payload["src_vpc"])  == "table" and payload["src_vpc"]  or {}
    local dest_vpc = type(payload["dest_vpc"]) == "table" and payload["dest_vpc"] or {}
    local vpc_name = src_vpc["vpc_name"] or dest_vpc["vpc_name"] or e["vpc_name"]
    if vpc_name then cloud.vpc_uid = tostring(vpc_name or "") end

    return cloud
end

--------------------------------------------------------------------------------
-- local function buildDevice
-- Constructs OCSF device object from the reporting VM instance.
-- reporter=SRC → use src_instance; reporter=DEST → use dest_instance.
--------------------------------------------------------------------------------
local function buildDevice(payload, e)
    local reporter = tostring(payload["reporter"] or e["reporter"] or ""):upper()

    local instance_obj
    if reporter == "DEST" then
        instance_obj = payload["dest_instance"]
    else
        instance_obj = payload["src_instance"]
    end

    if type(instance_obj) ~= "table" then return nil end

    local dev = {}

    local vm_name = instance_obj["vm_name"]
    local zone    = instance_obj["zone"]
    local region  = instance_obj["region"]
    local proj    = instance_obj["project_id"]

    if vm_name then dev.name       = tostring(vm_name or "") end
    if zone    then dev.zone       = tostring(zone    or "") end
    if region  then dev.region     = tostring(region  or "") end
    if proj    then dev.project_id = tostring(proj    or "") end

    -- Device type: Virtual Machine
    dev.type    = "Virtual"
    dev.type_id = 9

    if next(dev) == nil then return nil end
    return dev
end

--------------------------------------------------------------------------------
-- local function buildObservables
-- Constructs OCSF observables[] from key network indicator fields.
-- type_id: 1=Hostname, 2=IP Address, 99=Other
--------------------------------------------------------------------------------
local function buildObservables(payload, e)
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

    local conn = type(payload["connection"]) == "table" and payload["connection"] or {}

    local src_ip   = conn["src_ip"]   or e["src_ip"]   or e["source_ip"]
    local dst_ip   = conn["dest_ip"]  or e["dest_ip"]  or e["destination_ip"] or e["dst_ip"]
    local src_port = conn["src_port"] or e["src_port"] or e["source_port"]
    local dst_port = conn["dest_port"] or e["dest_port"] or e["destination_port"] or e["dst_port"]

    addObs("src_endpoint.ip",   2,  src_ip)
    addObs("dst_endpoint.ip",   2,  dst_ip)
    addObs("src_endpoint.port", 99, src_port)
    addObs("dst_endpoint.port", 99, dst_port)

    -- VM names
    local src_inst = type(payload["src_instance"])  == "table" and payload["src_instance"]  or {}
    local dst_inst = type(payload["dest_instance"]) == "table" and payload["dest_instance"] or {}
    addObs("src_endpoint.name", 1, src_inst["vm_name"])
    addObs("dst_endpoint.name", 1, dst_inst["vm_name"])

    -- ASNs from location objects
    local src_loc = type(payload["src_location"])  == "table" and payload["src_location"]  or {}
    local dst_loc = type(payload["dest_location"]) == "table" and payload["dest_location"] or {}
    if src_loc["asn"] then addObs("src_endpoint.asn", 99, tostring(src_loc["asn"] or "")) end
    if dst_loc["asn"] then addObs("dst_endpoint.asn", 99, tostring(dst_loc["asn"] or "")) end

    if #obs == 0 then return nil end
    return obs
end

--------------------------------------------------------------------------------
-- MAIN: processEvent
-- Entry point required by the Observo Lua transform runtime.
-- All helpers are declared as local functions ABOVE this function.
-- Handles both:
--   (A) Raw nested GCP Cloud Logging JSON (jsonPayload + resource.labels)
--   (B) Pre-parsed flat records (individual fields already at top level)
--------------------------------------------------------------------------------
function processEvent(event)

    --------------------------------------------------------------------------
    -- INNER: core transform — wrapped in pcall for pipeline safety
    --------------------------------------------------------------------------
    local function execute(e)

        -- Track consumed source keys to populate unmapped correctly
        local consumed = {}

        -----------------------------------------------------------------------
        -- 1. Extract nested GCP structure
        -----------------------------------------------------------------------
        local payload        = {}
        local resource_labels = {}

        if FEATURES.PARSE_NESTED_GCP then
            payload, _ = extractPayload(e)
            resource_labels = parseResourceLabels(e)
            consumed["jsonPayload"]     = true
            consumed["resource"]        = true
            consumed["receiveTimestamp"] = true
        end

        -----------------------------------------------------------------------
        -- 2. Resolve activity_id
        -----------------------------------------------------------------------
        local activity_id = normActivityId(payload, e)

        -----------------------------------------------------------------------
        -- 3. Seed OCSF skeleton with required constant fields
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
            -- VPC flow logs represent allowed traffic (logged = passed firewall)
            action_id     = 1,
            action        = "Allowed",
            metadata = {
                version = "1.3.0",
                product = {
                    vendor_name = "Google",
                    name        = "GCP VPC Flow Logs",
                    feature     = { name = "VPC Flow Logs" },
                },
            },
            osint    = {},
            unmapped = {},
        }

        -----------------------------------------------------------------------
        -- 4. Apply FIELD_MAP: scalar source field → OCSF destination path
        -----------------------------------------------------------------------
        for src_field, dest_path in pairs(FIELD_MAP) do
            local val = e[src_field]
            if val ~= nil and val ~= "" then
                if dest_path == "time"       or
                   dest_path == "start_time" or
                   dest_path == "end_time"   then
                    val = toEpochMs(val)
                end
                if val ~= nil then
                    deepSet(ocsf, dest_path, val)
                    consumed[src_field] = true
                end
            end
        end

        -----------------------------------------------------------------------
        -- 5. Resolve time with fallback chain
        -----------------------------------------------------------------------
        if ocsf.time == nil then
            -- Try payload start_time first (most precise flow timestamp)
            local payload_start = payload["start_time"]
            if payload_start then
                local ts = toEpochMs(payload_start)
                if ts then ocsf.time = ts end
            end
        end
        if ocsf.time == nil then
            local fallbacks = { "timestamp", "receiveTimestamp", "_time" }
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
        -- 6. start_time and end_time from payload
        -----------------------------------------------------------------------
        local p_start = payload["start_time"] or e["start_time"]
        local p_end   = payload["end_time"]   or e["end_time"]

        if p_start then
            local ts = toEpochMs(p_start)
            if ts then ocsf.start_time = ts end
            consumed["start_time"] = true
        end
        if p_end then
            local ts = toEpochMs(p_end)
            if ts then ocsf.end_time = ts end
            consumed["end_time"] = true
        end

        -- Duration from RTT or start/end delta
        local rtt = tonumber(payload["rtt_msec"] or e["rtt_msec"])
        if rtt then
            ocsf.duration = rtt
            consumed["rtt_msec"] = true
        elseif ocsf.start_time and ocsf.end_time then
            local delta = ocsf.end_time - ocsf.start_time
            if delta >= 0 then ocsf.duration = delta end
        end

        -----------------------------------------------------------------------
        -- 7. metadata.uid from insertId
        -----------------------------------------------------------------------
        local insert_id = e["insertId"] or e["insert_id"]
        if insert_id then
            deepSet(ocsf, "metadata.uid", tostring(insert_id or ""))
            consumed["insertId"]   = true
            consumed["insert_id"]  = true
        end

        -- logName → metadata.product.feature.name
        local log_name = e["logName"] or e["log_name"]
        if log_name then
            deepSet(ocsf, "metadata.product.feature.name", tostring(log_name or ""))
            consumed["logName"]   = true
            consumed["log_name"]  = true
        end

        -----------------------------------------------------------------------
        -- 8. src_endpoint (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SRC_ENDPOINT then
            local ep = buildSrcEndpoint(payload, e)
            if ep then ocsf.src_endpoint = ep end
            consumed["src_ip"]      = true
            consumed["source_ip"]   = true
            consumed["src_port"]    = true
            consumed["source_port"] = true
        end

        -----------------------------------------------------------------------
        -- 9. dst_endpoint (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_DST_ENDPOINT then
            local ep = buildDstEndpoint(payload, e)
            if ep then
                ocsf.dst_endpoint = ep
            else
                ocsf.dst_endpoint = {}
            end
            consumed["dest_ip"]          = true
            consumed["destination_ip"]   = true
            consumed["dst_ip"]           = true
            consumed["dest_port"]        = true
            consumed["destination_port"] = true
            consumed["dst_port"]         = true
        end

        -----------------------------------------------------------------------
        -- 10. connection_info (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CONNECTION then
            local ci = buildConnectionInfo(payload, e)
            if ci then ocsf.connection_info = ci end
            consumed["protocol"]    = true
            consumed["transport"]   = true
            consumed["ip_protocol"] = true
            consumed["reporter"]    = true
        end

        -----------------------------------------------------------------------
        -- 11. traffic (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_TRAFFIC then
            local tr = buildTraffic(payload, e)
            if tr then ocsf.traffic = tr end
            consumed["bytes_sent"]        = true
            consumed["packets_sent"]      = true
            consumed["bytes_received"]    = true
            consumed["packets_received"]  = true
        end

        -----------------------------------------------------------------------
        -- 12. cloud (required)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CLOUD then
            ocsf.cloud = buildCloud(resource_labels, payload, e)
            consumed["project_id"]      = true
            consumed["zone"]            = true
            consumed["region"]          = true
            consumed["subnetwork_name"] = true
            consumed["vpc_name"]        = true
        end

        -----------------------------------------------------------------------
        -- 13. device (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_DEVICE then
            local dev = buildDevice(payload, e)
            if dev then ocsf.device = dev end
        end

        -----------------------------------------------------------------------
        -- 14. observables (recommended)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_OBSERVABLES then
            local obs = buildObservables(payload, e)
            if obs then ocsf.observables = obs end
        end

        -----------------------------------------------------------------------
        -- 15. Disposition mirrors action for VPC flow logs
        -----------------------------------------------------------------------
        ocsf.disposition_id = 1
        ocsf.disposition    = "Allowed"

        -----------------------------------------------------------------------
        -- 16. raw_data
        -----------------------------------------------------------------------
        if FEATURES.PRESERVE_RAW then
            local ok_enc, raw_str = pcall(json.encode, e)
            if ok_enc and raw_str then
                ocsf.raw_data = raw_str
            end
        end

        -----------------------------------------------------------------------
        -- 17. Collect remaining unmapped fields
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
        -- 18. Strip empty strings / empty tables
        -----------------------------------------------------------------------
        if FEATURES.STRIP_EMPTY then
            stripEmpty(ocsf)
        end

        -----------------------------------------------------------------------
        -- 19. Compose human-readable message (table.concat, no .. in loop)
        -----------------------------------------------------------------------
        local msg_parts = {}

        local src_ip_lbl  = deepGet(ocsf, "src_endpoint.ip")
        local dst_ip_lbl  = deepGet(ocsf, "dst_endpoint.ip")
        local src_prt_lbl = deepGet(ocsf, "src_endpoint.port")
        local dst_prt_lbl = deepGet(ocsf, "dst_endpoint.port")
        local proto_lbl   = deepGet(ocsf, "connection_info.protocol_name")
        local dir_lbl     = deepGet(ocsf, "connection_info.direction")
        local proj_lbl    = deepGet(ocsf, "cloud.account.uid")
        local zone_lbl    = deepGet(ocsf, "cloud.zone")

        table.insert(msg_parts, "GCP VPC Flow:")
        if proto_lbl   then table.insert(msg_parts, "proto="   .. tostring(proto_lbl   or "")) end
        if dir_lbl     then table.insert(msg_parts, "dir="     .. tostring(dir_lbl     or "")) end
        if src_ip_lbl  then table.insert(msg_parts, "src="     .. tostring(src_ip_lbl  or "")) end
        if src_prt_lbl then table.insert(msg_parts, "sport="   .. tostring(src_prt_lbl or "")) end
        if dst_ip_lbl  then table.insert(msg_parts, "dst="     .. tostring(dst_ip_lbl  or "")) end
        if dst_prt_lbl then table.insert(msg_parts, "dport="   .. tostring(dst_prt_lbl or "")) end
        if proj_lbl    then table.insert(msg_parts, "project=" .. tostring(proj_lbl    or "")) end
        if zone_lbl    then table.insert(msg_parts, "zone="    .. tostring(zone_lbl    or "")) end

        ocsf.message = table.concat(msg_parts, " ")

        -----------------------------------------------------------------------
        -- 20. Encode final OCSF event as raw JSON into message field
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
        event["_ocsf_serializer"]   = "gcp_vpc_flow_network_activity"
        event["_ocsf_parse_failed"] = "true"
        return event
    end

end -- end processEvent()
