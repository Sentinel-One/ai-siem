-- OCSF Network Activity (4001) serializer for AWS VPC Flow Logs v2
-- Remediation per 2026-04-19 Orion: correct source field names.

local CLASS_UID = 4001
local CATEGORY_UID = 4
local TYPE_UID = 400101

-- Safe millisecond clock (pcall-guarded per Observo sandbox rules)
function safeTimeMs()
    local ok, secs = pcall(os.time)
    if ok and secs then return secs * 1000 end
    return 0
end

function getNestedField(obj, path)
    if obj == nil or path == nil or path == '' then return nil end
    local cursor = obj
    for key in string.gmatch(path, '[^.]+') do
        if type(cursor) ~= 'table' then return nil end
        if cursor[key] == nil then return nil end
        cursor = cursor[key]
    end
    return cursor
end
function setNestedField(obj, path, value)
    if obj == nil or value == nil or path == nil or path == '' then return end
    if type(obj) ~= 'table' then return end
    local keys = {}
    for key in string.gmatch(path, '[^.]+') do table.insert(keys, key) end
    if #keys == 0 then return end
    local cursor = obj
    local limit = #keys - 1
    for i = 1, limit do
        if cursor[keys[i]] == nil then cursor[keys[i]] = {} end
        cursor = cursor[keys[i]]
    end
    cursor[keys[#keys]] = value
end
function getValue(tbl, key, default)
    if tbl == nil then return default end
    local v = tbl[key]
    if v == nil then return default end
    return v
end
function no_nulls(d)
    if type(d) == 'table' then
        for k, v in pairs(d) do
            if type(v) == 'userdata' then d[k] = nil
            elseif type(v) == 'table' then no_nulls(v) end
        end
    end
    return d
end

function actionToId(action)
    if action == nil then return 0 end
    local s = string.upper(tostring(action))
    if s == "ACCEPT" then return 1 end
    if s == "REJECT" then return 2 end
    return 0
end

function buildSkeleton(t)
    local ts = t or safeTimeMs()
    return {
        class_uid = CLASS_UID,
        category_uid = CATEGORY_UID,
        type_uid = TYPE_UID,
        activity_id = 6,
        severity_id = 1,
        time = ts,
        metadata = { version = "1.1.0", product = { name = "VPC Flow Logs", vendor_name = "AWS" } },
        src_endpoint = {}, dst_endpoint = {}, connection_info = {}, traffic = {}, cloud = { provider = "AWS" },
        unmapped = {}
    }
end

function processEvent(event)
    if type(event) ~= 'table' then return buildSkeleton() end
    no_nulls(event)

    local start_ts = tonumber(getValue(event, "start"))
    local end_ts = tonumber(getValue(event, "end"))
    local ts = (start_ts and (start_ts * 1000)) or safeTimeMs()

    local result = buildSkeleton(ts)

    -- Endpoints
    setNestedField(result, "src_endpoint.ip", getValue(event, "srcaddr"))
    setNestedField(result, "src_endpoint.port", tonumber(getValue(event, "srcport")))
    setNestedField(result, "dst_endpoint.ip", getValue(event, "dstaddr"))
    setNestedField(result, "dst_endpoint.port", tonumber(getValue(event, "dstport")))
    setNestedField(result, "src_endpoint.interface_uid", getValue(event, "interface_id"))

    -- Connection protocol (IANA number)
    local proto = tonumber(getValue(event, "protocol"))
    setNestedField(result, "connection_info.protocol_num", proto)
    if proto == 6 then setNestedField(result, "connection_info.protocol_name", "tcp")
    elseif proto == 17 then setNestedField(result, "connection_info.protocol_name", "udp")
    elseif proto == 1 then setNestedField(result, "connection_info.protocol_name", "icmp") end
    setNestedField(result, "connection_info.direction_id", 3)

    -- Traffic volumes
    setNestedField(result, "traffic.bytes_out", tonumber(getValue(event, "bytes")))
    setNestedField(result, "traffic.packets_out", tonumber(getValue(event, "packets")))

    -- Action
    local action_id = actionToId(getValue(event, "action"))
    result.action_id = action_id
    result.action = (action_id == 1) and "Allowed" or (action_id == 2) and "Denied" or "Unknown"
    if action_id == 2 then result.severity_id = 3 end

    -- Cloud context
    setNestedField(result, "cloud.account.uid", getValue(event, "account_id"))
    setNestedField(result, "cloud.region", getValue(event, "region"))
    setNestedField(result, "cloud.zone", getValue(event, "az_id"))
    setNestedField(result, "cloud.vpc_uid", getValue(event, "vpc_id"))

    -- Timing
    setNestedField(result, "start_time", start_ts and start_ts * 1000 or nil)
    setNestedField(result, "end_time", end_ts and end_ts * 1000 or nil)
    setNestedField(result, "duration", (start_ts and end_ts) and (end_ts - start_ts) * 1000 or nil)

    -- Status
    local status = getValue(event, "flowlogstatus")
    setNestedField(result, "status", status)
    setNestedField(result, "status_id", (status == "OK") and 1 or 0)

    -- Observables
    result.observables = {
        { name = "src_endpoint.ip", type = "IP Address", type_id = 2, value = getValue(event, "srcaddr") },
        { name = "dst_endpoint.ip", type = "IP Address", type_id = 2, value = getValue(event, "dstaddr") },
    }

    setNestedField(result, "raw_data", event)
    setNestedField(result, "metadata.log_name", "vpc-flow-logs-v" .. tostring(getValue(event, "version", "2")))
    return result
end
