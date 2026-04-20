-- OCSF Device Inventory Info (class_uid 5001) serializer
-- Source: SentinelOne agent telemetry / Observo Agent metrics logs
-- Reclassified from 1007 Process Activity per 2026-04-19 Orion validation.

local CLASS_UID = 5001
local CATEGORY_UID = 5
local TYPE_UID = 500101
local ACTIVITY_ID = 1

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

function buildSkeleton(t)
    local ts = t or safeTimeMs()
    return {
        class_uid = CLASS_UID,
        category_uid = CATEGORY_UID,
        type_uid = TYPE_UID,
        activity_id = ACTIVITY_ID,
        severity_id = 1,
        time = ts,
        metadata = {
            version = "1.1.0",
            product = { name = "SentinelOne Agent", vendor_name = "SentinelOne" }
        },
        device = {},
        unmapped = {}
    }
end

function processEvent(event)
    if type(event) ~= 'table' then return buildSkeleton() end
    no_nulls(event)

    local ts = getValue(event, "event.time") or getValue(event, "timestamp") or safeTimeMs()
    if type(ts) == 'string' then
        local n = tonumber(ts); if n then ts = n end
    end

    local result = buildSkeleton(ts)

    -- Device identity
    local agent_uuid = getValue(event, "agent.uuid")
    local endpoint_name = getValue(event, "endpoint.name")
    setNestedField(result, "device.uid", agent_uuid or getValue(event, "endpoint.uid"))
    setNestedField(result, "device.name", endpoint_name)
    setNestedField(result, "device.hostname", endpoint_name)
    setNestedField(result, "device.type", getValue(event, "endpoint.type"))

    -- OS
    setNestedField(result, "device.os.name", getValue(event, "os.name") or getValue(event, "endpoint.os"))
    setNestedField(result, "device.os.type", getValue(event, "endpoint.os"))

    -- Agent list
    local agent_name = getValue(event, "dataSource.vendor") or "SentinelOne Agent"
    local agent_version = getValue(event, "agent.version")
    if agent_uuid or agent_version then
        result.device.agent_list = {
            {
                name = tostring(agent_name),
                version = agent_version and tostring(agent_version) or "unknown",
                type = "EDR",
                uid = agent_uuid
            }
        }
    end

    -- Org context
    setNestedField(result, "device.groups", { { name = getValue(event, "account.name"), uid = getValue(event, "account.id") } })
    setNestedField(result, "device.location.desc", getValue(event, "site.name"))

    -- Metadata
    setNestedField(result, "metadata.uid", getValue(event, "event.id"))
    setNestedField(result, "metadata.event_code", getValue(event, "meta.event.name"))
    setNestedField(result, "metadata.log_name", getValue(event, "event.category"))

    -- Observables
    result.observables = {}
    if endpoint_name then
        table.insert(result.observables, { name = "device.name", type = "Hostname", type_id = 1, value = endpoint_name })
    end
    if agent_uuid then
        table.insert(result.observables, { name = "device.uid", type = "Other UID", type_id = 40, value = agent_uuid })
    end

    -- Preserve raw event for downstream debugging
    setNestedField(result, "unmapped.raw_event", event)
    setNestedField(result, "raw_data", event)
    setNestedField(result, "status_id", 1)
    setNestedField(result, "message", "Device inventory info from " .. tostring(getValue(event, "dataSource.vendor", "agent")))

    return result
end
