-- OCSF Detection Finding (2004) serializer for Microsoft Defender for Cloud alerts.
-- Remediation per 2026-04-19 Orion: keep class 2004; fill finding_info, attacks[], resources[], cloud.

local CLASS_UID = 2004
local CATEGORY_UID = 2

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

function parseIsoMs(s)
    if type(s) ~= 'string' then return nil end
    local y, mo, d, h, mi, se = s:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if not y then return nil end
    local ok, v = pcall(function() return os.time({year=tonumber(y), month=tonumber(mo), day=tonumber(d), hour=tonumber(h), min=tonumber(mi), sec=tonumber(se)}) * 1000 end)
    if ok then return v end
    return nil
end

function severityId(s)
    if s == nil then return 1 end
    local v = string.lower(tostring(s))
    if v == "informational" or v == "info" then return 1 end
    if v == "low" then return 2 end
    if v == "medium" then return 3 end
    if v == "high" then return 4 end
    if v == "critical" then return 5 end
    return 1
end

function buildSkeleton(t)
    local ts = t or safeTimeMs()
    return {
        class_uid = CLASS_UID,
        category_uid = CATEGORY_UID,
        type_uid = 200401,
        activity_id = 1,
        severity_id = 1,
        status_id = 1,
        time = ts,
        metadata = { version = "1.1.0", product = { name = "Defender for Cloud", vendor_name = "Microsoft" } },
        finding_info = { uid = "unknown", title = "Microsoft Defender for Cloud alert" },
        attacks = {}, resources = {}, evidences = {}, cloud = { provider = "Azure" },
        unmapped = {}
    }
end

function processEvent(event)
    if type(event) ~= 'table' then return buildSkeleton() end
    no_nulls(event)

    local ts = parseIsoMs(getValue(event, "timeGenerated")) or safeTimeMs()
    local result = buildSkeleton(ts)

    -- finding_info
    setNestedField(result, "finding_info.uid", getValue(event, "alertId") or "unknown")
    setNestedField(result, "finding_info.title", getValue(event, "alertDisplayName") or "Defender for Cloud alert")
    setNestedField(result, "finding_info.desc", getValue(event, "description"))
    setNestedField(result, "finding_info.types", { getValue(event, "alertType") })
    local sol = getValue(event, "remediationSteps")
    if type(sol) == 'table' then
        setNestedField(result, "finding_info.remediation.desc", table.concat(sol, "; "))
    end

    -- status
    local st = getValue(event, "status") or "Active"
    local st_l = string.lower(tostring(st))
    if st_l == "active" then setNestedField(result, "status_id", 1)
    elseif st_l == "resolved" or st_l == "dismissed" then setNestedField(result, "status_id", 6)
    else setNestedField(result, "status_id", 99) end
    setNestedField(result, "status", st)
    setNestedField(result, "severity_id", severityId(getValue(event, "severity")))

    -- MITRE attacks[]
    local tactics = getValue(event, "tactics") or {}
    local techniques = getValue(event, "techniques") or {}
    for i, tactic in ipairs(tactics) do
        local entry = { tactic = { name = tostring(tactic) } }
        if techniques[i] then
            entry.technique = { uid = tostring(techniques[i]), name = tostring(techniques[i]) }
        end
        entry.version = "14.1"
        table.insert(result.attacks, entry)
    end

    -- Cloud subscription
    setNestedField(result, "cloud.account.uid", getValue(event, "subscriptionId"))

    -- Resources
    local ri = getValue(event, "resourceIdentifiers") or {}
    for _, r in ipairs(ri) do
        table.insert(result.resources, {
            name = getValue(event, "compromisedEntity") or r.azureResourceId,
            uid = r.azureResourceId,
            type = r.type or "AzureResource",
            cloud_partition = "Azure"
        })
    end
    if #result.resources == 0 and getValue(event, "compromisedEntity") then
        table.insert(result.resources, { name = getValue(event, "compromisedEntity"), type = "AzureResource" })
    end

    -- Evidences from entities
    local entities = getValue(event, "entities") or {}
    for _, e in ipairs(entities) do
        table.insert(result.evidences, { data = e })
    end

    -- Metadata
    setNestedField(result, "metadata.uid", getValue(event, "alertId"))
    setNestedField(result, "metadata.log_name", getValue(event, "productComponentName"))
    setNestedField(result, "metadata.event_code", getValue(event, "alertType"))

    -- Observables from entities
    result.observables = {}
    for _, e in ipairs(entities) do
        local et = string.lower(tostring(e.type or ""))
        if et == "ip" and e.address then
            table.insert(result.observables,
                { name = "entity.ip", type = "IP Address", type_id = 2, value = e.address })
        elseif et == "account" and e.name then
            table.insert(result.observables, { name = "entity.user", type = "User Name", type_id = 4, value = e.name })
        end
    end

    result.message = tostring(result.finding_info.title)
    setNestedField(result, "raw_data", event)
    return result
end
