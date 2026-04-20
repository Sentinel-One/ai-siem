-- OCSF Account Change (3001) serializer for Azure AD / Entra ID audit events.
-- Remediation per 2026-04-19 Orion: was 3004, corrected to 3001.

local CLASS_UID = 3001
local CATEGORY_UID = 3

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

-- Azure AD operationType -> OCSF activity_id
-- 1=Create, 2=Read, 3=Update, 4=Delete, 5=Enable, 6=Disable (others unmapped -> 99 Other)
function activityForOperation(op)
    if op == nil then return 0 end
    local s = tostring(op)
    if type(s) ~= 'string' then return 0 end
    s = string.lower(s)
    if s:find("add") or s:find("create") then return 1 end
    if s:find("get") or s:find("read") or s:find("list") then return 2 end
    if s:find("update") or s:find("modif") or s:find("change") or s:find("patch") then return 3 end
    if s:find("delete") or s:find("remov") then return 4 end
    if s:find("enable") or s:find("unlock") then return 5 end
    if s:find("disable") or s:find("lock") then return 6 end
    return 99
end

function parseIso8601ToMs(s)
    if type(s) ~= 'string' then return nil end
    local y, mo, d, h, mi, se = s:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if not y then return nil end
    local ok, t = pcall(function()
        return os.time({year = tonumber(y), month = tonumber(mo), day = tonumber(d),
            hour = tonumber(h), min = tonumber(mi), sec = tonumber(se)})
    end)
    if ok and t then return t * 1000 end
    return nil
end

function buildSkeleton(t, act)
    local ts = t or safeTimeMs()
    return {
        class_uid = CLASS_UID,
        category_uid = CATEGORY_UID,
        type_uid = 300100 + (act or 0),
        activity_id = act or 0,
        severity_id = 1,
        time = ts,
        metadata = { version = "1.1.0", product = { name = "Azure AD", vendor_name = "Microsoft" } },
        user = {}, actor = { user = {} }, cloud = { provider = "Azure" },
        unmapped = {}
    }
end

function processEvent(event)
    if type(event) ~= 'table' then return buildSkeleton() end
    no_nulls(event)

    local ts = parseIso8601ToMs(getValue(event, "activityDateTime")) or safeTimeMs()
    local op = getValue(event, "operationType") or getValue(event, "activityDisplayName")
    local activity_id = activityForOperation(op)

    local result = buildSkeleton(ts, activity_id)

    -- Target user
    local targetResources = getValue(event, "targetResources") or {}
    local target = targetResources[1] or {}
    setNestedField(result, "user.name", getValue(target, "userPrincipalName") or getValue(target, "displayName"))
    setNestedField(result, "user.uid", getValue(target, "id"))
    setNestedField(result, "user.type", getValue(target, "type"))
    setNestedField(result, "user.full_name", getValue(target, "displayName"))

    -- Actor (initiating user)
    local initiator = getNestedField(event, "initiatedBy.user") or {}
    setNestedField(result, "actor.user.name", getValue(initiator, "userPrincipalName"))
    setNestedField(result, "actor.user.uid", getValue(initiator, "id"))
    setNestedField(result, "actor.user.full_name", getValue(initiator, "displayName"))
    setNestedField(result, "src_endpoint.ip", getValue(initiator, "ipAddress"))

    -- Tenant / cloud
    setNestedField(result, "cloud.account.uid", getValue(event, "tenantId"))
    setNestedField(result, "cloud.account.type", "Azure AD Tenant")

    -- Result / status
    local rres = getValue(event, "result") or "success"
    local rres_low = string.lower(tostring(rres))
    if rres_low == "success" then
        result.status_id = 1; result.status = "Success"
    else
        result.status_id = 2; result.status = "Failure"; result.severity_id = 3
    end
    setNestedField(result, "status_detail", getValue(event, "resultReason"))

    -- Modified properties -> enrichments
    if target.modifiedProperties then
        result.enrichments = {}
        for _, prop in ipairs(target.modifiedProperties) do
            table.insert(result.enrichments, {
                name = getValue(prop, "displayName"),
                data = { old = getValue(prop, "oldValue"), new = getValue(prop, "newValue") },
                type = "attribute_change"
            })
        end
    end

    -- Metadata
    setNestedField(result, "metadata.uid", getValue(event, "id"))
    setNestedField(result, "metadata.correlation_uid", getValue(event, "correlationId"))
    setNestedField(result, "metadata.log_name", getValue(event, "category"))
    setNestedField(result, "metadata.log_provider", getValue(event, "loggedByService"))

    -- Observables
    result.observables = {}
    if result.user and result.user.name then
        table.insert(result.observables,
            { name = "user.name", type = "User Name", type_id = 4, value = result.user.name })
    end
    if result.actor.user.name then
        table.insert(result.observables,
            { name = "actor.user.name", type = "User Name", type_id = 4, value = result.actor.user.name })
    end
    if getValue(initiator, "ipAddress") then
        table.insert(result.observables,
            { name = "src_endpoint.ip", type = "IP Address", type_id = 2, value = getValue(initiator, "ipAddress") })
    end

    result.message = string.format("Azure AD %s (%s) by %s",
        tostring(op or "audit"),
        result.status or "Unknown",
        tostring(result.actor.user.name or "system"))
    setNestedField(result, "raw_data", event)

    return result
end
