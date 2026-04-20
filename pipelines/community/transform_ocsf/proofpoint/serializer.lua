-- OCSF Detection Finding (2004) serializer for Proofpoint TAP email threat events.
-- Remediation per 2026-04-19 Orion: reclassified from 4012 to 2004.

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

function severityIdFromScores(spam, phish)
    local sp = tonumber(spam) or 0
    local ph = tonumber(phish) or 0
    local m = math.max(sp, ph)
    if m >= 80 then return 5 end
    if m >= 60 then return 4 end
    if m >= 40 then return 3 end
    if m >= 20 then return 2 end
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
        metadata = { version = "1.1.0", product = { name = "Proofpoint TAP", vendor_name = "Proofpoint" } },
        finding_info = { uid = "unknown", title = "Proofpoint detection" },
        actor = { user = {} }, user = {}, evidences = {}, email = {}, cloud = { provider = "Proofpoint" },
        unmapped = {}
    }
end

function processEvent(event)
    if type(event) ~= 'table' then return buildSkeleton() end
    no_nulls(event)

    local ts = parseIsoMs(getValue(event, "messageTime")) or safeTimeMs()
    local result = buildSkeleton(ts)

    -- finding_info
    setNestedField(result, "finding_info.uid", getValue(event, "GUID") or getValue(event, "messageID") or "unknown")
    setNestedField(result, "finding_info.title", getValue(event, "threatName") or getValue(event, "subject") or "Proofpoint email threat")
    setNestedField(result, "finding_info.desc", getValue(event, "threatInfoDescription") or getValue(event, "subject"))

    -- Types from classification / modulesRun
    local types = {}
    local cls = getValue(event, "classification"); if cls then table.insert(types, tostring(cls)) end
    local modules = getValue(event, "modulesRun") or {}
    for _, m in ipairs(modules) do table.insert(types, tostring(m)) end
    if #types > 0 then setNestedField(result, "finding_info.types", types) end

    -- Actor (sender)
    setNestedField(result, "actor.user.email_addr", getValue(event, "sender"))
    setNestedField(result, "actor.user.name", getValue(event, "headerFrom"))
    setNestedField(result, "src_endpoint.ip", getValue(event, "senderIP"))

    -- Recipient
    local recipients = getValue(event, "recipient") or getValue(event, "toAddresses") or {}
    if type(recipients) == 'table' and recipients[1] then
        setNestedField(result, "user.email_addr", recipients[1])
    end

    -- Email object
    setNestedField(result, "email.message_uid", getValue(event, "messageID"))
    setNestedField(result, "email.subject", getValue(event, "subject"))
    setNestedField(result, "email.from", getValue(event, "sender"))
    if type(recipients) == 'table' then setNestedField(result, "email.to", recipients) end
    setNestedField(result, "email.size", tonumber(getValue(event, "messageSize")))
    setNestedField(result, "email.smtp_from", getValue(event, "sender"))

    -- Evidences (URLs, malware, subject)
    local urls = getValue(event, "threatUrl") or getValue(event, "threatsInfoMap") or {}
    if type(urls) == 'string' then urls = { urls } end
    if type(urls) == 'table' then
        for _, u in ipairs(urls) do
            table.insert(result.evidences, { data = { url = u }, type = "url" })
        end
    end
    local mal = getValue(event, "malwareFamily")
    if mal then table.insert(result.evidences, { data = { malware_family = mal }, type = "malware" }) end
    table.insert(result.evidences,
        { data = { subject = getValue(event, "subject"), sender = getValue(event, "sender") }, type = "email_headers" })

    -- Severity
    local sev = severityIdFromScores(getValue(event, "spamScore"), getValue(event, "phishScore"))
    result.severity_id = sev

    -- Status mapping (quarantined, delivered, blocked)
    local pr = getValue(event, "policyRoutes") or {}
    if type(pr) == 'table' and pr[1] then
        local r0 = string.lower(tostring(pr[1]))
        if r0 == "quarantine" then result.status_id = 6 -- Supressed/Handled
        elseif r0 == "block" or r0 == "reject" then result.status_id = 2
        else result.status_id = 1 end
    end

    -- Metadata
    setNestedField(result, "metadata.uid", getValue(event, "id") or getValue(event, "GUID"))
    setNestedField(result, "metadata.log_name", "proofpoint_tap")
    setNestedField(result, "metadata.event_code", tostring(getValue(event, "QID") or ""))
    setNestedField(result, "metadata.correlation_uid", getValue(event, "cluster"))

    -- Observables
    result.observables = {}
    if getValue(event, "sender") then
        table.insert(result.observables, { name = "actor.user.email_addr", type = "Email Address", type_id = 5, value = getValue(event, "sender") })
    end
    if type(recipients) == 'table' and recipients[1] then
        table.insert(result.observables, { name = "user.email_addr", type = "Email Address", type_id = 5, value = recipients[1] })
    end
    if getValue(event, "senderIP") then
        table.insert(result.observables, { name = "src_endpoint.ip", type = "IP Address", type_id = 2, value = getValue(event, "senderIP") })
    end

    result.message = string.format("Proofpoint threat '%s' from %s to %s",
        tostring(result.finding_info.title),
        tostring(getValue(event, "sender") or "unknown"),
        tostring((type(recipients) == 'table' and recipients[1]) or "unknown"))
    setNestedField(result, "raw_data", event)
    return result
end
