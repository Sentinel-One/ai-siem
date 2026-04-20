-- OCSF Detection Finding (2004) serializer for Proofpoint Mail / Protection Server.
-- Designed for maximum resilience: the Log Message field will ALWAYS show the
-- raw log payload regardless of whether the upstream pipeline parsed it into
-- fields or kept it as a syslog string.

local CLASS_UID = 2004
local CATEGORY_UID = 2

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

-- Flatten ANY value into a readable string. Never returns nil, never throws.
-- Tables become key=value comma lists (one level deep is enough for logs).
function flattenToString(v, depth)
    if depth == nil then depth = 0 end
    if v == nil then return "" end
    local t = type(v)
    if t == 'string' then return v end
    if t == 'number' or t == 'boolean' then return tostring(v) end
    if depth > 3 then return "..." end
    if t == 'table' then
        local parts = {}
        for k, val in pairs(v) do
            local sk = tostring(k)
            local sv = flattenToString(val, depth + 1)
            if #sv > 200 then sv = string.sub(sv, 1, 200) end
            table.insert(parts, sk .. "=" .. sv)
        end
        return table.concat(parts, " ")
    end
    return tostring(v) or ""
end

-- Find the raw log text in the event, wherever the upstream pipeline put it.
-- Checks every known convention (data/message/raw/rawMessage/_raw/log/line).
-- If none present, falls back to flattening the whole event to a readable string.
function pickRawMessage(event)
    if type(event) ~= 'table' then return tostring(event) end
    local candidates = {"data", "message", "rawMessage", "raw_message", "raw", "_raw", "log", "line", "body"}
    for _, key in ipairs(candidates) do
        local v = getValue(event, key)
        if type(v) == 'string' and #v > 0 then
            return v
        end
    end
    -- Second pass: any top-level string value that looks like a log line
    for _, v in pairs(event) do
        if type(v) == 'string' and #v > 20 then
            return v
        end
    end
    -- Last resort: flatten the event
    return flattenToString(event, 0)
end

function parseSendmailLine(line)
    local out = {}
    if type(line) ~= 'string' or #line == 0 then return out end
    out.queue_id = line:match("sendmail%[[%d]+%]:%s+([%w%d]+)")
    out.from_addr = line:match("[%s,]from=<([^>]+)>")
        or line:match("^from=<([^>]+)>")
        or line:match("[%s,]from=([^%s,>]+)")
    out.to_addr = line:match("[%s,]to=<([^>]+)>")
        or line:match("^to=<([^>]+)>")
        or line:match("[%s,]to=([^%s,>]+)")
    local sz = line:match("size=(%d+)")
    if sz then out.size = tonumber(sz) end
    out.stat = line:match("stat=([^,%s]+)")
    out.relay = line:match("relay=([%w%.%-_]+)")
    return out
end

function parseIsoMs(s)
    if type(s) ~= 'string' then return nil end
    local y, mo, d, h, mi, se = s:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if not y then return nil end
    local ok, v = pcall(function()
        return os.time({year = tonumber(y), month = tonumber(mo), day = tonumber(d),
                         hour = tonumber(h), min = tonumber(mi), sec = tonumber(se)}) * 1000
    end)
    if ok and v then return v end
    return nil
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
        metadata = { version = "1.1.0",
                     product = { name = "Proofpoint Mail", vendor_name = "Proofpoint" } },
        finding_info = { uid = "unknown", title = "Proofpoint Mail event" },
        actor = { user = {} }, user = {}, evidences = {}, email = {},
        cloud = { provider = "Proofpoint" },
        unmapped = {}
    }
end

function processEvent(event)
    if type(event) ~= 'table' then
        local skel = buildSkeleton()
        setNestedField(skel, "message", flattenToString(event, 0))
        return skel
    end
    no_nulls(event)

    -- ALWAYS set message to something meaningful from the event.
    local raw_msg = pickRawMessage(event)
    local ts = parseIsoMs(raw_msg) or safeTimeMs()
    local result = buildSkeleton(ts)
    setNestedField(result, "message", raw_msg)

    -- Best-effort sendmail parse (only runs usefully when raw_msg is a sendmail line).
    local parsed = parseSendmailLine(raw_msg)

    -- finding_info.uid
    local uid = parsed.queue_id
        or getValue(event, "id")
        or getValue(event, "GUID")
        or getValue(event, "messageID")
        or "unknown"
    setNestedField(result, "finding_info.uid", uid)

    -- finding_info.title
    local title
    if parsed.stat then
        title = "Proofpoint Mail " .. tostring(parsed.stat)
    else
        title = getValue(event, "threatName")
            or getValue(event, "subject")
            or "Proofpoint Mail event"
    end
    setNestedField(result, "finding_info.title", title)

    -- Actor / user
    local sender = parsed.from_addr or getValue(event, "sender")
    if type(sender) == 'string' and #sender > 0 then
        setNestedField(result, "actor.user.email_addr", sender)
        setNestedField(result, "email.from", sender)
        setNestedField(result, "email.smtp_from", sender)
    end

    local tap_recipients = getValue(event, "recipient") or getValue(event, "toAddresses")
    local primary_rcpt = parsed.to_addr
    if not primary_rcpt and type(tap_recipients) == 'table' and type(tap_recipients[1]) == 'string' then
        primary_rcpt = tap_recipients[1]
    end
    if type(primary_rcpt) == 'string' and #primary_rcpt > 0 then
        setNestedField(result, "user.email_addr", primary_rcpt)
        setNestedField(result, "email.smtp_to", primary_rcpt)
        setNestedField(result, "email.to", { primary_rcpt })
    end

    setNestedField(result, "email.message_uid", getValue(event, "messageID"))
    setNestedField(result, "email.subject", getValue(event, "subject"))
    if parsed.size then setNestedField(result, "email.size", parsed.size) end
    if parsed.relay then setNestedField(result, "email.delivered_to", parsed.relay) end

    -- Status
    if parsed.stat then
        local s = parsed.stat:lower()
        if s:match("sent") then
            setNestedField(result, "status_id", 1)
            setNestedField(result, "status", "Sent")
        elseif s:match("defer") or s:match("queued") then
            setNestedField(result, "status_id", 3)
            setNestedField(result, "status", parsed.stat)
        elseif s:match("bounce") or s:match("reject") or s:match("refus") then
            setNestedField(result, "status_id", 2)
            setNestedField(result, "status", parsed.stat)
            setNestedField(result, "severity_id", 3)
        else
            setNestedField(result, "status", parsed.stat)
        end
    end

    -- Metadata
    setNestedField(result, "metadata.uid", getValue(event, "id"))
    setNestedField(result, "metadata.log_name", "proofpoint_mail")
    setNestedField(result, "metadata.correlation_uid",
        getNestedField(event, "metadata.customerId") or getValue(event, "cluster"))

    local agent_host = getNestedField(event, "metadata.origin.data.agent")
        or getNestedField(event, "pps.agent")
    if type(agent_host) == 'string' then
        setNestedField(result, "src_endpoint.hostname", agent_host)
    end
    local cid = getNestedField(event, "metadata.origin.data.cid")
    if type(cid) == 'string' then setNestedField(result, "cloud.account.name", cid) end
    local theater = getNestedField(event, "metadata.origin.data.theater")
    if type(theater) == 'string' then setNestedField(result, "cloud.region", theater) end

    -- Evidences
    if sender or primary_rcpt or parsed.queue_id then
        table.insert(result.evidences, { data = {
            queue_id = parsed.queue_id,
            sender = sender,
            recipient = primary_rcpt,
            stat = parsed.stat,
            relay = parsed.relay,
        }, type = "email_headers" })
    end

    -- Observables
    result.observables = {}
    if type(sender) == 'string' and #sender > 0 then
        table.insert(result.observables,
            { name = "actor.user.email_addr", type = "Email Address", type_id = 5, value = sender })
    end
    if type(primary_rcpt) == 'string' and #primary_rcpt > 0 then
        table.insert(result.observables,
            { name = "user.email_addr", type = "Email Address", type_id = 5, value = primary_rcpt })
    end
    if type(agent_host) == 'string' and #agent_host > 0 then
        table.insert(result.observables,
            { name = "src_endpoint.hostname", type = "Hostname", type_id = 1, value = agent_host })
    end
    if type(parsed.queue_id) == 'string' and #parsed.queue_id > 0 then
        table.insert(result.observables,
            { name = "finding_info.uid", type = "Other UID", type_id = 40, value = parsed.queue_id })
    end

    setNestedField(result, "raw_data", event)
    return result
end
