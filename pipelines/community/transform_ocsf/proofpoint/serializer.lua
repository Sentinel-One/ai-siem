-- OCSF Detection Finding (2004) serializer for Proofpoint Mail / Protection Server
-- sendmail syslog events as delivered by Observo's PPS collector.
--
-- Incorporates Orion review fixes (2026-04-20):
--   * parseIsoMs is timezone-aware (the raw syslog timestamp carries -05:00
--     and we previously dropped it, yielding events 5h off).
--   * no_nulls runs on the OUTPUT result, never on the incoming event (avoids
--     mutating the event the downstream pipeline also sees).
--   * Email delivery outcomes go into disposition_id (1 Allowed / 2 Blocked /
--     14 Delayed / 25 Rejected) -- NOT status_id. For class 2004,
--     status_id means New/In Progress/Suppressed/Resolved -- completely
--     different semantics.
--   * pcall-guarded os.time() throughout.

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

-- Scrub userdata nil markers. Applied only to the OUTPUT result, never to
-- the incoming event -- the pipeline downstream may still need the event
-- intact.
function no_nulls(d)
    if type(d) == 'table' then
        for k, v in pairs(d) do
            if type(v) == 'userdata' then d[k] = nil
            elseif type(v) == 'table' then no_nulls(v) end
        end
    end
    return d
end

function stripBrackets(s)
    if type(s) ~= 'string' then return s end
    local inner = s:match("^<(.*)>$")
    if inner then return inner end
    return s
end

-- Timezone-aware ISO-8601 parser. Handles "2026-04-20T12:01:11.185179-05:00"
-- and normalizes to UTC milliseconds. os.time() on a calendar table treats
-- the input as LOCAL time; to get a stable UTC ms we compute the local
-- result then subtract our local epoch offset and add the parsed offset.
function parseIsoMs(s)
    if type(s) ~= 'string' then return nil end
    local y, mo, d, h, mi, se = s:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if not y then return nil end
    local offset_secs = 0
    if s:sub(-1) == "Z" then
        offset_secs = 0
    else
        local sgn, oh, om = s:match("([%+%-])(%d%d):(%d%d)$")
        if sgn and oh and om then
            offset_secs = (tonumber(oh) * 3600 + tonumber(om) * 60)
            if sgn == "-" then offset_secs = -offset_secs end
        end
    end
    local yN, moN, dN = tonumber(y), tonumber(mo), tonumber(d)
    local hN, miN, seN = tonumber(h), tonumber(mi), tonumber(se)
    if not (yN and moN and dN and hN and miN and seN) then return nil end
    local yAdj = yN
    if moN <= 2 then yAdj = yN - 1 end
    local era = math.floor(yAdj / 400)
    local yoe = yAdj - era * 400
    local mp
    if moN > 2 then mp = moN - 3 else mp = moN + 9 end
    local doy = math.floor((153 * mp + 2) / 5) + dN - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468
    local utc_seconds = days * 86400 + hN * 3600 + miN * 60 + seN - offset_secs
    return utc_seconds * 1000
end

function buildSkeleton(t)
    local ts = t or safeTimeMs()
    return {
        class_uid = CLASS_UID,
        category_uid = CATEGORY_UID,
        type_uid = 200401,
        activity_id = 1,
        severity_id = 1,
        status_id = 1,  -- OCSF 2004: 1 = New (finding lifecycle, NOT delivery)
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
    if type(event) ~= 'table' then return no_nulls(buildSkeleton()) end

    local sm = getValue(event, "sm") or {}
    local md = getValue(event, "metadata") or {}
    local origin_data = getNestedField(event, "metadata.origin.data") or {}
    local tls = getValue(event, "tls") or {}

    -- Timestamp: prefer the per-event syslog ts (has -05:00 offset),
    -- then the ingestion timestamp (has Z offset), then sm.messageTs.
    local ts = parseIsoMs(getValue(event, "ts"))
        or parseIsoMs(getValue(event, "timestamp"))
        or parseIsoMs(getValue(sm, "messageTs"))
        or safeTimeMs()

    local result = buildSkeleton(ts)

    -- MESSAGE: the raw syslog line verbatim (what the analyst sees in Log Message).
    local raw_line = getValue(event, "data")
    if type(raw_line) == 'string' and #raw_line > 0 then
        setNestedField(result, "message", raw_line)
    else
        setNestedField(result, "message", "Proofpoint Mail event")
    end

    -- finding_info.uid: queue id preferred, then sm.guid, then event.id.
    local qid = getValue(sm, "qid") or getValue(sm, "guid") or getValue(event, "id") or "unknown"
    setNestedField(result, "finding_info.uid", tostring(qid))

    local stat = getValue(sm, "stat")
    local title
    if type(stat) == 'string' and #stat > 0 then
        local stat_word = stat:match("^(%a+)")
        title = "Proofpoint Mail " .. (stat_word or stat)
    elseif getValue(sm, "from") then
        title = "Proofpoint Mail queued"
    elseif getValue(sm, "to") then
        title = "Proofpoint Mail delivery"
    else
        title = "Proofpoint Mail event"
    end
    setNestedField(result, "finding_info.title", title)

    -- Actor / sender
    local sender = stripBrackets(getValue(sm, "from"))
    if type(sender) == 'string' and #sender > 0 then
        setNestedField(result, "actor.user.email_addr", sender)
        setNestedField(result, "email.from", sender)
        setNestedField(result, "email.smtp_from", sender)
    end

    -- Recipient (array or single string)
    local primary_rcpt
    local rcpt_list = {}
    local sm_to = getValue(sm, "to")
    if type(sm_to) == 'table' then
        for _, r in ipairs(sm_to) do
            local clean = stripBrackets(r)
            if type(clean) == 'string' and #clean > 0 then
                table.insert(rcpt_list, clean)
                if not primary_rcpt then primary_rcpt = clean end
            end
        end
    elseif type(sm_to) == 'string' then
        primary_rcpt = stripBrackets(sm_to)
        if primary_rcpt and #primary_rcpt > 0 then rcpt_list = { primary_rcpt } end
    end
    if type(primary_rcpt) == 'string' and #primary_rcpt > 0 then
        setNestedField(result, "user.email_addr", primary_rcpt)
        setNestedField(result, "email.smtp_to", primary_rcpt)
    end
    if #rcpt_list > 0 then
        setNestedField(result, "email.to", rcpt_list)
    end

    -- Email envelope
    local msgid = stripBrackets(getValue(sm, "msgid"))
    if type(msgid) == 'string' and #msgid > 0 then
        setNestedField(result, "email.message_uid", msgid)
    end
    local size = tonumber(getValue(sm, "sizeBytes"))
    if size then setNestedField(result, "email.size", size) end
    local relay = getValue(sm, "relay")
    if type(relay) == 'string' and #relay > 0 then
        setNestedField(result, "email.delivered_to", relay)
    end

    -- DELIVERY OUTCOME -> disposition_id (NOT status_id, per OCSF 2004 semantics).
    -- status_id on class 2004 is the finding lifecycle state
    -- (1 New / 2 In Progress / 3 Suppressed / 4 Resolved). We leave it at 1 (New).
    -- disposition_id carries the action outcome:
    --   1  = Allowed (sent)
    --   2  = Blocked (rejected/refused)
    --   14 = Delayed (deferred/queued)
    --   25 = Rejected (bounced)
    if type(stat) == 'string' and #stat > 0 then
        local s = stat:lower()
        if s:match("^sent") then
            setNestedField(result, "disposition_id", 1)
            setNestedField(result, "disposition", "Allowed")
        elseif s:match("defer") or s:match("queued") then
            setNestedField(result, "disposition_id", 14)
            setNestedField(result, "disposition", "Delayed")
        elseif s:match("bounce") or s:match("unknown") or s:match("user unknown") then
            setNestedField(result, "disposition_id", 25)
            setNestedField(result, "disposition", "Rejected")
            setNestedField(result, "severity_id", 3)
        elseif s:match("reject") or s:match("refus") or s:match("block") then
            setNestedField(result, "disposition_id", 2)
            setNestedField(result, "disposition", "Blocked")
            setNestedField(result, "severity_id", 3)
        end
    end
    local dsn = getValue(sm, "dsn")
    if type(dsn) == 'string' and #dsn > 0 then
        setNestedField(result, "status_detail", "DSN " .. dsn)
    end

    -- TLS context (skip "NONE" values)
    local tls_version = getValue(tls, "version")
    if type(tls_version) == 'string' and tls_version ~= "NONE" and #tls_version > 0 then
        setNestedField(result, "tls.version", tls_version)
    end
    local tls_cipher = getValue(tls, "cipher")
    if type(tls_cipher) == 'string' and tls_cipher ~= "NONE" and #tls_cipher > 0 then
        setNestedField(result, "tls.cipher", tls_cipher)
    end

    -- Metadata & cloud context from Observo envelope
    setNestedField(result, "metadata.uid", getValue(event, "id"))
    setNestedField(result, "metadata.log_name", "proofpoint_mail")
    setNestedField(result, "metadata.correlation_uid",
        getValue(sm, "guid") or getValue(md, "customerId"))

    local agent_host = getValue(origin_data, "agent") or getNestedField(event, "pps.agent")
    if type(agent_host) == 'string' and #agent_host > 0 then
        setNestedField(result, "src_endpoint.hostname", agent_host)
    end
    local cid = getValue(origin_data, "cid") or getNestedField(event, "pps.cid")
    if type(cid) == 'string' and #cid > 0 then
        setNestedField(result, "cloud.account.name", cid)
    end
    local theater = getValue(origin_data, "theater") or getNestedField(event, "pps.theater")
    if type(theater) == 'string' and #theater > 0 then
        setNestedField(result, "cloud.region", theater)
    end

    -- Evidences
    if sender or primary_rcpt or qid then
        table.insert(result.evidences, { data = {
            queue_id = qid,
            sender = sender,
            recipient = primary_rcpt,
            stat = stat,
            relay = relay,
            msgid = msgid,
            size = size,
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
    if type(qid) == 'string' and #qid > 0 and qid ~= "unknown" then
        table.insert(result.observables,
            { name = "finding_info.uid", type = "Other UID", type_id = 40, value = qid })
    end
    if type(msgid) == 'string' and #msgid > 0 then
        table.insert(result.observables,
            { name = "email.message_uid", type = "Other UID", type_id = 40, value = msgid })
    end

    setNestedField(result, "raw_data", event)
    -- Scrub userdata on the RESULT only (not on event).
    return no_nulls(result)
end
