-- OCSF Detection Finding (2004) serializer for Proofpoint Mail / Protection Server
-- sendmail syslog events as delivered by Observo's PPS collector.
--
-- Observo PARSES the sendmail line upstream and exposes structured fields
-- under event.sm.*. This serializer reads those directly and avoids regex:
--
--   event = {
--     data      = "<raw syslog line>",
--     id        = "<observo event uid>",
--     ts        = "2026-04-20T12:01:11.185179-05:00",
--     timestamp = "2026-04-20T17:01:45.850050142Z",
--     metadata  = { customerId, origin = { data = {agent, cid, theater} } },
--     pps       = { agent, cid, theater },
--     sm        = { qid, guid, from, to, msgid, sizeBytes, nrcpts, relay,
--                   mailer, stat, dsn, delay, xdelay, proto, daemon, auth,
--                   class, messageTs, pri },
--     tls       = { cipher, verify, version }
--   }
--
-- Log Message is always event.data so the raw syslog is visible in Observo.
-- Email fields are populated from event.sm.* (much more reliable than parsing).

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

-- Strip <...> angle brackets from RFC5321 addresses. Returns the address
-- verbatim if no brackets are present.
function stripBrackets(s)
    if type(s) ~= 'string' then return s end
    local inner = s:match("^<(.*)>$")
    if inner then return inner end
    return s
end

-- Parse an ISO-8601 timestamp like "2026-04-20T12:01:11.185179-05:00" into ms.
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
    if type(event) ~= 'table' then return buildSkeleton() end
    no_nulls(event)

    local sm = getValue(event, "sm") or {}
    local md = getValue(event, "metadata") or {}
    local origin_data = getNestedField(event, "metadata.origin.data") or {}
    local tls = getValue(event, "tls") or {}

    local ts = parseIsoMs(getValue(event, "ts"))
        or parseIsoMs(getValue(event, "timestamp"))
        or parseIsoMs(getValue(sm, "messageTs"))
        or safeTimeMs()

    local result = buildSkeleton(ts)

    -- MESSAGE: the raw syslog line, verbatim. This is what the customer sees
    -- in the Observo Log Message panel.
    local raw_line = getValue(event, "data")
    if type(raw_line) == 'string' and #raw_line > 0 then
        setNestedField(result, "message", raw_line)
    else
        setNestedField(result, "message", "Proofpoint Mail event")
    end

    -- finding_info: prefer sendmail queue id as uid, fall back to guid / observo id.
    local qid = getValue(sm, "qid") or getValue(sm, "guid") or getValue(event, "id") or "unknown"
    setNestedField(result, "finding_info.uid", tostring(qid))

    local stat = getValue(sm, "stat")
    local title
    if type(stat) == 'string' and #stat > 0 then
        -- "Sent (...)" lines have the action in the stat prefix.
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

    -- Email sender / actor
    local sender = stripBrackets(getValue(sm, "from"))
    if type(sender) == 'string' and #sender > 0 then
        setNestedField(result, "actor.user.email_addr", sender)
        setNestedField(result, "email.from", sender)
        setNestedField(result, "email.smtp_from", sender)
    end

    -- Recipient: sm.to is an array OR the sm.to field may be absent on from= lines.
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

    -- Email envelope details
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
    local mailer = getValue(sm, "mailer")
    if type(mailer) == 'string' then setNestedField(result, "email.x_originating_ip", mailer) end

    -- Status from sendmail stat= or dsn=
    if type(stat) == 'string' and #stat > 0 then
        local s = stat:lower()
        if s:match("^sent") then
            setNestedField(result, "status_id", 1) -- Success
            setNestedField(result, "status", "Sent")
        elseif s:match("defer") or s:match("queued") then
            setNestedField(result, "status_id", 3)
            setNestedField(result, "status", stat:sub(1, 40))
        elseif s:match("bounce") or s:match("reject") or s:match("refus") or s:match("unknown") then
            setNestedField(result, "status_id", 2)
            setNestedField(result, "status", stat:sub(1, 40))
            setNestedField(result, "severity_id", 3)
        else
            setNestedField(result, "status", stat:sub(1, 40))
        end
    end
    local dsn = getValue(sm, "dsn")
    if type(dsn) == 'string' and #dsn > 0 then
        setNestedField(result, "status_code", dsn)
    end

    -- TLS context (if present, otherwise skip)
    local tls_version = getValue(tls, "version")
    if type(tls_version) == 'string' and tls_version ~= "NONE" then
        setNestedField(result, "tls.version", tls_version)
    end
    local tls_cipher = getValue(tls, "cipher")
    if type(tls_cipher) == 'string' and tls_cipher ~= "NONE" then
        setNestedField(result, "tls.cipher", tls_cipher)
    end

    -- Observo envelope -> metadata + cloud
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
    return result
end
