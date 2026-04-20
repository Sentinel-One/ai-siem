-- OCSF Detection Finding (2004) serializer for Proofpoint Mail / Protection Server
-- sendmail syslog events shipped via the ppops agents.
--
-- Input shape (observed in the Observo UI on 2026-04-20):
--   {
--     "data": "2026-04-20T10:55:17.078188-05:00 m0Z47039 sendmail[1584358]: 63KEwj...",
--     "id":   "L+lg4IZKM+rQ/HOhC7tJYQ",
--     "metadata": {
--       "customerId": "<uuid>",
--       "origin": { "data": { "agent": "m0Z47039.ppops.net",
--                             "cid": "fnbnebraska_hosted",
--                             "theater": "us" } }
--     },
--     "pps": { "agent": "m0Z47039.ppops.net" }
--   }
--
-- The raw sendmail line lives in event.data as a string -- this is what we
-- put into the OCSF message field. We also best-effort parse it to pull the
-- queue id (for finding_info.uid), from=/to= addresses, size=, and stat=.

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
    local ok, v = pcall(function()
        return os.time({year = tonumber(y), month = tonumber(mo), day = tonumber(d),
                         hour = tonumber(h), min = tonumber(mi), sec = tonumber(se)}) * 1000
    end)
    if ok and v then return v end
    return nil
end

-- Pull common fields out of a sendmail syslog line.
-- Returns a table with: queue_id, from_addr, to_addr, size, stat, relay.
-- Any field not found in the line stays nil.
function parseSendmailLine(line)
    local out = {}
    if type(line) ~= 'string' or #line == 0 then return out end

    -- Queue id sits right after 'sendmail[<pid>]: '
    -- e.g. "sendmail[1584358]: 63KEwj00134567"
    out.queue_id = line:match("sendmail%[[%d]+%]:%s+([%w%d]+)")

    -- from=<addr> (the canonical sendmail form). Require a word-boundary
    -- separator (start-of-string, space, tab, or comma) before "from=" so we
    -- never match strings like "xfrom=" or misaligned positions.
    local fa = line:match("[%s,]from=<([^>]+)>")
        or line:match("^from=<([^>]+)>")
        or line:match("[%s,]from=([^%s,>]+)")
        or line:match("^from=([^%s,>]+)")
    if fa then out.from_addr = fa end

    -- to=<addr> (same boundary rule; prevents "proto=ESMTP" from matching).
    local ta = line:match("[%s,]to=<([^>]+)>")
        or line:match("^to=<([^>]+)>")
        or line:match("[%s,]to=([^%s,>]+)")
        or line:match("^to=([^%s,>]+)")
    if ta then out.to_addr = ta end

    -- size=NNNN
    local sz = line:match("size=(%d+)")
    if sz then out.size = tonumber(sz) end

    -- stat=Sent | stat=Deferred | stat=Bounced | stat=Rejected
    local st = line:match("stat=([^,%s]+)")
    if st then out.stat = st end

    -- relay=host.domain [ipaddress]
    local rl = line:match("relay=([%w%.%-_]+)")
    if rl then out.relay = rl end

    return out
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

    -- Raw syslog line is in event.data (Proofpoint Mail / PPS shape).
    -- Older TAP callers put structured fields at the top level -- we still
    -- check for those so one script covers both input modes.
    local raw_line = getValue(event, "data")
        or getValue(event, "message")
        or getValue(event, "rawMessage")

    -- Timestamp: parse from the start of the syslog line, else from TAP
    -- messageTime, else current.
    local ts = nil
    if type(raw_line) == 'string' and #raw_line > 0 then
        ts = parseIsoMs(raw_line)
    end
    if not ts then ts = parseIsoMs(getValue(event, "messageTime")) end
    if not ts then ts = safeTimeMs() end

    local result = buildSkeleton(ts)

    -- MESSAGE: the raw log line, verbatim.
    if type(raw_line) == 'string' and #raw_line > 0 then
        setNestedField(result, "message", raw_line)
    else
        setNestedField(result, "message", "Proofpoint Mail event")
    end

    -- Parse the sendmail line for structured fields.
    local parsed = parseSendmailLine(raw_line)

    -- finding_info.uid: sendmail queue id preferred, then Observo event.id,
    -- then TAP GUID, then messageID.
    local uid = parsed.queue_id
        or getValue(event, "id")
        or getValue(event, "GUID")
        or getValue(event, "messageID")
        or "unknown"
    setNestedField(result, "finding_info.uid", uid)

    -- finding_info.title: for PPS lines we describe the action, for TAP we
    -- use threatName/subject.
    local title
    if parsed.stat then
        title = "Proofpoint Mail " .. tostring(parsed.stat)
    else
        title = getValue(event, "threatName")
            or getValue(event, "subject")
            or "Proofpoint Mail event"
    end
    setNestedField(result, "finding_info.title", title)

    -- Actor / user (sender / recipient)
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

    -- Email envelope details
    setNestedField(result, "email.message_uid", getValue(event, "messageID"))
    setNestedField(result, "email.subject", getValue(event, "subject"))
    if parsed.size then setNestedField(result, "email.size", parsed.size) end
    if parsed.relay then setNestedField(result, "email.delivered_to", parsed.relay) end

    -- Status mapping from sendmail stat=... or TAP policyRoutes
    if parsed.stat then
        local s = parsed.stat:lower()
        if s:match("sent") then
            setNestedField(result, "status_id", 1)   -- Success
            setNestedField(result, "status", "Sent")
        elseif s:match("defer") or s:match("queued") then
            setNestedField(result, "status_id", 3)   -- Pending
            setNestedField(result, "status", parsed.stat)
        elseif s:match("bounce") or s:match("reject") or s:match("refus") then
            setNestedField(result, "status_id", 2)   -- Failure
            setNestedField(result, "status", parsed.stat)
            setNestedField(result, "severity_id", 3)
        else
            setNestedField(result, "status", parsed.stat)
        end
    else
        local pr = getValue(event, "policyRoutes") or {}
        if type(pr) == 'table' and type(pr[1]) == 'string' then
            local r0 = pr[1]:lower()
            if r0 == "quarantine" then setNestedField(result, "status_id", 6)
            elseif r0 == "block" or r0 == "reject" then setNestedField(result, "status_id", 2)
            else setNestedField(result, "status_id", 1) end
        end
    end

    -- Metadata from the Observo envelope
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

    -- Evidences — email headers for triage
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
