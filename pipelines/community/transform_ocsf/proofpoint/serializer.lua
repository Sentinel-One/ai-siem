-- =====================================================================
-- OCSF Detection Finding (2004) serializer for Proofpoint Mail / PPS
-- sendmail syslog events as parsed and delivered by Observo's PPS collector.
--
-- Observo PARSES the sendmail line upstream and exposes structured
-- fields under event.sm.*. This serializer reads those directly.
--
--   event = {
--     data      = "<raw syslog line>",
--     id        = "<observo event uid>",
--     ts        = "2026-04-20T12:01:11.185179-05:00",
--     timestamp = "2026-04-20T17:01:45.850050142Z",     -- agent ingest UTC
--     metadata  = { customerId, origin = { data = {agent, cid, theater} } },
--     pps       = { agent, cid, theater },
--     sm        = { qid, guid, from, to, msgid, sizeBytes, nrcpts, relay,
--                   mailer, stat, dsn, delay, xdelay, proto, daemon, auth,
--                   class, messageTs, pri },
--     tls       = { cipher, verify, version }
--   }
--
-- v8 -- 2026-04-20 -- fixes vs. v7:
--   1. parseIsoMs now honors the timezone offset and millisecond fraction
--      (was: dropped TZ + fractional seconds, time was 5h off).
--   2. email.delivered_to no longer carries the relay host (was wrong:
--      sendmail relay is a hop, not a recipient). Relay is now split
--      into {hostname, ip} and placed in src_endpoint (inbound "from=")
--      or dst_endpoint (outbound "to="), with IP parsed from "host [ip]".
--   3. email.x_originating_ip removed (was incorrectly being set to
--      sm.mailer, e.g. literal string "esmtp"). Originating IP is now
--      derived from the inbound relay bracket and exposed as
--      src_endpoint.ip.
--   4. raw_data is now opt-in via INCLUDE_RAW_DATA flag (was: always
--      duplicated full event, which caused -115% pipeline optimization).
--   5. Empty objects (user, unmapped, evidences, observables, email)
--      are stripped before return.
--   6. status_id / severity_id mapped to OCSF Detection Finding (2004)
--      enum semantics, not Success/Failure ad-hoc.
--   7. finding_info.uid now combines sm.qid + direction so inbound
--      "from=" and outbound "to=" with the same qid don't collide.
--   8. tls fields moved into email.x_tls.* (top-level "tls" was outside
--      the OCSF schema and ended up in unmapped on the SIEM side).
--   9. dsn moved to email.x_dsn (was overloading status_code).
--  10. metadata.correlation_uid no longer falls back to customerId
--      (caused unrelated events to share a correlation_uid).
--  11. email.smtp_to / email.to consistent (both arrays).
--  12. relay hop, mailer, proto, auth, class, daemon promoted to
--      unmapped.* so they survive OCSF strict validators.
-- =====================================================================

local CLASS_UID = 2004
local CATEGORY_UID = 2
-- Set to true only for serializer debugging -- doubles output size.
local INCLUDE_RAW_DATA = false

-- ---------- helpers --------------------------------------------------
local function safeTimeMs()
    local ok, secs = pcall(os.time)
    if ok and secs then return secs * 1000 end
    return 0
end

local function getNestedField(obj, path)
    if obj == nil or path == nil or path == '' then return nil end
    local cursor = obj
    for key in string.gmatch(path, '[^.]+') do
        if type(cursor) ~= 'table' then return nil end
        if cursor[key] == nil then return nil end
        cursor = cursor[key]
    end
    return cursor
end

local function setNestedField(obj, path, value)
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

local function getValue(tbl, key, default)
    if tbl == nil then return default end
    local v = tbl[key]
    if v == nil then return default end
    return v
end

local function no_nulls(d)
    if type(d) == 'table' then
        for k, v in pairs(d) do
            if type(v) == 'userdata' then d[k] = nil
            elseif type(v) == 'table' then no_nulls(v) end
        end
    end
    return d
end

local function isEmptyTable(t)
    if type(t) ~= 'table' then return false end
    return next(t) == nil
end

-- Recursively prune empty tables and nil values from the result.
local function prune(t)
    if type(t) ~= 'table' then return t end
    for k, v in pairs(t) do
        if type(v) == 'table' then
            prune(v)
            if isEmptyTable(v) then t[k] = nil end
        end
    end
    return t
end

local function stripBrackets(s)
    if type(s) ~= 'string' then return s end
    local inner = s:match("^<(.*)>$")
    if inner then return inner end
    return s
end

-- Parse ISO-8601 like "2026-04-20T12:01:11.185179-05:00".
-- Returns milliseconds since the Unix epoch in UTC, honoring the offset
-- and the fractional second. Falls back to nil when the input doesn't
-- look like ISO-8601.
local function parseIsoMs(s)
    if type(s) ~= 'string' then return nil end
    local y, mo, d, h, mi, se, frac, tz =
        s:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)([%.%d]*)([Zz%+%-][%d:]*)")
    if not y then
        -- secondary attempt without TZ (treat as UTC)
        y, mo, d, h, mi, se = s:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
        if not y then return nil end
        tz = "Z"
        frac = ""
    end
    -- Build seconds-since-epoch using a manual UTC computation (os.time
    -- assumes local time, which silently drifts the result by the host
    -- TZ offset -- this is the bug we are fixing).
    local function daysFromCivil(yy, mm, dd)
        yy = yy - (mm <= 2 and 1 or 0)
        local era = math.floor(yy / 400)
        local yoe = yy - era * 400
        local doy = math.floor((153 * ((mm + (mm > 2 and -3 or 9))) + 2) / 5) + dd - 1
        local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
        return era * 146097 + doe - 719468
    end
    local secs = daysFromCivil(tonumber(y), tonumber(mo), tonumber(d)) * 86400
        + tonumber(h) * 3600 + tonumber(mi) * 60 + tonumber(se)
    -- Apply fractional second (millisecond resolution is all OCSF needs).
    local ms = 0
    if frac and #frac > 1 then
        local f = tonumber(frac) or 0
        ms = math.floor(f * 1000 + 0.5)
    end
    -- Subtract the declared TZ offset to land in UTC.
    local offsetSec = 0
    if tz and tz ~= "Z" and tz ~= "z" then
        local sign, oh, om = tz:match("([%+%-])(%d%d):?(%d?%d?)")
        if sign and oh then
            local oms = tonumber(om) or 0
            offsetSec = (tonumber(oh) * 3600 + oms * 60) * (sign == "-" and -1 or 1)
        end
    end
    return (secs - offsetSec) * 1000 + ms
end

-- Parse a sendmail relay field like:
--   "fnni-com.mail.protection.outlook.com. [52.101.42.18]"
--   "m0247037.ppops.net [127.0.0.1]"
-- into { hostname = "...", ip = "..." }.
local function parseRelay(s)
    if type(s) ~= 'string' or #s == 0 then return nil end
    local host, ip = s:match("^(%S+)%s+%[([%d%.:a-fA-F]+)%]")
    if host then
        host = host:gsub("%.$", "")  -- trim trailing dot
        return { hostname = host, ip = ip }
    end
    -- only a host, no bracket
    return { hostname = s }
end

-- ---------- skeleton -------------------------------------------------
local function buildSkeleton(t)
    local ts = t or safeTimeMs()
    return {
        class_uid = CLASS_UID,
        category_uid = CATEGORY_UID,
        type_uid = 200401,
        activity_id = 1,
        severity_id = 1,
        status_id = 1,
        time = ts,
        metadata = {
            version = "1.1.0",
            product = { name = "Proofpoint Mail", vendor_name = "Proofpoint" }
        },
        finding_info = { uid = "unknown", title = "Proofpoint Mail event" },
        actor = {},
        evidences = {},
        observables = {},
        email = {},
        cloud = { provider = "Proofpoint" },
        unmapped = {}
    }
end

-- ---------- main entry ------------------------------------------------
function processEvent(event)
    if type(event) ~= 'table' then return buildSkeleton() end
    no_nulls(event)

    local sm = getValue(event, "sm") or {}
    local md = getValue(event, "metadata") or {}
    local origin_data = getNestedField(event, "metadata.origin.data") or {}
    local tls = getValue(event, "tls") or {}

    -- Prefer event.ts (the syslog timestamp), then sm.messageTs, then
    -- the agent's ingest timestamp. parseIsoMs now honors timezone +
    -- fractional seconds.
    local ts = parseIsoMs(getValue(event, "ts"))
        or parseIsoMs(getValue(sm, "messageTs"))
        or parseIsoMs(getValue(event, "timestamp"))
        or safeTimeMs()

    local result = buildSkeleton(ts)

    -- ISO 8601 string for SIEMs that prefer time_dt
    setNestedField(result, "time_dt", getValue(event, "ts")
        or getValue(sm, "messageTs")
        or getValue(event, "timestamp"))

    -- ----- raw syslog as message ------------------------------------
    local raw_line = getValue(event, "data")
    if type(raw_line) == 'string' and #raw_line > 0 then
        setNestedField(result, "message", raw_line)
    else
        setNestedField(result, "message", "Proofpoint Mail event")
    end

    -- ----- direction (inbound vs outbound) --------------------------
    -- Type A "from=" lines have sm.from but not sm.to.
    -- Type B "to="   lines have sm.to but not sm.from.
    local has_from = type(getValue(sm, "from")) == 'string' and #getValue(sm, "from") > 0
    local has_to = (type(getValue(sm, "to")) == 'table' and #getValue(sm, "to") > 0)
        or (type(getValue(sm, "to")) == 'string' and #getValue(sm, "to") > 0)
    local direction
    if has_to and not has_from then
        direction = "Outbound"
    elseif has_from and not has_to then
        direction = "Inbound"
    end
    if direction then setNestedField(result, "email.direction", direction) end

    -- ----- finding_info --------------------------------------------
    -- qid alone collides between the inbound and outbound entry of the
    -- same message. Combine qid with direction to keep them distinct.
    local qid = getValue(sm, "qid") or getValue(sm, "guid") or getValue(event, "id")
    local uid_suffix = direction == "Outbound" and ":o"
        or direction == "Inbound" and ":i"
        or ""
    setNestedField(result, "finding_info.uid",
        tostring(qid or "unknown") .. uid_suffix)

    local stat = getValue(sm, "stat")
    local title
    if type(stat) == 'string' and #stat > 0 then
        local stat_word = stat:match("^(%a+)") or "event"
        title = "Proofpoint Mail " .. stat_word
    elseif has_from then
        title = "Proofpoint Mail queued"
    elseif has_to then
        title = "Proofpoint Mail delivery"
    else
        title = "Proofpoint Mail event"
    end
    setNestedField(result, "finding_info.title", title)

    -- ----- email envelope ------------------------------------------
    local sender = stripBrackets(getValue(sm, "from"))
    if type(sender) == 'string' and #sender > 0 then
        setNestedField(result, "actor.user.email_addr", sender)
        setNestedField(result, "email.from", sender)
        setNestedField(result, "email.smtp_from", sender)
    end

    -- Recipients: always emit as arrays for OCSF consistency.
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
        local clean = stripBrackets(sm_to)
        if type(clean) == 'string' and #clean > 0 then
            primary_rcpt = clean
            table.insert(rcpt_list, clean)
        end
    end
    if primary_rcpt then
        setNestedField(result, "user.email_addr", primary_rcpt)
    end
    if #rcpt_list > 0 then
        setNestedField(result, "email.to", rcpt_list)
        setNestedField(result, "email.smtp_to", rcpt_list)
    end

    -- Message-ID, size, mailer
    local msgid = stripBrackets(getValue(sm, "msgid"))
    if type(msgid) == 'string' and #msgid > 0 then
        setNestedField(result, "email.message_uid", msgid)
    end
    local size = tonumber(getValue(sm, "sizeBytes"))
    if size then setNestedField(result, "email.size", size) end
    local mailer = getValue(sm, "mailer")
    if type(mailer) == 'string' and #mailer > 0 then
        setNestedField(result, "email.x_mailer", mailer)
    end

    -- ----- relay hop -> src/dst endpoint ---------------------------
    -- For inbound (sm.from): relay is the local PPS host (127.0.0.1).
    -- For outbound (sm.to):  relay is the downstream MTA we delivered to.
    local relay_parsed = parseRelay(getValue(sm, "relay"))
    if relay_parsed then
        if direction == "Outbound" then
            if relay_parsed.hostname then
                setNestedField(result, "dst_endpoint.hostname", relay_parsed.hostname)
            end
            if relay_parsed.ip then
                setNestedField(result, "dst_endpoint.ip", relay_parsed.ip)
            end
        else
            -- Inbound (or unknown direction) -- relay is the originating
            -- hop as seen by sendmail. Surface it under src_endpoint.
            if relay_parsed.hostname then
                setNestedField(result, "src_endpoint.hostname", relay_parsed.hostname)
            end
            if relay_parsed.ip then
                setNestedField(result, "src_endpoint.ip", relay_parsed.ip)
            end
        end
    end

    -- The PPS agent (m0247037.ppops.net) -- always useful as the host
    -- that produced the syslog line.
    local agent_host = getValue(origin_data, "agent")
        or getNestedField(event, "pps.agent")
    if type(agent_host) == 'string' and #agent_host > 0 then
        setNestedField(result, "metadata.logged_time_dt",
            getValue(event, "timestamp"))
        if direction ~= "Outbound" then
            -- avoid clobbering parsed src_endpoint.hostname for outbound
            if not getNestedField(result, "src_endpoint.hostname") then
                setNestedField(result, "src_endpoint.hostname", agent_host)
            end
        end
    end

    -- ----- status / severity ---------------------------------------
    -- OCSF Detection Finding (2004) status_id enum:
    --   0 Unknown, 1 New, 2 In Progress, 3 Suppressed,
    --   4 Resolved, 99 Other
    if type(stat) == 'string' and #stat > 0 then
        local s = stat:lower()
        if s:match("^sent") then
            setNestedField(result, "status_id", 4)            -- Resolved
            setNestedField(result, "status", "Sent")
        elseif s:match("defer") or s:match("queued") then
            setNestedField(result, "status_id", 2)            -- In Progress
            setNestedField(result, "status", "Deferred")
        elseif s:match("bounce") or s:match("reject")
                or s:match("refus") or s:match("unknown") then
            setNestedField(result, "status_id", 99)           -- Other
            setNestedField(result, "status", "Bounced")
            setNestedField(result, "severity_id", 3)          -- Medium
        else
            setNestedField(result, "status_id", 99)
            setNestedField(result, "status", stat:sub(1, 80))
        end
    end

    -- DSN code goes alongside status as a custom email field -- not
    -- as the Detection Finding status_code (which has its own semantics).
    local dsn = getValue(sm, "dsn")
    if type(dsn) == 'string' and #dsn > 0 then
        setNestedField(result, "email.x_dsn", dsn)
    end

    -- ----- TLS context ----------------------------------------------
    -- Top-level "tls" is not part of the 2004 schema; surface it under
    -- email.x_tls so SIEM strict validators don't drop it into unmapped.
    local tls_version = getValue(tls, "version")
    if type(tls_version) == 'string' and tls_version ~= "NONE" then
        setNestedField(result, "email.x_tls.version", tls_version)
    end
    local tls_cipher = getValue(tls, "cipher")
    if type(tls_cipher) == 'string' and tls_cipher ~= "NONE" then
        setNestedField(result, "email.x_tls.cipher", tls_cipher)
    end
    local tls_verify = getValue(tls, "verify")
    if type(tls_verify) == 'string' and tls_verify ~= "NONE" then
        setNestedField(result, "email.x_tls.verify", tls_verify)
    end

    -- ----- envelope provenance --------------------------------------
    setNestedField(result, "metadata.uid", getValue(event, "id"))
    setNestedField(result, "metadata.log_name", "proofpoint_mail")
    -- Only set correlation_uid when we have the actual session guid;
    -- never fall back to customerId (unrelated events would share it).
    if getValue(sm, "guid") then
        setNestedField(result, "metadata.correlation_uid", sm.guid)
    end
    local cid = getValue(origin_data, "cid") or getNestedField(event, "pps.cid")
    if type(cid) == 'string' and #cid > 0 then
        setNestedField(result, "cloud.account.name", cid)
    end
    local theater = getValue(origin_data, "theater")
        or getNestedField(event, "pps.theater")
    if type(theater) == 'string' and #theater > 0 then
        setNestedField(result, "cloud.region", theater)
    end

    -- ----- unmapped (kept for forensic value) -----------------------
    local function um(field, source_key)
        local v = getValue(sm, source_key)
        if v ~= nil then setNestedField(result, "unmapped." .. field, v) end
    end
    um("proto", "proto")
    um("daemon", "daemon")
    um("auth", "auth")
    um("class", "class")
    um("delay", "delay")
    um("xdelay", "xdelay")
    um("pri", "pri")
    um("nrcpts", "nrcpts")
    um("relay_raw", "relay")
    if getValue(sm, "qid") then
        setNestedField(result, "unmapped.qid", sm.qid)
    end

    -- ----- evidence + observables ----------------------------------
    if sender or primary_rcpt or qid then
        table.insert(result.evidences, {
            type = "email_headers",
            data = {
                queue_id = qid,
                sender = sender,
                recipient = primary_rcpt,
                stat = stat,
                relay = getValue(sm, "relay"),
                msgid = msgid,
                size = size,
            }
        })
    end

    if type(sender) == 'string' and #sender > 0 then
        table.insert(result.observables, {
            name = "actor.user.email_addr", type = "Email Address",
            type_id = 5, value = sender
        })
    end
    if type(primary_rcpt) == 'string' and #primary_rcpt > 0 then
        table.insert(result.observables, {
            name = "user.email_addr", type = "Email Address",
            type_id = 5, value = primary_rcpt
        })
    end
    local s_host = getNestedField(result, "src_endpoint.hostname")
    if type(s_host) == 'string' and #s_host > 0 then
        table.insert(result.observables, {
            name = "src_endpoint.hostname", type = "Hostname",
            type_id = 1, value = s_host
        })
    end
    local s_ip = getNestedField(result, "src_endpoint.ip")
    if type(s_ip) == 'string' and #s_ip > 0 then
        table.insert(result.observables, {
            name = "src_endpoint.ip", type = "IP Address",
            type_id = 2, value = s_ip
        })
    end
    local d_host = getNestedField(result, "dst_endpoint.hostname")
    if type(d_host) == 'string' and #d_host > 0 then
        table.insert(result.observables, {
            name = "dst_endpoint.hostname", type = "Hostname",
            type_id = 1, value = d_host
        })
    end
    local d_ip = getNestedField(result, "dst_endpoint.ip")
    if type(d_ip) == 'string' and #d_ip > 0 then
        table.insert(result.observables, {
            name = "dst_endpoint.ip", type = "IP Address",
            type_id = 2, value = d_ip
        })
    end
    if type(qid) == 'string' and #qid > 0 then
        table.insert(result.observables, {
            name = "finding_info.uid", type = "Other UID",
            type_id = 40, value = qid
        })
    end
    if type(msgid) == 'string' and #msgid > 0 then
        table.insert(result.observables, {
            name = "email.message_uid", type = "Other UID",
            type_id = 40, value = msgid
        })
    end

    if INCLUDE_RAW_DATA then
        setNestedField(result, "raw_data", event)
    end

    return prune(result)
end
