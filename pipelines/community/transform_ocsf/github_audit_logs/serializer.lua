--------------------------------------------------------------------------------
-- GitHub Audit Log → OCSF 1.3.0 API Activity (class_uid = 6003)
-- Observo processEvent(event) contract
-- Author: Observo AI  |  Schema: OCSF 1.3.0  |  Class: API Activity (6003)
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- FEATURES: Runtime feature flags
--------------------------------------------------------------------------------
local FEATURES = {
    PRESERVE_RAW          = true,   -- keep raw_data field on the OCSF event
    ENRICH_HTTP_REQUEST   = true,   -- populate http_request object from user_agent / method
    ENRICH_RESOURCES      = true,   -- populate resources[] from repo / team / user fields
    ENRICH_CLOUD          = true,   -- populate cloud object from org / business fields
    ENRICH_SRC_ENDPOINT   = true,   -- populate src_endpoint from actor_ip / country_code
    STRIP_EMPTY_STRINGS   = true,   -- remove "" values before returning
    INCLUDE_OSINT         = true,   -- include empty osint stub (required by schema)
}

--------------------------------------------------------------------------------
-- FIELD_ORDERS: Canonical top-level key ordering for downstream consumers
-- (Lua tables are unordered; this table is used by serializers that respect it)
--------------------------------------------------------------------------------
local FIELD_ORDERS = {
    "class_uid",
    "class_name",
    "category_uid",
    "category_name",
    "activity_id",
    "activity_name",
    "type_uid",
    "type_name",
    "time",
    "severity_id",
    "severity",
    "status",
    "status_id",
    "status_code",
    "status_detail",
    "message",
    "metadata",
    "actor",
    "api",
    "http_request",
    "src_endpoint",
    "dst_endpoint",
    "cloud",
    "resources",
    "observables",
    "osint",
    "raw_data",
    "unmapped",
}

--------------------------------------------------------------------------------
-- ACTION_MAP: GitHub audit log action prefix → OCSF activity_id
-- activity_id: 0=Unknown 1=Create 2=Read 3=Update 4=Delete 99=Other
--------------------------------------------------------------------------------
local ACTION_MAP = {
    -- Create patterns
    create          = 1,
    add             = 1,
    invite          = 1,
    fork            = 1,
    push            = 1,
    publish         = 1,
    generate        = 1,
    register        = 1,
    deploy          = 1,
    open            = 1,
    -- Read patterns
    access          = 2,
    view            = 2,
    list            = 2,
    get             = 2,
    read            = 2,
    export          = 2,
    download        = 2,
    -- Update patterns
    update          = 3,
    edit            = 3,
    modify          = 3,
    change          = 3,
    enable          = 3,
    disable         = 3,
    rename          = 3,
    transfer        = 3,
    restore         = 3,
    merge           = 3,
    approve         = 3,
    -- Delete patterns
    delete          = 4,
    remove          = 4,
    destroy         = 4,
    revoke          = 4,
    cancel          = 4,
    reject          = 4,
    archive         = 4,
}

--------------------------------------------------------------------------------
-- OPERATION_TYPE_MAP: GitHub operation_type → OCSF activity_id (fallback)
--------------------------------------------------------------------------------
local OPERATION_TYPE_MAP = {
    create  = 1,
    read    = 2,
    update  = 3,
    remove  = 4,
    restore = 3,
    modify  = 3,
    access  = 2,
}

--------------------------------------------------------------------------------
-- ACTIVITY_NAMES: activity_id → human-readable name
--------------------------------------------------------------------------------
local ACTIVITY_NAMES = {
    [0]  = "Unknown",
    [1]  = "Create",
    [2]  = "Read",
    [3]  = "Update",
    [4]  = "Delete",
    [99] = "Other",
}

--------------------------------------------------------------------------------
-- STATUS_MAP: GitHub result/outcome strings → OCSF status + status_id
--------------------------------------------------------------------------------
local STATUS_MAP = {
    success     = { label = "Success", id = 1 },
    succeeded   = { label = "Success", id = 1 },
    allow       = { label = "Success", id = 1 },
    permitted   = { label = "Success", id = 1 },
    failure     = { label = "Failure", id = 2 },
    failed      = { label = "Failure", id = 2 },
    deny        = { label = "Failure", id = 2 },
    denied      = { label = "Failure", id = 2 },
    blocked     = { label = "Failure", id = 2 },
    error       = { label = "Failure", id = 2 },
    unknown     = { label = "Unknown", id = 0 },
}

--------------------------------------------------------------------------------
-- FIELD_MAP: GitHub audit log field → OCSF destination path
-- Paths use dot-notation; deepSet() resolves nested tables automatically.
--------------------------------------------------------------------------------
local FIELD_MAP = {
    -- Actor / User
    ["actor"]                           = "actor.user.name",
    ["actor_id"]                        = "actor.user.uid",
    ["actor_ip"]                        = "src_endpoint.ip",
    ["actor_location.country_code"]     = "src_endpoint.location.country",
    ["actor_location.region"]           = "src_endpoint.location.region",
    ["actor_location.city"]             = "src_endpoint.location.city",
    ["actor_location.postal_code"]      = "src_endpoint.location.postal_code",
    ["actor_location.latitude"]         = "src_endpoint.location.lat",
    ["actor_location.longitude"]        = "src_endpoint.location.long",

    -- Session / Token
    ["token_id"]                        = "actor.session.uid",
    ["hashed_token"]                    = "actor.session.credential_uid",
    ["programmatic_access_type"]        = "actor.session.issuer",

    -- API / Action
    ["action"]                          = "api.operation",
    ["operation_type"]                  = "api.request.flags",

    -- Repository / Resource
    ["repo"]                            = "api.request.data.repo",
    ["repo_id"]                         = "api.request.data.repo_id",

    -- Organization / Cloud
    ["org"]                             = "cloud.org.name",
    ["org_id"]                          = "cloud.org.uid",
    ["business"]                        = "cloud.account.name",
    ["business_id"]                     = "cloud.account.uid",

    -- HTTP / Network
    ["user_agent"]                      = "http_request.user_agent",
    ["request_id"]                      = "http_request.uid",

    -- Timing
    ["created_at"]                      = "time",
    ["@timestamp"]                      = "time",
    ["_time"]                           = "time",

    -- Metadata / Correlation
    ["_document_id"]                    = "metadata.uid",
    ["document_id"]                     = "metadata.uid",

    -- Status
    ["result"]                          = "status",
    ["result_type"]                     = "status_detail",
    ["explanation"]                     = "status_detail",
}

--------------------------------------------------------------------------------
-- HELPER: deepGet
-- Safely retrieves a value from a nested table using dot-notation path.
-- Supports simple array index syntax: "key[1]"
--------------------------------------------------------------------------------
local function deepGet(obj, path)
    if obj == nil or path == nil then return nil end
    local current = obj
    for part in path:gmatch("[^%.]+") do
        if current == nil then return nil end
        local key, idx = part:match("^(.-)%[(%d+)%]$")
        if key and idx then
            local tbl = current[key]
            if type(tbl) == "table" then
                current = tbl[tonumber(idx)]
            else
                return nil
            end
        else
            current = current[part]
        end
    end
    return current
end

--------------------------------------------------------------------------------
-- HELPER: deepSet
-- Safely sets a value in a nested table using dot-notation path.
-- Creates intermediate tables as needed.
-- Skips nil and empty-string values.
-- Auto-coerces numeric strings for port/id/uid/lat/long fields.
--------------------------------------------------------------------------------
local function deepSet(obj, path, value)
    if value == nil then return end
    if FEATURES.STRIP_EMPTY_STRINGS and value == "" then return end

    -- Numeric coercion for known numeric destination paths
    local numeric_hints = {
        "port", "uid", "lat", "long", "bytes", "packets",
        "severity_id", "status_id", "activity_id", "class_uid",
        "category_uid", "type_uid", "timezone_offset",
    }
    for _, hint in ipairs(numeric_hints) do
        if path:find(hint) then
            local n = tonumber(value)
            if n then value = n end
            break
        end
    end

    local keys = {}
    for k in path:gmatch("[^%.]+") do
        table.insert(keys, k)
    end

    local current = obj
    for i = 1, #keys - 1 do
        local k = keys[i]
        if type(current[k]) ~= "table" then
            current[k] = {}
        end
        current = current[k]
    end
    current[keys[#keys]] = value
end

--------------------------------------------------------------------------------
-- HELPER: stripEmpty
-- Recursively removes nil and empty-string values from a table.
--------------------------------------------------------------------------------
local function stripEmpty(t)
    if type(t) ~= "table" then return end
    local to_remove = {}
    for k, v in pairs(t) do
        if v == nil or v == "" then
            table.insert(to_remove, k)
        elseif type(v) == "table" then
            stripEmpty(v)
            if next(v) == nil then
                table.insert(to_remove, k)
            end
        end
    end
    for _, k in ipairs(to_remove) do
        t[k] = nil
    end
end

--------------------------------------------------------------------------------
-- HELPER: toEpochMs
-- Converts various GitHub timestamp formats to epoch milliseconds (integer).
-- Handles: Unix ms (number), ISO-8601 strings, epoch seconds.
--------------------------------------------------------------------------------
local function toEpochMs(val)
    if val == nil then return nil end

    -- Already a number
    if type(val) == "number" then
        -- GitHub created_at is epoch milliseconds
        if val > 1e12 then return math.floor(val) end
        -- Epoch seconds → ms
        return math.floor(val * 1000)
    end

    if type(val) == "string" then
        -- Try numeric string
        local n = tonumber(val)
        if n then
            if n > 1e12 then return math.floor(n) end
            return math.floor(n * 1000)
        end

        -- ISO-8601: "2024-06-15T12:34:56Z" or "2024-06-15T12:34:56.000Z"
        local y, mo, d, h, mi, s =
            val:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
        if y then
            local ok, ts = pcall(function()
                return os.time({
                    year  = tonumber(y),
                    month = tonumber(mo),
                    day   = tonumber(d),
                    hour  = tonumber(h),
                    min   = tonumber(mi),
                    sec   = tonumber(s),
                })
            end)
            if ok and ts then return ts * 1000 end
        end
    end

    return nil
end

--------------------------------------------------------------------------------
-- HELPER: inferActivityId
-- Derives OCSF activity_id from GitHub action string and operation_type.
-- Strategy:
--   1. Check operation_type (most explicit)
--   2. Parse the verb segment of action (e.g. "repo.create" → "create")
--   3. Scan ACTION_MAP for substring match on the full action string
--   4. Default to 99 (Other)
--------------------------------------------------------------------------------
local function inferActivityId(action, operation_type)
    -- 1. operation_type takes priority
    if operation_type then
        local ot = string.lower(tostring(operation_type))
        if OPERATION_TYPE_MAP[ot] then
            return OPERATION_TYPE_MAP[ot]
        end
    end

    if action == nil then return 0 end
    local act_lower = string.lower(tostring(action))

    -- 2. Extract verb: last segment after last dot (e.g. "org.add_member" → "add_member")
    --    then first word before underscore (e.g. "add_member" → "add")
    local verb_segment = act_lower:match("%.([^%.]+)$") or act_lower
    local verb = verb_segment:match("^([a-z]+)") or verb_segment

    if ACTION_MAP[verb] then
        return ACTION_MAP[verb]
    end

    -- 3. Substring scan for compound verbs
    for pattern, id in pairs(ACTION_MAP) do
        if act_lower:find(pattern) then
            return id
        end
    end

    -- 4. Default: Other
    return 99
end

--------------------------------------------------------------------------------
-- HELPER: inferStatus
-- Maps GitHub result / outcome strings to OCSF status + status_id.
--------------------------------------------------------------------------------
local function inferStatus(val)
    if val == nil then return nil, nil end
    local lower = string.lower(tostring(val))
    local entry = STATUS_MAP[lower]
    if entry then
        return entry.label, entry.id
    end
    return "Other", 99
end

--------------------------------------------------------------------------------
-- HELPER: buildResources
-- Constructs the OCSF resources[] array from GitHub repo / team / user targets.
--------------------------------------------------------------------------------
local function buildResources(event)
    local resources = {}

    local function addResource(name, rtype, uid)
        if name or uid then
            table.insert(resources, {
                name  = name  or nil,
                type  = rtype or "Unknown",
                uid   = uid   or nil,
            })
        end
    end

    addResource(event["repo"],       "Repository", tostring(event["repo_id"] or ""))
    addResource(event["team"],       "Team",       tostring(event["team_id"] or ""))
    addResource(event["user"],       "User",       tostring(event["user_id"] or ""))
    addResource(event["project"],    "Project",    nil)
    addResource(event["workflow"],   "Workflow",   nil)
    addResource(event["runner_id"] and ("runner:" .. tostring(event["runner_id"])) or nil,
                "Runner", tostring(event["runner_id"] or ""))

    if #resources == 0 then return nil end
    return resources
end

--------------------------------------------------------------------------------
-- HELPER: buildObservables
-- Constructs OCSF observables[] from key indicator fields.
--------------------------------------------------------------------------------
local function buildObservables(event)
    local obs = {}

    local function addObs(name, type_id, value)
        if value and value ~= "" then
            table.insert(obs, {
                name     = name,
                type_id  = type_id,
                type     = "Other",
                value    = tostring(value),
            })
        end
    end

    -- type_id 1 = Hostname, 2 = IP Address, 3 = URL, 20 = User Name, 99 = Other
    addObs("actor",          20, event["actor"])
    addObs("actor_ip",        2, event["actor_ip"])
    addObs("repo",           99, event["repo"])
    addObs("org",            99, event["org"])
    addObs("hashed_token",   99, event["hashed_token"])

    if #obs == 0 then return nil end
    return obs
end

--------------------------------------------------------------------------------
-- MAIN: processEvent
-- Entry point required by the Observo Lua transform runtime.
--------------------------------------------------------------------------------
function processEvent(event)

    --------------------------------------------------------------------------
    -- INNER: core transform logic (wrapped in pcall for safety)
    --------------------------------------------------------------------------
    local function execute(e)

        -- Snapshot of all source keys for unmapped tracking
        local source_keys = {}
        for k in pairs(e) do source_keys[k] = true end

        -- Keys consumed by explicit mappings (excluded from unmapped)
        local consumed = {}

        -----------------------------------------------------------------------
        -- 1. Seed the OCSF skeleton with required constant fields
        -----------------------------------------------------------------------
        local ocsf = {
            class_uid     = 6003,
            class_name    = "API Activity",
            category_uid  = 6,
            category_name = "Application Activity",
            severity_id   = 1,          -- Informational (default; override below)
            severity      = "Informational",
            metadata = {
                version = "1.3.0",
                product = {
                    vendor_name = "GitHub",
                    name        = "GitHub Audit Log",
                    feature     = { name = "Audit" },
                },
            },
            osint    = {},              -- required by schema; populated if data present
            unmapped = {},
        }

        -----------------------------------------------------------------------
        -- 2. Apply FIELD_MAP: source field → OCSF destination path
        -----------------------------------------------------------------------
        for src_field, dest_path in pairs(FIELD_MAP) do
            -- Support dot-notation source paths (e.g. "actor_location.country_code")
            local val = deepGet(e, src_field)
            if val ~= nil then
                -- Special handling: time fields → epoch ms
                if dest_path == "time" then
                    val = toEpochMs(val)
                end
                if val ~= nil then
                    deepSet(ocsf, dest_path, val)
                    consumed[src_field] = true
                end
            end
        end

        -----------------------------------------------------------------------
        -- 3. Resolve time: prefer created_at, fallback chain
        -----------------------------------------------------------------------
        if ocsf.time == nil then
            local fallbacks = { "created_at", "@timestamp", "_time", "timestamp", "time" }
            for _, fb in ipairs(fallbacks) do
                local ts = toEpochMs(e[fb])
                if ts then
                    ocsf.time = ts
                    consumed[fb] = true
                    break
                end
            end
        end
        -- Final fallback: current time
        if ocsf.time == nil then
            local ok, ts = pcall(os.time)
            ocsf.time = ok and (ts * 1000) or 0
        end

        -----------------------------------------------------------------------
        -- 4. Infer activity_id, type_uid, activity_name
        -----------------------------------------------------------------------
        local action         = e["action"]
        local operation_type = e["operation_type"]
        local activity_id    = inferActivityId(action, operation_type)

        ocsf.activity_id   = activity_id
        ocsf.activity_name = ACTIVITY_NAMES[activity_id] or "Other"
        ocsf.type_uid      = 6003 * 100 + activity_id   -- e.g. 600301 for Create
        ocsf.type_name     = "API Activity: " .. (ACTIVITY_NAMES[activity_id] or "Other")

        consumed["action"]         = true
        consumed["operation_type"] = true

        -----------------------------------------------------------------------
        -- 5. Status resolution
        -----------------------------------------------------------------------
        local raw_status = e["result"] or e["outcome"] or e["status"]
        if raw_status then
            local label, id = inferStatus(raw_status)
            ocsf.status    = label
            ocsf.status_id = id
            consumed["result"]  = true
            consumed["outcome"] = true
            consumed["status"]  = true
        end

        if e["result_type"] and e["result_type"] ~= "" then
            ocsf.status_code = tostring(e["result_type"])
            consumed["result_type"] = true
        end

        if e["explanation"] and e["explanation"] ~= "" then
            ocsf.status_detail = tostring(e["explanation"])
            consumed["explanation"] = true
        end

        -----------------------------------------------------------------------
        -- 6. Severity inference from action / result
        -----------------------------------------------------------------------
        -- Elevate severity for destructive or failed operations
        if ocsf.status_id == 2 then
            -- Failure → Low severity
            ocsf.severity_id = 2
            ocsf.severity    = "Low"
        end
        if activity_id == 4 then
            -- Delete → Medium severity
            ocsf.severity_id = 3
            ocsf.severity    = "Medium"
        end
        -- Explicit severity override from source
        if e["severity"] then
            local sev_lower = string.lower(tostring(e["severity"]))
            local sev_map = {
                informational = { id = 1, label = "Informational" },
                low           = { id = 2, label = "Low" },
                medium        = { id = 3, label = "Medium" },
                high          = { id = 4, label = "High" },
                critical      = { id = 5, label = "Critical" },
                fatal         = { id = 6, label = "Fatal" },
            }
            local sev_entry = sev_map[sev_lower]
            if sev_entry then
                ocsf.severity_id = sev_entry.id
                ocsf.severity    = sev_entry.label
                consumed["severity"] = true
            end
        end

        -----------------------------------------------------------------------
        -- 7. Enrich: http_request object
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_HTTP_REQUEST then
            if not ocsf.http_request then ocsf.http_request = {} end
            if e["user_agent"] and e["user_agent"] ~= "" then
                ocsf.http_request.user_agent = e["user_agent"]
                consumed["user_agent"] = true
            end
            if e["request_id"] and e["request_id"] ~= "" then
                ocsf.http_request.uid = e["request_id"]
                consumed["request_id"] = true
            end
            -- HTTP method inference from action verb
            if action then
                local act_lower = string.lower(tostring(action))
                if act_lower:find("create") or act_lower:find("add") or
                   act_lower:find("push")   or act_lower:find("fork") then
                    ocsf.http_request.http_method = "POST"
                elseif act_lower:find("delete") or act_lower:find("remove") or
                       act_lower:find("destroy") then
                    ocsf.http_request.http_method = "DELETE"
                elseif act_lower:find("update") or act_lower:find("edit") or
                       act_lower:find("modify")  or act_lower:find("enable") or
                       act_lower:find("disable") then
                    ocsf.http_request.http_method = "PATCH"
                elseif act_lower:find("get") or act_lower:find("list") or
                       act_lower:find("view") or act_lower:find("access") then
                    ocsf.http_request.http_method = "GET"
                end
            end
            if next(ocsf.http_request) == nil then
                ocsf.http_request = nil
            end
        end

        -----------------------------------------------------------------------
        -- 8. Enrich: resources[]
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_RESOURCES then
            local resources = buildResources(e)
            if resources then
                ocsf.resources = resources
                consumed["repo"]       = true
                consumed["repo_id"]    = true
                consumed["team"]       = true
                consumed["team_id"]    = true
                consumed["user"]       = true
                consumed["user_id"]    = true
                consumed["project"]    = true
                consumed["workflow"]   = true
                consumed["runner_id"]  = true
            end
        end

        -----------------------------------------------------------------------
        -- 9. Enrich: cloud object
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_CLOUD then
            if not ocsf.cloud then ocsf.cloud = {} end
            ocsf.cloud.provider = "GitHub"
            if e["org"] and e["org"] ~= "" then
                if not ocsf.cloud.org then ocsf.cloud.org = {} end
                ocsf.cloud.org.name = e["org"]
                consumed["org"] = true
            end
            if e["org_id"] then
                if not ocsf.cloud.org then ocsf.cloud.org = {} end
                ocsf.cloud.org.uid = tostring(e["org_id"])
                consumed["org_id"] = true
            end
            if e["business"] and e["business"] ~= "" then
                if not ocsf.cloud.account then ocsf.cloud.account = {} end
                ocsf.cloud.account.name = e["business"]
                consumed["business"] = true
            end
            if e["business_id"] then
                if not ocsf.cloud.account then ocsf.cloud.account = {} end
                ocsf.cloud.account.uid = tostring(e["business_id"])
                consumed["business_id"] = true
            end
        end

        -----------------------------------------------------------------------
        -- 10. Enrich: src_endpoint (ensure required object exists)
        -----------------------------------------------------------------------
        if FEATURES.ENRICH_SRC_ENDPOINT then
            if not ocsf.src_endpoint then ocsf.src_endpoint = {} end
            -- Ensure at minimum an empty object satisfies the required field
        end

        -----------------------------------------------------------------------
        -- 11. Ensure required actor object exists
        -----------------------------------------------------------------------
        if not ocsf.actor then ocsf.actor = {} end
        if not ocsf.actor.user then ocsf.actor.user = {} end

        -- Populate actor.user.type_id (1 = User)
        ocsf.actor.user.type_id = 1
        ocsf.actor.user.type    = "User"

        -- actor.user.account (GitHub org context)
        if e["org"] and e["org"] ~= "" then
            if not ocsf.actor.user.account then ocsf.actor.user.account = {} end
            ocsf.actor.user.account.name = e["org"]
        end

        -----------------------------------------------------------------------
        -- 12. Ensure required api object exists
        -----------------------------------------------------------------------
        if not ocsf.api then ocsf.api = {} end
        if action and action ~= "" then
            ocsf.api.operation = action
            consumed["action"] = true
        end
        -- api.service: GitHub REST/GraphQL
        ocsf.api.service = {
            name    = e["programmatic_access_type"] or "GitHub REST API",
            version = e["api_version"] or nil,
        }
        consumed["programmatic_access_type"] = true
        consumed["api_version"]              = true

        -- api.request: additional request context
        if not ocsf.api.request then ocsf.api.request = {} end
        if e["_document_id"] or e["document_id"] then
            ocsf.api.request.uid = e["_document_id"] or e["document_id"]
            consumed["_document_id"] = true
            consumed["document_id"]  = true
        end

        -----------------------------------------------------------------------
        -- 13. Observables
        -----------------------------------------------------------------------
        local observables = buildObservables(e)
        if observables then
            ocsf.observables = observables
        end

        -----------------------------------------------------------------------
        -- 14. OSINT stub (required by schema)
        -----------------------------------------------------------------------
        if FEATURES.INCLUDE_OSINT then
            ocsf.osint = {}
        end

        -----------------------------------------------------------------------
        -- 15. raw_data preservation
        -----------------------------------------------------------------------
        if FEATURES.PRESERVE_RAW then
            local ok_enc, raw_str = pcall(json.encode, e)
            if ok_enc and raw_str then
                ocsf.raw_data = raw_str
            end
        end

        -----------------------------------------------------------------------
        -- 16. Collect unmapped fields
        -----------------------------------------------------------------------
        local mapped_top_level = {
            "actor", "actor_id", "actor_ip", "actor_location",
            "action", "operation_type",
            "repo", "repo_id", "team", "team_id",
            "user", "user_id", "project", "workflow", "runner_id",
            "org", "org_id", "business", "business_id",
            "user_agent", "request_id",
            "created_at", "@timestamp", "_time", "timestamp", "time",
            "_document_id", "document_id",
            "result", "outcome", "status", "result_type", "explanation",
            "severity",
            "token_id", "hashed_token", "programmatic_access_type", "api_version",
        }
        local mapped_set = {}
        for _, k in ipairs(mapped_top_level) do mapped_set[k] = true end
        for k in pairs(consumed) do mapped_set[k] = true end

        for k, v in pairs(e) do
            if not mapped_set[k] then
                ocsf.unmapped[k] = v
            end
        end
        if next(ocsf.unmapped) == nil then
            ocsf.unmapped = nil
        end

        -----------------------------------------------------------------------
        -- 17. Strip empty strings / empty tables (optional)
        -----------------------------------------------------------------------
        if FEATURES.STRIP_EMPTY_STRINGS then
            stripEmpty(ocsf)
        end

        -----------------------------------------------------------------------
        -- 18. Compose human-readable message
        -----------------------------------------------------------------------
        local actor_name = deepGet(ocsf, "actor.user.name") or "unknown"
        local api_op     = deepGet(ocsf, "api.operation")   or "unknown"
        local org_name   = deepGet(ocsf, "cloud.org.name")  or ""
        local repo_name  = deepGet(ocsf, "api.request.data.repo") or ""

        local msg_parts = {
            string.format("GitHub audit: actor=%s action=%s", actor_name, api_op),
        }
        if org_name  ~= "" then table.insert(msg_parts, "org="  .. org_name)  end
        if repo_name ~= "" then table.insert(msg_parts, "repo=" .. repo_name) end
        ocsf.message = table.concat(msg_parts, " ")

        -----------------------------------------------------------------------
        -- 19. Encode final OCSF event into message as raw JSON string
        --     (OCSF convention: message contains the full serialized event)
        -----------------------------------------------------------------------
        local ok_msg, json_str = pcall(json.encode, ocsf)
        if ok_msg and json_str then
            ocsf.message = json_str
        end

        return ocsf
    end -- end execute()

    --------------------------------------------------------------------------
    -- Safety wrapper: pcall prevents pipeline crashes on malformed events
    --------------------------------------------------------------------------
    local ok, result = pcall(execute, event)
    if ok then
        return result
    else
        -- Passthrough with error annotation on failure
        event["_ocsf_error"]          = tostring(result)
        event["_ocsf_serializer"]     = "github_audit_api_activity"
        event["_ocsf_parse_failed"]   = "true"
        return event
    end

end -- end processEvent()
