
-- Lua implementation for Okta OCSF 1.0.0 schema

-- Helper function to safely access nested dictionary keys
function safelyAccessNestedDictKeys(keys, dictObject)
    local current = dictObject
    for _, key in ipairs(keys) do
        if current and type(current) == "table" then
            current = current[key]
        else
            return nil
        end
    end
    return current
end

-- Helper function to split string by delimiter
function split(str, delimiter)
    local result = {}
    -- Escape special regex characters in delimiter
    local escapedDelimiter = delimiter:gsub("[%.%+%*%?%^%$%(%)%[%]%%]", "%%%1")
    local pattern = "([^" .. escapedDelimiter .. "]+)"

    for token in str:gmatch(pattern) do
        table.insert(result, token)
    end

    -- Handle empty string case
    if #result == 0 and #str > 0 then
        table.insert(result, str)
    end

    return result
end

-- Helper function to convert timestamp to milliseconds
function convertToMilliseconds(timestamp)
    if not timestamp or timestamp == "" then
        return nil
    end
    
    -- Parse ISO 8601 timestamp (e.g., "2023-04-24T04:55:30.535Z")
    local year, month, day, hour, min, sec, ms = timestamp:match("(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)%.(%d%d%d)Z")
    
    if year and month and day and hour and min and sec and ms then
        -- Convert to milliseconds since epoch
        local time = os.time({
            year = tonumber(year),
            month = tonumber(month),
            day = tonumber(day),
            hour = tonumber(hour),
            min = tonumber(min),
            sec = tonumber(sec)
        })
        return (time * 1000) + tonumber(ms)
    end
    
    return nil
end

-- Ordered JSON encoding helpers (FIELD_ORDERS like Cisco Duo)
local FIELD_ORDERS = {
    root = {
        "actor", "client", "device", "authenticationContext", "displayMessage",
        "eventType", "outcome", "published", "securityContext", "severity",
        "debugContext", "legacyEventType", "transaction", "uuid", "version",
        "request", "target"
    },
    actor = {"id", "type", "alternateId", "displayName", "detailEntry"},
    client = {"userAgent", "zone", "device", "id", "ipAddress", "geographicalContext"},
    userAgent = {"rawUserAgent", "os", "browser"},
    geographicalContext = {"city", "state", "country", "postalCode", "geolocation"},
    geolocation = {"lat", "lon"},
    authenticationContext = {
        "authenticationProvider", "credentialProvider", "credentialType", "issuer",
        "interface", "authenticationStep", "externalSessionId"
    },
    issuer = {"id", "type"},
    outcome = {"result", "reason"},
    securityContext = {"asNumber", "asOrg", "isp", "domain", "isProxy"},
    debugContext = {"debugData"},
    debugData = {"initiationType", "redirectUri", "requestId", "dtHash", "signOnMode", "requestUri", "threatSuspected", "url", "risk", "deviceFingerprint", "authnRequestId", "behaviors", "warningPercent", "rateLimitBucketUuid", "rateLimitSecondsToReset", "threshold", "timeSpan", "rateLimitScopeType", "userId", "timeUnit"},
    transaction = {"type", "id", "detail"},
    request = {"ipChain"},
    ipChain = {"ip", "geographicalContext", "version", "source"},
    dst_endpoint = {"uid", "svc_name"},
    user = {"id", "email_addr", "name"},
    target = {"id", "type", "alternateId", "displayName", "detailEntry"}
}

local function encodeWithFieldOrder(obj, fieldOrder)
    local items = {}
    -- Phase 1: predefined order
    for _, fieldName in ipairs(fieldOrder) do
        if obj[fieldName] ~= nil then
            local valueStr = encodeJson(obj[fieldName], fieldName)
            if valueStr ~= nil then
                table.insert(items, '"' .. fieldName .. '": ' .. valueStr)
            end
        end
    end
    -- Phase 2: remaining fields
    for k, v in pairs(obj) do
        local found = false
        for _, fieldName in ipairs(fieldOrder) do
            if k == fieldName then found = true; break end
        end
        if not found then
            local keyStr = type(k) == "string" and k or tostring(k)
            local valueStr = encodeJson(v, k)
            if valueStr ~= nil then
                table.insert(items, '"' .. keyStr:gsub('"', '\\"') .. '": ' .. valueStr)
            end
        end
    end
    -- If no items were added, return nil to skip empty objects
    if #items == 0 then
        return nil
    end
    return "{" .. table.concat(items, ", ") .. "}"
end

-- JSON encoding function (from AWS CloudTrail) - Compact single-line output
function encodeJson(obj, key)
    if obj == nil or obj == "NULL_PLACEHOLDER" or obj == "" then
        return nil  -- Skip null and empty fields entirely
    elseif type(obj) == "boolean" then
        return tostring(obj)
    elseif type(obj) == "number" then
        return tostring(obj)
    elseif type(obj) == "string" then
        return '"' .. obj:gsub('"', '\\"') .. '"'
    elseif type(obj) == "table" then
        local isArray = true
        local maxIndex = 0
        for k, v in pairs(obj) do
            if type(k) ~= "number" then
                isArray = false
                break
            end
            maxIndex = math.max(maxIndex, k)
        end

        if isArray then
            local items = {}
            for i = 1, maxIndex do
                local elementKey = key or tostring(i)
                local encoded = encodeJson(obj[i], elementKey)
                if encoded ~= nil then
                    table.insert(items, encoded)
                end
            end
            -- Return nil for empty arrays to skip them entirely
            if #items == 0 then
                return nil
            end
            return "[" .. table.concat(items, ", ") .. "]"
        else
            -- Check if this is an empty object - if so, return nil to skip it
            if next(obj) == nil then
                return nil
            end

            -- If we have a field order for this object key, use it
            if key and FIELD_ORDERS[key] then
                return encodeWithFieldOrder(obj, FIELD_ORDERS[key])
            end
            -- If top-level message root, use root order
            if key == "root" and FIELD_ORDERS.root then
                return encodeWithFieldOrder(obj, FIELD_ORDERS.root)
            end
            -- Fallback: unordered (natural) encoding
            local items = {}
            for k, v in pairs(obj) do
                local keyStr = type(k) == "string" and k or tostring(k)
                local valueStr = encodeJson(v, keyStr)
                -- Only include fields that have non-nil values
                if valueStr ~= nil then
                    table.insert(items, '"' .. keyStr:gsub('"', '\\"') .. '": ' .. valueStr)
                end
            end
            -- If no items were added, return nil to skip empty objects
            if #items == 0 then
                return nil
            end
            return "{" .. table.concat(items, ", ") .. "}"
        end
    else
        return '"' .. tostring(obj) .. '"'
    end
end

-- Get default mapping for event type
function getDefaultMapping(eventType)
    local defaultMapping = {
        ["user.session.start"] = {
            {source = "uuid", target = "metadata.uid"},
            {source = "published", target = "metadata.original_time"},
            {source = "version", target = "api.version"},
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "client.ipAddress", target = "src_endpoint.ip"},
            {source = "client.id", target = "src_endpoint.uid"},
            {source = "client.geographicalContext.city", target = "src_endpoint.location.city"},
            {source = "client.geographicalContext.country", target = "src_endpoint.location.country"},
            {source = "client.geographicalContext.geolocation.lat", target = "location.coordinates.lat"},
            {source = "client.geographicalContext.geolocation.lon", target = "location.coordinates.lon"},
            {source = "client.geographicalContext.postalCode", target = "src_endpoint.location.postal_code"},
            {source = "client.geographicalContext.state", target = "src_endpoint.location.region"},
            {source = "client.userAgent.rawUserAgent", target = "http_request.user_agent"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "authenticationContext.externalSessionId", target = "session.uid"},
            {source = "authenticationContext.issuer.id", target = "actor.idp.uid"},
            {source = "authenticationContext.issuer.type", target = "actor.idp.name"},
            {source = "authenticationContext.authenticationProvider", target = "service.name"},
            {source = "authenticationContext.credentialProvider", target = "actor.invoked_by"},
            {source = "authenticationContext.credentialType", target = "actor.user.account.type"},
            {source = "debugContext.debugData.requestUri", target = "http_request.url.path"},
            {source = "debugContext.debugData.url", target = "http_request.url.query_string"},
            {source = "debugContext.debugData.requestId", target = "http_request.uid"},
            {source = "debugContext.debugData.origin", target = "device.hostname"},
            {source = "debugContext.debugData.risk", target = "device.risk_level"},
            {source = "securityContext.isp", target = "src_endpoint.location.isp"},
            {source = "securityContext.domain", target = "src_endpoint.location.domain"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"}
        },
        ["user.authentication.sso"] = {
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "client.ipAddress", target = "src_endpoint.ip"},
            {source = "client.id", target = "src_endpoint.uid"},
            {source = "client.geographicalContext.city", target = "src_endpoint.location.city"},
            {source = "client.geographicalContext.country", target = "src_endpoint.location.country"},
            {source = "client.geographicalContext.geolocation.lat", target = "location.coordinates.lat"},
            {source = "client.geographicalContext.geolocation.lon", target = "location.coordinates.lon"},
            {source = "client.geographicalContext.postalCode", target = "src_endpoint.location.postal_code"},
            {source = "client.geographicalContext.state", target = "src_endpoint.location.region"},
            {source = "client.userAgent.rawUserAgent", target = "http_request.user_agent"},
            {source = "authenticationContext.externalSessionId", target = "session.uid"},
            {source = "authenticationContext.issuer.id", target = "actor.idp.uid"},
            {source = "authenticationContext.issuer.type", target = "actor.idp.name"},
            {source = "authenticationContext.authenticationProvider", target = "service.name"},
            {source = "authenticationContext.credentialProvider", target = "actor.invoked_by"},
            {source = "authenticationContext.credentialType", target = "actor.user.account.type"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"},
            {source = "published", target = "metadata.original_time"},
            {source = "securityContext.isp", target = "src_endpoint.location.isp"},
            {source = "securityContext.domain", target = "src_endpoint.location.domain"},
            {source = "debugContext.debugData.requestUri", target = "http_request.url.path"},
            {source = "debugContext.debugData.url", target = "http_request.url.query_string"},
            {source = "debugContext.debugData.requestId", target = "http_request.uid"},
            {source = "debugContext.debugData.signOnMode", target = "auth_protocol"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "transaction.detail", target = "raw_data"},
            {source = "uuid", target = "metadata.uid"},
            {source = "version", target = "api.version"},
            -- target fields
            {source = "dst_endpoint_uid", target = "dst_endpoint.uid"},
            {source = "actor_user_uid", target = "actor.user.uid"},
            {source = "dst_endpoint_svc_name", target = "dst_endpoint.svc_name"},
            {source = "actor_email_addr", target = "actor.email_addr"}
            --{source = "actor_user_name", target = "user.name"}
        },
        ["user.lifecycle.activate"] = {
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "client.ipAddress", target = "src_endpoint.ip"},
            {source = "client.id", target = "src_endpoint.uid"},
            {source = "client.geographicalContext.city", target = "src_endpoint.location.city"},
            {source = "client.geographicalContext.country", target = "src_endpoint.location.country"},
            {source = "client.geographicalContext.geolocation.lat", target = "location.coordinates.lat"},
            {source = "client.geographicalContext.geolocation.lon", target = "location.coordinates.lon"},
            {source = "client.geographicalContext.postalCode", target = "src_endpoint.location.postal_code"},
            {source = "client.geographicalContext.state", target = "src_endpoint.location.region"},
            {source = "client.userAgent.browser", target = "client.userAgent.browser"},
            {source = "client.userAgent.rawUserAgent", target = "http_request.user_agent"},
            {source = "authenticationContext.externalSessionId", target = "actor.session.uid"},
            {source = "authenticationContext.issuer.id", target = "actor.idp.uid"},
            {source = "authenticationContext.issuer.type", target = "actor.idp.name"},
            {source = "authenticationContext.credentialProvider", target = "actor.invoked_by"},
            {source = "authenticationContext.credentialType", target = "actor.user.account.type"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"},
            {source = "published", target = "metadata.original_time"},
            {source = "securityContext.isp", target = "src_endpoint.location.isp"},
            {source = "securityContext.domain", target = "src_endpoint.location.domain"},
            {source = "debugContext.debugData.requestUri", target = "http_request.url.path"},
            {source = "debugContext.debugData.url", target = "http_request.url.query_string"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "transaction.detail", target = "raw_data"},
            {source = "uuid", target = "metadata.uid"},
            {source = "version", target = "api.version"}
            -- target
            --{source = "user_id", target = "user.id"}
            --{source = "user_email_addr", target = "user.email_addr"}
            --{source = "user_name", target = "user.name"}
        },
        ["user.lifecycle.create"] = {
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "client.userAgent.rawUserAgent", target = "http_request.user_agent"},
            {source = "client.id", target = "src_endpoint.uid"},
            {source = "client.ipAddress", target = "src_endpoint.ip"},
            {source = "client.geographicalContext.city", target = "src_endpoint.location.city"},
            {source = "client.geographicalContext.state", target = "src_endpoint.location.region"},
            {source = "client.geographicalContext.country", target = "src_endpoint.location.country"},
            {source = "client.geographicalContext.postalCode", target = "src_endpoint.location.postal_code"},
            {source = "client.geographicalContext.geolocation.lat", target = "location.coordinates.lat"},
            {source = "client.geographicalContext.geolocation.lon", target = "location.coordinates.lon"},
            {source = "authenticationContext.credentialProvider", target = "actor.invoked_by"},
            {source = "authenticationContext.credentialType", target = "actor.user.account.type"},
            {source = "authenticationContext.issuer.id", target = "actor.idp.uid"},
            {source = "authenticationContext.issuer.type", target = "actor.idp.name"},
            {source = "authenticationContext.externalSessionId", target = "actor.session.uid"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"},
            {source = "published", target = "metadata.original_time"},
            {source = "securityContext.isp", target = "src_endpoint.location.isp"},
            {source = "securityContext.domain", target = "src_endpoint.location.domain"},
            {source = "debugContext.debugData.requestId", target = "api.request.uid"},
            {source = "debugContext.debugData.requestUri", target = "http_request.url.path"},
            {source = "debugContext.debugData.url", target = "http_request.url.query_string"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "transaction.detail", target = "raw_data"},
            {source = "uuid", target = "metadata.uid"},
            {source = "version", target = "api.version"}
            -- target
            --{source = "user_id", target = "user.id"}
            --{source = "user_email_addr", target = "user.email_addr"},
            --{source = "user_name", target = "user.name"}
        },
        ["user.lifecycle.deactivate"] = {
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "client.userAgent.rawUserAgent", target = "http_request.user_agent"},
            {source = "client.id", target = "src_endpoint.uid"},
            {source = "client.ipAddress", target = "src_endpoint.ip"},
            {source = "client.geographicalContext.city", target = "src_endpoint.location.city"},
            {source = "client.geographicalContext.state", target = "src_endpoint.location.region"},
            {source = "client.geographicalContext.country", target = "src_endpoint.location.country"},
            {source = "client.geographicalContext.postalCode", target = "src_endpoint.location.postal_code"},
            {source = "client.geographicalContext.geolocation.lat", target = "location.coordinates.lat"},
            {source = "client.geographicalContext.geolocation.lon", target = "location.coordinates.lon"},
            {source = "authenticationContext.credentialProvider", target = "actor.invoked_by"},
            {source = "authenticationContext.credentialType", target = "actor.user.account.type"},
            {source = "authenticationContext.issuer.id", target = "actor.idp.uid"},
            {source = "authenticationContext.issuer.type", target = "actor.idp.name"},
            {source = "authenticationContext.externalSessionId", target = "actor.session.uid"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"},
            {source = "published", target = "metadata.original_time"},
            {source = "securityContext.isp", target = "src_endpoint.location.isp"},
            {source = "securityContext.domain", target = "src_endpoint.location.domain"},
            {source = "debugContext.debugData.requestId", target = "api.request.uid"},
            {source = "debugContext.debugData.requestUri", target = "http_request.url.path"},
            {source = "debugContext.debugData.url", target = "http_request.url.query_string"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "transaction.detail", target = "raw_data"},
            {source = "uuid", target = "metadata.uid"},
            {source = "version", target = "api.version"}
            -- target
            --{source = "user_id", target = "user.id"},
            --{source = "user_email_addr", target = "user.email_addr"},
            --{source = "user_name", target = "user.name"}
        },
        ["policy.evaluate_sign_on"] = {
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "client.userAgent.rawUserAgent", target = "http_request.user_agent"},
            {source = "client.id", target = "src_endpoint.uid"},
            {source = "client.ipAddress", target = "src_endpoint.ip"},
            {source = "client.geographicalContext.city", target = "src_endpoint.location.city"},
            {source = "client.geographicalContext.state", target = "src_endpoint.location.region"},
            {source = "client.geographicalContext.country", target = "src_endpoint.location.country"},
            {source = "client.geographicalContext.postalCode", target = "src_endpoint.location.postal_code"},
            {source = "client.geographicalContext.geolocation.lat", target = "location.coordinates.lat"},
            {source = "client.geographicalContext.geolocation.lon", target = "location.coordinates.lon"},
            {source = "authenticationContext.authenticationProvider", target = "name"},
            {source = "authenticationContext.credentialProvider", target = "actor.invoked_by"},
            {source = "authenticationContext.credentialType", target = "actor.user.account.type"},
            {source = "authenticationContext.externalSessionId", target = "session.uid"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"},
            {source = "published", target = "metadata.original_time"},
            {source = "securityContext.isp", target = "src_endpoint.location.isp"},
            {source = "securityContext.domain", target = "src_endpoint.location.domain"},
            {source = "debugContext.debugData.deviceFingerprint", target = "device.uid"},
            {source = "debugContext.debugData.requestId", target = "http_request.uid"},
            {source = "debugContext.debugData.risk", target = "device.risk_level"},
            {source = "debugContext.debugData.requestUri", target = "http_request.url.path"},
            {source = "debugContext.debugData.url", target = "http_request.url.query_string"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "transaction.detail", target = "raw_data"},
            {source = "uuid", target = "metadata.uid"},
            {source = "version", target = "api.version"},
            -- target fields
            {source = "actor.authorization.policy.uid", target = "actor.authorization.policy.uid"},
            {source = "actor.authorization.policy.name", target = "actor.authorization.policy.name"},
            {source = "actor.authorization.policy.rule.uid", target = "actor.authorization.policy.rule.uid"},
            {source = "actor.authorization.policy.rule.name", target = "actor.authorization.policy.rule.name"}
        },
        ["system.org.rate_limit.warning"] = {
            {source = "uuid", target = "metadata.uid"},
            {source = "published", target = "metadata.original_time"},
            {source = "version", target = "api.version"},
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "client.ipAddress", target = "src_endpoint.ip"},
            {source = "client.id", target = "src_endpoint.uid"},
            {source = "client.geographicalContext.city", target = "src_endpoint.location.city"},
            {source = "client.geographicalContext.country", target = "src_endpoint.location.country"},
            {source = "client.geographicalContext.geolocation.lat", target = "location.coordinates.lat"},
            {source = "client.geographicalContext.geolocation.lon", target = "location.coordinates.lon"},
            {source = "client.geographicalContext.postalCode", target = "src_endpoint.location.postal_code"},
            {source = "client.geographicalContext.state", target = "src_endpoint.location.region"},
            {source = "client.userAgent.rawUserAgent", target = "http_request.user_agent"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "transaction.detail", target = "raw_data"},
            {source = "authenticationContext.externalSessionId", target = "actor.session.uid"},
            {source = "authenticationContext.issuer.id", target = "actor.idp.uid"},
            {source = "authenticationContext.issuer.type", target = "actor.idp.name"},
            {source = "authenticationContext.credentialProvider", target = "actor.invoked_by"},
            {source = "authenticationContext.credentialType", target = "actor.user.account.type"},
            {source = "debugContext.debugData.requestUri", target = "http_request.url.path"},
            {source = "debugContext.debugData.url", target = "http_request.url.query_string"},
            {source = "debugContext.debugData.requestId", target = "http_request.uid"},
            {source = "securityContext.isp", target = "src_endpoint.location.isp"},
            {source = "securityContext.domain", target = "src_endpoint.location.domain"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"}
        },
        ["application.user_membership.add"] = {
            {source = "uuid", target = "metadata.uid"},
            {source = "published", target = "metadata.original_time"},
            {source = "version", target = "api.version"},
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "client.ipAddress", target = "src_endpoint.ip"},
            {source = "client.id", target = "src_endpoint.uid"},
            {source = "client.geographicalContext.city", target = "src_endpoint.location.city"},
            {source = "client.geographicalContext.country", target = "src_endpoint.location.country"},
            {source = "client.geographicalContext.geolocation.lat", target = "location.coordinates.lat"},
            {source = "client.geographicalContext.geolocation.lon", target = "location.coordinates.lon"},
            {source = "client.geographicalContext.postalCode", target = "src_endpoint.location.postal_code"},
            {source = "client.geographicalContext.state", target = "src_endpoint.location.region"},
            {source = "client.userAgent.rawUserAgent", target = "http_request.user_agent"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "transaction.detail", target = "raw_data"},
            {source = "authenticationContext.externalSessionId", target = "actor.session.uid"},
            {source = "authenticationContext.issuer.id", target = "actor.idp.uid"},
            {source = "authenticationContext.issuer.type", target = "actor.idp.name"},
            {source = "authenticationContext.credentialProvider", target = "actor.invoked_by"},
            {source = "authenticationContext.credentialType", target = "actor.user.account.type"},
            {source = "debugContext.debugData.requestUri", target = "http_request.url.path"},
            {source = "debugContext.debugData.url", target = "http_request.url.query_string"},
            {source = "debugContext.debugData.requestId", target = "http_request.uid"},
            {source = "debugContext.debugData.origin", target = "device.hostname"},
            {source = "debugContext.debugData.risk", target = "device.risk_level"},
            {source = "securityContext.isp", target = "src_endpoint.location.isp"},
            {source = "securityContext.domain", target = "src_endpoint.location.domain"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"},
            -- target fields
            {source = "dst_endpoint_uid", target = "dst_endpoint.uid"},
            {source = "dst_endpoint_svc_name", target = "dst_endpoint.svc_name"},
            {source = "actor_user_uid", target = "actor.user.uid"},
            {source = "actor_email_addr", target = "actor.email_addr"}
            --{source = "actor_user_name", target = "user.name"}
        },
        ["application.lifecycle.update"] = {
            {source = "actor.id", target = "actor.user.uid"},
            {source = "actor.type", target = "actor.user.type"},
            {source = "actor.alternateId", target = "actor.user.email_addr"},
            {source = "actor.displayName", target = "actor.user.name"},
            {source = "outcome.result", target = "status"},
            {source = "outcome.reason", target = "status_detail"},
            {source = "published", target = "metadata.original_time"},
            {source = "transaction.id", target = "metadata.correlation_uid"},
            {source = "transaction.detail", target = "raw_data"},
            {source = "uuid", target = "metadata.uid"},
            -- target fields
            {source = "dst_endpoint_uid", target = "dst_endpoint.uid"},
            {source = "dst_endpoint_svc_name", target = "dst_endpoint.svc_name"},

            --{source = "actor_user_uid", target = "actor.user.uid"},
            {source = "actor_email_addr", target = "actor.email_addr"}
            --{source = "actor_user_name", target = "user.name"}
        }
    }

    return defaultMapping[eventType] or getGenericOktaMapping()
end

-- Generic Okta mapping
function getGenericOktaMapping()
    return {
        {source = "actor.id", target = "actor.user.uid"},
        {source = "actor.alternateId", target = "actor.user.email_addr"},
        {source = "actor.displayName", target = "actor.user.name"},
        {source = "outcome.result", target = "status"},
        {source = "outcome.reason", target = "status_detail"},
        {source = "published", target = "metadata.original_time"},
        {source = "transaction.id", target = "metadata.correlation_uid"},
        {source = "transaction.detail", target = "raw_data"},
        {source = "uuid", target = "metadata.uid"}
    }
end

-- Common mapping
function getCommonMapping()
    return {
        {source = "category_name", target = "category_name"},
        {source = "category_uid", target = "category_uid"},
        {source = "class_uid", target = "class_uid"},
        {source = "severity_id", target = "severity_id"},
        {source = "activity_name", target = "activity_name"},
        {source = "activity_id", target = "activity_id"},
        {source = "type_uid", target = "type_uid"},
        {source = "vendor_name", target = "metadata.product.vendor_name"},
        {source = "name", target = "metadata.product.name"},
        {source = "OCSF_version", target = "metadata.version"},
        {source = "time", target = "time"},
        {source = "status_id", target = "status_id"},
        {source = "type_id", target = "actor.user.type_id"},
        {source = "observables", target = "observables"},
        {source = "dataSource.category", target = "dataSource.category"},
        {source = "site.id", target = "site.id"},
        {source = "dataSource.name", target = "dataSource.name"},
        {source = "dataSource.vendor", target = "dataSource.vendor"},
        {source = "message", target = "message"},
        {source = "class_name", target = "class_name"},
        {source = "type_name", target = "type_name"}
    }
end

-- Parse security domain
function parseSecurityDomain(parsedLog)
    if parsedLog["src_endpoint.location.domain"] == "." then
        parsedLog["src_endpoint.location.domain"] = nil
    end
    return parsedLog
end

-- Set site ID
function setSiteId(oktaLog, siteId)
    oktaLog["site"] = {id = siteId}
    return oktaLog
end

-- Parse risk level
function parseRiskLevel(parsedLog)
    local riskLevelMapper = {
        ["Info"] = 0, ["Low"] = 1, ["Medium"] = 2,
        ["High"] = 3, ["Critical"] = 4
    }
    local riskPrefix = "level="
    local finalRiskLevel = "Other"
    local finalRiskLevelId = 99

    -- Look for risk level in the already-mapped device.risk_level field
    local riskLevel = ""
    if parsedLog["device"] and parsedLog["device"]["risk_level"] then
        riskLevel = parsedLog["device"]["risk_level"]
    end
    
    for riskLevelName, riskLevelId in pairs(riskLevelMapper) do
        if string.find(string.lower(riskLevel), string.lower(riskPrefix .. riskLevelName)) then
            finalRiskLevel = riskLevelName
            finalRiskLevelId = riskLevelId
            break
        end
    end

    -- Set the parsed risk level back to the device object
    if not parsedLog["device"] then parsedLog["device"] = {} end
    parsedLog["device"]["risk_level"] = finalRiskLevel
    parsedLog["device"]["risk_level_id"] = finalRiskLevelId
    return parsedLog
end

-- Find event type
function findEventType(log)
    local eventType = log["eventType"]
    if eventType == nil then
        return "unknown"
    end
    return eventType
end

-- Get category UID
function getCategoryUID(eventType)
    local categoryMapping = {
        ["user.session.start"] = 3,
        ["user.authentication.sso"] = 3,
        ["user.lifecycle.activate"] = 2,
        ["user.lifecycle.create"] = 3,
        ["user.lifecycle.deactivate"] = 3,
        ["policy.evaluate_sign_on"] = 3,
        ["system.org.rate_limit.warning"] = 3,
        ["application.user_membership.add"] = 3,
        ["application.lifecycle.update"] = 6
    }
    return categoryMapping[eventType] or 0
end

-- Get class mapping
function getClassMapping(eventType)
    local classMapping = {
        ["user.session.start"] = {name = "Authentication", id = 3002},
        ["user.authentication.sso"] = {name = "Authentication", id = 3002},
        ["user.lifecycle.activate"] = {name = "Account Change", id = 3001},
        ["user.lifecycle.create"] = {name = "Account Change", id = 3001},
        ["user.lifecycle.deactivate"] = {name = "Account Change", id = 3001},
        ["policy.evaluate_sign_on"] = {name = "Authentication", id = 3002},
        ["system.org.rate_limit.warning"] = {name = "API Activity", id = 6003},
        ["application.user_membership.add"] = {name = "Account Change", id = 3001},
        ["application.lifecycle.update"] = {name = "Application Lifecycle", id = 6002}
    }
    local mapping = classMapping[eventType] or {name = "Base Event", id = 0}
    return mapping.name, mapping.id
end

-- Get status default OCSF mapping
function getStatusDefaultOCSFMapping(status)
    if status == nil then
        return 0
    end

    local statusMapping = {
        ["SUCCESS"] = 1,
        ["FAILURE"] = 2
    }
    return statusMapping[status] or 99
end

-- Get activity name
function getActivityName(eventType, eventTypeDisplayName)
    local activityMapping = {
        ["user.session.start"] = {name = "Logon", id = 1},
        ["user.authentication.sso"] = {name = "Logon", id = 1},
        ["user.lifecycle.activate"] = {name = "Enable", id = 2},
        ["user.lifecycle.create"] = {name = "Create", id = 1},
        ["user.lifecycle.deactivate"] = {name = "Disable", id = 5},
        ["policy.evaluate_sign_on"] = {name = "Logon", id = 1},
        ["application.user_membership.add"] = {name = "Attach Policy", id = 7}
    }
    local mapping = activityMapping[eventType] or {name = eventTypeDisplayName, id = 99}
    return mapping.name, mapping.id
end

-- Get user type
function getUserType(oktaUserType)
    local userTypeMapping = {
        ["Unknown"] = 0,
        ["User"] = 1,
        ["Admin"] = 2,
        ["System"] = 3,
        ["Other"] = 99
    }
    for user, id in pairs(userTypeMapping) do
        if string.find(oktaUserType or "", user) then
            return id
        end
    end
    return 99
end

-- Get category mapper
function getCategoryMapper(eventType)
    local categoryMapper = {
        ["user.session.start"] = "Identity & Access Management",
        ["user.authentication.sso"] = "Identity & Access Management",
        ["user.lifecycle.activate"] = "Identity & Access Management",
        ["user.lifecycle.create"] = "Identity & Access Management",
        ["user.lifecycle.deactivate"] = "Identity & Access Management",
        ["policy.evaluate_sign_on"] = "Identity & Access Management",
        ["system.org.rate_limit.warning"] = "Application Activity",
        ["application.user_membership.add"] = "Identity & Access Management",
        ["application.lifecycle.update"] = "Application Activity"
    }
    return categoryMapper[eventType] or "Uncategorized"
end

-- Get type name
function getTypeName(eventType)
    local typeMapper = {
        ["user.session.start"] = "Authentication: Logon",
        ["user.authentication.sso"] = "Authentication: Logon",
        ["user.lifecycle.activate"] = "Account Change: Enable",
        ["user.lifecycle.create"] = "Account Change: Create",
        ["user.lifecycle.deactivate"] = "Account Change: Disable",
        ["policy.evaluate_sign_on"] = "Authentication: Logon",
        ["system.org.rate_limit.warning"] = "API Activity: Other",
        ["application.user_membership.add"] = "Account Change: Attach Policy",
        ["application.lifecycle.update"] = "Application Lifecycle: Other"
    }
    return typeMapper[eventType] or "Base Event: Other"
end

-- Get observables
function getObservables(log)
    local observables = {}

    -- Hostname observable
    local hostname = safelyAccessNestedDictKeys({"debugContext", "debugData", "origin"}, log)
    if hostname and hostname ~= "" and hostname ~= "null" then
        table.insert(observables, {
            type_id = 1,
            type = "Hostname",
            name = "device.hostname",
            value = hostname
        })
    end

    -- IP Address observable
    local clientIpAddress = safelyAccessNestedDictKeys({"client", "ipAddress"}, log)
    if clientIpAddress and clientIpAddress ~= "" and clientIpAddress ~= "null" then
        table.insert(observables, {
            type_id = 2,
            type = "IP Address",
            name = "src_endpoint.ip",
            value = clientIpAddress
        })
    end

    -- User Name observable
    local userName = safelyAccessNestedDictKeys({"actor", "displayName"}, log)
    if userName and userName ~= "" and userName ~= "null" then
        table.insert(observables, {
            type_id = 4,
            type = "User Name",
            name = "actor.user.name",
            value = userName
        })
    end

    -- Email Address observable
    local emailAddress = safelyAccessNestedDictKeys({"actor", "alternateId"}, log)
    if emailAddress and emailAddress ~= "" and emailAddress ~= "null" then
        table.insert(observables, {
            type_id = 5,
            type = "Email Address",
            name = "actor.user.email_addr",
            value = emailAddress
        })
    end

    -- URL String observable
    local requestUri = safelyAccessNestedDictKeys({"debugContext", "debugData", "requestUri"}, log)
    if requestUri and requestUri ~= "" and requestUri ~= "null" then
        table.insert(observables, {
            type_id = 6,
            type = "URL String",
            name = "http_request.url.path",
            value = requestUri
        })
    end

    -- Geo Location observable
    local lat = safelyAccessNestedDictKeys({"client", "geographicalContext", "geolocation", "lat"}, log)
    local lon = safelyAccessNestedDictKeys({"client", "geographicalContext", "geolocation", "lon"}, log)
    local notAllowedItems = {{}, {}, "", nil}
    local latAllowed = true
    local lonAllowed = true
    for _, item in ipairs(notAllowedItems) do
        if lat == item then latAllowed = false end
        if lon == item then lonAllowed = false end
    end
    if latAllowed and lonAllowed and lat and lon then
        table.insert(observables, {
            type_id = 26,
            type = "Geo Location",
            name = "client.geographicalContext.geolocation",
            value = lat .. ", " .. lon
        })
    end

    return observables
end

-- Process target fields into flat keys for mapping
function processTargetFields(log, eventType)
    local targetFields = {}
    
    if eventType == "user.authentication.sso" or
            eventType == "application.user_membership.add" or
            eventType == "application.lifecycle.update" then
        local target = log["target"]
        if target and type(target) == "table" then
            for _, t in ipairs(target) do
                if type(t) == "table" then
                    if t["type"] == "AppInstance" then
                        log["dst_endpoint_uid"] = t["type"]
                        log["dst_endpoint_svc_name"] = t["displayName"]
                    elseif t["type"] == "AppUser" then
                        -- Override specific fields with target values
                        log["actor_user_uid"] = t["type"]  -- "AppUser" overrides actor.id
                        log["actor_email_addr"] = t["alternateId"]  -- "unknown" for actor.email_addr
                        log["actor_user_name"] = t["displayName"]  -- "John Cena" (same as original)
                        
                        -- Override actor.id for actor.user.uid mapping
                        if log["actor"] then
                            log["actor"]["id"] = t["type"]  -- "AppUser" for actor.user.uid
                            -- Keep actor.alternateId as original for actor.user.email_addr mapping
                            -- Don't override actor.alternateId - let it stay as "john.cena@wwe.com"
                        end
                    end
                end
            end
        end
    elseif eventType == "user.lifecycle.activate" or
            eventType == "user.lifecycle.create" or
            eventType == "user.lifecycle.deactivate" then
        local target = log["target"]
        if target and type(target) == "table" and #target > 0 then
            local t = target[1]
            if type(t) == "table" then
                targetFields["user_id"] = t["id"]
                targetFields["user_email_addr"] = t["alternateId"]
                targetFields["user_name"] = t["displayName"]
            end
        end
    elseif eventType == "policy.evaluate_sign_on" then
        local target = log["target"]
        if target and type(target) == "table" then
            for _, t in ipairs(target) do
                if type(t) == "table" then
                    if t["type"] == "PolicyEntity" then
                        targetFields["actor"] = {
                            authorization = {
                                policy = {
                                    name = t["displayName"],
                                    uid = t["id"]
                                }
                            }
                        }
                    elseif t["type"] == "PolicyRule" then
                        targetFields["actor"] = {
                            authorization = {
                                policy = {
                                    rule = {
                                        uid = t["id"],
                                        name = t["displayName"]
                                    }
                                }
                            }
                        }
                    end
                end
            end
        end
    end

    return targetFields
end

-- Generate severity mapping
function generateSeverityMapping(availableSeverityList)
    local defaultSeverityMapping = {
        ["DEBUG"] = 0, ["INFO"] = 1, ["WARN"] = 3, ["ERROR"] = 5, ["OTHER"] = 99
    }
    local defaultSeverityMappingKeys = {"DEBUG", "INFO", "WARN", "ERROR", "OTHER"}
    local severityIDMapping = {}

    for severityTypeIndex = 1, #availableSeverityList do
        if availableSeverityList[severityTypeIndex] then
            local key = defaultSeverityMappingKeys[severityTypeIndex]
            severityIDMapping[key] = defaultSeverityMapping[key]
        end
    end
    return severityIDMapping
end

-- Get severity ID
function getSeverityID(eventType, logSeverity)
    local severityMapping = {
        ["user.session.start"] = generateSeverityMapping({true, true, true, true, true}),
        ["user.authentication.sso"] = generateSeverityMapping({true, true, true, false, false}),
        ["user.lifecycle.activate"] = generateSeverityMapping({true, true, true, false, false}),
        ["user.lifecycle.create"] = generateSeverityMapping({false, true, false, false, false}),
        ["user.lifecycle.deactivate"] = generateSeverityMapping({false, true, false, false, false}),
        ["policy.evaluate_sign_on"] = generateSeverityMapping({false, true, false, false, false}),
        ["system.org.rate_limit.warning"] = generateSeverityMapping({true, true, true, false, false}),
        ["application.user_membership.add"] = generateSeverityMapping({true, true, true, false, false}),
        ["application.lifecycle.update"] = generateSeverityMapping({false, true, false, false, false})
    }
    local eventSeverityMapping = severityMapping[eventType] or {}
    return eventSeverityMapping[logSeverity] or 99
end

-- Generate synthetic fields
function generateSyntheticFields(log, eventType, originalLog)
    -- Set nested metadata fields
    if not log["metadata"] then log["metadata"] = {} end
    if not log["metadata"]["product"] then log["metadata"]["product"] = {} end
    log["metadata"]["product"]["vendor_name"] = "Okta"
    log["metadata"]["product"]["name"] = "Okta"
    log["metadata"]["version"] = "1.0.0"

    local publishedTime = safelyAccessNestedDictKeys({"published"}, originalLog)
    if publishedTime then
        log["time"] = convertToMilliseconds(publishedTime)
    end

    -- Use the event type passed as parameter instead of finding it again
    log["category_name"] = getCategoryMapper(eventType)
    log["category_uid"] = getCategoryUID(eventType)

    local className, classUid = getClassMapping(eventType)
    log["class_name"] = className
    log["class_uid"] = classUid

    -- Dynamic severity calculation
    log["severity_id"] = getSeverityID(eventType, originalLog["severity"])

    local activityName, activityId = getActivityName(eventType, originalLog["displayMessage"] or "Other")
    log["activity_name"] = activityName
    log["activity_id"] = activityId

    log["type_uid"] = (classUid * 100) + activityId
    log["type_name"] = getTypeName(eventType)

    local outcomeResult = safelyAccessNestedDictKeys({"outcome", "result"}, originalLog)
    log["status_id"] = getStatusDefaultOCSFMapping(outcomeResult)

    local actorType = safelyAccessNestedDictKeys({"actor", "type"}, originalLog)

	if not log["actor"] then log["actor"] = {} end
	if not log["actor"]["user"] then log["actor"]["user"] = {} end
	log["actor"]["user"]["type_id"] = getUserType(actorType)
	log["actor"]["user"]["type"] = actorType or "User"
    -- Actor email_addr is now set by target field mappings, don't override

    -- Handle postal code conversion to string
    local postalCode = safelyAccessNestedDictKeys({"client", "geographicalContext", "postalCode"}, log)
    if postalCode then
        if not log["client"] then log["client"] = {} end
        if not log["client"]["geographicalContext"] then log["client"]["geographicalContext"] = {} end
        log["client"]["geographicalContext"]["postalCode"] = tostring(postalCode)
    end

    -- Target fields are now processed earlier in oktaLogsMapping


    log["event.type"] = log["activity_name"] or eventType
    log["dataSource"] = {name = "Okta", category = "security", vendor = "Okta"}
    
    -- Add session field (skip root session for lifecycle events except deactivate)
    local sessionId = safelyAccessNestedDictKeys({"authenticationContext", "externalSessionId"}, originalLog)
    if not (eventType == "user.lifecycle.activate" or eventType == "user.lifecycle.create") then
        if eventType == "user.lifecycle.deactivate" then
            -- For deactivate events, add session to existing actor object if it exists
            if log["actor"] then
                log["actor"]["session"] = {uid = sessionId or "unknown"}
            else
                log["session"] = {uid = sessionId or "unknown"}
            end
        end
    end
    
    -- Add user field from actor only for non-lifecycle events
    --local userName = safelyAccessNestedDictKeys({"actor", "displayName"}, originalLog)
    --if userName and not (eventType == "user.lifecycle.activate" or eventType == "user.lifecycle.create" or eventType == "user.lifecycle.deactivate" or eventType == "user.session.start") then
    --    log["user"] = {name = userName}
    --end

    return log
end


-- Helper function to check if a field should be ignored
function shouldIgnoreField(fieldName)

    local ignoreFields = {
        "_okta_event_type", "_ob", "ts", "timestamp"
    }

    for _, field in ipairs(ignoreFields) do
        if fieldName == field or string.find(fieldName, "^" .. field .. "%.") then
            return true
        end
    end
    return false
end

-- Helper function to check if a value is empty (empty object, array, or null)
function isEmptyValue(value)
    if value == nil or value == "NULL_PLACEHOLDER" then
        return true
    end
    if type(value) == "string" and (value == "" or value == "null") then
        return true
    end
    if type(value) == "table" then
        -- Check if it's an empty table
        if next(value) == nil then
            return true
        end
        -- For unmapped fields, recursively check nested values to filter out empty nested objects
        local hasNonEmptyValues = false
        for k, v in pairs(value) do
            if not isEmptyValue(v) then
                hasNonEmptyValues = true
                break
            end
        end
        return not hasNonEmptyValues
    end
    return false
end

-- Helper function to add unmapped fields as a truly nested object (no dotted keys)
function addUnmappedFields(sourceObj, targetObj, mappedFields, prefixParts)
    prefixParts = prefixParts or {}
    for key, value in pairs(sourceObj) do
        -- Skip ignored fields
        if shouldIgnoreField(key) then
            goto continue
        end

        -- Build current dotted path for mapped check
        local currentPathParts = {}
        for i = 1, #prefixParts do currentPathParts[i] = prefixParts[i] end
        table.insert(currentPathParts, key)
        local currentPath = table.concat(currentPathParts, ".")

        -- Check if this exact path has been mapped
        local isMapped = mappedFields[currentPath] or false

        if not isMapped and value ~= nil then
            if type(value) == "table" then
                local nestedObj = {}
                addUnmappedFields(value, nestedObj, mappedFields, currentPathParts)
                
                -- Check if ALL direct children were mapped
                local allChildrenMapped = true
                for childKey, childValue in pairs(value) do
                    local childPath = currentPath .. "." .. childKey
                    if not mappedFields[childPath] then
                        allChildrenMapped = false
                        break
                    end
                end
                
                -- Only add parent if it has unmapped children OR no children were mapped
                if next(nestedObj) and not allChildrenMapped then
                    targetObj[key] = nestedObj
                end
                -- Don't add empty objects to unmapped
            else
                -- Only add non-empty values to unmapped
                if not isEmptyValue(value) then
                    targetObj[key] = value
                end
            end
        end
        ::continue::
    end
end

-- Helper function to build nested object structure from flat dotted keys
function buildNestedStructure(flatObj)
    local nested = {}
    for key, value in pairs(flatObj) do
        local keys = split(key, ".")
        local current = nested
        for i = 1, #keys - 1 do
            local k = keys[i]
            if not current[k] then
                current[k] = {}
            elseif type(current[k]) ~= "table" then
                -- If the existing value is not a table, we can't create nested structure
                -- Skip this key to avoid conflicts
                goto continue
            end
            current = current[k]
        end
        
        -- Special handling for raw_data field - encode as JSON string
        if keys[#keys] == "raw_data" then
            -- For raw_data, we want the value as a JSON string, not double-encoded
            if type(value) == "table" then
                current[keys[#keys]] = encodeJson(value, "raw_data")
            else
                -- If it's already a string, use it as-is
                current[keys[#keys]] = tostring(value)
            end
        else
            current[keys[#keys]] = value
        end
        ::continue::
    end
    return nested
end

-- Helper function to set nested value (marks field as processed)
function setNestedValue(obj, keys, value)
    local current = obj
    for i = 1, #keys - 1 do
        if not current[keys[i]] then
            current[keys[i]] = {}
        end
        current = current[keys[i]]
    end
    current[keys[#keys]] = value
end


-- Helper function to filter out ignored fields using shouldIgnoreField
function filterIgnoredFields(log)
    local function filterObject(obj, prefix)
        prefix = prefix or ""
        local filteredObj = {}

        for key, value in pairs(obj) do
            local fullKey = prefix == "" and key or prefix .. "." .. key

            if not shouldIgnoreField(fullKey) then
                if type(value) == "table" then
                    local filteredValue = filterObject(value, fullKey)
                    if next(filteredValue) then  -- Only add non-empty tables
                        filteredObj[key] = filteredValue
                    end
                else
                    filteredObj[key] = value
                end
            end
        end
        return filteredObj
    end

    return filterObject(log)
end


-- Helper function to create ordered JSON message using FIELD_ORDER approach
function createOrderedMessage(log, eventType)
    -- Filter out null values and empty strings from the log before creating message
    local filteredLog = {}
    for k, v in pairs(log) do
        if v ~= nil and v ~= "" and v ~= "null" then
            if type(v) == "table" then
                local filteredValue = filterNullValues(v)
                if next(filteredValue) then  -- Only add non-empty tables
                    filteredLog[k] = filteredValue
                end
            else
                filteredLog[k] = v
            end
        end
    end
    
    -- Apply domain filtering to the message for lifecycle events only
    if eventType == "user.lifecycle.create" or eventType == "user.lifecycle.deactivate" or eventType == "user.session.start" then
        filteredLog = applyDomainFiltering(filteredLog)
    end
    
    -- Use FIELD_ORDERS.root to create ordered JSON string
    local orderedJson = encodeWithFieldOrder(filteredLog, FIELD_ORDERS.root)
    return orderedJson or "{}"
end

-- Helper function to recursively filter out null values from nested tables
function filterNullValues(obj)
    local filtered = {}
    for k, v in pairs(obj) do
        if v ~= nil and v ~= "" and v ~= "null" then
            if type(v) == "table" then
                local filteredValue = filterNullValues(v)
                if next(filteredValue) then  -- Only add non-empty tables
                    filtered[k] = filteredValue
                end
            else
                filtered[k] = v
            end
        end
    end
    return filtered
end

-- Helper function to apply domain filtering recursively
function applyDomainFiltering(obj)
    if type(obj) ~= "table" then
        return obj
    end
    
    local filtered = {}
    for k, v in pairs(obj) do
        if type(v) == "table" then
            local filteredValue = applyDomainFiltering(v)
            if next(filteredValue) then  -- Only add non-empty tables
                filtered[k] = filteredValue
            end
        else
            -- Skip domain fields with value "." and isp fields that duplicate asOrg
            if k == "domain" and v == "." then
                -- Skip this field
            elseif k == "isp" and obj["asOrg"] and v == obj["asOrg"] then
                -- Skip isp field when it's the same as asOrg
            else
                filtered[k] = v
            end
        end
    end
    return filtered
end

-- Simplified Okta logs mapping function
function oktaLogsMapping(log)
    -- STEP 1: First filter out ignored fields using shouldIgnoreField
    log = filterIgnoredFields(log)

    -- STEP 2: Find event type first
    local eventType = findEventType(log)
    
    -- STEP 3: Create ordered JSON message from original log BEFORE any modifications
    local originalLog = {}
    for k, v in pairs(log) do
        originalLog[k] = v
    end
    log.message = createOrderedMessage(originalLog, eventType)

    -- STEP 4: Process target fields to create flat keys for mapping
    local targetFields = processTargetFields(log, eventType)
    
    -- Apply target fields to log for specific events so mappings can consume them
    if eventType == "policy.evaluate_sign_on" then
        for key, value in pairs(targetFields) do
            if key == "actor" then
                if not log["actor"] then log["actor"] = {} end
                for subKey, subValue in pairs(value) do
                    log["actor"][subKey] = subValue
                end
            else
                log[key] = value
            end
        end
    elseif eventType == "user.lifecycle.activate" or eventType == "user.lifecycle.create" or eventType == "user.lifecycle.deactivate" then
        -- For lifecycle events, expose target-derived user fields on the log
        for key, value in pairs(targetFields) do
            log[key] = value
        end
    end

    -- STEP 4: Get mapping for event type
    local mappings = getDefaultMapping(eventType)

    -- Merge with common mapping
    local commonMappings = getCommonMapping()
    for _, mapping in ipairs(commonMappings) do
        table.insert(mappings, mapping)
    end

    -- STEP 4: Apply mappings and track processed fields
    local parsedData = {}
    local mappedFields = {}
    for _, mapping in ipairs(mappings) do
        local sourcePath = mapping.source
        local targetPath = mapping.target
        local keys = split(sourcePath, ".")
        local value = safelyAccessNestedDictKeys(keys, log)

        if value ~= nil and value ~= "" and value ~= "null" then
            if targetPath == "src_endpoint.location.domain" and value == "." then
                -- Skip this field for any event when domain is a single dot
            else
                -- Update target in parsedData
                parsedData[targetPath] = value
                -- Track mapped field by source path
                mappedFields[sourcePath] = true
            end
        end
    end

    -- STEP 5: Add remaining non-null fields to unmapped
    parsedData["unmapped"] = {}
    local ignoreUnmappedFields = {
        "actor_user_uid",
        "actor_email_addr", 
        "actor_user_name",
        "user_id",
        "user_email_addr",
        "user_name"
    }
    for _, field in ipairs(ignoreUnmappedFields) do
        mappedFields[field] = true
    end

    addUnmappedFields(log, parsedData["unmapped"], mappedFields, {})
    
    -- Apply domain filtering to unmapped fields as well
    parsedData["unmapped"] = applyDomainFiltering(parsedData["unmapped"])

    -- STEP 6: Convert flat dotted keys to nested objects
    parsedData = buildNestedStructure(parsedData)

    -- STEP 7: Apply post-processing
    parsedData = parseSecurityDomain(parsedData)
    parsedData = parseRiskLevel(parsedData)

    -- STEP 8: Generate synthetic fields
    parsedData = generateSyntheticFields(parsedData, eventType, log)
    
    -- STEP 9: Generate observables for specific event types (after synthetic fields)
    local observablesEventTypes = {
        "user.authentication.sso",
        "application.user_membership.add",
        "user.lifecycle.activate",
        "user.lifecycle.create",
        "user.lifecycle.deactivate",
        "policy.evaluate_sign_on",
        "system.org.rate_limit.warning",
        "user.session.start"
    }

    for _, eventTypeName in ipairs(observablesEventTypes) do
        if eventType == eventTypeName then
            local observables = getObservables(log)
            -- Convert observables to array format
            local observablesArray = {}
            for _, obs in ipairs(observables) do
                table.insert(observablesArray, obs)
            end
            parsedData["observables"] = observablesArray
            break
        end
    end
    
    parsedData = convertToNested(parsedData, eventType)
    return parsedData
end

-- Convert flat parsed data to nested JSON structure with field ordering
function convertToNested(parsedData, eventType)
    local nested = {}
    
    -- First, build the nested structure
    for key, value in pairs(parsedData) do
        -- Special case: keep event.type as flattened field (don't nest it)
        if key == "event.type" then
            nested["event.type"] = value  -- Keep as flattened event.type
            goto continue
        end
        
        local keys = split(key, ".")
        local current = nested
        
        -- Navigate to the parent object
        for i = 1, #keys - 1 do
            local k = keys[i]
            if not current[k] then
                current[k] = {}
            elseif type(current[k]) ~= "table" then
                -- If the existing value is not a table, we can't create nested structure
                -- Skip this key to avoid conflicts
                goto continue
            end
            current = current[k]
        end
        
        -- Set the final value - special handling for raw_data field
        if keys[#keys] == "raw_data" then
            -- For raw_data, we want the value as a JSON string, not double-encoded
            if type(value) == "table" then
                current[keys[#keys]] = encodeJson(value, "raw_data")
            else
                -- If it's already a string, use it as-is
                current[keys[#keys]] = tostring(value)
            end
        else
            current[keys[#keys]] = value
        end
        ::continue::
    end
    
    -- Then, apply field ordering to the nested structure
    return applyFieldOrdering(nested, nil, eventType)
end

-- Apply field ordering to nested structure
function applyFieldOrdering(obj, fieldOrder, eventType)
    fieldOrder = fieldOrder or FIELD_ORDERS.root
    local ordered = {}
    
    -- Phase 1: Add fields in predefined order
    for _, fieldName in ipairs(fieldOrder) do
        if obj[fieldName] ~= nil then
            if type(obj[fieldName]) == "table" then
                -- Recursively apply ordering to nested objects
                local nestedFieldOrder = FIELD_ORDERS[fieldName]
                ordered[fieldName] = applyFieldOrdering(obj[fieldName], nestedFieldOrder, eventType)
            else
                ordered[fieldName] = obj[fieldName]
            end
        end
    end
    
    -- Phase 2: Add remaining fields not in the predefined order
    for key, value in pairs(obj) do
        local found = false
        for _, fieldName in ipairs(fieldOrder) do
            if key == fieldName then 
                found = true
                break 
            end
        end
        
        if not found then
            if type(value) == "table" then
                -- Recursively apply ordering to nested objects
                local nestedFieldOrder = FIELD_ORDERS[key]
                ordered[key] = applyFieldOrdering(value, nestedFieldOrder, eventType)
            else
                ordered[key] = value
            end
        end
    end
    
    return ordered
end

-- Convert ISO 8601 timestamp to Unix epoch milliseconds
function convertToMilliseconds(timestamp)
  if not timestamp or timestamp == "" then
    return nil
  end
  
  -- Parse ISO 8601 format: "2025-09-29T09:15:40Z" or "2025-09-29T09:15:40.123Z"
  local year, month, day, hour, min, sec, ms = string.match(timestamp, "(%d+)%-(%d+)%-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z")
  
  if year and month and day and hour and min and sec then
    local t = {
      year = tonumber(year),
      month = tonumber(month),
      day = tonumber(day),
      hour = tonumber(hour),
      min = tonumber(min),
      sec = tonumber(sec),
      isdst = false
    }
    
    -- Get local time interpretation
    local local_seconds = os.time(t)
    
    -- Get what this represents in UTC
    local utc_date = os.date("!*t", local_seconds)
    
    local unix_seconds
    -- Check if the UTC interpretation matches our input
    if utc_date.year == tonumber(year) and utc_date.month == tonumber(month) and 
       utc_date.day == tonumber(day) and utc_date.hour == tonumber(hour) and 
       utc_date.min == tonumber(min) and utc_date.sec == tonumber(sec) then
      -- We are already in UTC, use as-is
      unix_seconds = local_seconds
    else
      -- Calculate the correct UTC timestamp
      local utc_seconds = os.time(utc_date)
      local offset = local_seconds - utc_seconds
      unix_seconds = local_seconds + offset  -- Add offset to get UTC
    end
    
    -- Add milliseconds if present
    local milli = 0
    if ms and ms ~= "" then
      milli = tonumber((ms .. "000"):sub(1, 3))  -- pad/truncate to 3 digits
    end
    
    return unix_seconds * 1000 + milli
  end
  
  return nil
end

-- Main event processing function
function processEvent(event)
    return oktaLogsMapping(event)
end