-- GCP Audit Log OCSF 1.0.0 Schema Serializer
local FEATURES = {
    FLATTEN_EVENT_TYPE = true,
    CLEANUP_EMPTY_NULL = true,
}

local BaseEvent = {
    CATEGORY_UID = 3,
    CATEGORY_NAME = "Identity & Access Management",
    TIMEZONE_OFFSET = 0,
    STATUS_ID = 0,
    STATUS = "Unknown"
}

local DataSourceEvent = {
    VENDOR = "GCP",
    NAME = "GCP Audit",
    CATEGORY = "security"
}

local MetaDataEvent = {
    LOG_PROVIDER = "GCP Audit",
    PRODUCT_LANG = "en",
    PRODUCT_NAME = "GCP Audit",
    PRODUCT_VENDOR_NAME = "GCP",
    VERSION = "1.0.0"
}

local Mapping = {
    SEVERITY = {
        ["INFO"] = {1, "Informational"},
        ["CRITICAL"] = {5, "Critical"}
    },
    ACTIVITY = {
        admin_activity = {99, "AdminActivity"},
        data_access = {99, "DataAccess"},
        system_event = {99, "SystemEvent"},
        policy_denied = {99, "PolicyDenied"}
    },
    TYPE = {
        admin_activity = {300499, "Entity Management: AdminActivity"},
        data_access = {300499, "Entity Management: DataAccess"},
        system_event = {300499, "Entity Management: SystemEvent"},
        policy_denied = {300599, "User Access Management: PolicyDenied"}
    },
    CLASS = {
        admin_activity = {3004, "Entity Management"},
        data_access = {3004, "Entity Management"},
        system_event = {3004, "Entity Management"},
        policy_denied = {3005, "User Access Management"}
    }
}

local MAPPED_FIELDS = {}

local FIELD_ORDERS = {
    root = {
        "activity_id","activity_name","category_uid","category_name","class_uid","class_name","severity_id","type_uid","type_name","dataSource","site.id","metadata.product.name","metadata.product.vendor_name","metadata.version","actor.user.email_addr","device.ip","api.service.name","entity.name","resource.name","metadata.uid","metadata.original_time","metadata.logged_time","metadata.log_name","metadata.event_code","api.operation","cloud.provider","event.type","message","status_code","status","status_detail","time"
    },
    metadata = {"original_time", "logged_time", "log_name", "event_code", "uid", "product", "version", "currentLocations", "deviceState", "@type", "violationReason", "intermediateServices", "securityPolicyInfo", "resourceNames", "ingressViolations", "vpcServiceControlsUniqueId"},
    product = {"name", "vendor_name"},
    dataSource = {"category", "name", "vendor"},
    site = {"id"},
    event = {"type"},
    message = {"protoPayload", "insertId", "resource", "timestamp", "severity", "logName", "operation", "receiveTimestamp"},
    protoPayload = {"@type", "status", "authenticationInfo", "requestMetadata", "serviceName", "methodName", "authorizationInfo", "resourceName", "resourceLocation", "request", "metadata"},
    status = {"code", "message", "details"},
    authenticationInfo = {"principalEmail"},
    requestMetadata = {"callerIp", "callerSuppliedUserAgent", "requestAttributes", "destinationAttributes"},
    requestAttributes = {"time", "reason", "auth"},
    authorizationInfo = {"resource", "permission", "granted", "resourceAttributes"},
    resource = {"type", "labels"},
    operation = {"id", "producer", "first"},
    labels = {"method", "service", "project_id", "location", "bucket_name", "subnetwork_name", "subnetwork_id"},
    request = {"@type"},
    preconditionFailure = {"@type", "violations"},
    details = {"@type", "violations"},
    violations = {"description", "type"},
    ingressViolations = {"targetResource", "servicePerimeter"},
    securityPolicyInfo = {"organizationId", "servicePerimeterName"},
}


local FIELD_MAPPINGS = {
    {source = "activity_id", target = "activity_id"},
    {source = "activity_name", target = "activity_name"},
    {source = "category_uid", target = "category_uid"},
    {source = "category_name", target = "category_name"},
    {source = "class_uid", target = "class_uid"},
    {source = "class_name", target = "class_name"},
    {source = "severity_id", target = "severity_id"},
    {source = "type_uid", target = "type_uid"},
    {source = "status_code", target = "status_code"},
    {source = "status", target = "status"},
    {source = "status_detail", target = "status_detail"},
    {source = "dataSource", target = "dataSource"},
    {source = "site.id", target = "site.id"},
    {source = "metadata.product.name", target = "metadata.product.name"},
    {source = "metadata.product.vendor_name", target = "metadata.product.vendor_name"},
    {source = "metadata.version", target = "metadata.version"},
    {source = "metadata.uid", target = "metadata.uid"},
    {source = "metadata.original_time", target = "metadata.original_time"},
    {source = "metadata.logged_time", target = "metadata.logged_time"},
    {source = "metadata.log_name", target = "metadata.log_name"},
    {source = "metadata.event_code", target = "metadata.event_code"},
    {source = "actor.user.email_addr", target = "actor.user.email_addr"},
    {source = "device.ip", target = "device.ip"},
    {source = "api.service.name", target = "api.service.name"},
    {source = "api.operation", target = "api.operation"},
    {source = "entity.name", target = "entity.name"},
    {source = "resource.name", target = "resource.name"},
    {source = "cloud.provider", target = "cloud.provider"},
    {source = "time", target = "time"},
    {source = "message", target = "message"}
    --{source = "event.type", target = "event.type"},

}

local IGNORE_KEYS = {
    _ob = true,
    message_id = true,
}

local function split(str, delimiter)
    if not str or str == "" then
        return {}
    end
    local result = {}
    for token in string.gmatch(str, "([^" .. delimiter .. "]+)") do
        table.insert(result, token)
    end
    return result
end

local function getValueByPath(obj, path)
    local current = obj
    for _, part in ipairs(split(path, ".")) do

        if type(current) ~= "table" then
            return nil
        end

        local key = tonumber(part) or part

        current = current[key]
    end
    return current
end

local function setValueByPath(obj, path, value)
    local parts = split(path, ".")
    local current = obj
    for i = 1, #parts - 1 do
        local key = tonumber(parts[i]) or parts[i]
        if current[key] == nil or type(current[key]) ~= "table" then
            current[key] = {}
        end
        current = current[key]
    end
    local last = parts[#parts]
    if value == nil then
        current[last] = nil
    else
        current[last] = value
    end
end

local function deepCopy(value, ignoreKeys)
    if type(value) ~= "table" then
        return value
    end

    local copy = {}
    for k, v in pairs(value) do
        if not (ignoreKeys and ignoreKeys[k]) then
            copy[k] = deepCopy(v, ignoreKeys)
        end
    end
    return copy
end

local function convertUtcToMilliseconds(timestamp)
    if not timestamp or timestamp == "" then
        return nil
    end
    local year, month, day, hour, min, sec, frac =
        string.match(timestamp, "(%d+)%-(%d+)%-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z")
    if not year then
        return nil
    end
    local timeStruct = {
        year = tonumber(year),
        month = tonumber(month),
        day = tonumber(day),
        hour = tonumber(hour),
        min = tonumber(min),
        sec = tonumber(sec),
        isdst = false
    }
    local localSeconds = os.time(timeStruct)
    local utcDate = os.date("!*t", localSeconds)
    local adjustedSeconds
    if utcDate.year == timeStruct.year and utcDate.month == timeStruct.month and
        utcDate.day == timeStruct.day and utcDate.hour == timeStruct.hour and
        utcDate.min == timeStruct.min and utcDate.sec == timeStruct.sec then
        adjustedSeconds = localSeconds
    else
        local utcSeconds = os.time(utcDate)
        adjustedSeconds = localSeconds + (localSeconds - utcSeconds)
    end
    local milli = 0
    if frac and frac ~= "" then
        milli = tonumber((frac .. "000"):sub(1, 3))
    end
    return adjustedSeconds * 1000 + milli
end

local function encodeJson(obj, key)
    if obj == nil or obj == "NULL_PLACEHOLDER" or obj == "" then
        return nil
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
            if #items == 0 then
                return nil
            end
            return "[" .. table.concat(items, ", ") .. "]"
        else
            local items = {}
            local fieldOrder = FIELD_ORDERS[key] or {}

            -- Phase 1: ordered keys
            for _, fieldName in ipairs(fieldOrder) do
                local v = obj[fieldName]
                if v ~= nil then
                    local encoded = encodeJson(v, fieldName)
                    if encoded ~= nil then
                        table.insert(items, '"' .. fieldName:gsub('"', '\\"') .. '": ' .. encoded)
                    end
                end
            end

            -- Phase 2: remaining keys
            for k, v in pairs(obj) do
                local found = false
                for _, fieldName in ipairs(fieldOrder) do
                    if k == fieldName then
                        found = true
                        break
                    end
                end
                if not found then
                    local keyStr = type(k) == "string" and k or tostring(k)
                    local encoded = encodeJson(v, keyStr)
                    if encoded ~= nil then
                        table.insert(items, '"' .. keyStr:gsub('"', '\\"') .. '": ' .. encoded)
                    end
                end
            end

            if #items == 0 then
                return nil
            end
            return "{" .. table.concat(items, ", ") .. "}"
        end
    else
        return '"' .. tostring(obj) .. '"'
    end
end

local function filterNullValues(obj)
    local filtered = {}
    for k, v in pairs(obj or {}) do
        if v ~= nil and v ~= "" and v ~= "null" then
            if type(v) == "table" then
                local nested = filterNullValues(v)
                if next(nested) then
                    filtered[k] = nested
                end
            else
                filtered[k] = v
            end
        end
    end
    return filtered
end

local function isArrayTable(obj)
    if type(obj) ~= "table" then
        return false
    end
    local count = 0
    for k, _ in pairs(obj) do
        if type(k) ~= "number" then
            return false
        end
        count = count + 1
    end
    return count == #obj
end

local function applyFieldOrdering(obj, fieldOrder)
    if isArrayTable(obj) then
        local out = {}
        for i = 1, #obj do
            out[i] = obj[i]
        end
        return out
    end
    local ordered = {}
    for _, key in ipairs(fieldOrder or {}) do
        if obj[key] ~= nil then
            if type(obj[key]) == "table" then
                ordered[key] = applyFieldOrdering(obj[key], FIELD_ORDERS[key])
            else
                ordered[key] = obj[key]
            end
        end
    end
    for key, value in pairs(obj or {}) do
        local found = false
        for _, orderedKey in ipairs(fieldOrder or {}) do
            if orderedKey == key then
                found = true
                break
            end
        end
        if not found then
            if type(value) == "table" then
                ordered[key] = applyFieldOrdering(value, FIELD_ORDERS[key])
            else
                ordered[key] = value
            end
        end
    end
    return ordered
end

local function collectUnmapped(source, target, ignoreKeys)
    for key, value in pairs(source or {}) do
        if not (ignoreKeys and ignoreKeys[key]) then
            if type(value) == "table" then
                local nested = {}
                collectUnmapped(value, nested, ignoreKeys)
                if next(nested) then
                    target[key] = nested
                end
            else
                target[key] = value
            end
        end
    end
end

local function getSeverityInfo(severity)
    local normalized = severity and severity:upper() or ""
    local info = Mapping.SEVERITY[normalized]
    if info then
        return info[1], info[2]
    end
    return 99, "Unknown"  -- Default for unmapped severities (matches Python)
end

local function getEventType(logName)
    if not logName then
        return "unknown"
    end

    if string.find(logName, "activity") then
        return "admin_activity"
    elseif string.find(logName, "data_access") then
        return "data_access"
    elseif string.find(logName, "system_event") then
        return "system_event"
    elseif string.find(logName, "policy") then
        return "policy_denied"
    end

    return "unknown"
end

local function getActivityInfo(eventType)
    local info = Mapping.ACTIVITY[eventType]
    if info then
        return info[1], info[2]
    end
    return 99, "Unknown"
end

local function getTypeInfo(eventType)
    local info = Mapping.TYPE[eventType]
    if info then
        return info[1], info[2]
    end
    return 300499, "Entity Management: Unknown"
end

local function getClassInfo(eventType)
    local info = Mapping.CLASS[eventType]
    if info then
        return info[1], info[2]
    end
    return 3004, "Entity Management"
end

local function buildSource(event)
    local source = deepCopy(event, IGNORE_KEYS) or {}

    source.message = encodeJson(source, "message")

    -- Determine event type from logName
    local eventType = getEventType(source.logName)


    -- Get activity information
    local activity_id, activity_name = getActivityInfo(eventType)
    local type_uid, type_name = getTypeInfo(eventType)
    local class_uid, class_name = getClassInfo(eventType)

    -- Get severity information
    local severity_id, severity_label = getSeverityInfo(source.severity)

    -- Set base event properties
    source.activity_id = activity_id
    source.activity_name = activity_name
    source.category_uid = BaseEvent.CATEGORY_UID
    source.category_name = BaseEvent.CATEGORY_NAME
    source.class_uid = class_uid
    source.class_name = class_name
    
    source.severity_id = severity_id
    source.type_uid = type_uid
    --source.type_name = type_name

    -- Set data source
    source.dataSource = {
        vendor = DataSourceEvent.VENDOR,
        name = DataSourceEvent.NAME,
        category = DataSourceEvent.CATEGORY
    }

    -- Set metadata
    source.metadata = source.metadata or {}
    source.metadata.product = source.metadata.product or {}
    source.metadata.product.name = MetaDataEvent.PRODUCT_NAME
    source.metadata.product.vendor_name = MetaDataEvent.PRODUCT_VENDOR_NAME
    source.metadata.version = MetaDataEvent.VERSION

    -- Set site if available (siteId can be passed as parameter or extracted from log)
    source.site = source.site or {}
    source.site.id = source.site.id or ""

    -- Set event type
    source.event = {type = activity_name or ""}

    -- Map GCP audit log specific fields
    source.metadata.original_time = source.timestamp
    MAPPED_FIELDS["timestamp"] = true
    source.metadata.logged_time = source.receiveTimestamp
    MAPPED_FIELDS["receiveTimestamp"] = true
    source.metadata.log_name = source.logName
    MAPPED_FIELDS["logName"] = true
    source.metadata.event_code = getValueByPath(source, "operation.id") or ""
    MAPPED_FIELDS["operation.id"] = true
    source.metadata.uid = source.insertId
    MAPPED_FIELDS["insertId"] = true
    -- Map actor and device information
    if source.protoPayload and source.protoPayload.authenticationInfo then
        source.actor = source.actor or {}
        source.actor.user = source.actor.user or {}
        source.actor.user.email_addr = source.protoPayload.authenticationInfo.principalEmail
        MAPPED_FIELDS["protoPayload.authenticationInfo.principalEmail"] = true
    end

    if source.protoPayload and source.protoPayload.requestMetadata then
        source.device = source.device or {}
        source.device.ip = source.protoPayload.requestMetadata.callerIp
        MAPPED_FIELDS["protoPayload.requestMetadata.callerIp"] = true
    end

    -- Map API information
    if source.protoPayload then
        source.api = source.api or {}
        source.api.service = source.api.service or {}
        source.api.service.name = source.protoPayload.serviceName
        MAPPED_FIELDS["protoPayload.serviceName"] = true
        source.api.operation = getValueByPath(source, "operation.producer") or ""
        MAPPED_FIELDS["operation.producer"] = true
    end

    -- Map resource information
    -- For policy denied events, use resource.name (not entity.name)
    -- For all other events, use entity.name (if resourceName exists)
    if source.protoPayload and source.protoPayload.resourceName then
        if eventType == "policy_denied" then
            source.resource = source.resource or {}
            source.resource.name = source.protoPayload.resourceName
        else
            source.entity = source.entity or {}
            source.entity.name = source.protoPayload.resourceName
        end
        MAPPED_FIELDS["protoPayload.resourceName"] = true
    end

    -- Extract status fields from protoPayload.status (satisfies getpolicyDeniedOCSFMapping)
    if source.protoPayload and source.protoPayload.status then
        source.status_code = source.protoPayload.status.code
        source.status = source.protoPayload.status.message
        source.status_detail = source.protoPayload.status.details
        -- Mark status fields as mapped to avoid duplication
        MAPPED_FIELDS["protoPayload.status.code"] = true
        MAPPED_FIELDS["protoPayload.status.message"] = true
        MAPPED_FIELDS["protoPayload.status.details"] = true
    end

    -- Set cloud provider
    source.cloud = source.cloud or {}
    source.cloud.provider = "GCP"


    -- Set time
    source.time = convertUtcToMilliseconds(source.timestamp)
    -- timestamp is already marked as mapped above

    -- Build message directly with ordering-aware encoder

    return source
end

local function cleanupEmptyNull(obj)

    if type(obj) ~= "table" then
        if type(obj) == "string" then
            local lower = obj:lower()
            if lower == "" or lower == "null" then
                return nil
            end
        end
        return obj
    end

    for key, value in pairs(obj) do
        local cleaned = cleanupEmptyNull(value)
        if cleaned == nil then
            obj[key] = nil
        else
            obj[key] = cleaned
        end
    end

    if next(obj) == nil then
        return nil
    end
    return obj
end

local function processEvent(event)
    if type(event) ~= "table" then
        return nil
    end

    -- reset mapped fields per event to avoid cross-event leakage
    MAPPED_FIELDS = {}

    local source = buildSource(event)

    local result = {}

    for _, mapping in ipairs(FIELD_MAPPINGS) do
        local value = getValueByPath(source, mapping.source)
        if value ~= nil then
            setValueByPath(result, mapping.target, deepCopy(value))
            MAPPED_FIELDS[mapping.source] = true
        end
    end

    -- Remove mapped fields from original event
    for key, _ in pairs(MAPPED_FIELDS) do
        setValueByPath(event, key, nil)
    end

    -- Collect remaining unmapped fields (fields not mapped to OCSF output)
    local unmapped = {}
    collectUnmapped(event, unmapped, IGNORE_KEYS)
    if next(unmapped) then
        result.unmapped = unmapped
    end

    if FEATURES.FLATTEN_EVENT_TYPE then
        if source and source.event then
            result['event.type'] = source.event.type
        end
    end

    if FEATURES.CLEANUP_EMPTY_NULL then
        cleanupEmptyNull(result)
    end

    return result
end