
-- Azure Platform to OCSF Mapping Script
-- Maps Azure Platform log events to OCSF v1.1.0 format
-- Supports: Administrative, Security, Alert, Policy, Storage (Read/Write/Delete), SignIn, Audit, Provisioning logs
--
-- Usage: processEvent(event) -> ocsf_event

local FEATURES = {
    FLATTEN_EVENT_TYPE = true,
}

function mappedFields(fieldMappings)
  local mapped = {}
  for _, v in ipairs(fieldMappings) do
    source = v['source']
    mapped[source] = true
  end
  return mapped
end

-- Helper to check if a table is an array
local function isArray(t)
    if type(t) ~= "table" then return false end
    local i = 0
    for _ in pairs(t) do
        i = i + 1
        if t[i] == nil then
            return false
        end
    end
    return true
end

local function parse_iso8601_to_milli(time_str)
    if not time_str or time_str == "" then return nil end
    local year, month, day, hour, min, sec, frac = 
        time_str:match("(%d+)%-(%d+)%-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)Z?")
    if not year then return nil end
    
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

function copyUnmappedFields(event, fieldMappings, result)
    -- copy everything else to unmapped
    flattenEvent = flattenObject(event)
    mapped = mappedFields(fieldMappings)
    for k, v in pairs(flattenEvent) do
        if k ~= "_ob" and not mapped[k] and v ~= nil and v ~= "" then
            setNestedField(result, "unmapped." .. k, v)
        end
    end
    return result
end

function flattenObject(tbl, prefix, result)
    result = result or {}
    prefix = prefix or ""
    for k, v in pairs(tbl) do
        local keyPath = prefix ~= "" and (prefix .. "." .. tostring(k)) or tostring(k)
        local vtype = type(v)
        if vtype == "table" then
            if isArray(v) then
                -- Keep arrays as is
                result[keyPath] = v
            else
                flattenObject(v, keyPath, result)
            end
        elseif vtype == "userdata" then
            -- Handle userdata safely
            local ok, s = pcall(tostring, v)
            if not ok then
                result[keyPath] = nil
            end
            if s == "userdata: (nil)" then
                result[keyPath] = nil
            end
            if s == "userdata: 0x0" then
                result[keyPath] = nil
            end
        else
            result[keyPath] = v
        end
    end
    return result
end

local ADMIN_FIELD_ORDERS = {
    root = {
        "callerIpAddress",
        "category",
        "correlationId",
        "durationMs",
        "identity",
        "level",
        "location",
        "operationName",
        "properties",
        "resourceId",
        "resourceType",
        "resultSignature",
        "resultType",
        "tenantId",
        "time"
    },
    identity = {
        "claims"
    },
    claims = {
        "appid",
        "groups",
        "ipaddr",
        "name",
        "http://schemas.microsoft.com/identity/claims/objectidentifier",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    },
    properties = {
        "resourceGroup",
        "resourceLocation"
    }
}

local SECURITY_FIELD_ORDERS = {
    root = {
        "category",
        "correlationId",
        "level",
        "location",
        "operationName",
        "properties",
        "resourceId",
        "resultDescription",
        "resultType",
        "time"
    }
}

local ALERT_FIELD_ORDERS = {
    root = {
        "caller",
        "category",
        "correlationId",
        "level",
        "operationName",
        "properties",
        "resourceId",
        "resultDescription",
        "resultType",
        "time"
    }
}

local POLICY_FIELD_ORDERS = {
    root = {
        "callerIpAddress",
        "category",
        "correlationId",
        "durationMs",
        "identity",
        "level",
        "location",
        "operationName",
        "properties",
        "resourceId",
        "resultSignature",
        "resultType",
        "tenantId",
        "time"
    }
}

local RESOURCE_FIELD_ORDERS = {
    root = {
        "callerIpAddress",
        "category",
        "correlationId",
        "durationMs",
        "identity",
        "level",
        "location",
        "operationName",
        "properties",
        "resourceId",
        "resourceType",
        "schemaVersion",
        "statusCode",
        "statusText",
        "time",
        "uri"
    }
}

local SIGN_IN_FIELD_ORDERS = {
    root = {
        "callerIpAddress",
        "category",
        "correlationId",
        "durationMs",
        "identity",
        "level",
        "location",
        "operationName",
        "properties",
        "resourceId",
        "resultType",
        "tenantId",
        "time"
    }
}

local AUDIT_FIELD_ORDERS = {
    root = {
        "category",
        "correlationId",
        "durationMs",
        "identity",
        "level",
        "operationName",
        "properties",
        "resourceId",
        "resultType",
        "tenantId",
        "time"
    }
}

local PROVISIONING_FIELD_ORDERS = {
    root = {
        "category",
        "correlationId",
        "durationMs",
        "identity",
        "level",
        "operationName",
        "properties",
        "resourceId",
        "resultType",
        "tenantId",
        "time"
    }
}

local BASE_FIELD_ORDERS = {
    root = {
        "category",
        "correlationId",
        "identity",
        "level",
        "location",
        "operationName",
        "properties",
        "resourceId",
        "resultType",
        "time"
    }
}

ARRAY_FIELDS = {
    observables = true,
    resources = true,
}

-- Optimized JSON encoding function with predefined ordering
function encodeJson(obj, key, field_orders)
  if obj == nil or obj == "NULL_PLACEHOLDER" then
    return "null"
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
    
    if isArray and maxIndex > 0 then
      local items = {}
      for i = 1, maxIndex do
        -- Use the parent key for predefined ordering if available
        local elementKey = key or tostring(i)
        table.insert(items, obj[i] ~= nil and encodeJson(obj[i], elementKey, field_orders) or "null")
      end
      return "[" .. table.concat(items, ", ") .. "]"
    elseif isArray and ARRAY_FIELDS[key] == true then
      -- case of empty array []
      return "[]"
    else
      local items = {}
      local fieldOrder = field_orders[key] or {}
      
      -- Phase 1: Process fields in predefined order
      for _, fieldName in ipairs(fieldOrder) do
        local v = obj[fieldName]
        if v ~= nil then
          table.insert(items, '"' .. fieldName:gsub('"', '\\"') .. '": ' .. encodeJson(v, fieldName, field_orders))
        else 
          table.insert(items, '"' .. fieldName:gsub('"', '\\"') .. '": ' .. "null")
        end
      end
      
      -- Phase 2: Process remaining fields
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
          table.insert(items, '"' .. keyStr:gsub('"', '\\"') .. '": ' .. encodeJson(v, keyStr, field_orders))
        end
      end
      
      return "{" .. table.concat(items, ", ") .. "}"
    end
  else
    return '"' .. tostring(obj) .. '"'
  end
end


function setNestedField(obj, path, value)
    if value == nil or path == nil or path == '' then return end

    local keys = {}
    for key in string.gmatch(path, '[^.]+') do
        if key and key ~= '' then
            table.insert(keys, key)
        end
    end

    if #keys == 0 then return end

    local current = obj
    for i = 1, #keys - 1 do
        local key = keys[i]
        if key then
            local arrayIndex = string.match(key, '(.-)%[(%d+)%]')
            if arrayIndex then
                local baseName = string.match(key, '(.-)%[')
                local index = tonumber(string.match(key, '%[(%d+)%]')) + 1
                if current[baseName] == nil then
                    current[baseName] = {}
                end
                if current[baseName][index] == nil then
                    current[baseName][index] = {}
                end
                current = current[baseName][index]
            else
                if current[key] == nil then
                    current[key] = {}
                end
                current = current[key]
            end
        end
    end

    local finalKey = keys[#keys]
    if finalKey then
        local arrayIndex = string.match(finalKey, '(.-)%[(%d+)%]')
        if arrayIndex then
            local baseName = string.match(finalKey, '(.-)%[')
            local index = tonumber(string.match(finalKey, '%[(%d+)%]')) + 1
            if current[baseName] == nil then
                current[baseName] = {}
            end
            current[baseName][index] = value
        else
            current[finalKey] = value
        end
    end
end

function getNestedField(obj, path)
    if obj == nil or path == nil or path == '' then return nil end

    local keys = {}
    for key in string.gmatch(path, '[^.]+') do
        if key and key ~= '' then
            table.insert(keys, key)
        end
    end

    if #keys == 0 then return nil end

    local current = obj
    for _, key in ipairs(keys) do
        if current == nil or key == nil then return nil end

        local arrayIndex = string.match(key, '(.-)%[(%d+)%]')
        if arrayIndex then
            local baseName = string.match(key, '(.-)%[')
            local index = tonumber(string.match(key, '%[(%d+)%]')) + 1
            if current[baseName] == nil or current[baseName][index] == nil then
                return nil
            end
            current = current[baseName][index]
        else
            if current[key] == nil then
                return nil
            end
            current = current[key]
        end
    end
    return current
end

function copyField(source, target, sourcePath, targetPath)
    if source == nil or target == nil or sourcePath == nil or targetPath == nil then
        return
    end
    if sourcePath == '' or targetPath == '' then
        return
    end
    local value = getNestedField(source, sourcePath)
    if value ~= nil then
        setNestedField(target, targetPath, value)
    end
end

function getValue(tbl, key, default)
    local value = tbl[key]
    if value == nil then
        return default
    else
        return value
    end
end

function getSeverityId(level)
    if level == nil then
        return 0
    end
    local severityMap = {
        Critical = 5,
        Information = 1,
        Informational = 1,
        Warning = 99,
        Error = 6
    }
    return severityMap[level] or 0
end

function getDefaultMapping(event)
    local category = getValue(event, "category", "Other")
    local result = {}
    result.activity_id = 99
    result.metadata = {
        product = {name = "Azure Platform", vendor_name = "Microsoft"},
        version = "1.1.0"
    }
    result.severity_id = getSeverityId(getValue(event, "level", nil))
    result.dataSource = {category = "security", name = "Azure Platform", vendor = "Microsoft"}
    result.cloud = {provider = "Azure", account = {type_id = "6", type = "Azure AD Account"}}
    result.event = {type = category}
    result.activity_name = category
    return result
end

function getObservables(event, category)
    local observables = {}
    local resourceUid = getValue(event, "resourceId", nil)
    local ipAddress = getValue(event, "callerIpAddress", nil)
    local location = getValue(event, "location", nil)
    local userAgent = getNestedField(event, "properties.userAgent")
    local caller = getValue(event, "caller", nil)
    local tokenHash = getNestedField(event, "identity.tokenHash")
    local uri = getValue(event, "uri", nil)
    local initiatedBy = getNestedField(event, "properties.initiatedBy.Name")

    if category == "Administrative" then
        if resourceUid then
            table.insert(observables, {name = "resources.uid", type_id = 10, type = "Resource UID", value = resourceUid})
        end
        if ipAddress then
            table.insert(observables, {name = "src_endpoint.ip", type_id = 2, type = "IP Address", value = ipAddress})
        end
    elseif category == "Security" then
        if resourceUid then
            table.insert(observables, {name = "resource.uid", type_id = 10, type = "Resource UID", value = resourceUid})
        end
        if userAgent then
            table.insert(observables, {name = "unmapped.properties.userAgent", type_id = 99, type = "Other", value = userAgent})
        end
        if location then
            table.insert(observables, {name = "unmapped.location", type_id = 26, type = "Geo Location", value = location})
        end
    elseif category == "Alert" then
        if resourceUid then
            table.insert(observables, {name = "resources.uid", type_id = 10, type = "Resource UID", value = resourceUid})
        end
        if caller then
            table.insert(observables, {name = "actor.user.name", type_id = 4, type = "User Name", value = caller})
        end
    elseif category == "Policy" then
        if resourceUid then
            table.insert(observables, {name = "resources.uid", type_id = 10, type = "Resource UID", value = resourceUid})
        end
        if ipAddress then
            table.insert(observables, {name = "src_endpoint.ip", type_id = 2, type = "IP Address", value = ipAddress})
        end
    elseif category == "StorageRead" or category == "StorageWrite" or category == "StorageDelete" then
        if resourceUid then
            table.insert(observables, {name = "resources.uid", type_id = 10, type = "Resource UID", value = resourceUid})
        end
        if ipAddress then
            table.insert(observables, {name = "src_endpoint.ip", type_id = 2, type = "IP Address", value = ipAddress})
        end
        if tokenHash then
            table.insert(observables, {name = "unmapped.identity.tokenHash", type_id = 8, type = "Hash", value = tokenHash})
        end
        if uri then
            table.insert(observables, {name = "http_request.url.url_string", type_id = 6, type = "URL String", value = uri})
        end
        if location then
            table.insert(observables, {name = "cloud.region", type_id = 26, type = "Geo Location", value = location})
        end
    elseif category == "SignInLogs" then
        if resourceUid then
            table.insert(observables, {name = "resources.uid", type_id = 10, type = "Resource UID", value = resourceUid})
        end
        if ipAddress then
            table.insert(observables, {name = "src_endpoint.ip", type_id = 2, type = "IP Address", value = ipAddress})
        end
        if location then
            table.insert(observables, {name = "cloud.region", type_id = 26, type = "Geo Location", value = location})
        end
    elseif category == "AuditLogs" then
        if resourceUid then
            table.insert(observables, {name = "resources.uid", type_id = 10, type = "Resource UID", value = resourceUid})
        end
        if userAgent then
            table.insert(observables, {name = "http_request.user_agent", type_id = 99, type = "Other", value = userAgent})
        end
    elseif category == "ProvisioningLogs" then
        if resourceUid then
            table.insert(observables, {name = "resources.uid", type_id = 10, type = "Resource UID", value = resourceUid})
        end
        if initiatedBy then
            table.insert(observables, {name = "actor.user.name", type_id = 4, type = "User Name", value = initiatedBy})
        end
    end
    return observables
end

function buildResources(event)
    local resources = {}
    local resourceUid = getValue(event, "resourceId", nil)
    local resourceType = getValue(event, "resourceType", nil)
    local resourceLocation = getNestedField(event, "properties.resourceLocation")
    local resourceGroup = getNestedField(event, "properties.resourceGroup")

    -- Use index [1] to ensure encodeJson treats this as an array
    if resourceUid and resourceLocation and resourceGroup and resourceType then
        resources[1] = {uid = resourceUid, region = resourceLocation, type = resourceType, group = {name = resourceGroup}}
    elseif resourceUid and resourceGroup and resourceType then
        resources[1] = {uid = resourceUid, type = resourceType, group = {name = resourceGroup}}
    elseif resourceLocation and resourceGroup and resourceType then
        resources[1] = {region = resourceLocation, type = resourceType, group = {name = resourceGroup}}
    elseif resourceUid and resourceLocation and resourceType then
        resources[1] = {uid = resourceUid, type = resourceType, region = resourceLocation}
    elseif resourceUid and resourceType then
        resources[1] = {uid = resourceUid, type = resourceType}
    elseif resourceLocation and resourceType then
        resources[1] = {region = resourceLocation, type = resourceType}
    elseif resourceLocation and resourceUid then
        resources[1] = {region = resourceLocation, uid = resourceUid}
    elseif resourceGroup and resourceType then
        resources[1] = {group = {name = resourceGroup}, type = resourceType}
    elseif resourceUid then
        resources[1] = {uid = resourceUid}
    elseif resourceLocation then
        resources[1] = {region = resourceLocation}
    elseif resourceGroup then
        resources[1] = {group = {name = resourceGroup}}
    elseif resourceType then
        resources[1] = {type = resourceType}
    end
    return resources
end

function getAdminEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 6003
    result.class_name = "API Activity"
    result.category_uid = 6
    result.category_name = "Application Activity"
    result.activity_id = 99
    result.activity_name = "Administrative"
    result.type_uid = 600399
    result.type_name = "API Activity: Other"
    result.observables = getObservables(event, "Administrative")
    result.resources = buildResources(event)

    local fieldMappings = {
        {source='identity.claims.appid', target='api.service.uid'},
        {source='identity.claims.groups', target='actor.user.groups'},
        {source='identity.claims.ipaddr', target='dst_endpoint.ip'},
        {source='identity.claims.name', target='actor.user.name'},
        {source='identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', target='actor.idp.name'},
        {source='identity.claims.http://schemas.microsoft.com/identity/claims/objectidentifier', target='actor.idp.uid'},
        {source='correlationId', target='metadata.correlation_uid'},
        {source='category', target='metadata.log_name'},
        {source='time', target='metadata.original_time'},
        {source='operationName', target='api.operation'},
        {source='tenantId', target='metadata.tenant_uid'},
        {source='durationMs', target='duration'},
        {source='callerIpAddress', target='src_endpoint.ip'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        if mapping.source ~= 'identity.claims.groups' then
            copyField(event, result, mapping.source, mapping.target)
        end
    end

    local identity = event.identity or {}
    local claims = identity.claims or {}
    
    local idp_name = claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]
    local idp_uid = claims["http://schemas.microsoft.com/identity/claims/objectidentifier"]

    if idp_name or idp_uid then
        result.actor = result.actor or {}
        result.actor.idp = result.actor.idp or {}
        result.actor.idp.name = idp_name
        result.actor.idp.uid = idp_uid
    end

    local groupsStr = claims["groups"]
    if groupsStr and groupsStr ~= "" then
        result.actor = result.actor or {}
        result.actor.user = result.actor.user or {}
        
        result.actor.user.groups = {}
        result.actor.user.groups[1] = { uid = groupsStr }
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getSecurityEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 2002
    result.class_name = "Vulnerability Finding"
    result.category_uid = 2
    result.category_name = "Findings"
    result.activity_id = 99
    result.activity_name = "Security"
    result.type_uid = 200299
    result.type_name = "Vulnerability Finding: Other"
    result.observables = getObservables(event, "Security")

    local fieldMappings = {
        {source='correlationId', target='metadata.correlation_uid'},
        {source='category', target='metadata.log_name'},
        {source='time', target='metadata.original_time'},
        {source='operationName', target='api.operation'},
        {source='resourceId', target='resource.uid'},
        {source='resultDescription', target='finding_info.desc'},
        {source='properties.resourceType', target='resource.type'},
        {source='properties.alertId', target='metadata.uid'},
        {source='properties.azureADUser', target='actor.user.name'},
        {source='properties.accessKeyUsedToGenerateSASToken', target='actor.session.uid'},
        {source='properties.productComponentName', target='metadata.product.feature.name'},
        {source='properties.attackedResourceType', target='unmapped.properties.attackedResourceType'},
        {source='properties.eventName', target='metadata.loggers'},
        {source='properties.operationId', target='metadata.loggers'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getAlertEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 2004
    result.class_name = "Detection Finding"
    result.category_uid = 2
    result.category_name = "Findings"
    result.activity_id = 99
    result.activity_name = "Alert"
    result.type_uid = 200499
    result.type_name = "Detection Finding: Other"
    result.observables = getObservables(event, "Alert")
    result.resources = buildResources(event)

    local fieldMappings = {
        {source='correlationId', target='metadata.correlation_uid'},
        {source='resultDescription', target='finding_info.desc'},
        {source='category', target='metadata.log_name'},
        {source='time', target='metadata.original_time'},
        {source='operationName', target='api.operation'},
        {source='caller', target='actor.user.name'},
        {source='properties.tenantId', target='metadata.tenant_uid'},
        {source='properties.eventDataId', target='metadata.uid'},
        {source='properties.eventTimestamp', target='metadata.logged_time'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getPolicyEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 6003
    result.class_name = "API Activity"
    result.category_uid = 6
    result.category_name = "Application Activity"
    result.activity_id = 99
    result.activity_name = "Policy"
    result.type_uid = 600399
    result.type_name = "API Activity: Other"
    result.observables = getObservables(event, "Policy")
    result.resources = buildResources(event)

    local fieldMappings = {
        {source='identity.claims.appid', target='api.service.uid'},
        {source='identity.claims.groups', target='actor.user.groups'},
        {source='identity.claims.ipaddr', target='dst_endpoint.ip'},
        {source='identity.claims.name', target='actor.user.full_name'},
        {source='identity.claims.http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', target='actor.idp.name'},
        {source='identity.claims.http://schemas.microsoft.com/identity/claims/objectidentifier', target='actor.idp.uid'},
        {source='correlationId', target='metadata.correlation_uid'},
        {source='category', target='metadata.log_name'},
        {source='time', target='metadata.original_time'},
        {source='operationName', target='api.operation'},
        {source='durationMs', target='duration'},
        {source='callerIpAddress', target='src_endpoint.ip'},
        {source='tenantId', target='metadata.tenant_uid'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        if mapping.source ~= 'identity.claims.groups' then
            copyField(event, result, mapping.source, mapping.target)
        end
    end

    local identity = event.identity or {}
    local claims = identity.claims or {}
    
    local idp_name = claims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]
    local idp_uid = claims["http://schemas.microsoft.com/identity/claims/objectidentifier"]

    if idp_name or idp_uid then
        result.actor = result.actor or {}
        result.actor.idp = result.actor.idp or {}
        result.actor.idp.name = idp_name
        result.actor.idp.uid = idp_uid
    end

    local groupsStr = claims["groups"]
    if groupsStr and groupsStr ~= "" then
        result.actor = result.actor or {}
        result.actor.user = result.actor.user or {}
        
        result.actor.user.groups = {}
        result.actor.user.groups[1] = { uid = groupsStr }
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getStorageReadEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 6003
    result.class_name = "API Activity"
    result.category_uid = 6
    result.category_name = "Application Activity"
    result.activity_id = 2
    result.activity_name = "Read"
    result.type_uid = 600302
    result.event.type = "Read"
    result.type_name = "API Activity: Read"
    result.observables = getObservables(event, "StorageRead")
    result.resources = buildResources(event)

    local fieldMappings = {
        {source='time', target='metadata.original_time'},
        {source='category', target='metadata.log_name'},
        {source='operationName', target='api.operation'},
        {source='schemaVersion', target='metadata.log_version'},
        {source='statusCode', target='status_code'},
        {source='statusText', target='status_detail'},
        {source='durationMs', target='duration'},
        {source='callerIpAddress', target='src_endpoint.ip'},
        {source='correlationId', target='metadata.correlation_uid'},
        {source='identity.type', target='actor.user.type'},
        {source='identity.requester.appId', target='api.service.uid'},
        {source='identity.requester.objectId', target='actor.idp.uid'},
        {source='identity.requester.tenantId', target='metadata.tenant_uid'},
        {source='location', target='cloud.region'},
        {source='properties.accountName', target='actor.user.account.name'},
        {source='properties.userAgentHeader', target='http_request.user_agent'},
        {source='uri', target='http_request.url.url_string'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getStorageWriteEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 6003
    result.class_name = "API Activity"
    result.category_uid = 6
    result.category_name = "Application Activity"
    result.activity_id = 3
    result.activity_name = "Update"
    result.type_uid = 600303
    result.type_name = "API Activity: Update"
    result.event.type = "Update"
    result.observables = getObservables(event, "StorageWrite")
    result.resources = buildResources(event)

    local fieldMappings = {
        {source='time', target='metadata.original_time'},
        {source='category', target='metadata.log_name'},
        {source='operationName', target='api.operation'},
        {source='schemaVersion', target='metadata.log_version'},
        {source='statusCode', target='status_code'},
        {source='statusText', target='status_detail'},
        {source='durationMs', target='duration'},
        {source='callerIpAddress', target='src_endpoint.ip'},
        {source='correlationId', target='metadata.correlation_uid'},
        {source='identity.type', target='actor.user.type'},
        {source='identity.requester.appId', target='api.service.uid'},
        {source='identity.requester.objectId', target='actor.idp.uid'},
        {source='identity.requester.tenantId', target='metadata.tenant_uid'},
        {source='location', target='cloud.region'},
        {source='properties.accountName', target='actor.user.account.name'},
        {source='properties.userAgentHeader', target='http_request.user_agent'},
        {source='uri', target='http_request.url.url_string'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getStorageDeleteEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 6003
    result.class_name = "API Activity"
    result.category_uid = 6
    result.category_name = "Application Activity"
    result.activity_id = 4
    result.activity_name = "Delete"
    result.type_uid = 600304
    result.type_name = "API Activity: Delete"
    result.event.type = "Delete"
    result.observables = getObservables(event, "StorageDelete")
    result.resources = buildResources(event)

    local fieldMappings = {
        {source='time', target='metadata.original_time'},
        {source='category', target='metadata.log_name'},
        {source='operationName', target='api.operation'},
        {source='schemaVersion', target='metadata.log_version'},
        {source='statusCode', target='status_code'},
        {source='statusText', target='status_detail'},
        {source='durationMs', target='duration'},
        {source='callerIpAddress', target='src_endpoint.ip'},
        {source='correlationId', target='metadata.correlation_uid'},
        {source='identity.type', target='actor.user.type'},
        {source='identity.requester.appId', target='api.service.uid'},
        {source='identity.requester.objectId', target='actor.idp.uid'},
        {source='identity.requester.tenantId', target='metadata.tenant_uid'},
        {source='location', target='cloud.region'},
        {source='properties.accountName', target='actor.user.account.name'},
        {source='properties.userAgentHeader', target='http_request.user_agent'},
        {source='uri', target='http_request.url.url_string'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getSignInEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 3002
    result.class_name = "Authentication"
    result.category_uid = 3
    result.category_name = "Identity & Access Management"
    result.activity_id = 1
    result.activity_name = "Logon"
    result.type_uid = 300201
    result.type_name = "Authentication: Logon"
    result.event.type = "Logon"
    result.observables = getObservables(event, "SignInLogs")

    -- Handle coordinates
    local lat = getNestedField(event, "properties.location.geoCoordinates.latitude")
    local lon = getNestedField(event, "properties.location.geoCoordinates.longitude")
    if lat and lon then
        result.src_endpoint = result.src_endpoint or {}
        result.src_endpoint.location = result.src_endpoint.location or {}
        result.src_endpoint.location.coordinates = {lat, lon}
    end

    local fieldMappings = {
        {source='time', target='metadata.original_time'},
        {source='resourceId', target='metadata.uid'},
        {source='operationName', target='api.operation'},
        {source='category', target='metadata.log_name'},
        {source='tenantId', target='metadata.tenant_uid'},
        {source='durationMs', target='duration'},
        {source='callerIpAddress', target='src_endpoint.ip'},
        {source='correlationId', target='metadata.correlation_uid'},
        {source='identity', target='actor.idp.name'},
        {source='location', target='cloud.region'},
        {source='properties.id', target='metadata.uid_alt'},
        {source='properties.createdDateTime', target='metadata.logged_time_dt'},
        {source='properties.userDisplayName', target='actor.user.name'},
        {source='properties.userId', target='actor.user.uid'},
        {source='properties.appId', target='api.service.uid'},
        {source='properties.appDisplayName', target='api.service.name'},
        {source='properties.ipAddress', target='dst_endpoint.ip'},
        {source='properties.status.errorCode', target='status_code'},
        {source='properties.userAgent', target='http_request.user_agent'},
        {source='properties.deviceDetail.deviceId', target='device.uid'},
        {source='properties.deviceDetail.operatingSystem', target='device.os.name'},
        {source='properties.location.city', target='src_endpoint.location.city'},
        {source='properties.location.state', target='src_endpoint.location.region'},
        {source='properties.location.countryOrRegion', target='src_endpoint.location.country'},
        {source='properties.originalRequestId', target='http_request.uid'},
        {source='properties.tokenIssuerType', target='actor.session.issuer'},
        {source='properties.userType', target='actor.user.type'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getAuditEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 6003
    result.class_name = "API Activity"
    result.category_uid = 6
    result.category_name = "Application Activity"
    result.activity_id = 99
    result.activity_name = "AuditLogs"
    result.type_uid = 600399
    result.type_name = "API Activity: Other"
    result.observables = getObservables(event, "AuditLogs")
    result.resources = buildResources(event)

    local fieldMappings = {
        {source='time', target='metadata.original_time'},
        {source='operationName', target='api.operation'},
        {source='category', target='metadata.log_name'},
        {source='tenantId', target='metadata.tenant_uid'},
        {source='durationMs', target='duration'},
        {source='correlationId', target='metadata.correlation_uid'},
        {source='identity', target='actor.idp.name'},
        {source='properties.id', target='metadata.uid'},
        {source='properties.activityDateTime', target='metadata.logged_time_dt'},
        {source='properties.loggedByService', target='metadata.log_provider'},
        {source='properties.userAgent', target='http_request.user_agent'},
        {source='properties.initiatedBy.app.appId', target='api.service.uid'},
        {source='properties.initiatedBy.app.displayName', target='api.service.name'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getProvisioningEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 6003
    result.class_name = "API Activity"
    result.category_uid = 6
    result.category_name = "Application Activity"
    result.activity_id = 99
    result.activity_name = "ProvisioningLogs"
    result.type_uid = 600399
    result.type_name = "API Activity: Other"
    result.observables = getObservables(event, "ProvisioningLogs")
    result.resources = buildResources(event)

    local fieldMappings = {
        {source='time', target='metadata.original_time'},
        {source='operationName', target='api.operation'},
        {source='category', target='metadata.log_name'},
        {source='tenantId', target='metadata.tenant_uid'},
        {source='durationMs', target='duration'},
        {source='correlationId', target='metadata.correlation_uid'},
        {source='identity', target='actor.idp.name'},
        {source='properties.id', target='metadata.uid'},
        {source='properties.activityDateTime', target='metadata.logged_time_dt'},
        {source='properties.servicePrincipal.Id', target='api.service.uid'},
        {source='properties.servicePrincipal.Name', target='api.service.name'},
        {source='properties.sourceSystem.Id', target='src_endpoint.uid'},
        {source='properties.sourceSystem.Name', target='src_endpoint.name'},
        {source='properties.targetSystem.Id', target='dst_endpoint.uid'},
        {source='properties.targetSystem.Name', target='dst_endpoint.name'},
        {source='properties.initiatedBy.Type', target='actor.user.type'},
        {source='properties.initiatedBy.Id', target='actor.user.uid'},
        {source='properties.initiatedBy.Name', target='actor.user.name'},
        {source='properties.provisioningStatusInfo.errorInformation', target='status_detail'},
        {source='properties.statusInfo.Status', target='status'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.category', target='dataSource.category'},
        {source='cloud.account.type_id', target='cloud.account.type_id'},
        {source='cloud.account.type', target='cloud.account.type'},
        {source='cloud.provider', target='cloud.provider'},
        {source='activity_id', target='activity_id'},
        {source='activity_name', target='activity_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='severity_id', target='severity_id'},
        {source='event.type', target='event.type'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='message', target='message'},
        {source='observables', target='observables'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getBaseEventMapping(event)
    local baseEventMapping = {}
    local skippableFields = {
        class_uid = true,
        class_name = true,
        category_uid = true,
        category_name = true,
        activity_id = true,
        activity_name = true,
        type_uid = true,
        type_name = true,
        metadata = true,
        dataSource = true,
        event = true,
        cloud = true,
    }
    for field_name, field_value in pairs(event) do
        local field_name_str = tostring(field_name)
        if not skippableFields[field_name_str] and field_name_str ~= "_ob" and field_value ~= nil and field_value ~= "" then
            baseEventMapping[field_name_str] = "unmapped." .. field_name_str
        end
    end

    local specificMappings = {
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["metadata.version"] = "metadata.version",
        ["dataSource.category"] = "dataSource.category",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["cloud.provider"] = "cloud.provider",
        ["cloud.account.type_id"] = "cloud.account.type_id",
        ["cloud.account.type"] = "cloud.account.type",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["activity_name"] = "activity_name",
        ["activity_id"] = "activity_id",
        ["severity_id"] = "severity_id",
        ["message"] = "message",
    }

    -- Merge the specific mappings into the base map
    for key, value in pairs(specificMappings) do
        baseEventMapping[key] = value
    end

    return baseEventMapping
end

function getBaseEvents(event)
    local result = {}
    local category = getValue(event, "category", "Other")
    result["class_uid"] = 0
    result["class_name"] = "Base Event"
    result["category_uid"] = 0
    result["category_name"] = "Uncategorized"
    result["activity_id"] = 99
    result["activity_name"] = "Other"
    result["type_uid"] = 99
    result["type_name"] = "Base Event: Other"
    result["metadata"] = {product = {name = "Azure Platform", vendor_name = "Microsoft"}, version = "1.1.0"}
    result["dataSource"] = {category = "security", name = "Azure Platform", vendor = "Microsoft"}
    result["cloud"] = {provider = "Azure", account = {type_id = "6", type = "Azure AD Account"}}
    result["event"] = {type = "Other"}
    result["severity_id"] = getSeverityId(getValue(event, "level", nil))

    fieldMappings = getBaseEventMapping(event)
    for source, target in pairs(fieldMappings) do
        copyField(event, result, source, target)
    end
    return result
end

function processAzurePlatformEvent(event)
    local result = {}
    local field_order = {}
    local category = getValue(event, "category", "")

    if string.find(category, "Administrative") then
        result = getAdminEvents(event)
        field_order = ADMIN_FIELD_ORDERS
    elseif category == "Security" then
        result = getSecurityEvents(event)
        field_order = SECURITY_FIELD_ORDERS
    elseif string.find(category, "Alert") then
        result = getAlertEvents(event)
        field_order = ALERT_FIELD_ORDERS
    elseif string.find(category, "Policy") then
        result = getPolicyEvents(event)
        field_order = POLICY_FIELD_ORDERS
    elseif category == "StorageRead" then
        result = getStorageReadEvents(event)
        field_order = RESOURCE_FIELD_ORDERS
    elseif category == "StorageWrite" then
        result = getStorageWriteEvents(event)
        field_order = RESOURCE_FIELD_ORDERS
    elseif category == "StorageDelete" then
        result = getStorageDeleteEvents(event)
        field_order = RESOURCE_FIELD_ORDERS
    elseif string.find(category, "SignInLogs") or string.find(category, "SignIn") then
        result = getSignInEvents(event)
        field_order = SIGN_IN_FIELD_ORDERS
    elseif string.find(category, "AuditLogs") or string.find(category, "Audit") then
        result = getAuditEvents(event)
        field_order = AUDIT_FIELD_ORDERS
    elseif string.find(category, "ProvisioningLogs") or string.find(category, "Provisioning") then
        result = getProvisioningEvents(event)
        field_order = PROVISIONING_FIELD_ORDERS
    else
        -- If nothing matches we return base event
        result = getBaseEvents(event)
        field_order = BASE_FIELD_ORDERS
    end

    -- preserve the original event in the message field
    local cleanEvent = {}
    for key, value in pairs(event) do
        if key ~= "_ob" and key ~= "timestamp" then
            cleanEvent[key] = value
        end
    end
    result.message = encodeJson(cleanEvent, "root", field_order)

    -- Apply universal time conversion
    local timeField = getValue(event, "time", nil)
    if timeField then
        -- Azure time is ISO 8601 string, keep as is for metadata.original_time
        result["time"] = parse_iso8601_to_milli(timeField)
        
        -- Also clean 'time' from unmapped if sub-functions didn't filter it
        if result.unmapped then
            result.unmapped.time = nil
        end
    end

    if FEATURES.FLATTEN_EVENT_TYPE then
        if result and result.event then
            result['event.type'] = result.event.type
        end
    end
    return result
end

-- Main event processing function
function processEvent(event)
    if event == nil then
        return {}
    end
    return processAzurePlatformEvent(event)
end

