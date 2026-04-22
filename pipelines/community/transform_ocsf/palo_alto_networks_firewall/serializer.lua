-- Palo Alto Networks Firewall to OCSF Mapping Script
-- Maps PANW Firewall threat log events to OCSF S1 Security Alert format
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

local THREAT_FIELD_ORDERS = {
    root = {
        "@logid",
        "action",
        "actionflags",
        "app",
        "category",
        "cloud_hostname",
        "config_ver",
        "contenttype",
        "device_name",
        "direction",
        "domain",
        "dst",
        "dstloc",
        "dport",
        "dstuser",
        "filedigest",
        "filename",
        "filetype",
        "flags",
        "from",
        "http_method",
        "http2_connection",
        "inbound_if",
        "misc",
        "natdport",
        "natdst",
        "natsport",
        "natsrc",
        "outbound_if",
        "parent_session_id",
        "parent_start_time",
        "pcap_id",
        "proto",
        "receive_time",
        "repeatcnt",
        "reportid",
        "rule",
        "rule_uuid",
        "seqno",
        "serial",
        "sessionid",
        "severity",
        "sport",
        "src",
        "srcloc",
        "srcuser",
        "subtype",
        "thr_category",
        "threat_name",
        "threatid",
        "tid",
        "time_generated",
        "time_received",
        "to",
        "tunnel",
        "tunnelid",
        "tunneltype",
        "type",
        "url_idx",
        "user_agent",
        "vsys",
        "vsys_id",
        "vsys_name",
        "wildfire"
    }
}

ARRAY_FIELDS = {
    attack_surface_ids = true,
    observables = true,
    evidences = true,
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

function getNestedValue(tbl, key1, key2, default)
    if tbl == nil then return default end
    local nested = tbl[key1]
    if nested == nil then return default end
    local value = nested[key2]
    if value == nil then return default end
    return value
end

function getSeverityId(severity)
    local severityId = 3
    if severity == "informational" then
        severityId = 1
    elseif severity == "low" then
        severityId = 2
    elseif severity == "medium" then
        severityId = 3
    elseif severity == "high" then
        severityId = 4
    elseif severity == "critical" then
        severityId = 5
    end
    return severityId
end

function getS1ClassificationId(subtype)
    local classificationIdMapping = {
        spyware = 34,
        virus = 37,
        ["ml-virus"] = 37,
        ["wildfire-virus"] = 37
    }
    if subtype == nil then return 0 end
    local subtypeLower = string.lower(subtype)
    for classification, classificationTypeId in pairs(classificationIdMapping) do
        if string.find(subtypeLower, classification) then
            return classificationTypeId
        end
    end
    return 0
end

function convertTimeToTimestamp(timeStr)
    if timeStr == nil or timeStr == "" then return 0 end
    -- Parse time in format "YYYY/MM/DD HH:MM:SS"
    local year, month, day, hour, min, sec = string.match(timeStr, "(%d+)/(%d+)/(%d+) (%d+):(%d+):(%d+)")
    if year == nil then return 0 end
    local t = {
        year = tonumber(year),
        month = tonumber(month),
        day = tonumber(day),
        hour = tonumber(hour),
        min = tonumber(min),
        sec = tonumber(sec)
    }
    local ts = os.time(t)
    local utc_ts = os.time(os.date("!*t", ts))
    local offset = os.difftime(ts, utc_ts)
    return (ts + offset) * 1000
end

function getResources(event)
    local name = getValue(event, "srcuser", nil)
    if name == nil or name == "" then
        name = getValue(event, "device_name", nil)
    end
    local serial = getValue(event, "serial", "")
    local srcuser = getValue(event, "srcuser", "")
    local uid = serial
    if srcuser ~= nil and srcuser ~= "" then
        uid = serial .. "-" .. srcuser
    end
    local resources = {
        {name = name, uid = uid}
    }
    return resources
end

function getEvidences(event)
    local srcCountry = getNestedValue(event, "srcloc", "#text", "")
    local dstCountry = getNestedValue(event, "dstloc", "#text", "")
    local evidences = {
        {
            src_endpoint = {
                ip = getValue(event, "src", ""),
                port = tonumber(getValue(event, "sport", "0")) or 0,
                location = {
                    country = srcCountry
                }
            },
            dst_endpoint = {
                ip = getValue(event, "dst", ""),
                port = tonumber(getValue(event, "dport", "0")) or 0,
                location = {
                    country = dstCountry
                }
            },
            connection_info = {
                protocol_name = getValue(event, "proto", ""),
                direction_id = 0
            },
            process = {
                session = {
                    uid = getValue(event, "sessionid", "")
                },
                parent_process = {
                    session = {
                        uid = getValue(event, "parent_session_id", "")
                    }
                },
                tid = tonumber(getValue(event, "tid", "0")) or 0
            }
        }
    }
    return evidences
end

function getObservables(event)
    local observables = {
        {
            type = "IP Address",
            type_id = 2,
            name = "src",
            value = getValue(event, "src", "")
        },
        {
            type = "IP Address",
            type_id = 2,
            name = "dst",
            value = getValue(event, "dst", "")
        }
    }
    return observables
end

function getRelatedEvents(event)
    local receiveTime = getValue(event, "receive_time", "")
    local timestamp = convertTimeToTimestamp(receiveTime)
    local threatid = getValue(event, "threatid", "")
    local severity = getValue(event, "severity", "")
    local severityId = getSeverityId(severity)
    
    local commonFields = {
        time = timestamp,
        uid = threatid,
        severity = severity,
        severity_id = severityId
    }
    
    local relatedEvents = {
        {
            time = commonFields.time,
            uid = commonFields.uid,
            severity = commonFields.severity,
            severity_id = commonFields.severity_id,
            type = "Source IP Address: " .. getValue(event, "src", "")
        },
        {
            time = commonFields.time,
            uid = commonFields.uid,
            severity = commonFields.severity,
            severity_id = commonFields.severity_id,
            type = "Destination IP Address: " .. getValue(event, "dst", "")
        },
        {
            time = commonFields.time,
            uid = commonFields.uid,
            severity = commonFields.severity,
            severity_id = commonFields.severity_id,
            type = "Rule: " .. getValue(event, "rule", "")
        },
        {
            time = commonFields.time,
            uid = commonFields.uid,
            severity = commonFields.severity,
            severity_id = commonFields.severity_id,
            type = "Rule UUID: " .. getValue(event, "rule_uuid", "")
        },
        {
            time = commonFields.time,
            uid = commonFields.uid,
            severity = commonFields.severity,
            severity_id = commonFields.severity_id,
            type = "Inbound Interface: " .. getValue(event, "inbound_if", "")
        },
        {
            time = commonFields.time,
            uid = commonFields.uid,
            severity = commonFields.severity,
            severity_id = commonFields.severity_id,
            type = "Outbound Interface: " .. getValue(event, "outbound_if", "")
        }
    }
    return relatedEvents
end

function getThreatEvents(event)
    local result = {}
    local severity = getValue(event, "severity", "")
    local subtype = getValue(event, "subtype", "")
    local receiveTime = getValue(event, "receive_time", "")
    local timeGenerated = getValue(event, "time_generated", "")
    local timeReceived = getValue(event, "time_received", "")
    
    -- Set OCSF class fields
    result.class_uid = 99602001
    result.class_name = "S1 Security Alert"
    result.category_uid = 2
    result.category_name = "Findings"
    result.activity_id = 1
    result.activity_name = "Create"
    result.type_uid = 9960200101
    result.type_name = "S1 Security Alert: Create"
    
    -- Set severity
    result.severity = severity
    result.severity_id = getSeverityId(severity)
    
    -- Set status and state
    result.status_id = 1
    result.state_id = 1
    
    -- Set classification
    result.s1_classification = subtype
    result.s1_classification_id = getS1ClassificationId(subtype)
    
    -- Set attack surface
    result.attack_surface_ids = {1}
    
    -- Set metadata
    result.metadata = {
        logged_time = convertTimeToTimestamp(timeGenerated),
        original_time = timeReceived,
        event_code = getValue(event, "@logid", ""),
        log_name = getValue(event, "type", ""),
        product = {
            name = "Palo Alto Networks Firewall",
            vendor_name = "Palo Alto Networks"
        },
        version = "1.1.0-dev",
        extensions = {
            {uid = "996", name = "s1", version = "0.1.0"}
        }
    }
    
    -- Set dataSource
    result.dataSource = {
        name = "Palo Alto Networks Firewall",
        category = "security",
        vendor = "Palo Alto Networks"
    }
    
    -- Set finding_info
    local threatid = getValue(event, "threatid", "")
    local seqno = getValue(event, "seqno", "")
    result.finding_info = {
        uid = threatid .. "-" .. seqno .. "-" .. tostring(os.time() * 1000000000),
        title = getValue(event, "threat_name", ""),
        desc = getValue(event, "characteristic_of_app", ""),
        related_events = getRelatedEvents(event),
        analytic = {
            category = getValue(event, "thr_category", ""),
            type_id = 99
        }
    }
    
    -- Set risk level
    result.risk_level = getValue(event, "risk_of_app", "")
    
    -- Set count
    local repeatcnt = getValue(event, "repeatcnt", "0")
    result.count = tonumber(repeatcnt) or 0
    
    -- Set time
    result.time = convertTimeToTimestamp(receiveTime)
    
    -- Set resources, evidences, observables
    result.resources = getResources(event)
    result.evidences = getEvidences(event)
    result.observables = getObservables(event)
    
    -- Field mappings for unmapped fields
    local fieldMappings = {
        {source='@logid', target='metadata.event_code'},
        {source='subtype', target='s1_classification'},
        {source='type', target='metadata.log_name'},
        {source='characteristic_of_app', target='finding_info.desc'},
        {source='risk_of_app', target='risk_level'},
        {source='severity', target='severity'},
        {source='threat_name', target='finding_info.title'},
        {source='action', target='unmapped.action'},
        {source='actionflags', target='unmapped.actionflags'},
        {source='app', target='unmapped.app'},
        {source='category', target='unmapped.category'},
        {source='cloud_hostname', target='unmapped.cloud_hostname'},
        {source='config_ver', target='unmapped.config_ver'},
        {source='contenttype', target='unmapped.contenttype'},
        {source='device_name', target='unmapped.device_name'},
        {source='direction', target='unmapped.direction'},
        {source='domain', target='unmapped.domain'},
        {source='dst', target='unmapped.dst'},
        {source='dstloc', target='unmapped.dstloc'},
        {source='dport', target='unmapped.dport'},
        {source='dstuser', target='unmapped.dstuser'},
        {source='filedigest', target='unmapped.filedigest'},
        {source='filename', target='unmapped.filename'},
        {source='filetype', target='unmapped.filetype'},
        {source='flags', target='unmapped.flags'},
        {source='from', target='unmapped.from'},
        {source='http_method', target='unmapped.http_method'},
        {source='http2_connection', target='unmapped.http2_connection'},
        {source='inbound_if', target='unmapped.inbound_if'},
        {source='misc', target='unmapped.misc'},
        {source='natdport', target='unmapped.natdport'},
        {source='natdst', target='unmapped.natdst'},
        {source='natsport', target='unmapped.natsport'},
        {source='natsrc', target='unmapped.natsrc'},
        {source='outbound_if', target='unmapped.outbound_if'},
        {source='parent_session_id', target='unmapped.parent_session_id'},
        {source='parent_start_time', target='unmapped.parent_start_time'},
        {source='pcap_id', target='unmapped.pcap_id'},
        {source='proto', target='unmapped.proto'},
        {source='receive_time', target='unmapped.receive_time'},
        {source='repeatcnt', target='unmapped.repeatcnt'},
        {source='reportid', target='unmapped.reportid'},
        {source='rule', target='unmapped.rule'},
        {source='rule_uuid', target='unmapped.rule_uuid'},
        {source='seqno', target='unmapped.seqno'},
        {source='serial', target='unmapped.serial'},
        {source='sessionid', target='unmapped.sessionid'},
        {source='sport', target='unmapped.sport'},
        {source='src', target='unmapped.src'},
        {source='srcloc', target='unmapped.srcloc'},
        {source='srcuser', target='unmapped.srcuser'},
        {source='thr_category', target='unmapped.thr_category'},
        {source='threatid', target='unmapped.threatid'},
        {source='tid', target='unmapped.tid'},
        {source='time_generated', target='unmapped.time_generated'},
        {source='time_received', target='unmapped.time_received'},
        {source='to', target='unmapped.to'},
        {source='tunnel', target='unmapped.tunnel'},
        {source='tunnelid', target='unmapped.tunnelid'},
        {source='tunneltype', target='unmapped.tunneltype'},
        {source='url_idx', target='unmapped.url_idx'},
        {source='user_agent', target='unmapped.user_agent'},
        {source='vsys', target='unmapped.vsys'},
        {source='vsys_id', target='unmapped.vsys_id'},
        {source='vsys_name', target='unmapped.vsys_name'},
        {source='wildfire', target='unmapped.wildfire'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='metadata.version', target='metadata.version'},
        {source='metadata.extensions', target='metadata.extensions'},
        {source='dataSource.category', target='dataSource.category'},
        {source='dataSource.name', target='dataSource.name'},
        {source='dataSource.vendor', target='dataSource.vendor'},
        {source='class_uid', target='class_uid'},
        {source='class_name', target='class_name'},
        {source='category_uid', target='category_uid'},
        {source='category_name', target='category_name'},
        {source='type_uid', target='type_uid'},
        {source='type_name', target='type_name'},
        {source='activity_name', target='activity_name'},
        {source='activity_id', target='activity_id'},
        {source='severity_id', target='severity_id'},
        {source='status_id', target='status_id'},
        {source='state_id', target='state_id'},
        {source='s1_classification_id', target='s1_classification_id'},
        {source='attack_surface_ids', target='attack_surface_ids'},
        {source='resources', target='resources'},
        {source='evidences', target='evidences'},
        {source='observables', target='observables'},
        {source='finding_info', target='finding_info'},
        {source='time', target='time'},
        {source='count', target='count'},
    }

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function processSecurityFinding(event)
    local result = {}
    local field_order = THREAT_FIELD_ORDERS
    
    -- Process as threat event (PANW Firewall threat logs)
    result = getThreatEvents(event)
    
    -- preserve the original event in the message field
    local cleanEvent = {}
    for key, value in pairs(event) do
        if key ~= "_ob" then
            cleanEvent[key] = value
        end
    end
    result.message = encodeJson(cleanEvent, "root", field_order)

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
    return processSecurityFinding(event)
end

