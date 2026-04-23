-- Darktrace 1.1.0 OCSF Serializer

local FEATURES = {
    CLEANUP_EMPTY_NULL = true,
}

local COMMON_MAPPING = {
    {source = "action", target = "action"},
    {source = "action_id", target = "action_id"},
    {source = "category_uid", target = "category_uid"},
    {source = "category_name", target = "category_name"},
    {source = "class_uid", target = "class_uid"},
    {source = "class_name", target = "class_name"},
    {source = "activity_id", target = "activity_id"},
    {source = "activity_name", target = "activity_name"},
    {source = "type_uid", target = "type_uid"},
    {source = "type_name", target = "type_name"},
    {source = "severity_id", target = "severity_id"},
    {source = "metadata.product.vendor_name", target = "metadata.product.vendor_name"},
    {source = "metadata.product.name", target = "metadata.product.name"},
    {source = "metadata.version", target = "metadata.version"},
    {source = "metadata.original_time", target = "metadata.original_time"},
    {source = "dataSource.category", target = "dataSource.category"},
    {source = "dataSource.name", target = "dataSource.name"},
    {source = "dataSource.vendor", target = "dataSource.vendor"},
    {source = "site.id", target = "site.id"},
    {source = "message", target = "message"},
    {source = "user.type_id", target = "user.type_id"},
    {source = "observables", target = "observables"}
}

local GROUPS_LOGS_MAPPING = {
    {source = "id", target = "metadata.uid"},
    {source = "mitreTactics", target = "attacks.tactics"},
    {source = "category", target = "severity"},
    {source = "start", target = "start_time"},
    {source = "start_time", target = "time"},
    {source = "end", target = "end_time"},
    {source = "finding_info.uid", target = "finding_info.uid"},
    {source = "finding_info.first_seen_time", target = "finding_info.first_seen_time"},
    {source = "finding_info.title", target = "finding_info.title"},
    {source = "finding_info.product_uid", target = "finding_info.product_uid"},
    {source = "finding_info.desc", target = "finding_info.desc"}
}

local INCIDENTS_LOGS_MAPPING = {
    {source = "createdAt", target = "finding_info.created_time"},
    {source = "mitreTactics", target = "attacks.tactics"},
    {source = "start_time", target = "start_time"},
    {source = "end_time", target = "end_time"},
    {source = "device.namespace_pid", target = "device.namespace_pid"},
    {source = "device.hostname", target = "device.hostname"},
    {source = "device.ip", target = "device.ip"},
    {source = "device.mac", target = "device.mac"},
    {source = "device.subnet", target = "device.subnet"},
    {source = "device.uid", target = "device.uid"},
    {source = "device.subnet_uid", target = "device.subnet_uid"},
    {source = "device.type_id", target = "device.type_id"},
    {source = "authorizations", target = "authorizations"},
    {source = "risk_score", target = "risk_score"},
    {source = "id", target = "finding_info.uid"},
    {source = "title", target = "finding_info.title"},
    {source = "finding_info.first_seen_time", target = "finding_info.first_seen_time"},
    {source = "finding_info.product_uid", target = "finding_info.product_uid"},
    {source = "summary", target = "finding_info.desc"},
    {source = "severity", target = "severity"},
    {source = "metadata.original_time", target = "time"}
}

local MODEL_BREACHES_LOGS_MAPPING = {
    {source = "authorizations", target = "authorizations"},
    {source = "time", target = "metadata.original_time"},
    {source = "creationTime", target = "finding_info.created_time"},
    {source = "resources", target = "resources"},
    {source = "resources_result", target = "resources_result"},
    {source = "severity", target = "severity"},
    {source = "device.uid", target = "device.uid"},
    {source = "device.type_id", target = "device.type_id"}
}

local STATUS_LOGS_MAPPING = {
    {source = "ipAddress", target = "device.ip"},
    {source = "hostname", target = "device.hostname"},
    {source = "uuid", target = "device.uid"},
    {source = "device.type_id", target = "device.type_id"},
    {source = "device.type", target = "device.type"},
    {source = "device.subnet_uid", target = "device.subnet_uid"},
    {source = "device.network_interfaces", target = "device.network_interfaces"},
    {source = "severity", target = "severity"}
}

local function convert_to_epoch_milliseconds(timestamp)
    if not timestamp or timestamp == "" then
        return nil
    end
    local year, month, day, hour, min, sec, frac =
        string.match(timestamp, "(%d+)%-(%d+)%-(%d+) (%d+):(%d+)")
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

-- Constant Fields

local function get_group_logs_computed_fields(event)
    local fields = {
        ["dataSource"] = {
            ["category"] = "security",
            ["name"] = "Darktrace",
            ["vendor"] = "Darktrace",
        },
        ["metadata"] = {
            ["product"] = {
                ["name"] = "Darktrace",
                ["vendor_name"] = "Darktrace",
            },
            ["version"] = "1.1.0",
            ["uid"] = event["id"],
            ["original_time"] = type(event["start"]) == "number" and event["start"] or convert_to_epoch_milliseconds(event["start"] or ""),
        },
        ["action"] = "Other",
        ["action_id"] = 99,
        ["activity_id"] = 1,
        ["activity_name"] = "Create",
        ["event.type"] = "Create",
        ["category_name"] = "Findings",
        ["category_uid"] = 2,
        ["class_name"] = "Detection Finding",
        ["class_uid"] = 2004,
        ["type_name"] = "Detection Finding: Create",
        ["type_uid"] = 200401,
        ["severity_id"] = 99,
        ["time"] = type(event["start"]) == "number" and event["start"] or convert_to_epoch_milliseconds(event["start"] or "")
    }

    local incident_events = event["incidentEvents"] or {}
    -- Check if list is not empty (Lua tables are 1-indexed)
    if #incident_events > 0 then
        local incident = incident_events[1]
        fields["finding_info"] = {
            ["uid"] = incident["uuid"],
            ["first_seen_time"] = incident["start"],
            ["title"] = incident["title"],
            ["product_uid"] = incident["triggerDid"],
        }
    end

    local observables_array = {}
    for _, incident in ipairs(incident_events) do
        -- Resource UID observable object
        local uuid_val = incident["uuid"] or ""
        if uuid_val ~= "" then
            table.insert(observables_array, {type_id = 10, type = "Resource UID", name = "finding_info.uid", value = uuid_val})
        end

        -- Process observable object
        local title_val = incident["title"] or ""
        if title_val ~= "" then
            table.insert(observables_array, {type_id = 25, type = "Process", name = "finding_info.title", value = title_val})
        end
    end

    if #observables_array > 0 then
        fields["observables"] = observables_array
    end

    return fields
end

local function get_incidents_logs_computed_fields(event)
    local fields = {
        ["dataSource"] = {
            ["category"] = "security",
            ["name"] = "Darktrace",
            ["vendor"] = "Darktrace",
        },
        ["metadata"] = {
            ["product"] = {
                ["name"] = "Darktrace",
                ["vendor_name"] = "Darktrace",
            },
            ["version"] = "1.1.0",
            ["original_time"] = type(event["relatedBreaches"][1]["timestamp"]) == "number" and event["relatedBreaches"][1]["timestamp"] or convert_to_epoch_milliseconds(event["relatedBreaches"][1]["timestamp"] or "")
        },
        ["action"] = "Other",
        ["action_id"] = 99,
        ["activity_id"] = 1,
        ["activity_name"] = "Create",
        ["event.type"] = "Create",
        ["category_name"] = "Findings",
        ["category_uid"] = 2,
        ["class_name"] = "Detection Finding",
        ["class_uid"] = 2004,
        ["type_name"] = "Detection Finding: Create",
        ["type_uid"] = 200401,
        ["severity_id"] = 99,
        ["time"] = type(event["relatedBreaches"][1]["timestamp"]) == "number" and event["relatedBreaches"][1]["timestamp"] or convert_to_epoch_milliseconds(event["relatedBreaches"][1]["timestamp"] or "")
    }

    local periods = event["periods"] or {}
    if #periods > 0 then
        fields["start_time"] = periods[1]["start"]
        fields["end_time"] = periods[1]["end"]
    end

    local related_breaches = event["relatedBreaches"] or {}
    if #related_breaches > 0 then
        fields["authorizations"] = {
            {
                ["policy"] = {
                    ["name"] = related_breaches[1]["modelName"],
                    ["uid"] = related_breaches[1]["pbid"]
                }
            }
        }
        fields["risk_score"] = related_breaches[1]["threatScore"]
    end

    local breach_devices = event["breachDevices"] or {}
    if #breach_devices > 0 then
        fields["device"] = {
            ["namespace_pid"] = breach_devices[1]["identifier"],
            ["hostname"] = breach_devices[1]["hostname"],
            ["ip"] = breach_devices[1]["ip"],
            ["mac"] = breach_devices[1]["mac"],
            ["subnet"] = breach_devices[1]["subnet"],
            ["uid"] = breach_devices[1]["did"],
            ["subnet_uid"] = breach_devices[1]["sid"],
            ["type_id"] = 0
        }
    end

    local observables_array = {}
    for _, incident in ipairs(breach_devices) do
        -- Hostname observable object
        local hostname_val = incident["hostname"] or ""
        if hostname_val ~= "" then
            local hostname_obj = {}
            hostname_obj["type_id"] = 1
            hostname_obj["type"] = "Hostname"
            hostname_obj["name"] = "device.hostname"
            hostname_obj["value"] = hostname_val
            table.insert(observables_array, hostname_obj)
        end

        -- IP Address observable object
        local ip_val = incident["ip"] or ""
        if ip_val ~= "" then
            local ip_obj = {}
            ip_obj["type_id"] = 2
            ip_obj["type"] = "IP Address"
            ip_obj["name"] = "device.ip"
            ip_obj["value"] = ip_val
            table.insert(observables_array, ip_obj)
        end

        -- MAC Address observable object
        local mac_val = incident["mac"] or ""
        if mac_val ~= "" then
            local mac_obj = {}
            mac_obj["type_id"] = 3
            mac_obj["type"] = "MAC Address"
            mac_obj["name"] = "device.mac"
            mac_obj["value"] = mac_val
            table.insert(observables_array, mac_obj)
        end
    end

    if #observables_array > 0 then
        fields["observables"] = observables_array
    end

    return fields
end

local function get_modelbreaches_logs_computed_fields(event)
    local fields = {
        ["dataSource"] = {
            ["category"] = "security",
            ["name"] = "Darktrace",
            ["vendor"] = "Darktrace",
        },
        ["metadata"] = {
            ["product"] = {
                ["name"] = "Darktrace",
                ["vendor_name"] = "Darktrace",
            },
            ["version"] = "1.1.0",
            ["original_time"] = type(event["time"]) == "number" and event["time"] or convert_to_epoch_milliseconds(event["time"] or "")
        },
        ["action"] = "Other",
        ["action_id"] = 99,
        ["activity_id"] = 1,
        ["activity_name"] = "Create",
        ["event.type"] = "Create",
        ["category_name"] = "Findings",
        ["category_uid"] = 2,
        ["class_name"] = "Detection Finding",
        ["class_uid"] = 2004,
        ["type_name"] = "Detection Finding: Create",
        ["type_uid"] = 200401,
        ["severity_id"] = 99,
        ["time"] = type(event["time"]) == "number" and event["time"] or convert_to_epoch_milliseconds(event["time"] or "")
    }

    fields["authorizations"] = {
        {
            ["policy"] = {
                ["uid"] = event["pbid"]
            }
        }
    }

    local model = event["model"] or {}
    local model_then = model["then"]
    -- In Lua, empty tables are true, so check if not nil.
    -- If 'then' might be an empty table {}, you might need next(model_then) check, 
    -- but usually API responses omit keys or return nil if missing.
    if model_then then
        fields["resources"] = {
            {
                ["name"] = model_then["name"],
                ["uid"] = model_then["uuid"],
                ["version"] = model_then["version"],
                ["data"] = model_then
            }
        }
    end

    local model_now = model["now"]
    -- Note: Original Python code had a bug: 'if model_then:' check for 'resources_result'
    -- I assumed you wanted 'if model_now:' here based on context.
    -- If you want strict translation of the bug, change 'model_now' to 'model_then' in the if condition.
    if model_now then 
        fields["resources_result"] = {
            {
                ["name"] = model_now["name"],
                ["uid"] = model_now["uuid"],
                ["version"] = model_now["version"],
                ["data"] = model_now
            }
        }
    end

    local device = event["device"] or {}
    local device_did = device["did"]
    if device_did then
        fields["device"] = {
            ["uid"] = device_did,
            ["type_id"] = 0
        }
    end

    return fields
end

local function get_status_logs_computed_fields(event)
    local fields = {
        ["dataSource"] = {
            ["category"] = "security",
            ["name"] = "Darktrace",
            ["vendor"] = "Darktrace",
        },
        ["metadata"] = {
            ["product"] = {
                ["name"] = "Darktrace",
                ["vendor_name"] = "Darktrace",
            },
            ["version"] = "1.1.0",
            ["original_time"] = type(event["time"]) == "number" and event["time"] or convert_to_epoch_milliseconds(event["time"] or "")
        },
        ["device"] = {
            ["type_id"] = 99,
            ["type"] = event["type"],
            ["hostname"] = event["hostname"],
            ["ip"] = event["ipAddress"],
            ["network_interfaces"] = {
                {
                    ["ip"] = event["networkInterfacesAddress_eth0"],
                    ["type_id"] = 1,
                    ["type"] = "Wired"
                }
            }
        },
        ["time"] = type(event["time"]) == "number" and event["time"] or convert_to_epoch_milliseconds(event["time"] or ""),
        ["activity_id"] = 1,
        ["activity_name"] = "Log",
        ["event.type"] = "Log",
        ["category_name"] = "Discovery",
        ["category_uid"] = 5,
        ["class_name"] = "Device Config State",
        ["class_uid"] = 5002,
        ["type_name"] = "Device Config State: Log",
        ["type_uid"] = 500201,
        ["severity_id"] = 99,
    }
    
    -- Initialize device table

    local subnet_data = event["subnetData"] or {}
    if #subnet_data >= 1 then
        local sid = subnet_data[1]["sid"]
        fields["device"]["subnet_uid"] = sid
    end

    fields["observables"] = {}
    
    local hostname = event["hostname"]
    if hostname and hostname ~= "" then
        table.insert(fields["observables"], {
            ["type_id"] = 1,
            ["type"] = "Hostname",
            ["name"] = "device.hostname",
            ["value"] = hostname,
        })
    end

    local ip_address = event["ipAddress"]
    if ip_address and ip_address ~= "" then
        table.insert(fields["observables"], {
            ["type_id"] = 2,
            ["type"] = "IP Address",
            ["name"] = "device.ip",
            ["value"] = ip_address,
        })
    end

    return fields
end




local function getConstantFields(event_type, event) 
    if event_type == "aianalyst/groups" then
        return get_group_logs_computed_fields(event)
    elseif event_type == "aianalyst/incidentevents" then
        return get_incidents_logs_computed_fields(event)
    elseif event_type == "modelbreaches" then
        return get_modelbreaches_logs_computed_fields(event)
    elseif event_type == "status" then
        return get_status_logs_computed_fields(event)
    end
end

local IGNORE_KEYS = {
    _ob = true,
    _darktrace_event_type = true,
    _darktrace_query_time = true,
    _darktrace_start_time = true,
    _darktrace_end_time = true,
    timestamp = true
}


-- Utility functions
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

-- Helper: Encode Lua table to JSON string with field ordering
local function encodeJson(obj, fieldOrder, key)
  if obj == nil then
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
      if isArray then
          local items = {}
          for i = 1, maxIndex do
              table.insert(items, encodeJson(obj[i], fieldOrder, key))
          end
          return "[" .. table.concat(items, ",") .. "]"
      else
          local items = {}
          local fieldOrdering = fieldOrder[key] or {}
          
          -- Phase 1: ordered keys
          for _, fieldName in ipairs(fieldOrdering) do
              local v = obj[fieldName]
              if v ~= nil then
                  local encoded = encodeJson(v, fieldOrder, fieldName)
                  if encoded ~= nil then
                      table.insert(items, '"' .. fieldName:gsub('"', '\\"') .. '":' .. encoded)
                  end
              end
          end
          
          -- Phase 2: remaining keys (not in fieldOrder)
          for k, v in pairs(obj) do
              local found = false
              for _, fieldName in ipairs(fieldOrdering) do
                  if k == fieldName then
                      found = true
                      break
                  end
              end
              if not found then
                  local keyStr = type(k) == "string" and k or tostring(k)
                  local encoded = encodeJson(v, fieldOrder, keyStr)
                  if encoded ~= nil then
                      table.insert(items, '"' .. keyStr:gsub('"', '\\"') .. '":' .. encoded)
                  end
              end
          end
          
          return "{" .. table.concat(items, ",") .. "}"
      end
  else
      return '"' .. tostring(obj) .. '"'
  end
end

local GROUPS_FIELD_ORDER = {
  message = {
    "id", "active", "acknowledged", "pinned", "userTriggered", "externalTriggered", 
    "previousIds", "incidentEvents", "mitreTactics", "devices", "initialDevices", 
    "category", "groupScore", "start", "end", "edges"
  },
  incidentEvents = {
    "uuid", "start", "title", "triggerDid", "visible"
  },
  edges = {
    "isAction", "source", "target", "start", "incidentEvent", "description", "details"
  },
  source = {
    "nodeType", "value"
  },
  target = {
    "nodeType", "value"
  }
}

local INCIDENT_FIELD_ORDER = {
  message = {
    "summariser", "acknowledged", "pinned", "createdAt", "attackPhases", "mitreTactics",
    "title", "id", "children", "category", "currentGroup", "groupCategory", "groupScore",
    "groupPreviousGroups", "activityId", "groupingIds", "groupByActivity", "userTriggered",
    "externalTriggered", "aiaScore", "summary", "periods", "breachDevices", "relatedBreaches",
    "details"
  },
  periods = {
    "start", "end"
  },
  breachDevices = {
    "identifier", "hostname", "ip", "mac", "subnet", "did", "sid"
  },
  relatedBreaches = {
    "modelName", "pbid", "threatScore", "timestamp"
  },
  details = {
    "contents", "header"
  },
  contents = {
    "key", "type", "values"
  },
  values = {
    "identifier", "hostname", "ip", "mac", "subnet", "did", "sid"
  }
}

local MODEL_BREACH_FIELD_ORDER = {
  message = {
    "commentCount", "pbid", "time", "creationTime", "model", 
    "triggeredComponents", "score", "device"
  },
  model = {
    "then", "now"
  },
  -- 'then' is a reserved keyword in Lua, so we use bracket notation
  ["then"] = {
    "name", "pid", "phid", "uuid", "logic", "throttle", "sharedEndpoints", 
    "actions", "tags", "interval", "delay", "sequenced", "active", "modified", 
    "activeTimes", "autoUpdatable", "autoUpdate", "autoSuppress", "description", 
    "behaviour", "defeats", "created", "edited", "message", "version", 
    "priority", "category", "compliance"
  },
  now = {
    "name", "pid", "phid", "uuid", "logic", "throttle", "sharedEndpoints", 
    "actions", "tags", "interval", "delay", "sequenced", "active", "modified", 
    "activeTimes", "autoUpdatable", "autoUpdate", "autoSuppress", "description", 
    "behaviour", "defeats", "created", "edited", "message", "version", 
    "priority", "category", "compliance"
  },
  actions = {
    "alert", "antigena", "breach", "model", "setPriority", "setTag", "setType"
  },
  activeTimes = {
    "devices", "tags", "type", "version"
  },
  created = { "by" },
  edited = { "by" },
  triggeredComponents = {
    "time", "cbid", "cid", "chid", "size", "threshold", "interval", 
    "logic", "version", "metric", "triggeredFilters"
  },
  metric = {
    "mlid", "name", "label"
  },
  triggeredFilters = {
    "cfid", "id", "filterType", "arguments", "comparatorType", "trigger"
  },
  arguments = { "value" },
  trigger = { "value" },
  device = { "did" },
  
  -- Logic structures (Shared by model logic and component logic)
  logic = {
    "data", "type", "version"
  },
  -- Recursive data structure for component logic
  data = {
    "left", "operator", "right"
  },
  left = {
    "left", "operator", "right"
  },
  right = {
    "left", "operator", "right"
  }
}

local STATUS_FIELD_ORDER = {
  message = {
    "excessTraffic", "time", "installed", "mobileAppConfigured", "version", "ipAddress",
    "modelsUpdated", "modelPackageVersion", "bundleVersion", "bundleDate", "bundleInstalledDate",
    "hostname", "inoculation", "applianceOSCode", "license", "saasConnectorLicense",
    "antigenaSaasLicense", "syslogTLSSHA1Fingerprint", "syslogTLSSHA256Fingerprint",
    "antigenaNetworkEnabled", "antigenaNetworkLicense", "antigenaNetworkRunning",
    "logIngestionReplicated", "logIngestionProcessed", "logIngestionTCP", "logIngestionUDP",
    "logIngestionTypes", "logIngestionMatches", "licenseCounts", "type", "diskUtilization",
    "uptime", "systemUptime", "load", "cpu", "memoryUsed", "dataQueue", "darkflowQueue",
    "networkInterfacesState_eth0", "networkInterfacesAddress_eth0",
    "networkInterfacesReceived_eth0", "networkInterfacesTransmitted_eth0",
    "bandwidthCurrent", "bandwidthCurrentString", "bandwidthAverage", "bandwidthAverageString",
    "bandwidth7DayPeak", "bandwidth7DayPeakString", "bandwidth2WeekPeak", "bandwidth2WeekPeakString",
    "processedBandwidthCurrent", "processedBandwidthCurrentString", "processedBandwidthAverage",
    "processedBandwidthAverageString", "processedBandwidth7DayPeak", "processedBandwidth7DayPeakString",
    "processedBandwidth2WeekPeak", "processedBandwidth2WeekPeakString",
    "eventsPerMinuteCurrent", "probes", "connectionsPerMinuteCurrent", "connectionsPerMinuteAverage",
    "connectionsPerMinute7DayPeak", "connectionsPerMinute2WeekPeak", "operatingSystems",
    "newDevices4Weeks", "newDevices7Days", "newDevices24Hours", "newDevicesHour",
    "activeDevices4Weeks", "activeDevices7Days", "activeDevices24Hours", "activeDevicesHour",
    "deviceHostnames", "deviceMACAddresses", "deviceRecentIPChange", "models", "modelsBreached",
    "modelsSuppressed", "devicesModeled", "recentUnidirectionalConnections",
    "mostRecentCOTPTraffic", "mostRecentDCE_RPCTraffic", "mostRecentDHCPTraffic",
    "mostRecentDNSTraffic", "mostRecentFTPTraffic", "mostRecentGSSAPITraffic", "mostRecentH2Traffic",
    "mostRecentHTTPTraffic", "mostRecentHTTPSTraffic", "mostRecentKERBEROSTraffic",
    "mostRecentLDAPTraffic", "mostRecentNETLOGONTraffic", "mostRecentNTLMTraffic",
    "mostRecentNTPTraffic", "mostRecentRDPTraffic", "mostRecentSMBTraffic", "mostRecentSOCKSTraffic",
    "mostRecentSSHTraffic", "mostRecentSSLTraffic", "ignoreAnalysisCredentials",
    "internalIPRangeList", "internalIPRanges", "dnsServers", "internalDomains",
    "internalAndExternalDomains", "proxyServers", "subnets", "subnetData"
  },
  probes = {"1", "2", "3"},
  ["1"] = {
    "id", "mappedId", "antigenaNetworkBlockedConnections", "configuredServer", "version",
    "ipAddress", "bundleVersion", "bundleDate", "bundleInstalledDate", "metadata", "hostname",
    "time", "installed", "kernel", "applianceOSCode", "syslogTLSSHA1Fingerprint",
    "syslogTLSSHA256Fingerprint", "antigenaNetworkRunning", "logIngestionReplicated",
    "logIngestionProcessed", "logIngestionTCP", "logIngestionUDP", "logIngestionDecryption",
    "type", "diskUtilization", "uptime", "systemUptime", "load", "cpu", "memoryUsed",
    "networkInterfacesState_ens5", "networkInterfacesAddress_ens5",
    "networkInterfacesReceived_ens5", "networkInterfacesTransmitted_ens5",
    "bandwidthCurrent", "bandwidthCurrentString", "bandwidthAverage", "bandwidthAverageString",
    "bandwidth7DayPeak", "bandwidth7DayPeakString", "bandwidth2WeekPeak",
    "bandwidth2WeekPeakString", "processedBandwidthCurrent", "processedBandwidthCurrentString",
    "processedBandwidthAverage", "processedBandwidthAverageString",
    "processedBandwidth7DayPeak", "processedBandwidth7DayPeakString",
    "processedBandwidth2WeekPeak", "processedBandwidth2WeekPeakString",
    "connectionsPerMinuteCurrent", "connectionsPerMinuteAverage",
    "connectionsPerMinute7DayPeak", "connectionsPerMinute2WeekPeak",
    "label", "error", "lastContact"
  },
  ["2"] = {
    "id", "mappedId", "antigenaNetworkBlockedConnections", "configuredServer", "version",
    "ipAddress", "bundleVersion", "bundleDate", "bundleInstalledDate", "metadata", "hostname",
    "time", "installed", "kernel", "applianceOSCode", "syslogTLSSHA1Fingerprint",
    "syslogTLSSHA256Fingerprint", "antigenaNetworkRunning", "logIngestionReplicated",
    "logIngestionProcessed", "logIngestionTCP", "logIngestionUDP", "logIngestionDecryption",
    "type", "diskUtilization", "uptime", "systemUptime", "load", "cpu", "memoryUsed",
    "networkInterfacesState_ens5", "networkInterfacesAddress_ens5",
    "networkInterfacesReceived_ens5", "networkInterfacesTransmitted_ens5",
    "bandwidthCurrent", "bandwidthCurrentString", "bandwidthAverage", "bandwidthAverageString",
    "bandwidth7DayPeak", "bandwidth7DayPeakString", "bandwidth2WeekPeak",
    "bandwidth2WeekPeakString", "processedBandwidthCurrent", "processedBandwidthCurrentString",
    "processedBandwidthAverage", "processedBandwidthAverageString",
    "processedBandwidth7DayPeak", "processedBandwidth7DayPeakString",
    "processedBandwidth2WeekPeak", "processedBandwidth2WeekPeakString",
    "connectionsPerMinuteCurrent", "connectionsPerMinuteAverage",
    "connectionsPerMinute7DayPeak", "connectionsPerMinute2WeekPeak",
    "label", "error", "lastContact"
  },
  ["3"] = {
    "id", "mappedId", "antigenaNetworkBlockedConnections", "configuredServer", "version",
    "ipAddress", "bundleVersion", "bundleDate", "bundleInstalledDate", "metadata", "hostname",
    "time", "installed", "kernel", "applianceOSCode", "syslogTLSSHA1Fingerprint",
    "syslogTLSSHA256Fingerprint", "antigenaNetworkRunning", "logIngestionReplicated",
    "logIngestionProcessed", "logIngestionTCP", "logIngestionUDP", "logIngestionDecryption",
    "type", "diskUtilization", "uptime", "systemUptime", "load", "cpu", "memoryUsed",
    "networkInterfacesState_ens5", "networkInterfacesAddress_ens5",
    "networkInterfacesReceived_ens5", "networkInterfacesTransmitted_ens5",
    "bandwidthCurrent", "bandwidthCurrentString", "bandwidthAverage", "bandwidthAverageString",
    "bandwidth7DayPeak", "bandwidth7DayPeakString", "bandwidth2WeekPeak",
    "bandwidth2WeekPeakString", "processedBandwidthCurrent", "processedBandwidthCurrentString",
    "processedBandwidthAverage", "processedBandwidthAverageString",
    "processedBandwidth7DayPeak", "processedBandwidth7DayPeakString",
    "processedBandwidth2WeekPeak", "processedBandwidth2WeekPeakString",
    "connectionsPerMinuteCurrent", "connectionsPerMinuteAverage",
    "connectionsPerMinute7DayPeak", "connectionsPerMinute2WeekPeak",
    "label", "error", "lastContact"
  },

  antigenaNetworkBlockedConnections = {
    "attempted", "failed"
  },
  
  subnetData = {
    "sid", "network", "devices", "clientDevices", "mostRecentTraffic", "mostRecentDHCP", "kerberosQuality"
  },
  
  eventsPerMinuteCurrent = {
    "networkConnections", "logInputConnections", "cSensorConnections", "cSensorNotices",
    "cSensorDeviceDetails", "cSensorModelEvents", "networkNotices", "networkDeviceDetails",
    "networkModelEvents", "logInputNotices", "logInputDeviceDetails", "logInputModelEvents",
    "saasNotices", "saasModelEvents"
  },
  
  licenseCounts = {
    "saas", "licenseIPCount"
  },
  
  saas = {
    "total"
  },

  -- Dynamic keys; listing those present in the log to ensure order if they appear
  logIngestionTypes = {
    "TestingDeviceObjects-connectionlogs", "TestingDeviceObjects2-connectionlogs",
    "TestingDeviceObjects3-connectionlogs", "TestingDeviceObjects4-connectionlogs"
  },
  
  logIngestionMatches = {
    "TestMatch", "TestSrcHostname", "TestingDeviceObjects-connectionlogs"
  }
}


local function get_msg_field_ordering(event_type)
    if event_type == "aianalyst/groups" then
        return GROUPS_FIELD_ORDER
    elseif event_type == "aianalyst/incidentevents" then
        return INCIDENT_FIELD_ORDER
    elseif event_type == "modelbreaches" then
        return MODEL_BREACH_FIELD_ORDER
    elseif event_type == "status" then
        return STATUS_FIELD_ORDER
    end
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

local function collectUnmapped(source, target)
    for key, value in pairs(source or {}) do
        if type(value) == "table" then
            local nested = {}
            collectUnmapped(value, nested)
            if next(nested) then
                target[key] = nested
            end
        else
            target[key] = value
        end
    end
end

local function getEventType(source)
    if source["start"] then
        return "aianalyst/groups"
    elseif source["relatedBreaches"] then
        return "aianalyst/incidentevents"
    elseif source["time"] and source["triggeredComponents"] then
        return "modelbreaches"
    else
        return "status"
    end
end

function processEvent(event)
    if type(event) ~= "table" then
        return nil
    end

    local MAPPED_FIELDS = {}

    local source = deepCopy(event, IGNORE_KEYS)

    local event_type = getEventType(source)

    local result = {}
    
    for _, mapping in ipairs(COMMON_MAPPING) do
        local value = getValueByPath(source, mapping.source)
        if value ~= nil then
            setValueByPath(result, mapping.target, deepCopy(value))
        end
        MAPPED_FIELDS[mapping.source] = true
    end

    if event_type == "aianalyst/groups" then
        for _, mapping in ipairs(GROUPS_LOGS_MAPPING) do
            local value = getValueByPath(source, mapping.source)
            if value ~= nil then
                setValueByPath(result, mapping.target, deepCopy(value))
            end
            MAPPED_FIELDS[mapping.source] = true
        end
    elseif event_type == "aianalyst/incidentevents" then
        for _, mapping in ipairs(INCIDENTS_LOGS_MAPPING) do
            local value = getValueByPath(source, mapping.source)
            if value ~= nil then
                setValueByPath(result, mapping.target, deepCopy(value))
            end
            MAPPED_FIELDS[mapping.source] = true
        end
    elseif event_type == "modelbreaches" then
        for _, mapping in ipairs(MODEL_BREACHES_LOGS_MAPPING) do
            local value = getValueByPath(source, mapping.source)
            if value ~= nil then
                setValueByPath(result, mapping.target, deepCopy(value))
            end
            MAPPED_FIELDS[mapping.source] = true
        end
    elseif event_type == "status" then
        for _, mapping in ipairs(STATUS_LOGS_MAPPING) do
            local value = getValueByPath(source, mapping.source)
            if value ~= nil then
                setValueByPath(result, mapping.target, deepCopy(value))
            end
            MAPPED_FIELDS[mapping.source] = true
        end
    end

    for key, value in pairs(getConstantFields(event_type, event)) do
        result[key] = value
    end

    -- Remove mapped fields from original event for unmapped collection
    for key, _ in pairs(MAPPED_FIELDS) do
        setValueByPath(event, key, nil)
    end
    
    for key, _ in pairs(IGNORE_KEYS) do
        setValueByPath(event, key, nil)
    end

    

    local unmapped = {}
    collectUnmapped(event, unmapped)
    unmapped["event.type"] = event_type
    result.unmapped = {}
    if next(unmapped) then
        -- Merge with existing unmapped
        for k, v in pairs(unmapped) do
            result.unmapped[k] = v
        end
    end

    result.message = encodeJson(source, get_msg_field_ordering(event_type), "message")

    if FEATURES.CLEANUP_EMPTY_NULL then
        cleanupEmptyNull(result)
    end

    return result
end