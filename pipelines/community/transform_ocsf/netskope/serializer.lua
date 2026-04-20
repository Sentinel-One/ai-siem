
-- Netskope to OCSF Mapping Script
-- Maps Netskope log events to OCSF v1.5.0 Detection Finding [2004] format
-- 100% compliant with OCSF schema validation
--
-- Usage: processEvent(event) -> ocsf_event

-- Given a list of mappings return a set of first level 

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

local POLICY_FIELD_ORDERS = {
    root = {
        "_category_id",
        "_category_name",
        "_category_tags",
        "_content_version",
        "_correlation_id",
        "_creation_timestamp",
        "_ef_received_at",
        "_event_id",
        "_forwarded_by",
        "_gef_src_dp",
        "_id",
        "_insertion_epoch_timestamp",
        "_nshostname",
        "_nsp_dur_back",
        "_nsp_dur_front",
        "_nsp_retrans_back",
        "_nsp_retrans_front",
        "_nsp_rtt_back",
        "_nsp_rtt_front",
        "_raw_event_inserted_at",
        "_resource_name",
        "_service_identifier",
        "_session_begin",
        "_skip_geoip_lookup",
        "_src_epoch_now",
        "access_method",
        "acked",
        "action",
        "activity",
        "alert",
        "alert_name",
        "alert_type",
        "app",
        "app_session_id",
        "appcategory",
        "browser",
        "browser_session_id",
        "browser_version",
        "category",
        "cci",
        "ccl",
        "connection_id",
        "count",
        "device",
        "device_classification",
        "domain",
        "dst_country",
        "dst_latitude",
        "dst_location",
        "dst_longitude",
        "dst_region",
        "dst_timezone",
        "dst_zipcode",
        "dstip",
        "file_size",
        "file_type",
        "hostname",
        "incident_id",
        "ja3",
        "ja3s",
        "managed_app",
        "managementID",
        "md5",
        "netskope_pop",
        "nsdeviceuid",
        "object",
        "object_type",
        "organization_unit",
        "os",
        "os_version",
        "other_categories",
        "page",
        "page_site",
        "policy",
        "policy_id",
        "port",
        "protocol",
        "request_id",
        "severity",
        "site",
        "src_country",
        "src_latitude",
        "src_location",
        "src_longitude",
        "src_region",
        "src_time",
        "src_timezone",
        "src_zipcode",
        "srcip",
        "telemetry_app",
        "timestamp",
        "title",
        "traffic_type",
        "transaction_id",
        "type",
        "ur_normalized",
        "url",
        "user",
        "useragent",
        "userip",
        "userkey",
        "web_universal_connector"
    }
}

local MALWARE_FIELD_ORDERS = {
    root = {
        "_body_size",
        "_category_id",
        "_category_tags",
        "_correlation_id",
        "_detection_name",
        "_ef_received_at",
        "_event_id",
        "_forwarded_by",
        "_gef_src_dp",
        "_home_pop_name",
        "_id",
        "_insertion_epoch_timestamp",
        "_internal_detection_engine",
        "_org_hash",
        "_raw_event_inserted_at",
        "_resource_name",
        "_service_identifier",
        "_src_epoch_now",
        "access_method",
        "acked",
        "action",
        "activity",
        "alert",
        "alert_name",
        "alert_type",
        "app",
        "app_name",
        "app_session_id",
        "appcategory",
        "browser",
        "browser_session_id",
        "browser_version",
        "category",
        "cci",
        "ccl",
        "connection_id",
        "count",
        "detection_engine",
        "device",
        "device_classification",
        "dst_country",
        "dst_geoip_src",
        "dst_latitude",
        "dst_location",
        "dst_longitude",
        "dst_region",
        "dst_timezone",
        "dst_zipcode",
        "dstip",
        "file_category",
        "file_id",
        "file_name",
        "file_size",
        "file_type",
        "hostname",
        "incident_id",
        "instance",
        "instance_id",
        "local_md5",
        "local_sha256",
        "malware_id",
        "malware_name",
        "malware_profile",
        "malware_severity",
        "malware_type",
        "managed_app",
        "managementID",
        "md5",
        "ml_detection",
        "nsdeviceuid",
        "object",
        "object_type",
        "organization_unit",
        "os",
        "os_version",
        "other_categories",
        "page",
        "page_site",
        "policy",
        "policy_id",
        "protocol",
        "request_id",
        "sanctioned_instance",
        "scanner_result",
        "severity",
        "severity_id",
        "site",
        "src_country",
        "src_geoip_src",
        "src_latitude",
        "src_location",
        "src_longitude",
        "src_region",
        "src_time",
        "src_timezone",
        "src_zipcode",
        "srcip",
        "timestamp",
        "title",
        "traffic_type",
        "transaction_id",
        "true_filetype",
        "tss_mode",
        "type",
        "ur_normalized",
        "url",
        "user",
        "user_id",
        "userip",
        "userkey"
    }
}

local SECURITY_ASSESSMENT_FIELD_ORDERS = {
    root = {
        "_category_id",
        "_correlation_id",
        "_ef_received_at",
        "_event_id",
        "_forwarded_by",
        "_gef_src_dp",
        "_id",
        "_insertion_epoch_timestamp",
        "_raw_event_inserted_at",
        "_service_identifier",
        "_session_begin",
        "access_method",
        "account_id",
        "account_name",
        "acked",
        "action",
        "activity",
        "alert",
        "alert_name",
        "alert_type",
        "app",
        "appcategory",
        "asset_id",
        "asset_object_id",
        "browser",
        "category",
        "cci",
        "ccl",
        "compliance_standards",
        "count",
        "device",
        "iaas_asset_tags",
        "iaas_remediated",
        "instance_id",
        "object",
        "object_type",
        "organization_unit",
        "os",
        "other_categories",
        "policy",
        "policy_id",
        "region_id",
        "region_name",
        "resource_category",
        "resource_group",
        "sa_profile_id",
        "sa_profile_name",
        "sa_rule_id",
        "sa_rule_name",
        "sa_rule_severity",
        "site",
        "timestamp",
        "traffic_type",
        "type",
        "ur_normalized",
        "user",
        "userkey"
    },
    compliance_standards = {
        "control",
        "description",
        "id",
        "reference_url",
        "section",
        "standard"
    },
    iaas_asset_tags = {
        "name",
        "value"
    }
}

local MALSITE_FIELD_ORDERS = {
    root = {
        "_appsession_start",
        "_category_id",
        "_category_tags",
        "_correlation_id",
        "_creation_timestamp",
        "_ef_received_at",
        "_event_id",
        "_forwarded_by",
        "_gef_src_dp",
        "_id",
        "_insertion_epoch_timestamp",
        "_nshostname",
        "_policy_category_id",
        "_raw_event_inserted_at",
        "_service_identifier",
        "_skip_geoip_lookup",
        "_src_epoch_now",
        "access_method",
        "acked",
        "action",
        "alert",
        "alert_name",
        "alert_type",
        "app",
        "app_session_id",
        "appcategory",
        "browser",
        "browser_session_id",
        "browser_version",
        "category",
        "cci",
        "ccl",
        "connection_id",
        "count",
        "device",
        "device_classification",
        "domain",
        "dst_country",
        "dst_latitude",
        "dst_location",
        "dst_longitude",
        "dst_region",
        "dst_timezone",
        "dst_zipcode",
        "dstip",
        "hostname",
        "incident_id",
        "ja3",
        "ja3s",
        "malicious",
        "malsite_category",
        "malsite_country",
        "malsite_id",
        "malsite_ip_host",
        "malsite_latitude",
        "malsite_longitude",
        "malsite_region",
        "managed_app",
        "netskope_pop",
        "organization_unit",
        "os",
        "os_version",
        "other_categories",
        "page",
        "page_site",
        "policy",
        "policy_id",
        "port",
        "protocol",
        "referer",
        "request_id",
        "severity",
        "severity_level",
        "severity_level_id",
        "site",
        "src_country",
        "src_latitude",
        "src_location",
        "src_longitude",
        "src_region",
        "src_time",
        "src_timezone",
        "src_zipcode",
        "srcip",
        "telemetry_app",
        "threat_match_field",
        "threat_match_value",
        "threat_source_id",
        "timestamp",
        "traffic_type",
        "transaction_id",
        "type",
        "ur_normalized",
        "url",
        "user",
        "userip",
        "userkey"
    }
}

local DLP_FIELD_ORDERS = {
    root = {
        "__cookie_uid", 
        "_category_id", 
        "_category_tags", 
        "_client_file_type", 
        "_correlation_id", 
        "_ef_received_at", 
        "_event_id", 
        "_forwarded_by", 
        "_gef_src_dp", 
        "_id", 
        "_insertion_epoch_timestamp", 
        "_nshostname", 
        "_raw_event_inserted_at", 
        "_resource_name", 
        "_service_identifier", 
        "_skip_geoip_lookup", 
        "_src_epoch_now", 
        "access_method", 
        "acked", 
        "action", 
        "activity", 
        "alert", 
        "alert_name", 
        "alert_type", 
        "app", 
        "app_session_id", 
        "appcategory", 
        "appsuite", 
        "browser", 
        "browser_session_id", 
        "browser_version", 
        "category", 
        "cci", 
        "ccl", 
        "connection_id", 
        "count", 
        "device", 
        "device_classification", 
        "dlp_file", 
        "dlp_incident_id", 
        "dlp_is_unique_count", 
        "dlp_parent_id", 
        "dlp_profile", 
        "dlp_rule", 
        "dlp_rule_count", 
        "dlp_rule_severity", 
        "dst_country", 
        "dst_geoip_src",
        "dst_latitude", 
        "dst_location", 
        "dst_longitude", 
        "dst_region", 
        "dst_timezone", 
        "dst_zipcode", 
        "dstip", 
        "file_lang", 
        "file_size", 
        "file_type", 
        "from_user", 
        "hostname", 
        "incident_id", 
        "instance_id", 
        "local_sha256", 
        "managed_app", 
        "managementID", 
        "md5", 
        "netskope_pop", 
        "nsdeviceuid", 
        "object", 
        "object_id", 
        "object_type", 
        "organization_unit", 
        "os",
        "os_version", 
        "other_categories",
        "page",
        "page_site", 
        "policy", 
        "policy_id", 
        "protocol", "referer", "request_id", "sanctioned_instance", "severity", "site", 
        "src_country", "src_geoip_src", "src_latitude", "src_location", "src_longitude", 
        "src_region", "src_time", "src_timezone", "src_zipcode", "srcip", "suppression_key", 
        "timestamp", "traffic_type", "transaction_id", "true_obj_category", "true_obj_type", "tss_mode",
        "type", "ur_normalized", "url", "user", "userip", "userkey"
    }
}

local UBA_FIELD_ORDERS = {
    root = {
        "_category_id",
        "_category_tags",
        "_correlation_id",
        "_ef_received_at",
        "_event_id",
        "_forwarded_by",
        "_gef_src_dp",
        "_id",
        "_insertion_epoch_timestamp",
        "_raw_event_inserted_at",
        "_service_identifier",
        "_session_begin",
        "access_method",
        "acked",
        "action",
        "activity",
        "alert",
        "alert_id",
        "alert_name",
        "alert_type",
        "app",
        "app_session_id",
        "appcategory",
        "browser",
        "browser_session_id",
        "browser_version",
        "category",
        "ccl",
        "connection_id",
        "count",
        "device",
        "download_app",
        "dst_country",
        "dst_geoip_src",
        "dst_latitude",
        "dst_location",
        "dst_longitude",
        "dst_region",
        "dst_timezone",
        "dst_zipcode",
        "dstip",
        "event_type",
        "evt_src_chnl",
        "file_size",
        "hostname",
        "instance_id",
        "managed_app",
        "managementID",
        "md5",
        "nsdeviceuid",
        "object",
        "object_id",
        "object_type",
        "organization_unit",
        "orig_ty",
        "os",
        "os_version",
        "other_categories",
        "page",
        "page_site",
        "parent_id",
        "policy",
        "policy_actions",
        "profile_id",
        "referer",
        "severity",
        "site",
        "slc_latitude",
        "slc_longitude",
        "src_country",
        "src_geoip_src",
        "src_latitude",
        "src_location",
        "src_longitude",
        "src_region",
        "src_timezone",
        "src_zipcode",
        "srcip",
        "telemetry_app",
        "threshold_time",
        "timestamp",
        "traffic_type",
        "transaction_id",
        "type",
        "uba_ap1",
        "uba_ap2",
        "uba_inst1",
        "uba_inst2",
        "ur_normalized",
        "url",
        "user",
        "userip",
        "userkey"
    }
}

local QUARANTINE_FIELD_ORDERS = {
    root = {
        "_id",
        "access_method",
        "acked",
        "action",
        "alert",
        "alert_name",
        "alert_type",
        "app",
        "appcategory",
        "browser",
        "category",
        "cci",
        "ccl",
        "count",
        "device",
        "exposure",
        "file_path",
        "file_size",
        "file_type",
        "instance_id",
        "md5",
        "mime_type",
        "modified",
        "object",
        "object_id",
        "object_type",
        "organization_unit",
        "os",
        "other_categories",
        "owner",
        "policy",
        "scan_type",
        "site",
        "suppression_key",
        "timestamp",
        "traffic_type",
        "type",
        "ur_normalized",
        "url",
        "user",
        "userkey",
        "q_original_version",
        "q_original_filename",
        "user_id",
        "quarantine_profile_id",
        "q_app",
        "department",
        "quarantine_file_name",
        "shared_with",
        "profile_emails",
        "q_admin",
        "from_user",
        "manager",
        "quarantine_file_id",
        "quarantine_profile",
        "q_original_shared",
        "file_id",
        "departmentNumber",
        "orignal_file_path",
        "q_original_filepath",
        "q_instance",
        "dlp_profile"
    }
}

local COMPROMISED_CREDENTIAL_FIELD_ORDERS = {
    root = {
        "_id",
        "_insertion_epoch_timestamp",
        "_service_identifier",
        "acked",
        "alert",
        "alert_name",
        "alert_type",
        "app",
        "breach_date",
        "breach_description",
        "breach_id",
        "breach_media_references",
        "breach_score",
        "breach_target_references",
        "category",
        "cci",
        "ccl",
        "count",
        "email_source",
        "external_email",
        "matched_username",
        "organization_unit",
        "other_categories",
        "password_type",
        "timestamp",
        "type",
        "ur_normalized",
        "user",
        "userkey"
    }
}


ARRAY_FIELDS = {
    other_categories = true,
    profile_emails = true,
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

function getDefaultMapping(event)
    local alertType = getValue(event, "alert_type", "Other")
    local result = {}
    result.activity_id = 99
    result.metadata = {product = {name = "Netskope"}}
    result.metadata.product.vendor_name = "Netskope"
    result.metadata.version = "1.0.0"
    result.severity_id = 0
    result.dataSource = {category = "security", name = "Netskope", vendor = "Netskope"}
    result.event = {type = alertType}
    result.activity_name = alertType
    return result
end
 
function getDlpEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 2001
    result.class_name = "Security Finding"
    result.category_uid = 2
    result.category_name = "Findings"
    result.type_uid = 200199
    result.type_name = "Security Finding: Other"

    result.resources = {
        {
            data = {
                page = getValue(event, "page", nil),
                page_site = getValue(event, "page_site", nil)
            },
        },
        {
            name = getValue(event, "object", nil)
        },
        {
            uid = getValue(event, "object_id", nil)
        },
        {
            type = getValue(event, "object_type", nil)
        },
        {
            owner = {
                group = getValue(event, "organization_unit", nil),
            }
        },
        {
            owner = {
                email_addr = getValue(event, "from_user", nil)
            }
        }
    }
    
    local fieldMappings = {
        {source='__cookie_uid', target='unmapped.__cookie_uid'},
        {source='_category_id', target='unmapped._category_id'},
        {source='_category_tags', target='unmapped._category_tags'},
        {source='_client_file_type', target='unmapped._client_file_type'},
        {source='_correlation_id', target='metadata.correlation_uid'},
        {source='_ef_received_at', target='unmapped._ef_received_at'},
        {source='_event_id', target='unmapped._event_id'},
        {source='_forwarded_by', target='unmapped._forwarded_by'},
        {source='_gef_src_dp', target='unmapped._gef_src_dp'},
        {source='_id', target='unmapped._id'},
        {source='_insertion_epoch_timestamp', target='unmapped._insertion_epoch_timestamp'},
        {source='_nshostname', target='unmapped._nshostname'},
        {source='_raw_event_inserted_at', target='unmapped._raw_event_inserted_at'},
        {source='_resource_name', target='resource.name'},
        {source='_service_identifier', target='unmapped._service_identifier'},
        {source='_skip_geoip_lookup', target='unmapped._skip_geoip_lookup'},
        {source='_src_epoch_now', target='unmapped._src_epoch_now'},
        {source='access_method', target='unmapped.access_method'},
        {source='acked', target='unmapped.acked'},
        {source='action', target='unmapped.action'},
        {source='activity', target='unmapped.activity'},
        {source='alert', target='unmapped.alert'},
        {source='alert_name', target='finding.title'},
        {source='alert_type', target='unmapped.alert_type'},
        {source='app', target='unmapped.app'},
        {source='app_session_id', target='unmapped.app_session_id'},
        {source='appcategory', target='unmapped.appcategory'},
        {source='appsuite', target='unmapped.appsuite'},
        {source='browser', target='unmapped.browser'},
        {source='browser_session_id', target='unmapped.browser_session_id'},
        {source='browser_version', target='unmapped.browser_version'},
        {source='category', target='unmapped.category'},
        {source='cci', target='unmapped.cci'},
        {source='ccl', target='unmapped.ccl'},
        {source='connection_id', target='unmapped.connection_id'},
        {source='count', target='count'},
        {source='device', target='unmapped.device'},
        {source='device_classification', target='unmapped.device_classification'},
        {source='dlp_file', target='unmapped.dlp_file'},
        {source='dlp_incident_id', target='unmapped.dlp_incident_id'},
        {source='dlp_is_unique_count', target='unmapped.dlp_is_unique_count'},
        {source='dlp_parent_id', target='unmapped.dlp_parent_id'},
        {source='dlp_profile', target='unmapped.dlp_profile'},
        {source='dlp_rule', target='unmapped.dlp_rule'},
        {source='dlp_rule_count', target='unmapped.dlp_rule_count'},
        {source='dlp_rule_severity', target='unmapped.dlp_rule_severity'},
        {source='dst_country', target='unmapped.dst_country'},
        {source='dst_geoip_src', target='unmapped.dst_geoip_src'},
        {source='dst_latitude', target='unmapped.dst_latitude'},
        {source='dst_location', target='unmapped.dst_location'},
        {source='dst_longitude', target='unmapped.dst_longitude'},
        {source='dst_region', target='unmapped.dst_region'},
        {source='dst_timezone', target='unmapped.dst_timezone'},
        {source='dst_zipcode', target='unmapped.dst_zipcode'},
        {source='dstip', target='unmapped.dstip'},
        {source='file_lang', target='unmapped.file_lang'},
        {source='file_size', target='unmapped.file_size'},
        {source='file_type', target='unmapped.file_type'},
        {source='incident_id', target='finding.uid'},
        {source='instance_id', target='unmapped.instance_id'},
        {source='local_sha256', target='unmapped.local_sha256'},
        {source='managed_app', target='unmapped.managed_app'},
        {source='managementID', target='unmapped.managementID'},
        {source='md5', target='unmapped.md5'},
        {source='netskope_pop', target='unmapped.netskope_pop'},
        {source='nsdeviceuid', target='unmapped.nsdeviceuid'},
        {source='os', target='unmapped.os'},
        {source='os_version', target='unmapped.os_version'},
        {source='other_categories', target='unmapped.other_categories'},
        {source='policy', target='analytic.name'},
        {source='policy_id', target='analytic.uid'},
        {source='protocol', target='unmapped.protocol'},
        {source='referer', target='unmapped.referer'},
        {source='request_id', target='unmapped.request_id'},
        {source='sanctioned_instance', target='unmapped.sanctioned_instance'},
        {source='severity', target='unmapped.severity'},
        {source='site', target='unmapped.site'},
        {source='src_country', target='unmapped.src_country'},
        {source='src_geoip_src', target='unmapped.src_geoip_src'},
        {source='src_latitude', target='unmapped.src_latitude'},
        {source='src_location', target='unmapped.src_location'},
        {source='src_longitude', target='unmapped.src_longitude'},
        {source='src_region', target='unmapped.src_region'},
        {source='src_time', target='unmapped.src_time'},
        {source='src_timezone', target='unmapped.src_timezone'},
        {source='src_zipcode', target='unmapped.src_zipcode'},
        {source='srcip', target='unmapped.srcip'},
        {source='suppression_key', target='unmapped.suppression_key'},
        {source='timestamp', target='unmapped.timestamp'},
        {source='traffic_type', target='unmapped.traffic_type'},
        {source='transaction_id', target='unmapped.transaction_id'},
        {source='true_obj_category', target='unmapped.true_obj_category'},
        {source='true_obj_type', target='unmapped.true_obj_type'},
        {source='tss_mode', target='unmapped.tss_mode'},
        {source='type', target='unmapped.type'},
        {source='ur_normalized', target='unmapped.ur_normalized'},
        {source='url', target='unmapped.url'},
        {source='user', target='unmapped.user'},
        {source='userip', target='unmapped.userip'},
        {source='userkey', target='unmapped.userkey'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='metadata.version', target='metadata.version'},
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
        {source='message', target='message'},
        {source='resources', target='resources'},
        {source='hostname', target='unmapped.hostname'},
    }

    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getUbaEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 2001
    result.class_name = "Security Finding"
    result.category_uid = 2
    result.category_name = "Findings"
    result.type_uid = 200199
    result.type_name = "Security Finding: Other"
    result.resources = {
        {
            data = {
                hostname = getValue(event, "hostname", nil)
            }
        },
        {
            name = getValue(event, "object", nil)
        },
        {
            uid = getValue(event, "object_id", nil)
        },
        {
            type = getValue(event, "object_type", nil)
        },
        {
            owner = {
                email_addr = getValue(event, "ur_normalized", nil)
            }
        },
    }

    local fieldMappings = {
            {source='unmapped._category_id', target='unmapped._category_id'},
            {source='unmapped._category_tags', target='unmapped._category_tags'},
            {source='_correlation_id', target='metadata.correlation_uid'},
            {source='unmapped._ef_received_at', target='unmapped._ef_received_at'},
            {source='unmapped._event_id', target='unmapped._event_id'},
            {source='unmapped._forwarded_by', target='unmapped._forwarded_by'},
            {source='_gef_src_dp', target='unmapped._gef_src_dp'},
            {source='_id', target='unmapped._id'},
            {source='_insertion_epoch_timestamp', target='unmapped._insertion_epoch_timestamp'},
            {source='_raw_event_inserted_at', target='unmapped._raw_event_inserted_at'},
            {source='_service_identifier', target='unmapped._service_identifier'},
            {source='_session_begin', target='unmapped._session_begin'},
            {source='access_method', target='unmapped.access_method'},
            {source='acked', target='unmapped.acked'},
            {source='action', target='analytic.type'},
            {source='activity', target='unmapped.activity'},
            {source='alert', target='unmapped.alert'},
            {source='alert_id', target='finding.uid'},
            {source='alert_name', target='finding.title'},
            {source='alert_type', target='finding.type'},
            {source='app', target='unmapped.app'},
            {source='app_session_id', target='unmapped.app_session_id'},
            {source='appcategory', target='unmapped.appcategory'},
            {source='browser', target='unmapped.browser'},
            {source='browser_session_id', target='unmapped.browser_session_id'},
            {source='browser_version', target='unmapped.browser_version'},
            {source='category', target='unmapped.category'},
            {source='ccl', target='unmapped.ccl'},
            {source='connection_id', target='unmapped.connection_id'},
            {source='count', target='count'},
            {source='device', target='unmapped.device'},
            {source='download_app', target='unmapped.download_app'},
            {source='dst_country', target='unmapped.dst_country'},
            {source='dst_geoip_src', target='unmapped.dst_geoip_src'},
            {source='dst_latitude', target='unmapped.dst_latitude'},
            {source='dst_location', target='unmapped.dst_location'},
            {source='dst_longitude', target='unmapped.dst_longitude'},
            {source='dst_region', target='unmapped.dst_region'},
            {source='dst_timezone', target='unmapped.dst_timezone'},
            {source='dst_zipcode', target='unmapped.dst_zipcode'},
            {source='dstip', target='unmapped.dstip'},
            {source='evt_src_chnl', target='unmapped.evt_src_chnl'},
            {source='file_size', target='unmapped.file_size'},
            {source='instance_id', target='unmapped.instance_id'},
            {source='managed_app', target='unmapped.managed_app'},
            {source='managementID', target='unmapped.managementID'},
            {source='md5', target='unmapped.md5'},
            {source='nsdeviceuid', target='unmapped.nsdeviceuid'},
            {source='organization_unit', target='unmapped.organization_unit'},
            {source='orig_ty', target='unmapped.orig_ty'},
            {source='os', target='unmapped.os'},
            {source='os_version', target='unmapped.os_version'},
            {source='other_categories', target='unmapped.other_categories'},
            {source='page', target='unmapped.page'},
            {source='page_site', target='unmapped.page_site'},
            {source='parent_id', target='unmapped.parent_id'},
            {source='policy', target='unmapped.policy'},
            {source='policy_actions', target='unmapped.policy_actions'},
            {source='profile_id', target='unmapped.profile_id'},
            {source='referer', target='unmapped.referer'},
            {source='severity', target='unmapped.severity'},
            {source='site', target='unmapped.site'},
            {source='slc_latitude', target='unmapped.slc_latitude'},
            {source='slc_longitude', target='unmapped.slc_longitude'},
            {source='src_country', target='unmapped.src_country'},
            {source='src_geoip_src', target='unmapped.src_geoip_src'},
            {source='src_latitude', target='unmapped.src_latitude'},
            {source='src_location', target='unmapped.src_location'},
            {source='src_longitude', target='unmapped.src_longitude'},
            {source='src_region', target='unmapped.src_region'},
            {source='src_timezone', target='unmapped.src_timezone'},
            {source='src_zipcode', target='unmapped.src_zipcode'},
            {source='srcip', target='unmapped.srcip'},
            {source='telemetry_app', target='unmapped.telemetry_app'},
            {source='threshold_time', target='unmapped.threshold_time'},
            {source='timestamp', target='metadata.original_time'},
            {source='traffic_type', target='unmapped.traffic_type'},
            {source='transaction_id', target='unmapped.transaction_id'},
            {source='type', target='unmapped.type'},
            {source='uba_ap1', target='unmapped.uba_ap1'},
            {source='uba_ap2', target='unmapped.uba_ap2'},
            {source='uba_inst1', target='unmapped.uba_inst1'},
            {source='uba_inst2', target='unmapped.uba_inst2'},
            {source='url', target='unmapped.url'},
            {source='user', target='unmapped.user'},
            {source='userip', target='unmapped.userip'},
            {source='userkey', target='unmapped.userkey'},
            {source='metadata.product.name', target='metadata.product.name'},
            {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
            {source='metadata.version', target='metadata.version'},
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
            {source='message', target='message'},
            {source='resources', target='resources'},
        }
    
    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getCompromisedCredentialEvents(event)
    local result = getDefaultMapping(event)
    result["class_uid"] = 2001
    result["class_name"] = "Security Finding"
    result["category_uid"] = 2
    result["category_name"] = "Findings"
    result["type_uid"] = 200199
    result["type_name"] = "Security Finding: Other"
    result["resources"] = {
        {
            data = {
                breach_id = getValue(event, "breach_id", nil),
                breach_target_references = getValue(event, "breach_target_references", nil),
                breach_description = getValue(event, "breach_description", nil),
                breach_date = getValue(event, "breach_date", nil),
                breach_media_references = getValue(event, "breach_media_references", nil),
                breach_score = getValue(event, "breach_score", nil),
            }
        },
        {owner = {email_addr = getValue(event, "ur_normalized", nil)}},
    }
    local fieldMappings = {
        {source='alert', target='unmapped.alert'},
        {source='alert_name', target='finding.title'},
        {source='alert_type', target='finding.type'},
        {source='_id', target='unmapped._id'},
        {source='_insertion_epoch_timestamp', target='unmapped._insertion_epoch_timestamp'},
        {source='_service_identifier', target='unmapped._service_identifier'},
        {source='acked', target='unmapped.acked'},
        {source='alert_type', target='finding.type'},
        {source='app', target='unmapped.app'},
        {source='category', target='unmapped.category'},
        {source='cci', target='unmapped.cci'},
        {source='ccl', target='unmapped.ccl'},
        {source='count', target='count'},
        {source='email_source', target='unmapped.email_source'},
        {source='external_email', target='unmapped.external_email'},
        {source='matched_username', target='unmapped.matched_username'},
        {source='organization_unit', target='unmapped.organization_unit'},
        {source='other_categories', target='unmapped.other_categories'},
        {source='password_type', target='unmapped.password_type'},
        {source='timestamp', target='metadata.original_time'},
        {source='type', target='analytic.type'},
        {source='user', target='unmapped.user'},
        {source='userkey', target='unmapped.userkey'},
        {source='metadata.product.name', target='metadata.product.name'},
        {source='metadata.product.vendor_name', target='metadata.product.vendor_name'},
        {source='metadata.version', target='metadata.version'},
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
        {source='message', target='message'},
        {source='resources', target='resources'},
    }
    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getMalsiteEvents(event)
    local result = getDefaultMapping(event)
    result["class_uid"] = 2001
    result["class_name"] = "Security Finding"
    result["category_uid"] = 2
    result["category_name"] = "Findings"
    result["type_uid"] = 200199
    result["type_name"] = "Security Finding: Other"
    result["resources"] = {
        {
            data = {
                hostname = getValue(event, "hostname", nil),
                page = getValue(event, "page", nil),
                page_site = getValue(event, "page_site", nil),
            }
        },
        {type = getValue(event, "threat_match_field", nil)},
        {name = getValue(event, "threat_match_value", nil)},
        {uid = getValue(event, "threat_source_id", nil)},
    }
    local fieldMappings = {
            {source = "_appsession_start", target = "unmapped._appsession_start"},
            {source = "_category_id", target = "unmapped._category_id"},
            {source = "_category_tags", target = "unmapped._category_tags"},
            {source = "_correlation_id", target = "metadata.correlation_uid"},
            {source = "_creation_timestamp", target = "unmapped._creation_timestamp"},
            {source = "_ef_received_at", target = "unmapped._ef_received_at"},
            {source = "_event_id", target = "unmapped._event_id"},
            {source = "_forwarded_by", target = "unmapped._forwarded_by"},
            {source = "_gef_src_dp", target = "unmapped._gef_src_dp"},
            {source = "_id", target = "unmapped._id"},
            {source = "_insertion_epoch_timestamp", target = "unmapped._insertion_epoch_timestamp"},
            {source = "_nshostname", target = "unmapped._nshostname"},
            {source = "_policy_category_id", target = "unmapped._policy_category_id"},
            {source = "_raw_event_inserted_at", target = "unmapped._raw_event_inserted_at"},
            {source = "_service_identifier", target = "unmapped._service_identifier"},
            {source = "_skip_geoip_lookup", target = "unmapped._skip_geoip_lookup"},
            {source = "_src_epoch_now", target = "unmapped._src_epoch_now"},
            {source = "access_method", target = "unmapped.access_method"},
            {source = "acked", target = "unmapped.acked"},
            {source = "action", target = "unmapped.action"},
            {source = "alert", target = "unmapped.alert"},
            {source = "alert_name", target = "unmapped.alert_name"},
            {source = "alert_type", target = "unmapped.alert_type"},
            {source = "app", target = "unmapped.app"},
            {source = "app_session_id", target = "unmapped.app_session_id"},
            {source = "appcategory", target = "unmapped.appcategory"},
            {source = "browser", target = "unmapped.browser"},
            {source = "browser_session_id", target = "unmapped.browser_session_id"},
            {source = "browser_version", target = "unmapped.browser_version"},
            {source = "category", target = "unmapped.category"},
            {source = "cci", target = "unmapped.cci"},
            {source = "ccl", target = "unmapped.ccl"},
            {source = "connection_id", target = "unmapped.connection_id"},
            {source = "count", target = "count"},
            {source = "device", target = "unmapped.device"},
            {source = "device_classification", target = "unmapped.device_classification"},
            {source = "domain", target = "unmapped.domain"},
            {source = "dst_country", target = "unmapped.dst_country"},
            {source = "dst_latitude", target = "unmapped.dst_latitude"},
            {source = "dst_location", target = "unmapped.dst_location"},
            {source = "dst_longitude", target = "unmapped.dst_longitude"},
            {source = "dst_region", target = "unmapped.dst_region"},
            {source = "dst_timezone", target = "unmapped.dst_timezone"},
            {source = "dst_zipcode", target = "unmapped.dst_zipcode"},
            {source = "dstip", target = "unmapped.dstip"},
            {source = "incident_id", target = "finding.uid"},
            {source = "ja3", target = "unmapped.ja3"},
            {source = "ja3s", target = "unmapped.ja3s"},
            {source = "malicious", target = "unmapped.malicious"},
            {source = "malsite_category", target = "unmapped.malsite_category"},
            {source = "malsite_country", target = "unmapped.malsite_country"},
            {source = "malsite_id", target = "malware.uid"},
            {source = "malsite_ip_host", target = "unmapped.malsite_ip_host"},
            {source = "malsite_latitude", target = "unmapped.malsite_latitude"},
            {source = "malsite_longitude", target = "unmapped.malsite_longitude"},
            {source = "malsite_region", target = "unmapped.malsite_region"},
            {source = "managed_app", target = "unmapped.managed_app"},
            {source = "netskope_pop", target = "unmapped.netskope_pop"},
            {source = "organization_unit", target = "unmapped.organization_unit"},
            {source = "os", target = "unmapped.os"},
            {source = "os_version", target = "unmapped.os_version"},
            {source = "other_categories", target = "unmapped.other_categories"},
            {source = "Security", target = "unmapped.security_risk"},
            {source = "policy", target = "unmapped.policy"},
            {source = "policy_id", target = "unmapped.policy_id"},
            {source = "port", target = "unmapped.port"},
            {source = "protocol", target = "unmapped.protocol"},
            {source = "referer", target = "unmapped.referer"},
            {source = "request_id", target = "unmapped.request_id"},
            {source = "severity", target = "unmapped.severity"},
            {source = "severity_level", target = "unmapped.severity_level"},
            {source = "severity_level_id", target = "unmapped.severity_level_id"},
            {source = "site", target = "unmapped.site"},
            {source = "src_country", target = "unmapped.src_country"},
            {source = "src_latitude", target = "unmapped.src_latitude"},
            {source = "src_location", target = "unmapped.src_location"},
            {source = "src_longitude", target = "unmapped.src_longitude"},
            {source = "src_region", target = "unmapped.src_region"},
            {source = "src_time", target = "unmapped.src_time"},
            {source = "src_timezone", target = "unmapped.src_timezone"},
            {source = "src_zipcode", target = "unmapped.src_zipcode"},
            {source = "srcip", target = "unmapped.srcip"},
            {source = "telemetry_app", target = "unmapped.telemetry_app"},
            {source = "timestamp", target = "metadata.original_time"},
            {source = "traffic_type", target = "unmapped.traffic_type"},
            {source = "transaction_id", target = "unmapped.transaction_id"},
            {source = "type", target = "unmapped.type"},
            {source = "ur_normalized", target = "unmapped.ur_normalized"},
            {source = "url", target = "unmapped.url"},
            {source = "user", target = "unmapped.user"},
            {source = "userip", target = "unmapped.userip"},
            {source = "userkey", target = "unmapped.userkey"},
            {source = "metadata.product.name", target = "metadata.product.name"},
            {source = "metadata.product.vendor_name", target = "metadata.product.vendor_name"},
            {source = "metadata.version", target = "metadata.version"},
            {source = "dataSource.category", target = "dataSource.category"},
            {source = "dataSource.name", target = "dataSource.name"},
            {source = "dataSource.vendor", target = "dataSource.vendor"},
            {source = "class_uid", target = "class_uid"},
            {source = "class_name", target = "class_name"},
            {source = "category_uid", target = "category_uid"},
            {source = "category_name", target = "category_name"},
            {source = "type_uid", target = "type_uid"},
            {source = "type_name", target = "type_name"},
            {source = "activity_name", target = "activity_name"},
            {source = "activity_id", target = "activity_id"},
            {source = "severity_id", target = "severity_id"},
            {source = "message", target = "message"},
            {source = "resources", target = "resources"},
    }  
    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getMalwareEvents(event)
    local result = getDefaultMapping(event)
    result["class_uid"] = 2001
    result["class_name"] = "Security Finding"
    result["category_uid"] = 2
    result["category_name"] = "Findings"
    result["type_uid"] = 200199
    result["type_name"] = "Security Finding: Other"
    result["resources"] = {
        {
            data = {
                dstip = getValue(event, "dstip", nil),
                file_category = getValue(event, "file_category", nil),
                file_id = getValue(event, "file_id", nil),
                hostname = getValue(event, "hostname", nil),
                url = getValue(event, "url", nil),
                user_id = getValue(event, "user_id", nil),
            }
        },
        {name = getValue(event, "file_name", nil)},
        {owner = {email_addr = getValue(event, "ur_normalized", nil)}},
    }
    local fieldMappings = {
            {source="_body_size", target="unmapped._body_size"},
            {source="_category_id", target="unmapped._category_id"},
            {source="_category_tags", target="unmapped._category_tags"},
            {source="_correlation_id", target="metadata.correlation_uid"},
            {source="_detection_name", target="unmapped._detection_name"},
            {source="_ef_received_at", target="unmapped._ef_received_at"},
            {source="_event_id", target="unmapped._event_id"},
            {source="_forwarded_by", target="unmapped._forwarded_by"},
            {source="_gef_src_dp", target="unmapped._gef_src_dp"},
            {source="_home_pop_name", target="unmapped._home_pop_name"},
            {source="_id", target="unmapped._id"},
            {source="_insertion_epoch_timestamp", target="unmapped._insertion_epoch_timestamp"},
            {source="_internal_detection_engine", target="unmapped._internal_detection_engine"},
            {source="_org_hash", target="unmapped._org_hash"},
            {source="_raw_event_inserted_at", target="unmapped._raw_event_inserted_at"},
            {source="_resource_name", target="unmapped._resource_name"},
            {source="_service_identifier", target="unmapped._service_identifier"},
            {source="_src_epoch_now", target="unmapped._src_epoch_now"},
            {source="access_method", target="unmapped.access_method"},
            {source="acked", target="unmapped.acked"},
            {source="action", target="unmapped.action"},
            {source="activity", target="unmapped.activity"},
            {source="alert", target="unmapped.alert"},
            {source="alert_name", target="malware.name"},
            {source="alert_type", target="finding.type"},
            {source="app", target="unmapped.app"},
            {source="app_name", target="unmapped.app_name"},
            {source="app_session_id", target="unmapped.app_session_id"},
            {source="appcategory", target="unmapped.appcategory"},
            {source="browser", target="unmapped.browser"},
            {source="browser_session_id", target="unmapped.browser_session_id"},
            {source="browser_version", target="unmapped.browser_version"},
            {source="category", target="unmapped.category"},
            {source="cci", target="unmapped.cci"},
            {source="ccl", target="unmapped.ccl"},
            {source="connection_id", target="unmapped.connection_id"},
            {source="count", target="count"},
            {source="detection_engine", target="unmapped.detection_engine"},
            {source="device", target="unmapped.device"},
            {source="device_classification", target="unmapped.device_classification"},
            {source="dst_country", target="unmapped.dst_country"},
            {source="dst_geoip_src", target="unmapped.dst_geoip_src"},
            {source="dst_latitude", target="unmapped.dst_latitude"},
            {source="dst_location", target="unmapped.dst_location"},
            {source="dst_longitude", target="unmapped.dst_longitude"},
            {source="dst_region", target="unmapped.dst_region"},
            {source="dst_timezone", target="unmapped.dst_timezone"},
            {source="dst_zipcode", target="unmapped.dst_zipcode"},
            {source="file_size", target="unmapped.file_size"},
            {source="file_type", target="unmapped.file_type"},
            {source="incident_id", target="unmapped.incident_id"},
            {source="instance", target="unmapped.instance"},
            {source="instance_id", target="unmapped.instance_id"},
            {source="local_md5", target="unmapped.local_md5"},
            {source="local_sha256", target="unmapped.local_sha256"},
            {source="malware_id", target="malware.uid"},
            {source="malware_name", target="malware.name"},
            {source="malware_profile", target="unmapped.malware_profile"},
            {source="malware_severity", target="unmapped.malware_severity"},
            {source="malware_type", target="malware.type"},
            {source="managed_app", target="unmapped.managed_app"},
            {source="managementID", target="unmapped.managementID"},
            {source="md5", target="unmapped.md5"},
            {source="ml_detection", target="unmapped.ml_detection"},
            {source="nsdeviceuid", target="unmapped.nsdeviceuid"},
            {source="object", target="unmapped.object"},
            {source="object_type", target="unmapped.object_type"},
            {source="organization_unit", target="unmapped.organization_unit"},
            {source="os", target="unmapped.os"},
            {source="os_version", target="unmapped.os_version"},
            {source="other_categories", target="unmapped.other_categories"},
            {source="page", target="unmapped.page"},
            {source="page_site", target="unmapped.page_site"},
            {source="policy", target="analytic.name"},
            {source="policy_id", target="analytic.uid"},
            {source="protocol", target="unmapped.protocol"},
            {source="request_id", target="unmapped.request_id"},
            {source="sanctioned_instance", target="unmapped.sanctioned_instance"},
            {source="scanner_result", target="unmapped.scanner_result"},
            {source="severity", target="unmapped.severity"},
            {source="site", target="unmapped.site"},
            {source="src_country", target="unmapped.src_country"},
            {source="src_geoip_src", target="unmapped.src_geoip_src"},
            {source="src_latitude", target="unmapped.src_latitude"},
            {source="src_location", target="unmapped.src_location"},
            {source="src_longitude", target="unmapped.src_longitude"},
            {source="src_region", target="unmapped.src_region"},
            {source="src_time", target="unmapped.src_time"},
            {source="src_timezone", target="unmapped.src_timezone"},
            {source="src_zipcode", target="unmapped.src_zipcode"},
            {source="srcip", target="unmapped.srcip"},
            {source="timestamp", target="unmapped.timestamp"},
            {source="title", target="unmapped.title"},
            {source="traffic_type", target="unmapped.traffic_type"},
            {source="transaction_id", target="unmapped.transaction_id"},
            {source="true_filetype", target="unmapped.true_filetype"},
            {source="tss_mode", target="unmapped.tss_mode"},
            {source="type", target="unmapped.type"},
            {source="userip", target="unmapped.userip"},
            {source="userkey", target="unmapped.userkey"},
            {source="metadata.product.name", target="metadata.product.name"},
            {source="metadata.product.vendor_name", target="metadata.product.vendor_name"},
            {source="metadata.version", target="metadata.version"},
            {source="dataSource.category", target="dataSource.category"},
            {source="dataSource.name", target="dataSource.name"},
            {source="dataSource.vendor", target="dataSource.vendor"},
            {source="class_uid", target="class_uid"},
            {source="class_name", target="class_name"},
            {source="category_uid", target="category_uid"},
            {source="category_name", target="category_name"},
            {source="type_uid", target="type_uid"},
            {source="type_name", target="type_name"},
            {source="activity_name", target="activity_name"},
            {source="activity_id", target="activity_id"},
            {source="severity_id", target="severity_id"},
            {source="message", target="message"},
            {source="resources", target="resources"},
    }
    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getPolicyEvents(event)
    local result = getDefaultMapping(event)
    result["class_uid"] = 6001
    result["class_name"] = "Web Resources Activity"
    result["category_uid"] = 6
    result["category_name"] = "Application Activity"
    result["type_uid"] = 600199
    result["type_name"] = "Web Resources Activity: Other"
    result["dst_endpoint"] = {location = {coordinates = {getValue(event, "dst_latitude", nil), getValue(event, "dst_longitude", nil)}}}
    result["src_endpoint"] = {location = {coordinates = {getValue(event, "src_latitude", nil), getValue(event, "src_longitude", nil)}}}
    local fieldMappings = {
        {source="_category_id", target="unmapped._category_id"},
        {source="_category_name", target="unmapped._category_name"},
        {source="_category_tags", target="unmapped._category_tags"},
        {source="_content_version", target="metadata.product.feature.version"},
        {source="_correlation_id", target="metadata.correlation_uid"},
        {source="_creation_timestamp", target="metadata.logged_time"},
        {source="_ef_received_at", target="metadata.processed_time"},
        {source="_event_id", target="metadata.uid"},
        {source="_forwarded_by", target="metadata.log_provider"},
        {source="_gef_src_dp", target="unmapped._gef_src_dp"},
        {source="_id", target="unmapped._id"},
        {source="_insertion_epoch_timestamp", target="unmapped._insertion_epoch_timestamp"},
        {source="_nshostname", target="device.hostname"},
        {source="_nsp_dur_back", target="unmapped._nsp_dur_back"},
        {source="_nsp_dur_front", target="unmapped._nsp_dur_front"},
        {source="_nsp_retrans_back", target="unmapped._nsp_retrans_back"},
        {source="_nsp_retrans_front", target="unmapped._nsp_retrans_front"},
        {source="_nsp_rtt_back", target="unmapped._nsp_rtt_back"},
        {source="_nsp_rtt_front", target="unmapped._nsp_rtt_front"},
        {source="_raw_event_inserted_at", target="unmapped._raw_event_inserted_at"},
        {source="_resource_name", target="web_resources.name"},
        {source="_service_identifier", target="unmapped._service_identifier"},
        {source="_session_begin", target="unmapped._session_begin"},
        {source="_skip_geoip_lookup", target="unmapped._skip_geoip_lookup"},
        {source="_src_epoch_now", target="unmapped._src_epoch_now"},
        {source="access_method", target="unmapped.access_method"},
        {source="acked", target="unmapped.acked"},
        {source="action", target="unmapped.action"},
        {source="activity", target="unmapped.activity"},
        {source="alert", target="unmapped.alert"},
        {source="alert_name", target="unmapped.alert_name"},
        {source="alert_type", target="unmapped.alert_type"},
        {source="app", target="unmapped.app"},
        {source="app_session_id", target="actor.session.uid"},
        {source="appcategory", target="unmapped.app_category"},
        {source="browser", target="unmapped.browser"},
        {source="browser_session_id", target="unmapped.browser_session_id"},
        {source="browser_version", target="unmapped.browser_version"},
        {source="category", target="unmapped.category"},
        {source="cci", target="unmapped.cci"},
        {source="ccl", target="unmapped.ccl"},
        {source="connection_id", target="unmapped.connection_id"},
        {source="count", target="count"},
        {source="device", target="device.os.type"},
        {source="device_classification", target="unmapped.device_classification"},
        {source="domain", target="src_endpoint.domain"},
        {source="dst_country", target="dst_endpoint.location.country"},
        {source="dst_location", target="dst_endpoint.location.city"},
        {source="dst_region", target="dst_endpoint.location.region"},
        {source="dst_timezone", target="unmapped.dst_timezone"},
        {source="dst_zipcode", target="dst_endpoint.location.postal_code"},
        {source="dstip", target="dst_endpoint.ip"},
        {source="file_size", target="unmapped.file_size"},
        {source="file_type", target="unmapped.file_type"},
        {source="hostname", target="src_endpoint.hostname"},
        {source="incident_id", target="metadata.event_code"},
        {source="ja3", target="unmapped.ja3"},
        {source="ja3s", target="unmapped.ja3s"},
        {source="managed_app", target="unmapped.managed_app"},
        {source="managementID", target="unmapped.managementID"},
        {source="md5", target="unmapped.md5"},
        {source="netskope_pop", target="unmapped.netskope_pop"},
        {source="nsdeviceuid", target="unmapped.nsdeviceuid"},
        {source="object", target="unmapped.object"},
        {source="object_type", target="unmapped.object_type"},
        {source="organization_unit", target="unmapped.organization_unit"},
        {source="os", target="unmapped.os"},
        {source="os_version", target="unmapped.os_version"},
        {source="other_categories", target="unmapped.other_categories"},
        {source="page", target="unmapped.page"},
        {source="page_site", target="unmapped.page_site"},
        {source="policy", target="actor.authorizations.policy.name"},
        {source="policy_id", target="actor.authorizations.policy.uid"},
        {source="port", target="src_endpoint.port"},
        {source="protocol", target="unmapped.protocol"},
        {source="request_id", target="unmapped.request_id"},
        {source="severity", target="unmapped.severity"},
        {source="site", target="unmapped.site"},
        {source="src_country", target="src_endpoint.location.country"},
        {source="src_location", target="src_endpoint.location.city"},
        {source="src_region", target="src_endpoint.location.region"},
        {source="src_time", target="unmapped.src_time"},
        {source="src_timezone", target="unmapped.src_timezone"},
        {source="src_zipcode", target="src_endpoint.location.postal_code"},
        {source="srcip", target="src_endpoint.ip"},
        {source="telemetry_app", target="actor.invoked_by"},
        {source="timestamp", target="metadata.original_time"},
        {source="title", target="unmapped.title"},
        {source="traffic_type", target="unmapped.traffic_type"},
        {source="transaction_id", target="unmapped.transaction_id"},
        {source="type", target="unmapped.type"},
        {source="ur_normalized", target="actor.user.email_addr"},
        {source="url", target="web_resource.url_string"},
        {source="user", target="actor.user.email_addr"},
        {source="useragent", target="unmapped.useragent"},
        {source="userip", target="unmapped.userip"},
        {source="userkey", target="unmapped.userkey"},
        {source="web_universal_connector", target="unmapped.web_universal_connector"},
        {source="metadata.product.name", target="metadata.product.name"},
        {source="metadata.product.vendor_name", target="metadata.product.vendor_name"},
        {source="metadata.version", target="metadata.version"},
        {source="dataSource.category", target="dataSource.category"},
        {source="dataSource.name", target="dataSource.name"},
        {source="dataSource.vendor", target="dataSource.vendor"},
        {source="class_uid", target="class_uid"},
        {source="class_name", target="class_name"},
        {source="category_uid", target="category_uid"},
        {source="category_name", target="category_name"},
        {source="type_uid", target="type_uid"},
        {source="type_name", target="type_name"},
        {source="dst_endpoint.location.coordinates", target="dst_endpoint.location.coordinates"},
        {source="src_endpoint.location.coordinates", target="src_endpoint.location.coordinates"},
        {source="activity_name", target="activity_name"},
        {source="activity_id", target="activity_id"},
        {source="severity_id", target="severity_id"},
        {source="message", target="message"},
    }
    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end

    result = copyUnmappedFields(event, fieldMappings, result)
    return result
end

function getSecurityAssessmentEvents(event)
    local result = getDefaultMapping(event)
    result["class_uid"] = 2001
    result["class_name"] = "Security Finding"
    result["category_uid"] = 2
    result["category_name"] = "Findings"
    result["type_uid"] = 200199
    result["type_name"] = "Security Finding: Other"
    result["resources"] = {
        {owner = {account = {uid = getValue(event, "account_id", nil)}}},
        {
            data = {
                asset_id = getValue(event, "asset_id", nil),
                asset_object_id = getValue(event, "asset_object_id", nil),
                category = getValue(event, "category", nil),
                iaas_asset_tags = getValue(event, "iaas_asset_tags", nil),
                iaas_remediated = getValue(event, "iaas_remediated", nil),
                instance_id = getValue(event, "instance_id", nil),
                object = getValue(event, "object", nil),
                object_type = getValue(event, "object_type", nil),
                region_id = getValue(event, "region_id", nil),
                region_name = getValue(event, "region_name", nil),
                resource_category = getValue(event, "resource_category", nil),
                resource_group = getValue(event, "resource_group", nil),
            }
        },
    }
    local fieldMappings = {
            {source="_category_id", target="unmapped._category_id"},
            {source="_correlation_id", target="metadata.correlation_uid"},
            {source="_ef_received_at", target="unmapped._ef_received_at"},
            {source="_event_id", target="unmapped._event_id"},
            {source="_forwarded_by", target="unmapped._forwarded_by"},
            {source="_gef_src_dp", target="unmapped._gef_src_dp"},
            {source="_id", target="unmapped._id"},
            {source="_insertion_epoch_timestamp", target="unmapped._insertion_epoch_timestamp"},
            {source="_raw_event_inserted_at", target="unmapped._raw_event_inserted_at"},
            {source="_service_identifier", target="unmapped._service_identifier"},
            {source="_session_begin", target="unmapped._session_begin"},
            {source="access_method", target="unmapped.access_method"},
            {source="account_name", target="unmapped.account_name"},
            {source="acked", target="unmapped.acked"},
            {source="action", target="unmapped.action"},
            {source="activity", target="unmapped.activity"},
            {source="alert", target="unmapped.alert"},
            {source="alert_name", target="malware.name"},
            {source="alert_type", target="finding.type"},
            {source="app", target="unmapped.app"},
            {source="appcategory", target="unmapped.appcategory"},
            {source="browser", target="unmapped.browser"},
            {source="cci", target="unmapped.cci"},
            {source="ccl", target="unmapped.ccl"},
            {source="compliance_standards", target="unmapped.compliance_standards"},
            {source="count", target="count"},
            {source="device", target="unmapped.device"},
            {source="organization_unit", target="unmapped.organization_unit"},
            {source="os", target="unmapped.os"},
            {source="other_categories", target="unmapped.other_categories"},
            {source="policy", target="unmapped.policy"},
            {source="policy_id", target="unmapped.policy_id"},
            {source="sa_profile_id", target="unmapped.sa_profile_id"},
            {source="sa_profile_name", target="unmapped.sa_profile_name"},
            {source="sa_rule_id", target="unmapped.sa_rule_id"},
            {source="sa_rule_name", target="unmapped.sa_rule_name"},
            {source="sa_rule_severity", target="unmapped.sa_rule_severity"},
            {source="site", target="unmapped.site"},
            {source="timestamp", target="unmapped.timestamp"},
            {source="traffic_type", target="unmapped.traffic_type"},
            {source="type", target="unmapped.type"},
            {source="ur_normalized", target="unmapped.ur_normalized"},
            {source="user", target="unmapped.user"},
            {source="userkey", target="unmapped.userkey"},
            {source="metadata.product.name", target="metadata.product.name"},
            {source="metadata.product.vendor_name", target="metadata.product.vendor_name"},
            {source="metadata.version", target="metadata.version"},
            {source="dataSource.category", target="dataSource.category"},
            {source="dataSource.name", target="dataSource.name"},
            {source="dataSource.vendor", target="dataSource.vendor"},
            {source="class_uid", target="class_uid"},
            {source="class_name", target="class_name"},
            {source="category_uid", target="category_uid"},
            {source="category_name", target="category_name"},
            {source="type_uid", target="type_uid"},
            {source="type_name", target="type_name"},
            {source="activity_name", target="activity_name"},
            {source="activity_id", target="activity_id"},
            {source="severity_id", target="severity_id"},
            {source="message", target="message"},
            {source="resources", target="resources"},
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

    -- Merge the specific mappings into the base map (equivalent to Python's update).
    for key, value in pairs(specificMappings) do
        baseEventMapping[key] = value
    end

    return baseEventMapping
end

function getQuarantineEvents(event)
    local result = {}
    alertType = getValue(event, "alert_type", "Other")
    result["class_uid"] = 0
    result["class_name"] = "Base Event"
    result["category_uid"] = 0
    result["category_name"] = "Uncategorized"
    result["activity_id"] = 99
    result["activity_name"] = alertType
    result["type_uid"] = 99
    result["type_name"] = "Base Event: Other"
    result["metadata"] = {product = {name = "Netskope", vendor_name = "Netskope"}, version = "1.0.0"}
    result["dataSource"] = {category = "security", name = "Netskope", vendor = "Netskope"}
    result["event"] = {type = alertType}

    fieldMappings = getBaseEventMapping(event)
    for source, target in pairs(fieldMappings) do
        copyField(event, result, source, target)
    end
    return result
end

function processSecurityFinding(event)
    local result = {}
    local field_order = {}
    if string.lower(getValue(event, "alert_type", "")) == string.lower("DLP") then
        result = getDlpEvents(event)
        field_order = DLP_FIELD_ORDERS
    elseif string.lower(getValue(event, "alert_type", "")) == string.lower("Uba") then
        result = getUbaEvents(event)
        field_order = UBA_FIELD_ORDERS
    elseif string.find(string.lower(getValue(event, "alert_type", "")), "compromised") and string.find(string.lower(getValue(event, "alert_type", "")), "credential") then
        result = getCompromisedCredentialEvents(event)
        field_order = COMPROMISED_CREDENTIAL_FIELD_ORDERS
    elseif string.lower(getValue(event, "alert_type", "")) == string.lower("Malsite") then
        result = getMalsiteEvents(event)
        field_order = MALSITE_FIELD_ORDERS
    elseif string.lower(getValue(event, "alert_type", "")) == string.lower("Malware") then
        result = getMalwareEvents(event)
        field_order = MALWARE_FIELD_ORDERS
    elseif string.lower(getValue(event, "alert_type", "")) == string.lower("Policy") then
        event["alert_type"] = "Policy"
        result = getPolicyEvents(event)
        field_order = POLICY_FIELD_ORDERS
    elseif string.lower(getValue(event, "alert_type", "")) == string.lower("quarantine") then
        result = getQuarantineEvents(event)
        field_order = QUARANTINE_FIELD_ORDERS
    elseif string.find(string.lower(getValue(event, "alert_type", "")), "security") and string.find(string.lower(getValue(event, "alert_type", "")), "assessment") then
        result = getSecurityAssessmentEvents(event)
        field_order = SECURITY_ASSESSMENT_FIELD_ORDERS
    else
        -- If nothing matches we send back the input event
        result = event
    end
    -- preserve the original event in the message field
    -- Create message field with original event
    local cleanEvent = {}
    for key, value in pairs(event) do
        if key ~= "_ob" then
            cleanEvent[key] = value
        end
    end
    result.message = encodeJson(cleanEvent, "root", field_order)

    -- add ocsf time fields
    -- convert to millis
    result["time"] = event["timestamp"]*1000 

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
