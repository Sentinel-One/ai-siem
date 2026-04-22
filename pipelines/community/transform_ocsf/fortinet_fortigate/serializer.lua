
-- FortiGate to OCSF Mapping Script
-- Maps Fortinet FortiGate log events to OCSF format

local FEATURES = { FLATTEN_EVENT_TYPE = true }

local function isArray(t)
    if type(t) ~= "table" then return false end
    local i = 0
    for _ in pairs(t) do
        i = i + 1
        if t[i] == nil then return false end
    end
    return true
end

function mappedFields(fieldMappings)
  local mapped = {}
  for _, v in ipairs(fieldMappings) do mapped[v['source']] = true end
  return mapped
end

function copyUnmappedFields(event, fieldMappings, result)
    local flattenEvent = flattenObject(event)
    local mapped = mappedFields(fieldMappings)
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
            if isArray(v) then result[keyPath] = v else flattenObject(v, keyPath, result) end
        elseif vtype == "userdata" then
            local ok, s = pcall(tostring, v)
            if ok and s ~= "userdata: (nil)" and s ~= "userdata: 0x0" then result[keyPath] = v end
        else
            result[keyPath] = v
        end
    end
    return result
end

function setNestedField(obj, path, value)
    if value == nil or path == nil or path == '' then return end
    local keys = {}
    for key in string.gmatch(path, '[^.]+') do if key and key ~= '' then table.insert(keys, key) end end
    if #keys == 0 then return end
    local current = obj
    for i = 1, #keys - 1 do
        local key = keys[i]
        if key then
            local arrayIndex = string.match(key, '(.-)%[(%d+)%]')
            if arrayIndex then
                local baseName = string.match(key, '(.-)%[')
                local index = tonumber(string.match(key, '%[(%d+)%]')) + 1
                if current[baseName] == nil then current[baseName] = {} end
                if current[baseName][index] == nil then current[baseName][index] = {} end
                current = current[baseName][index]
            else
                if current[key] == nil then current[key] = {} end
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
            if current[baseName] == nil then current[baseName] = {} end
            current[baseName][index] = value
        else
            current[finalKey] = value
        end
    end
end

function getNestedField(obj, path)
    if obj == nil or path == nil or path == '' then return nil end
    local keys = {}
    for key in string.gmatch(path, '[^.]+') do if key and key ~= '' then table.insert(keys, key) end end
    if #keys == 0 then return nil end
    local current = obj
    for _, key in ipairs(keys) do
        if current == nil or key == nil then return nil end
        local arrayIndex = string.match(key, '(.-)%[(%d+)%]')
        if arrayIndex then
            local baseName = string.match(key, '(.-)%[')
            local index = tonumber(string.match(key, '%[(%d+)%]')) + 1
            if current[baseName] == nil or current[baseName][index] == nil then return nil end
            current = current[baseName][index]
        else
            if current[key] == nil then return nil end
            current = current[key]
        end
    end
    return current
end

function copyField(source, target, sourcePath, targetPath)
    if source == nil or target == nil or sourcePath == nil or targetPath == nil then return end
    if sourcePath == '' or targetPath == '' then return end
    local value = getNestedField(source, sourcePath)
    if value ~= nil then setNestedField(target, targetPath, value) end
end

function getValue(tbl, key, default)
    local value = tbl[key]
    if value == nil then return default else return value end
end

function getSeverityId(level)
    local map = {information=1, low=2, notice=2, medium=3, warning=3, high=4, error=4, critical=5, alert=5, fatal=6}
    return map[level] or 99
end

function getDefaultMapping(event)
    local eventType = getValue(event, "type", "Other")
    local subtype = getValue(event, "subtype", "")
    local result = {}
    result.activity_id = 99
    result.metadata = {product = {name = "FortiGate", vendor_name = "Fortinet"}, version = "1.0.0"}
    result.severity_id = getSeverityId(getValue(event, "level", ""))
    result.dataSource = {category = "security", name = "FortiGate", vendor = "Fortinet"}
    result.event = {type = subtype ~= "" and subtype or eventType}
    result.activity_name = subtype ~= "" and subtype or eventType
    return result
end

function applyMappings(event, result, fieldMappings)
    for _, mapping in ipairs(fieldMappings) do
        copyField(event, result, mapping.source, mapping.target)
    end
    return copyUnmappedFields(event, fieldMappings, result)
end

function getTrafficEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 4001
    result.class_name = "Network Activity"
    result.category_uid = 4
    result.category_name = "Network Activity"
    result.type_uid = 400106
    result.type_name = "Network Activity: Traffic"
    result.activity_id = 6
    result.activity_name = "traffic"
    result.connection_info = {direction_id = 0}
    result.observables = {}
    if getValue(event, "srcip", nil) then result.observables[1] = {value = event.srcip, name = "src_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "dstip", nil) then result.observables[2] = {value = event.dstip, name = "dst_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "srcmac", nil) then result.observables[3] = {value = event.srcmac, name = "src_endpoint.mac", type = "MAC Address", type_id = 4} end
    if getValue(event, "dstmac", nil) then result.observables[4] = {value = event.dstmac, name = "dst_endpoint.mac", type = "MAC Address", type_id = 4} end
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="devid", target="device.uid"}, {source="devname", target="device.name"},
        {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"}, {source="srcip", target="src_endpoint.ip"},
        {source="dstip", target="dst_endpoint.ip"}, {source="srcport", target="src_endpoint.port"}, {source="dstport", target="dst_endpoint.port"},
        {source="srcmac", target="src_endpoint.mac"}, {source="dstmac", target="dst_endpoint.mac"}, {source="srcintf", target="src_endpoint.interface_name"},
        {source="dstintf", target="dst_endpoint.interface_name"}, {source="srccountry", target="src_endpoint.location.country"},
        {source="dstcountry", target="dst_endpoint.location.country"}, {source="proto", target="connection_info.protocol_num"},
        {source="service", target="src_endpoint.svc_name"}, {source="sessionid", target="actor.session.uid"},
        {source="policyid", target="actor.authorizations[0].policy.uid"}, {source="policyname", target="actor.authorizations[0].policy.name"},
        {source="app", target="app_name"}, {source="sentbyte", target="traffic.bytes_out"}, {source="rcvdbyte", target="traffic.bytes_in"},
        {source="sentpkt", target="traffic.packets_out"}, {source="rcvdpkt", target="traffic.packets_in"}, {source="vd", target="device.domain"},
        {source="tz", target="timezone_offset"}, {source="osname", target="device.os.name"}, {source="devtype", target="device.type"},
        {source="countapp", target="count"}, {source="logver", target="metadata.log_version"}, {source="identifier", target="metadata.event_code"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getVPNEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 4001
    result.class_name = "Network Activity"
    result.category_uid = 4
    result.category_name = "Network Activity"
    result.type_uid = 400199
    result.type_name = "Network Activity: Other"
    result.activity_id = 99
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"},
        {source="status", target="status_detail"}, {source="tz", target="timezone_offset"}, {source="logver", target="metadata.log_version"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getSecurityFindingEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 2001
    result.class_name = "Security Finding"
    result.category_uid = 2
    result.category_name = "Findings"
    result.type_uid = 200199
    result.type_name = "Security Finding: Other"
    result.activity_id = 99
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"},
        {source="logdesc", target="finding.title"}, {source="attack", target="finding.title"}, {source="ref", target="finding.src_url"},
        {source="sessionid", target="process.session.uid"}, {source="auditid", target="finding.uid"}, {source="criticalcount", target="count"},
        {source="audittime", target="finding.created_time"}, {source="tz", target="timezone_offset"}, {source="logver", target="metadata.log_version"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getVirusEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 2001
    result.class_name = "Security Finding"
    result.category_uid = 2
    result.category_name = "Findings"
    result.type_uid = 200199
    result.type_name = "Security Finding: Other"
    result.activity_id = 99
    result.activity_name = "virus"
    result.observables = {}
    if getValue(event, "srcip", nil) then result.observables[1] = {value = event.srcip, name = "src_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "dstip", nil) then result.observables[2] = {value = event.dstip, name = "dst_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "filename", nil) then result.observables[3] = {value = event.filename, name = "process.file.name", type = "File Name", type_id = 7} end
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"},
        {source="sessionid", target="process.session.uid"}, {source="action", target="status_detail"}, {source="attack", target="finding.desc"},
        {source="msg", target="finding.title"}, {source="crscore", target="risk_score"}, {source="virusid", target="malware[0].uid"},
        {source="virus", target="malware[0].name"}, {source="analyticscksum", target="process.file.hashes[0].value"},
        {source="filename", target="process.file.name"}, {source="url", target="finding.src_url"}, {source="dtype", target="malware[0].classifications"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getUTMEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 4001
    result.class_name = "Network Activity"
    result.category_uid = 4
    result.category_name = "Network Activity"
    result.type_uid = 400199
    result.type_name = "Network Activity: Other"
    result.activity_id = 99
    local action = string.lower(getValue(event, "action", ""))
    if action == "permit" or action == "accept" then result.activity_name = "Open"; result.activity_id = 1; result.type_uid = 400101; result.type_name = "Network Activity: Open"
    elseif action == "dropped" or action == "close" or action == "shutdown" then result.activity_name = "Close"; result.activity_id = 2; result.type_uid = 400102; result.type_name = "Network Activity: Close"
    elseif action == "clear_session" then result.activity_name = "Reset"; result.activity_id = 3; result.type_uid = 400103; result.type_name = "Network Activity: Reset"
    elseif action == "block" or action == "blocked" then result.activity_name = "Refuse"; result.activity_id = 5; result.type_uid = 400105; result.type_name = "Network Activity: Refuse"
    end
    result.observables = {}
    if getValue(event, "srcip", nil) then result.observables[1] = {value = event.srcip, name = "src_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "dstip", nil) then result.observables[2] = {value = event.dstip, name = "dst_endpoint.ip", type = "IP Address", type_id = 2} end
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="devid", target="device.uid"}, {source="devname", target="device.name"},
        {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"}, {source="tz", target="timezone_offset"},
        {source="srcip", target="src_endpoint.ip"}, {source="dstip", target="dst_endpoint.ip"}, {source="srcport", target="src_endpoint.port"},
        {source="dstport", target="dst_endpoint.port"}, {source="srcintf", target="src_endpoint.interface_name"}, {source="dstintf", target="dst_endpoint.interface_name"},
        {source="proto", target="connection_info.protocol_num"}, {source="service", target="src_endpoint.svc_name"}, {source="direction", target="connection_info.direction"},
        {source="sessionid", target="actor.session.uid"}, {source="appcat", target="actor.invoked_by"}, {source="app", target="app_name"},
        {source="hostname", target="device.hostname"}, {source="apprisk", target="risk_level"}, {source="scertcname", target="tls.certificate.subject"},
        {source="scertissuer", target="tls.certificate.issuer"}, {source="vd", target="device.domain"}, {source="filename", target="actor.process.file.name"},
        {source="filesize", target="actor.process.file.size"}, {source="filetype", target="actor.process.file.type"},
        {source="policyid", target="actor.authorizations[0].policy.uid"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getDLPEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 4002
    result.class_name = "HTTP Activity"
    result.category_uid = 4
    result.category_name = "Network Activity"
    result.type_uid = 400299
    result.type_name = "HTTP Activity: Other"
    result.activity_id = 99
    result.connection_info = {direction_id = 99}
    result.disposition_id = 99
    result.observables = {}
    if getValue(event, "srcip", nil) then result.observables[1] = {value = event.srcip, name = "src_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "dstip", nil) then result.observables[2] = {value = event.dstip, name = "dst_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "url", nil) then result.observables[3] = {value = event.url, name = "http_request.url.url_string", type = "URL String", type_id = 6} end
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="devid", target="device.uid"}, {source="devname", target="device.name"},
        {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"}, {source="policyid", target="actor.authorizations[0].policy.uid"},
        {source="sessionid", target="actor.session.uid"}, {source="user", target="actor.user.name"}, {source="srcip", target="src_endpoint.ip"},
        {source="dstip", target="dst_endpoint.ip"}, {source="srcport", target="src_endpoint.port"}, {source="dstport", target="dst_endpoint.port"},
        {source="srcintf", target="src_endpoint.interface_name"}, {source="dstintf", target="dst_endpoint.interface_name"},
        {source="proto", target="connection_info.protocol_num"}, {source="service", target="src_endpoint.svc_name"}, {source="direction", target="connection_info.direction"},
        {source="hostname", target="device.hostname"}, {source="url", target="http_request.url.url_string"}, {source="agent", target="http_request.user_agent"},
        {source="tz", target="timezone_offset"}, {source="srccountry", target="src_endpoint.location.country"}, {source="dstcountry", target="dst_endpoint.location.country"},
        {source="forwardedfor", target="http_request.x_forwarded_for"}, {source="httpmethod", target="http_request.http_method"},
        {source="referralurl", target="http_request.referrer"}, {source="vd", target="device.domain"}, {source="catdesc", target="http_request.url.categories"},
        {source="rcvdbyte", target="traffic.bytes_in"}, {source="sentbyte", target="traffic.bytes_out"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getDNSEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 4003
    result.class_name = "DNS Activity"
    result.category_uid = 4
    result.category_name = "Network Activity"
    result.connection_info = {direction_id = 99}
    local eventtype = string.lower(getValue(event, "eventtype", ""))
    if eventtype == "dns-query" then result.activity_name = "Query"; result.activity_id = 1; result.type_uid = 400301; result.type_name = "DNS Activity: Query"
    elseif eventtype == "dns-response" then result.activity_name = "Response"; result.activity_id = 2; result.type_uid = 400302; result.type_name = "DNS Activity: Response"
    else result.activity_id = 99; result.type_uid = 400399; result.type_name = "DNS Activity: Other"
    end
    result.observables = {}
    if getValue(event, "srcip", nil) then result.observables[1] = {value = event.srcip, name = "src_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "dstip", nil) then result.observables[2] = {value = event.dstip, name = "dst_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "qname", nil) then result.observables[3] = {value = event.qname, name = "query.hostname", type = "Hostname", type_id = 1} end
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="devid", target="device.uid"}, {source="devname", target="device.name"},
        {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"}, {source="policyid", target="actor.authorizations[0].policy.uid"},
        {source="sessionid", target="actor.session.uid"}, {source="user", target="actor.user.name"}, {source="srcip", target="src_endpoint.ip"},
        {source="dstip", target="dst_endpoint.ip"}, {source="srcport", target="src_endpoint.port"}, {source="dstport", target="dst_endpoint.port"},
        {source="srcintf", target="src_endpoint.interface_name"}, {source="dstintf", target="dst_endpoint.interface_name"},
        {source="proto", target="connection_info.protocol_num"}, {source="service", target="src_endpoint.svc_name"}, {source="direction", target="connection_info.direction"},
        {source="hostname", target="device.hostname"}, {source="tz", target="timezone_offset"}, {source="srccountry", target="src_endpoint.location.country"},
        {source="dstcountry", target="dst_endpoint.location.country"}, {source="vd", target="device.domain"}, {source="srcmac", target="src_endpoint.mac"},
        {source="xid", target="query.packet_uid"}, {source="qname", target="query.hostname"}, {source="qtype", target="query.type"},
        {source="qtypeval", target="query.opcode"}, {source="qclass", target="query.class"}, {source="ipaddr", target="answer.rdata"}, {source="msg", target="answer.type"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getSSHEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 4007
    result.class_name = "SSH Activity"
    result.category_uid = 4
    result.category_name = "Network Activity"
    result.type_uid = 400799
    result.type_name = "SSH Activity: Open"
    result.connection_info = {direction_id = 99}
    local action = string.lower(getValue(event, "action", ""))
    if action == "permit" or action == "accept" then result.activity_name = "Open"; result.activity_id = 1; result.type_uid = 400701; result.type_name = "SSH Activity: Open"
    elseif action == "dropped" or action == "close" or action == "shutdown" then result.activity_name = "Close"; result.activity_id = 2; result.type_uid = 400702; result.type_name = "SSH Activity: Close"
    elseif action == "clear_session" then result.activity_name = "Reset"; result.activity_id = 3; result.type_uid = 400703; result.type_name = "SSH Activity: Reset"
    elseif action == "block" or action == "blocked" then result.activity_name = "Refuse"; result.activity_id = 5; result.type_uid = 400705; result.type_name = "SSH Activity: Refuse"
    else result.activity_id = 99
    end
    result.observables = {}
    if getValue(event, "srcip", nil) then result.observables[1] = {value = event.srcip, name = "src_endpoint.ip", type = "IP Address", type_id = 2} end
    if getValue(event, "dstip", nil) then result.observables[2] = {value = event.dstip, name = "dst_endpoint.ip", type = "IP Address", type_id = 2} end
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="devid", target="device.uid"}, {source="devname", target="device.name"},
        {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"}, {source="policyid", target="actor.authorizations[0].policy.uid"},
        {source="sessionid", target="actor.session.uid"}, {source="user", target="actor.user.name"}, {source="srcip", target="src_endpoint.ip"},
        {source="dstip", target="dst_endpoint.ip"}, {source="srcport", target="src_endpoint.port"}, {source="dstport", target="dst_endpoint.port"},
        {source="srcintf", target="src_endpoint.interface_name"}, {source="dstintf", target="dst_endpoint.interface_name"},
        {source="proto", target="connection_info.protocol_num"}, {source="service", target="src_endpoint.svc_name"}, {source="direction", target="connection_info.direction"},
        {source="hostname", target="device.hostname"}, {source="tz", target="timezone_offset"}, {source="srccountry", target="src_endpoint.location.country"},
        {source="dstcountry", target="dst_endpoint.location.country"}, {source="vd", target="device.domain"}, {source="srcmac", target="src_endpoint.mac"},
        {source="login", target="actor.user.name"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getAPIEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 6003
    result.class_name = "API Activity"
    result.category_uid = 6
    result.category_name = "Application Activity"
    result.type_uid = 600399
    result.type_name = "API Activity: Other"
    result.activity_id = 99
    result.activity_name = "rest-api"
    result.observables = {}
    if getValue(event, "url", nil) then result.observables[1] = {value = event.url, name = "http_request.url.url_string", type = "URL String", type_id = 6} end
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="eventtime", target="metadata.original_time"}, {source="tz", target="timezone_offset"},
        {source="logid", target="metadata.uid"}, {source="user", target="actor.user.name"}, {source="method", target="http_request.http_method"},
        {source="path", target="http_request.url.path"}, {source="status", target="http_response.code"}, {source="url", target="http_request.url.url_string"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getDeviceConfigEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 5002
    result.class_name = "Device Config State"
    result.category_uid = 5
    result.category_name = "Discovery"
    result.type_uid = 500201
    result.type_name = "Device Config State: Other"
    result.activity_id = 1
    result.activity_name = "Log"
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="logid", target="metadata.uid"}, {source="vd", target="device.domain"},
        {source="eventtime", target="metadata.original_time"}, {source="sn", target="device.hw_info.serial_number"}, {source="ip", target="device.ip"},
        {source="imei", target="device.imei"}, {source="user", target="actor.user.name"}, {source="name", target="device.name"}, {source="tz", target="timezone_offset"},
    }
    return applyMappings(event, result, fieldMappings)
end

function getGenericEvents(event)
    local result = getDefaultMapping(event)
    result.class_uid = 2001
    result.class_name = "Security Finding"
    result.category_uid = 2
    result.category_name = "Findings"
    result.type_uid = 200199
    result.type_name = "Security Finding: Other"
    result.activity_id = 99
    local fieldMappings = {
        {source="subtype", target="metadata.log_name"}, {source="eventtime", target="metadata.original_time"}, {source="logid", target="metadata.uid"},
        {source="status", target="status_detail"}, {source="tz", target="timezone_offset"}, {source="logver", target="metadata.log_version"},
    }
    return applyMappings(event, result, fieldMappings)
end

function processFortiGateEvent(event)
    local result = {}
    local eventType = getValue(event, "type", "")
    local subtype = getValue(event, "subtype", "")
    
    if eventType == "traffic" then
        result = getTrafficEvents(event)
    elseif eventType == "event" and subtype == "vpn" then
        result = getVPNEvents(event)
    elseif subtype == "security-rating" or subtype == "ips" then
        result = getSecurityFindingEvents(event)
    elseif subtype == "virus" then
        result = getVirusEvents(event)
    elseif subtype == "app-ctrl" or subtype == "file-filter" or subtype == "ssl" or subtype == "voip" or subtype == "icap" then
        result = getUTMEvents(event)
    elseif subtype == "dlp" or subtype == "waf" or subtype == "webfilter" then
        result = getDLPEvents(event)
    elseif subtype == "dns" then
        result = getDNSEvents(event)
    elseif subtype == "ssh" then
        result = getSSHEvents(event)
    elseif subtype == "rest-api" then
        result = getAPIEvents(event)
    elseif subtype == "fortiextender" or subtype == "switch-controller" or subtype == "router" then
        result = getDeviceConfigEvents(event)
    elseif subtype == "anomaly" then
        result = getSecurityFindingEvents(event)
    elseif subtype == "gtp-all" then
        result = getUTMEvents(event)
    elseif subtype == "user" then
        result = getGenericEvents(event)
    elseif eventType == "event" then
        result = getGenericEvents(event)
    else
        result = getGenericEvents(event)
    end

    -- Handle time field
    local eventtime = getValue(event, "eventtime", nil)
    if eventtime then
        local ts = tonumber(eventtime)
        if ts then
            if ts > 10000000000000 then
                result["time"] = math.floor(ts / 1000)
            elseif ts > 10000000000 then
                result["time"] = ts
            else
                result["time"] = ts * 1000
            end
        end
    end

    if FEATURES.FLATTEN_EVENT_TYPE then
        if result and result.event then
            result['event.type'] = result.event.type
        end
    end
    return result
end

function processEvent(event)
    if event == nil then return {} end
    return processFortiGateEvent(event)
end
