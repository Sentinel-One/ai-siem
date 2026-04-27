-- palo_alto.lua beta
-- Maps pre-parsed palo_alto.* fields to OCSF schema
-- CSV parsing happens upstream; this script only does field mapping

------------------------------------------------------------------------
-- Helper: set nested field by dot-path
------------------------------------------------------------------------
local function set_field(obj, path, value)
    if not obj or not path or path == "" or value == nil or value == "" then
        return
    end
    local current = obj
    local segments = {}
    for seg in path:gmatch("[^%.]+") do
        local name, idx = seg:match("^(.-)%[(%d+)%]$")
        if name and name ~= "" then
            segments[#segments + 1] = name
            segments[#segments + 1] = tonumber(idx)
        elseif name then
            segments[#segments + 1] = tonumber(idx)
        else
            segments[#segments + 1] = seg
        end
    end
    for i = 1, #segments - 1 do
        local s = segments[i]
        if current[s] == nil then current[s] = {} end
        current = current[s]
    end
    current[segments[#segments]] = value
end

local function get_field(obj, path)
    if not obj or not path or path == "" then return nil end
    local current = obj
    for seg in path:gmatch("[^%.]+") do
        if type(current) ~= "table" then return nil end
        current = current[seg]
        if current == nil then return nil end
    end
    return current
end

local function to_int(val)
    if val == nil or val == "" then return nil end
    return tonumber(val)
end

------------------------------------------------------------------------
-- Mapping tables: palo_alto field -> OCSF field
------------------------------------------------------------------------

local THREAT_MAP = {
    -- Core fields
    {"receive_time", "time"},
    {"serial_number", "device.hw_info.serial_number"},
    {"log_type", "metadata.log_name"},
    {"log_subtype", "unmapped.sub_type"},
    {"generated_time", "metadata.original_time"},
    {"src_ip", "src_endpoint.ip"},
    {"dest_ip", "dst_endpoint.ip"},
    {"src_translated_ip", "src_endpoint.intermediate_ips[0]"},
    {"dest_translated_ip", "dst_endpoint.intermediate_ips[0]"},
    {"rule", "unmapped.rule_matched"},
    {"src_user", "actor.user.name"},
    {"dest_user", "unmapped.dst_user"},
    {"app", "app_name"},
    {"vsys", "unmapped.vsys"},
    {"src_zone", "unmapped.from_zone"},
    {"dest_zone", "unmapped.to_zone"},
    {"src_interface", "unmapped.inbound_if"},
    {"dest_interface", "unmapped.outbound_if"},
    {"log_forwarding_profile", "unmapped.log_action"},
    {"session_id", "actor.session.uid"},
    {"repeat_count", "unmapped.repeat_count"},
    {"src_port", "src_endpoint.port"},
    {"dest_port", "dst_endpoint.port"},
    {"src_translated_port", "unmapped.nat_src_port"},
    {"dest_translated_port", "unmapped.nat_dst_port"},
    {"session_flags", "unmapped.flags"},
    {"transport", "connection_info.protocol_name"},
    {"action", "unmapped.action"},
    {"misc", "unmapped.file"},
    {"threat", "unmapped.threat_id"},
    {"raw_category", "unmapped.url_category"},
    {"severity", "unmapped.severity"},
    {"direction", "unmapped.direction_of_attack"},
    {"sequence_number", "metadata.uid"},
    {"action_flags", "unmapped.action_flags"},
    {"src_location", "src_endpoint.location.region"},
    {"dest_location", "dst_endpoint.location.region"},
    {"content_type", "unmapped.contenttype"},
    {"pcap_id", "unmapped.pcap_id"},
    {"file_hash", "unmapped.file_digest"},
    {"cloud_address", "cloud.account_uid"},
    {"url_index", "unmapped.url_idx"},
    {"user_agent", "unmapped.user_agent"},
    {"file_type", "unmapped.file_type"},
    {"xff", "src_endpoint.intermediate_ips[1]"},
    {"referrer", "unmapped.referrer"},
    {"sender", "unmapped.sender_of_email"},
    {"subject", "unmapped.subject_of_email"},
    {"recipient", "unmapped.receipent_of_email"},
    {"report_id", "unmapped.report_id"},
    {"devicegroup_level1", "unmapped.dg_hier_level_1"},
    {"devicegroup_level2", "unmapped.dg_hier_level_2"},
    {"devicegroup_level3", "unmapped.dg_hier_level_3"},
    {"devicegroup_level4", "unmapped.dg_hier_level_4"},
    {"vsys_name", "unmapped.vsys_name"},
    {"dvc_name", "device.hostname"},
    {"http_method", "unmapped.http_method"},
    {"tunnel_id", "unmapped.tunnel_id"},
    {"tunnel_monitor_tag", "unmapped.tunnel_monitor_tag"},
    {"tunnel_session_id", "unmapped.tunnel_session_id"},
    {"tunnel_start_time", "unmapped.tunnel_start_time"},
    {"tunnel_type", "unmapped.tunnel_type"},
    {"threat_category", "unmapped.threat_category"},
    {"content_version", "unmapped.content_version"},
}

local TRAFFIC_MAP = {
    {"receive_time", "time"},
    {"serial_number", "device.hw_info.serial_number"},
    {"log_type", "metadata.log_name"},
    {"log_subtype", "unmapped.sub_type"},
    {"generated_time", "metadata.original_time"},
    {"src_ip", "src_endpoint.ip"},
    {"dest_ip", "dst_endpoint.ip"},
    {"src_translated_ip", "src_endpoint.intermediate_ips[0]"},
    {"dest_translated_ip", "dst_endpoint.intermediate_ips[0]"},
    {"rule", "unmapped.rule_matched"},
    {"src_user", "actor.user.name"},
    {"dest_user", "unmapped.dst_user"},
    {"app", "app_name"},
    {"vsys", "unmapped.vsys"},
    {"src_zone", "unmapped.from_zone"},
    {"dest_zone", "unmapped.to_zone"},
    {"src_interface", "unmapped.inbound_if"},
    {"dest_interface", "unmapped.outbound_if"},
    {"log_forwarding_profile", "unmapped.log_action"},
    {"session_id", "actor.session.uid"},
    {"repeat_count", "unmapped.repeat_count"},
    {"src_port", "src_endpoint.port"},
    {"dest_port", "dst_endpoint.port"},
    {"src_translated_port", "unmapped.nat_src_port"},
    {"dest_translated_port", "unmapped.nat_dst_port"},
    {"session_flags", "unmapped.flags"},
    {"transport", "connection_info.protocol_name"},
    {"action", "unmapped.action"},
    {"dvc_name", "device.hostname"},
    {"src_location", "src_endpoint.location.region"},
    {"dest_location", "dst_endpoint.location.region"},
}

local THREAT_CONSTANTS = {
    {"activity_name", "THREAT"},
    {"class_uid", 4001},
    {"activity_id", 99},
    {"category_uid", 4},
    {"type_uid", 400199},
    {"type_name", "Network Activity: Other"},
    {"class_name", "Network Activity"},
    {"category_name", "Network Activity"},
    {"metadata.version", "1.0.0-rc.3"},
    {"event.type", "THREAT"},
    {"status_id", 99},
    {"status", "Other"},
    {"connection_info.direction_id", 99},
    {"device.type_id", 99},
    {"dataSource.category", "security"},
    {"dataSource.name", "Palo Alto Networks Firewall"},
    {"dataSource.vendor", "Palo Alto Networks"},
    {"metadata.product.name", "Palo Alto Networks Firewall"},
    {"metadata.product.vendor_name", "Palo Alto Networks"},
}

local TRAFFIC_CONSTANTS = {
    {"class_uid", 4001},
    {"category_uid", 4},
    {"severity_id", 0},
    {"class_name", "Network Activity"},
    {"category_name", "Network Activity"},
    {"metadata.version", "1.0.0-rc.3"},
    {"metadata.log_name", "TRAFFIC"},
    {"status_id", 99},
    {"status", "Other"},
    {"connection_info.direction_id", 99},
    {"device.type_id", 99},
    {"dataSource.category", "security"},
    {"dataSource.name", "Palo Alto Networks Firewall"},
    {"dataSource.vendor", "Palo Alto Networks"},
    {"metadata.product.name", "Palo Alto Networks Firewall"},
    {"metadata.product.vendor_name", "Palo Alto Networks"},
}

local THREAT_COND_CONSTANTS = {
    {"severity_id", 1, "unmapped.severity", "informational"},
    {"severity_id", 2, "unmapped.severity", "low"},
    {"severity_id", 3, "unmapped.severity", "medium"},
    {"severity_id", 4, "unmapped.severity", "high"},
    {"severity_id", 5, "unmapped.severity", "critical"},
    {"status_id", 1, "unmapped.action", "allow"},
    {"status_id", 2, "unmapped.action", "deny"},
    {"status", "Success", "unmapped.action", "allow"},
    {"status", "Failure", "unmapped.action", "deny"},
}

local TRAFFIC_COND_CONSTANTS = {
    {"activity_id", 1, "unmapped.sub_type", "start"},
    {"activity_id", 2, "unmapped.sub_type", "end"},
    {"activity_id", 4, "unmapped.sub_type", "drop"},
    {"activity_id", 5, "unmapped.sub_type", "deny"},
    {"activity_name", "Open", "unmapped.sub_type", "start"},
    {"activity_name", "Close", "unmapped.sub_type", "end"},
    {"activity_name", "Fail", "unmapped.sub_type", "drop"},
    {"activity_name", "Refuse", "unmapped.sub_type", "deny"},
    {"status_id", 1, "unmapped.action", "allow"},
    {"status_id", 2, "unmapped.action", "deny"},
    {"status", "Success", "unmapped.action", "allow"},
    {"status", "Failure", "unmapped.action", "deny"},
}

local COPIES = {
    {"src_endpoint.ip", "observables[0].value"},
    {"dst_endpoint.ip", "observables[1].value"},
    {"device.hostname", "observables[2].value"},
}

local OBSERVABLES_CONSTANTS = {
    {"observables[0].type_id", 2},
    {"observables[0].type", "IP Address"},
    {"observables[0].name", "src_endpoint.ip"},
    {"observables[1].type_id", 2},
    {"observables[1].type", "IP Address"},
    {"observables[1].name", "dst_endpoint.ip"},
    {"observables[2].type_id", 1},
    {"observables[2].type", "Hostname"},
    {"observables[2].name", "device.hostname"},
}

------------------------------------------------------------------------
-- Apply mapping from palo_alto.* to event
------------------------------------------------------------------------
local function apply_map(pa, event, map)
    for _, m in ipairs(map) do
        local src, dst = m[1], m[2]
        local val = pa[src]
        if val ~= nil and val ~= "" then
            set_field(event, dst, val)
        end
    end
end

local function apply_constants(event, constants)
    for _, c in ipairs(constants) do
        set_field(event, c[1], c[2])
    end
end

local function apply_cond_constants(event, cond_constants)
    for _, c in ipairs(cond_constants) do
        local actual = get_field(event, c[3])
        if actual == c[4] then
            set_field(event, c[1], c[2])
        end
    end
end

local function apply_copies(event, copies)
    for _, c in ipairs(copies) do
        local val = get_field(event, c[1])
        if val then
            set_field(event, c[2], val)
        end
    end
end

local function cast_int_fields(event, fields)
    for _, path in ipairs(fields) do
        local val = get_field(event, path)
        if val ~= nil and val ~= "" then
            set_field(event, path, to_int(val))
        end
    end
end

------------------------------------------------------------------------
-- Main processEvent
------------------------------------------------------------------------
function processEvent(event)
    local pa = event.palo_alto
    if not pa then
        return event
    end

    local log_type = pa.log_type
    if not log_type then
        return event
    end

    log_type = log_type:upper()

    if log_type == "THREAT" then
        apply_map(pa, event, THREAT_MAP)
        apply_constants(event, THREAT_CONSTANTS)
        apply_constants(event, OBSERVABLES_CONSTANTS)
        apply_cond_constants(event, THREAT_COND_CONSTANTS)
        apply_copies(event, COPIES)
        cast_int_fields(event, {"src_endpoint.port", "dst_endpoint.port"})

    elseif log_type == "TRAFFIC" then
        apply_map(pa, event, TRAFFIC_MAP)
        apply_constants(event, TRAFFIC_CONSTANTS)
        apply_constants(event, OBSERVABLES_CONSTANTS)
        apply_cond_constants(event, TRAFFIC_COND_CONSTANTS)
        apply_copies(event, COPIES)
        cast_int_fields(event, {"src_endpoint.port", "dst_endpoint.port"})

    else
        set_field(event, "metadata.log_name", log_type)
        set_field(event, "unmapped.log_type", log_type)
    end

    return event
end
