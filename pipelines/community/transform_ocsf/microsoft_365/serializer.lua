-- Microsoft 365 (O365) OCSF 1.0.0 parser (ported from Python Parsers/microsoft)

-- Helpers

local function convertUtcToMilliseconds(timestamp)
    if not timestamp or timestamp == "" then
        return nil
    end
    local year, month, day, hour, min, sec, frac =
        string.match(timestamp, "(%d+)%-(%d+)%-(%d+)T(%d+):(%d+):(%d+)%.?(%d*)")
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

local function split(str, delimiter)
  local result = {}
  local s = tostring(str or "")
  local escaped = delimiter:gsub("[%.%+%*%?%^%$%(%)%[%]%%]", "%%%1")
  local pattern = "([^" .. escaped .. "]+)"
  for token in s:gmatch(pattern) do table.insert(result, token) end
  if #result == 0 and #s > 0 then table.insert(result, s) end
  return result
end

local function getByPath(obj, keys)
  local cur = obj
  for _, k in ipairs(keys) do
    if cur ~= nil and type(cur) == "table" then cur = cur[k] else return nil end
  end
  return cur
end

local function setByDottedPath(t, dotted, value)
  local keys = split(dotted, ".")
  local cur = t
  for i=1,#keys-1 do
    local k = keys[i]
    if type(cur[k]) ~= "table" then cur[k] = {} end
    cur = cur[k]
  end
  cur[keys[#keys]] = value
end

local function flatten_table(tbl, prefix, out)
  out = out or {}
  prefix = prefix or ""

  for k, v in pairs(tbl) do
    local key

    -- ARRAY HANDLING (0-based index)
    if type(k) == "number" then
      key = string.format("%s[%d]", prefix, k - 1)

    -- NORMAL OBJECT KEY
    else
      if prefix ~= "" then
        key = prefix .. "." .. k
      else
        key = k
      end
    end

    -- recurse
    if type(v) == "table" then
      flatten_table(v, key, out)
    else
      out[key] = v
    end
  end

  return out
end

local function apply_mapping(event, mapping)
  local out = {}

  -- normal mapping (existing behaviour)
  for src, dst in pairs(mapping) do
    local val = getByPath(event, split(src, "."))
    if val ~= nil then out[dst] = val end
  end

  -- NEW: auto-capture unmapped fields
  local flat_event = flatten_table(event)
  for src, val in pairs(flat_event) do
    if mapping[src] == nil then
      out["unmapped." .. src] = val
    end
  end

  return out
end

local function build_nested(flat)
  local nested = {}
  for k, v in pairs(flat) do setByDottedPath(nested, k, v) end
  return nested
end

local function cloneTable(src)
  local dst = {}
  for k,v in pairs(src or {}) do dst[k] = v end
  return dst
end

-- Simple email detection
local function is_email(s)
  if type(s) ~= "string" then return false end
  return s:find("@") ~= nil
end

-- Common + synthetic field helpers
local function get_status_default_ocsf_mapping(status)
  if status == "Success" then return 1
  elseif status == "Failure" then return 2
  else return 99 end
end

local function get_device_os_type(platform)
  local mapping = { Win = 100, Android = 201, ["iOS"] = 301 }
  if type(platform) ~= "string" then return 99 end
  return mapping[platform] or 99
end

local function get_actor_type_details(user_type)
  local map = {
    [0] = { type = "User", id = 1 },
    [2] = { type = "Admin", id = 2 },
    [4] = { type = "System", id = 4 },
  }
  local rec = map[user_type]
  if rec then return rec.type, rec.id else return "Other", 99 end
end

local function get_state_id(event_type)
  if type(event_type) == "string" and event_type:lower() == "dlprulematch" then return 1 else return 0 end
end

local function extract_policy_details(log)
  local analytic_id, analytic_name = nil, nil
  local pd = log["PolicyDetails"]
  if type(pd) == "table" and #pd > 0 and type(pd[1]) == "table" then
    if pd[1]["PolicyId"] then analytic_id = pd[1]["PolicyId"] end
    if pd[1]["PolicyName"] then analytic_name = pd[1]["PolicyName"] end
  end
  return analytic_id, analytic_name
end

local function get_device_property(log)
  local device_props = log["DeviceProperties"]
  if type(device_props) == "table" then
    for _, dp in ipairs(device_props) do
      if type(dp) == "table" then
        if dp["Name"] == "OS" then
          log["device_os_type"] = dp["Value"]
          log["device_os_type_id"] = (dp["Value"] == "Linux" and 200) or (dp["Value"] == "Windows" and 100) or 99
        elseif dp["Name"] == "SessionId" then
          log["actor_session_uid"] = dp["Value"]
        elseif dp["Name"] == "IsCompliantAndManaged" then
          log["device_is_compliant"] = dp["Value"]
          log["device_is_managed"] = dp["Value"]
        end
      end
    end
  end
  return log
end

local function get_resource_data(log)
  local out = {}
  local mprops = log["ModifiedProperties"]
  if type(mprops) == "table" then
    for _, obj in ipairs(mprops) do
      if type(obj) == "table" and obj["Name"] then
        out[obj["Name"]] = { NewValue = obj["NewValue"], OldValue = obj["OldValue"] }
      end
    end
  end
  return out
end

local function get_mgmt_observables(log)
  local obs = {}
  local sp = log["SharePointMetaData"]
  if type(sp) == "table" then
    if sp["FileName"] then table.insert(obs, { type_id = 7, type = "FileName", name = "process.file.name", value = sp["FileName"] }) end
    if sp["From"] then table.insert(obs, { type_id = 4, type = "User Name", name = "unmapped.sharePointMetaData.from", value = sp["From"] }) end
  end
  return obs
end

-- Synthetic for Graph API
local function set_graph_synthetic_fields(log, site_id)
  log["category_uid"] = 2
  log["class_uid"] = 2001
  log["class_name"] = "Security Finding"
  log["type_uid"] = 200199
  log["type_name"] = "Security Finding: Other"
  log["OCSF_version"] = "1.0.0"
  log["category_name"] = "Findings"
  log["activity_id"] = 99
  log["dataSource"] = { name = "Microsoft O365", category = "security", vendor = "Microsoft" }
  log["event"] = { type = log["status"] }
  log["cloud"] = { provider = "Microsoft Azure" }
  if site_id then log["site"] = { id = site_id } end
  -- observables
  local observables = {}
  if log["azureTenantId"] then table.insert(observables, { type_id = 10, type = "Resource UID", name = "unmapped.azureTenantId", value = log["azureTenantId"] }) end
  log["observables"] = observables
  if type(log["sourceMaterials"]) == "table" then log["sourceMaterials"] = log["sourceMaterials"][1] end
  return log
end

-- Severity for Mgmt
local function get_severity_id(event_type)
  local m = {
    dlprulematch = 1, dlpruleundo = 0, ["update user"] = 0, userloggedin = 0, ["add group"] = 0,
    ["add member to group"] = 0, ["delete group"] = 0, ["update group"] = 0, ["remove member from group"] = 0,
    ["add user"] = 0, ["reset user password"] = 0, ["delete user"] = 0, addedtogroup = 0, signinevent = 0,
  }
  return m[(event_type or ""):lower()] or 0
end

local function get_mgmt_log_mapping_fields(event_type)
  local map = {
    ["dlprulematch"] = {
      activity = { name = "Create", id = 99 }, class = { name = "Security Finding", id = 2001 }, category = { name = "Findings", id = 2 },
    },
    ["dlpruleundo"] = {
      activity = { name = "DLPRuleUndo", id = 99 }, class = { name = "Security Finding", id = 2001 }, category = { name = "Findings", id = 2 },
    },
    ["update user"] = {
      activity = { name = "Update user", id = 99 }, class = { name = "Account Change", id = 3001 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["userloggedin"] = {
      activity = { name = "Logon", id = 1 }, class = { name = "Authentication", id = 3002 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["add group"] = {
      activity = { name = "Add group", id = 99 }, class = { name = "Group Management", id = 3006 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["add member to group"] = {
      activity = { name = "Add User", id = 3 }, class = { name = "Group Management", id = 3006 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["delete group"] = {
      activity = { name = "Delete group", id = 99 }, class = { name = "Group Management", id = 3006 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["update group"] = {
      activity = { name = "Update group.", id = 99 }, class = { name = "Group Management", id = 3006 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["remove member from group"] = {
      activity = { name = "Remove User", id = 4 }, class = { name = "Group Management", id = 3006 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["add user"] = {
      activity = { name = "Create", id = 1 }, class = { name = "Account Change", id = 3001 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["reset user password"] = {
      activity = { name = "Password Reset", id = 4 }, class = { name = "Account Change", id = 3001 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["delete user"] = {
      activity = { name = "Delete", id = 6 }, class = { name = "Account Change", id = 3001 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["addedtogroup"] = {
      activity = { name = "Add User", id = 3 }, class = { name = "Group Management", id = 3006 }, category = { name = "Identity & Access Management", id = 3 },
    },
    ["signinevent"] = {
      activity = { name = "Logon", id = 1 }, class = { name = "Authentication", id = 3002 }, category = { name = "Identity & Access Management", id = 3 },
    },
  }
  local m = map[(event_type or ""):lower()] or { activity = { name = "Other", id = 99 }, class = { name = "Base Event", id = 0}, category = { name = "Uncategorized", id = 0 } }
  local class_name, class_id = m.class.name, m.class.id
  local activity_name, activity_id = m.activity.name, m.activity.id
  local type_name, type_id = string.format("%s: %s", class_name, activity_name), (class_id * 100) + activity_id
  local category_name, category_id = m.category.name, m.category.id
  return activity_name, activity_id, class_name, class_id, type_name, type_id, category_name, category_id
end

-- Mapping tables from python
local function get_default_graph_ocsf_mapping()
  return {
    ["activityGroupName"] = "resources.group_name",
    ["category"] = "finding.types",
    ["closedDateTime"] = "end_time_dt",
    ["confidence"] = "confidence",
    ["createdDateTime"] = "metadata.original_time",
    ["eventDateTime"] = "start_time_dt",
    ["id"] = "metadata.uid",
    ["lastModifiedDateTime"] = "finding.modified_time",
    ["sourceMaterials"] = "finding.src_url",
    ["status"] = "activity_name",
    ["vendorInformation.provider"] = "metadata.product.name",
    ["vendorInformation.providerVersion"] = "metadata.product.version",
    ["vendorInformation.vendor"] = "metadata.product.vendor_name",
    ["lastEventDateTime"] = "end_time",
    ["title"] = "finding.title",
    ["category_uid"] = "category_uid",
    ["class_uid"] = "class_uid",
    ["type_uid"] = "type_uid",
    ["category_name"] = "category_name",
    ["class_name"] = "class_name",
    ["type_name"] = "type_name",
    ["activity_id"] = "activity_id",
    ["cloud.provider"] = "cloud.provider",
    ["OCSF_version"] = "metadata.version",
    ["observables"] = "observables",
    ["dataSource.category"] = "dataSource.category",
    ["site.id"] = "site.id",
    ["event.type"] = "event.type",
    ["dataSource.name"] = "dataSource.name",
    ["dataSource.vendor"] = "dataSource.vendor",
  }
end

local function generic_mgmt_mapping()
  return {
    ["CreationTime"] = "metadata.original_time",
    ["Id"] = "metadata.uid",
    ["OrganizationId"] = "cloud.org.uid",
    ["Version"] = "metadata.product.version",
    ["Workload"] = "metadata.product.name",
  }
end
 
local function get_mgmt_default_mapping(event_type)
  -- ported from python OCSFMapping.get_mgmt_default_mapping
  local default = {
    ["dlprulematch"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["Operation"] = "finding.title",
      ["OrganizationId"] = "cloud.org.uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["IncidentId"] = "finding.uid",
      ["SharePointMetaData.FileID"] = "process.file.uid",
      ["SharePointMetaData.FileName"] = "process.file.name",
      ["SharePointMetaData.FileOwner"] = "process.file.owner.uid",
      ["SharePointMetaData.FilePathUrl"] = "process.file.path",
      ["SharePointMetaData.FileSize"] = "process.file.size",
      ["SharePointMetaData.From"] = "resources.data.from",
      ["SharePointMetaData.IsViewableByExternalUsers"] = "resources.data.is_viewable_by_external_users",
      ["SharePointMetaData.IsVisibleOnlyToOdbOwner"] = "resources.data.is_visible_only_to_Odb_owner",
      ["SharePointMetaData.ItemCreationTime"] = "finding.created_time",
      ["SharePointMetaData.ItemLastModifiedTime"] = "finding.modified_time",
      ["SharePointMetaData.ItemLastSharedTime"] = "resources.data.item_last_shared_time",
      ["SharePointMetaData.SensitivityLabelIds"] = "resources.data.sensitivity_label_ids",
      ["SharePointMetaData.SharedBy"] = "resources.data.shared_by",
      ["SharePointMetaData.SiteAdmin"] = "resources.data.site_admin",
      ["SharePointMetaData.SiteCollectionGuid"] = "resources.data.site_collection_guid",
      ["SharePointMetaData.SiteCollectionUrl"] = "resources.data.site_collection_url",
      ["SharePointMetaData.UniqueID"] = "resources.data.unique_id",
      ["state_id"] = "state_id",
      ["status_id"] = "status_id",
      ["analytic.uid"] = "analytic.uid",
      ["analytic.name"] = "analytic.name",
      ["analytic_type_id"] = "analytic.type_id",
      ["process_file_owner_type_id"] = "process.file.owner.type_id",
    },
    ["dlpruleundo"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["Operation"] = "finding.title",
      ["OrganizationId"] = "cloud.org.uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["IncidentId"] = "finding.uid",
      ["SharePointMetaData.FileID"] = "process.file.uid",
      ["SharePointMetaData.FileName"] = "process.file.name",
      ["SharePointMetaData.FileOwner"] = "process.file.owner.uid",
      ["SharePointMetaData.FilePathUrl"] = "process.file.path",
      ["SharePointMetaData.FileSize"] = "process.file.size",
      ["SharePointMetaData.From"] = "resources.data.from",
      ["SharePointMetaData.IsViewableByExternalUsers"] = "resources.data.is_viewable_by_external_users",
      ["SharePointMetaData.IsVisibleOnlyToOdbOwner"] = "resources.data.is_visible_only_to_Odb_owner",
      ["SharePointMetaData.ItemCreationTime"] = "finding.created_time",
      ["SharePointMetaData.ItemLastModifiedTime"] = "finding.modified_time",
      ["SharePointMetaData.ItemLastSharedTime"] = "resources.data.item_last_shared_time",
      ["SharePointMetaData.SensitivityLabelIds"] = "resources.data.sensitivity_label_ids",
      ["SharePointMetaData.SharedBy"] = "resources.data.shared_by",
      ["SharePointMetaData.SiteAdmin"] = "resources.data.site_admin",
      ["SharePointMetaData.SiteCollectionGuid"] = "resources.data.site_collection_guid",
      ["SharePointMetaData.SiteCollectionUrl"] = "resources.data.site_collection_url",
      ["SharePointMetaData.UniqueID"] = "resources.data.unique_id",
      ["analytic.uid"] = "analytic.uid",
      ["analytic.name"] = "analytic.name",
      ["analytic_type_id"] = "analytic.type_id",
      ["process_file_owner_type_id"] = "process.file.owner.type_id",
      ["state_id"] = "state_id",
    },
    ["update user"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["Operation"] = "activity_name",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ResultStatus"] = "status_detail",
      ["ActorContextId"] = "actor.user.org.uid",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
    },
    ["userloggedin"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ClientIP"] = "device.ip",
      ["ResultStatus"] = "status_detail",
      ["ActorContextId"] = "actor.user.org.uid",
      ["ActorIpAddress"] = "src_endpoint.ip",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["ApplicationId"] = "dst_endpoint.uid",
      ["ErrorNumber"] = "api.response.code",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
      ["device_os_type"] = "device.os.type",
      ["device_os_type_id"] = "device.os.type_id",
      ["actor_session_uid"] = "actor.session.uid",
      ["device_is_compliant"] = "device.is_compliant",
      ["device_is_managed"] = "device.is_managed",
    },
    ["add group"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["Operation"] = "activity_name",
      ["OrganizationId"] = "cloud.org.uid",
      ["ResultStatus"] = "status_detail",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ActorContextId"] = "actor.user.org.uid",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
      ["resource.data"] = "resource.data",
    },
    ["add member to group"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["ResultStatus"] = "status_detail",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ActorContextId"] = "actor.user.org.uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
      ["resource.data"] = "resource.data",
    },
    ["delete group"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ResultStatus"] = "status_detail",
      ["ActorContextId"] = "actor.user.org.uid",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
      ["resource.data"] = "resource.data",
    },
    ["update group"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["Operation"] = "activity_name",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ResultStatus"] = "status_detail",
      ["ActorContextId"] = "actor.user.org.uid",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
      ["resource.data"] = "resource.data",
    },
    ["remove member from group"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ResultStatus"] = "status_detail",
      ["ActorContextId"] = "actor.user.org.uid",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
      ["resource.data"] = "resource.data",
    },
    ["add user"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ResultStatus"] = "status_detail",
      ["ActorContextId"] = "actor.user.org.uid",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
    },
    ["reset user password"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ResultStatus"] = "status_detail",
      ["ActorContextId"] = "actor.user.org.uid",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
    },
    ["delete user"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.UserKey",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ResultStatus"] = "status_detail",
      ["ActorContextId"] = "actor.user.org.uid",
      ["InterSystemsId"] = "metadata.correlation_uid",
      ["TargetContextId"] = "user.org.uid",
      ["status_id"] = "status_id",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["user_email_addr"] = "user.email_addr",
      ["user_uid"] = "user.uid",
      ["user_type_id"] = "user.type_id",
      ["user_type"] = "user.type",
    },
    ["addedtogroup"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ClientIP"] = "device.ip",
      ["CorrelationId"] = "metadata.correlation_uid",
      ["EventSource"] = "resource.name",
      ["EventData"] = "status_detail",
      ["TargetUserOrGroupType"] = "user.groups.type",
      ["TargetUserOrGroupName"] = "user.groups.name",
      ["AppAccessContext.CorrelationId"] = "actor.idp.uid",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
    },
    ["signinevent"] = {
      ["CreationTime"] = "metadata.original_time",
      ["Id"] = "metadata.uid",
      ["OrganizationId"] = "cloud.org.uid",
      ["UserKey"] = "actor.user.credential_uid",
      ["Version"] = "metadata.product.version",
      ["Workload"] = "metadata.product.name",
      ["ClientIP"] = "src_endpoint.ip",
      ["CorrelationId"] = "metadata.correlation_uid",
      ["EventSource"] = "service.name",
      ["IsManagedDevice"] = "device.is_managed",
      ["Platform"] = "device.os.type",
      ["UserAgent"] = "http_request.user_agent",
      ["DeviceDisplayName"] = "device.ip",
      ["AppAccessContext.AADSessionId"] = "actor.session.uid",
      ["actor_user_email_addr"] = "actor.user.email_addr",
      ["actor_user_uid"] = "actor.user.uid",
      ["actor_user_type_id"] = "actor.user.type_id",
      ["actor_user_type"] = "actor.user.type",
      ["device_os_type_id"] = "device.os.type_id",
    },
  }
  local et = (event_type or ""):lower()
  return default[et] or generic_mgmt_mapping()
end

local function common_mapping()
  return {
    ["category_name"] = "category_name",
    ["category_uid"] = "category_uid",
    ["class_uid"] = "class_uid",
    ["severity_id"] = "severity_id",
    ["activity_name"] = "activity_name",
    ["activity_id"] = "activity_id",
    ["type_uid"] = "type_uid",
    ["product_vendor_name"] = "metadata.product.vendor_name",
    ["product_name"] = "metadata.product.name",
    ["OCSF_version"] = "metadata.version",
    ["observables"] = "observables",
    ["dataSource.category"] = "dataSource.category",
    ["site.id"] = "site.id",
    ["event.type"] = "event.type",
    ["dataSource.name"] = "dataSource.name",
    ["dataSource.vendor"] = "dataSource.vendor",
    ["message"] = "message",
    ["class_name"] = "class_name",
    ["type_name"] = "type_name",
    ["actor_user_email_addr"] = "actor.user.email_addr",
    ["actor_user_uid"] = "actor.user.uid",
    ["actor_user_type_id"] = "actor.user.type_id",
    ["actor_user_type"] = "actor.user.type",
    ["user_email_addr"] = "user.email_addr",
    ["user_uid"] = "user.uid",
    ["user_type_id"] = "user.type_id",
    ["user_type"] = "user.type",
    ["status_id"] = "status_id",
  }
end

-- Mgmt synthetic enrichment
local function set_mgmt_synthetic_fields(log, site_id)
  log["product_vendor_name"] = "Microsoft"
  log["OCSF_version"] = "1.0.0"
  local event_type = tostring(log["Operation"] or "Other")
  local event_type_dup = event_type:gsub("%.", "")

  log["severity_id"] = get_severity_id(event_type_dup)
  local activity_name, activity_id, class_name, class_uid, type_name, type_uid, category_name, category_uid = get_mgmt_log_mapping_fields(event_type_dup)
  log["activity_name"], log["activity_id"], log["class_name"], log["class_uid"], log["type_name"], log["type_uid"], log["category_name"], log["category_uid"] = activity_name, activity_id, class_name, class_uid, type_name, type_uid, category_name, category_uid

  log["status_id"] = get_status_default_ocsf_mapping(log["ResultStatus"])

  if site_id then log["site"] = { id = site_id } end

  if log["activity_id"] == 99 then
    log["event"] = { type = event_type }
    log["activity_name"] = event_type
  else
    log["event"] = { type = log["activity_name"] }
  end

  log["dataSource"] = { name = "Microsoft O365", category = "security", vendor = "Microsoft" }

  if event_type_dup:lower() == "dlprulematch" or event_type_dup:lower() == "dlpruleundo" then
    log["analytic_type_id"] = 1
    log["process_file_owner_type_id"] = 99
    log["observables"] = get_mgmt_observables(log)
    log["state_id"] = get_state_id(event_type_dup)
    local aid, aname = extract_policy_details(log)
    log["analytic"] = { uid = aid, name = aname }
  else
    -- set actor values
    if (event_type_dup:lower() == "userloggedin") then
      log["actor_user_type"], log["actor_user_type_id"] = "User", 1
    end
    local userId = log["UserId"]
    if is_email(userId) then
      log["actor_user_email_addr"] = userId
    elseif type(userId) == "string" and userId ~= "" then
      log["actor_user_uid"] = userId
    end
    local actors = log["Actor"]
    if type(actors) == "table" and #actors > 0 then
      for _, a in ipairs(actors) do
        if type(a) == "table" then
          local id = a["ID"]
          if is_email(id) then
            log["actor_user_email_addr"] = id
            local t, tid = get_actor_type_details(a["Type"])
            log["actor_user_type"], log["actor_user_type_id"] = t, tid
            break
          elseif type(id) == "string" and id:match("-") then
            log["actor_user_uid"] = id
            local t, tid = get_actor_type_details(a["Type"])
            log["actor_user_type"], log["actor_user_type_id"] = t, tid
            break
          end
        end
      end
    else
      local t, tid = get_actor_type_details(log["UserType"])
      log["actor_user_type"], log["actor_user_type_id"] = t, tid
    end

    -- set user target data
    local target = log["Target"]
    if type(target) == "table" and #target > 0 and type(target[1]) == "table" then
      local tid = target[1]["ID"]
      if is_email(tid) then log["user_email_addr"] = tid else log["user_uid"] = tid end
      local t, tidv = get_actor_type_details(target[1]["Type"])
      log["user_type"], log["user_type_id"] = t, tidv
    end
  end

  if log["UserKey"] == "Not Available" or log["UserKey"] == "NA" then log["UserKey"] = "" end

  local etl = event_type_dup:lower()
  if etl == "add group" or etl == "add member to group" or etl == "delete group" or etl == "update group" or etl == "remove member from group" then
    log["resource"] = { data = get_resource_data(log) }
  end

  if etl == "signinevent" then
    log["device_os_type_id"] = get_device_os_type(log["Platform"])
  end

  if etl == "userloggedin" then
    log = get_device_property(log)
  end

  return log
end

-- Parsers
local function default_graph_api_parser(alertLog)
  return build_nested(apply_mapping(alertLog, get_default_graph_ocsf_mapping()))
end

local function default_mgmt_api_parser(log)
  local event_type = tostring(log["Operation"] or "Other"):gsub("%.", "")
  local mapping = get_mgmt_default_mapping(event_type)
  -- merge with common mapping
  for src, dst in pairs(common_mapping()) do mapping[src] = dst end
  local flat = apply_mapping(log, mapping)
  return build_nested(flat)
end

-- API detection: Graph has createdDateTime, vendorInformation; Mgmt has CreationTime/Operation
local function detect_api(event)
  if event["createdDateTime"] or getByPath(event, {"vendorInformation"}) then return "Graph" end
  return "Mgmt"
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

local GRAPH_FIELD_ORDER = {
  message = {
    "id", "azureTenantId", "azureSubscriptionId", "riskScore", "tags", "activityGroupName", "assignedTo",
    "category", "closedDateTime", "comments", "confidence", "createdDateTime", "description", "detectionIds",
    "eventDateTime", "feedback", "incidentIds", "lastEventDateTime", "lastModifiedDateTime", "recommendedActions",
    "severity", "sourceMaterials", "status", "title", "vendorInformation", "alertDetections",
    "cloudAppStates", "fileStates", "hostStates", "historyStates", "investigationSecurityStates",
    "malwareStates", "messageSecurityStates", "networkConnections", "processes", "registryKeyStates", "securityResources",
    "triggers", "userStates", "uriClickSecurityStates", "vulnerabilityStates"
  },
  vendorInformation = {
    "provider", "providerVersion", "subProvider", "vendor", 
  },
  userStates = {
    "aadUserId", "accountName", "domainName", "emailRole", "isVpn", "logonDateTime", 
    "logonId", "logonIp", "logonLocation", "logonType", "onPremisesSecurityIdentifier",
    "riskScore", "userAccountType", "userPrincipalName"
  }
}

local MGMT_FIELD_ORDER = {
  ["dlprulematch"] = {
      message = {
        "CreationTime",
        "Id",
        "Operation",
        "OrganizationId",
        "RecordType",
        "UserKey",
        "UserType",
        "Version",
        "Workload",
        "ObjectId",
        "UserId",
        "IncidentId",
        "PolicyDetails",
        "SensitiveInfoDetectionIsIncluded",
        "SharePointMetaData",
      },
      PolicyDetails = {
        "PolicyId", "PolicyName", "Rules"
      },
      Rules = {
        "ActionParameters", "Actions", "ConditionsMatched", "ManagementRuleId", "RuleId", "RuleMode", "RuleName", "Severity"
      },
      ConditionsMatched = {
        "ConditionMatchedInNewScheme", "OtherConditions", "SensitiveInformation"
      },
      OtherConditions = {
        "Name", "Value"
      },
      SensitiveInformation = {
        "ClassifierType", "Confidence", "Count", "SensitiveInformationDetailedClassificationAttributes", 
        "SensitiveInformationDetections", "SensitiveInformationTypeName", "SensitiveType"
      },
      SensitiveInformationDetailedClassificationAttributes = {
        "Confidence", "Count", "IsMatch"
      },
      SensitiveInformationDetections = {
        "DetectedValues", "ResultsTruncated"
      },
      DetectedValues = {
        "Name", "Value"
      },
      SharePointMetaData = {
        "FileID", "FileName", "FileOwner", "FilePathUrl", "FileSize", "From", "IsViewableByExternalUsers",
        "IsVisibleOnlyToOdbOwner", "ItemCreationTime", "ItemLastModifiedTime", "ItemLastSharedTime",
        "SensitivityLabelIds", "SharedBy", "SiteAdmin", "SiteCollectionGuid", "SiteCollectionUrl", "UniqueID"
      }
    },
    ["dlpruleundo"] = {
      message = {
        "CreationTime",
        "Id",
        "Operation",
        "OrganizationId",
        "RecordType",
        "UserKey",
        "UserType",
        "Version",
        "Workload",
        "ObjectId",
        "UserId",
        "IncidentId",
        "PolicyDetails",
        "SensitiveInfoDetectionIsIncluded",
        "SharePointMetaData",
      },
      ExceptionInfo = {
        "Reason"
      },
      PolicyDetails = {
        "PolicyId", "PolicyName", "Rules"
      },
      Rules = {
        "ConditionsMatched", "ManagementRuleId", "OverriddenActions", "RuleId", "RuleMode", "RuleName", "Severity"
      },
      ConditionsMatched = {
        "ConditionMatchedInNewScheme", "SensitiveInformation"
      },
      SensitiveInformation = {
        "ClassifierType", "Confidence", "Count", "SensitiveInformationDetailedClassificationAttributes", 
        "SensitiveInformationDetections", "SensitiveInformationTypeName", "SensitiveType"
      },
      SensitiveInformationDetailedClassificationAttributes = {
        "Confidence", "Count", "IsMatch"
      },
      SensitiveInformationDetections = {
        "DetectedValues", "ResultsTruncated"
      },
      DetectedValues = {
        "Name", "Value"
      },
      SharePointMetaData = {
        "FileID", "FileName", "FileOwner", "FilePathUrl", "FileSize", "From", "IsViewableByExternalUsers",
        "IsVisibleOnlyToOdbOwner", "ItemCreationTime", "ItemLastModifiedTime", "ItemLastSharedTime",
        "SensitivityLabelIds", "SharedBy", "SiteAdmin", "SiteCollectionGuid", "SiteCollectionUrl", "UniqueID"
      }
      
    },
    ["update user"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId",
        "SupportTicketId", "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["userloggedin"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ClientIP", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "ActorIpAddress", "InterSystemsId", 
        "IntraSystemId", "SupportTicketId", "Target", "TargetContextId", "ApplicationId", "DeviceProperties", "ErrorNumber"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      },
      DeviceProperties = {
        "Name", "Value"
      }
    },
    ["add group"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", "ExtendedProperties",
        "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId", "SupportTicketId", 
        "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["add member to group"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId",
        "SupportTicketId", "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["delete group"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId",
        "SupportTicketId", "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["update group"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId",
        "SupportTicketId", "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["remove member from group"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId",
        "SupportTicketId", "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["add user"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId",
        "SupportTicketId", "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["reset user password"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId",
        "SupportTicketId", "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["delete user"] = {
      message = {
        "CreationTime", "Id", "Operation", "OrganizationId", "RecordType", "ResultStatus", "UserKey", 
        "UserType", "Version", "Workload", "ObjectId", "UserId", "AzureActiveDirectoryEventType", 
        "ExtendedProperties", "ModifiedProperties", "Actor", "ActorContextId", "InterSystemsId", "IntraSystemId",
        "SupportTicketId", "Target", "TargetContextId"
      },
      ExtendedProperties = {
        "Name", "Value"
      },
      ModifiedProperties = {
        "Name", "NewValue", "OldValue"
      },
      Actor = {
        "ID", "Type"
      },
      Target = {
        "ID", "Type"
      }
    },
    ["addedtogroup"] = {
      message = {
        "AppAccessContext",
        "CreationTime",
        "Id",
        "Operation",
        "OrganizationId", 
        "RecordType", 
        "UserKey",
        "UserType", 
        "Version", 
        "Workload", 
        "ClientIP", 
        "ObjectId", 
        "UserId", 
        "CorrelationId", 
        "EventSource", 
        "ItemType", 
        "Site", 
        "UserAgent", 
        "WebId", 
        "EventData", 
        "TargetUserOrGroupType", 
        "SiteUrl", 
        "TargetUserOrGroupName"
      },
      AppAccessContext = {
        "AADSessionId", "CorrelationId", "UniqueTokenId"
      },
    },
    ["signinevent"] = {
      message = {
        "AppAccessContext",
        "CreationTime",
        "Id",
        "Operation",
        "OrganizationId", 
        "RecordType", 
        "UserKey",
        "UserType", 
        "Version", 
        "Workload", 
        "ClientIP", 
        "UserId", 
        "AuthenticationType",
        "BrowserName",
        "BrowserVersion",
        "CorrelationId",
        "EventSource",
        "IsManagedDevice",
        "ItemType",
        "Platform",
        "UserAgent",
        "DeviceDisplayName"
      },
      AppAccessContext = {
        "AADSessionId", "CorrelationId", "UniqueTokenId"
      },
    },
}

local function get_field_order(api, event_type)
  if api == "Graph" then
    return GRAPH_FIELD_ORDER or {}
  else
    local et = (event_type or ""):lower()
    return MGMT_FIELD_ORDER[et] or {}
  end
end

local IGNORE_KEYS = {
  _ob = true,
  timestamp = true,  -- Ignore timestamp as we use start_time/end_time
}

-- Global entry point
function processEvent(event)
  local e = event or {}
  -- If input already has OCSF-shaped dotted keys (post-mapped), just build nested and return
  if e["metadata.original_time"] or e["category_uid"] or e["class_uid"] or e["dataSource.vendor"] then
    return build_nested(e)
  end
  -- allow site id from event.site.id or event.site_id
  local site_id = nil
  local st = e["site"]
  if type(st) == "table" and st["id"] then site_id = st["id"] elseif e["site_id"] then site_id = e["site_id"] end

  local api = detect_api(e)
  local working = cloneTable(e)

  if api == "Graph" then
    working = set_graph_synthetic_fields(working, site_id)
    local result = default_graph_api_parser(working)
    result.time = convertUtcToMilliseconds(e["createdDateTime"])
    -- Store original input as JSON string in message field (with field ordering)
    local originalInput = deepCopy(event, IGNORE_KEYS) or {}
    result.message = encodeJson(originalInput, get_field_order(api, ""), "message")
    return result
  else
    working = set_mgmt_synthetic_fields(working, site_id)
    local result = default_mgmt_api_parser(working)
    result.time = convertUtcToMilliseconds(e["CreationTime"])
    -- Store original input as JSON string in message field (with field ordering)
    local originalInput = deepCopy(event, IGNORE_KEYS) or {}
    local event_type = tostring(working["Operation"] or "Other"):gsub("%.", "")
    result.message = encodeJson(originalInput, get_field_order(api, event_type), "message")
    return result
  end
end
