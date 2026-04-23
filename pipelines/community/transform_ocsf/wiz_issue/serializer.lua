
local FEATURES = {
    FLATTEN_EVENT_TYPE = true,
}

-- Wiz to OCSF Mapping Script
local OCSF_VERSION = "v1.0.0-rc.3"

local WIZ_SEVERITY_MAP = {["INFORMATIONAL"]=1, ["LOW"]=2, ["MEDIUM"]=3, ["HIGH"]=4, ["CRITICAL"]=5, ["OTHER"]=99}
local WIZ_STATE_MAP = {["OPEN"]=1, ["IN_PROGRESS"]=2, ["REJECTED"]=3, ["RESOLVED"]=4, ["OTHER"]=99}
local OCSF_ACCOUNT_TYPE_ID = {["AWS"]=10, ["GCP"]=5, ["EKS"]=10, ["GKE"]=5}
local OCSF_ACCOUNT_TYPE_NAME = {[10]="AWS Account", [5]="GCP Account", [3]="AWS IAM User", [4]="AWS IAM Role"}

-- Field ordering templates for consistent JSON serialization
local FIELD_ORDERS = {
    root = {"activity_id", "analytic", "category_name", "category_uid", "class_name", "class_uid",
        "cloud", "dataSource", "event", "finding", "index", "metadata", "message", "resource",
        "severity", "severity_id", "state", "state_id",
        "status", "type_uid", "unmapped"
    },
    message = {
        "activity_id", "analytic_type", "analytic_type_id", "category_name", "category_uid",
        "class_name", "class_uid", "cloud_account_type", "cloud_account_type_id", "datasource",
        "entitySnapshot", "event", "id", "ocsf_version", "severity", "severity_id",
        "sourceRule", "state_id", "status", "type_uid", "updatedAt", "eventType", "readOnly", "createdAt"
    },
    entitySnapshot = {
        "cloudPlatform", "cloudProviderURL", "externalId", "id", "name", "nativeType",
        "projects", "providerId", "region", "resourceGroupExternalId", "status",
        "subscription", "subscriptionExternalId", "type", "wizResourceID"
    },
    sourceRule = {
        "description", "id", "name", "remediationInstructions", "resolutionRecommendation"
    },
    datasource = {
        "category", "name", "vendor"
    },
    subscription = {
        "externalId", "name", "id", "cloudProvider"
    },
    projects = {
        "name", "riskProfile", "id"
    },
    riskProfile = {
        "businessImpact"
    },
    unmapped = {
        "severity"
    }
}

-- JSON encoding function (from AWS CloudTrail)
function encodeJson(obj, key)
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
                local elementKey = key or tostring(i)
                table.insert(items, obj[i] ~= nil and encodeJson(obj[i], elementKey) or "null")
            end
            return "[" .. table.concat(items, ", ") .. "]"
        else
            local items = {}
            local fieldOrder = FIELD_ORDERS[key] or {}
            
            -- Phase 1: Process fields in predefined order
            for _, fieldName in ipairs(fieldOrder) do
                local v = obj[fieldName]
                if v ~= nil then
                    table.insert(items, '"' .. fieldName:gsub('"', '\\"') .. '": ' .. encodeJson(v, fieldName))
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
                    table.insert(items, '"' .. keyStr:gsub('"', '\\"') .. '": ' .. encodeJson(v, keyStr))
                end
            end
            
            return "{" .. table.concat(items, ", ") .. "}"
        end
    else
        return '"' .. tostring(obj) .. '"'
    end
end

-- Helper function to set nested fields (from AWS CloudTrail)
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
        if current[key] == nil then
            current[key] = {}
        end
        current = current[key]
    end
    current[keys[#keys]] = value
end

local IGNORE_FIELDS = { 
    _wiz_event_type = true, 
    _wiz_query_time = true, 
    _ts = true, 
    _ob = true,
    host = true,
    source_type = true,
    timestamp = true,
    type = true
}

local fieldMappings = {
    -- Finding and Analytic mappings
    {type="multi", source="sourceRule.description", targets={"finding.desc", "analytic.desc"}},
    {type="multi", source="sourceRule.name", targets={"finding.title", "analytic.name"}},
    {type="direct", source="sourceRule.resolutionRecommendation", target="finding.remediation.desc"},
    {type="direct", source="sourceRule.id", target="analytic.uid"},
    {type="direct", source="analytic_type_id", target="analytic.type_id"},
    {type="direct", source="analytic_type", target="analytic.type"},
    {type="direct", source="createdAt", target="finding.created_time"},
    {type="direct", source="updatedAt", target="finding.modified_time"},
    
    -- Cloud mappings
    {type="direct", priority1="entitySnapshot.subscription.cloudProvider", priority2="entitySnapshot.cloudPlatform", target="cloud.provider"},
    {type="direct", source="cloud_account_type", target="cloud.account.type"},
    {type="direct", source="cloud_account_type_id", target="cloud.account.type_id"},
    {type="direct", source="entitySnapshot.region", target="cloud.region"},
    {type="multi", priority1="entitySnapshot.subscription.externalId", priority2="entitySnapshot.subscriptionExternalId", targets={"cloud.account.uid", "cloud.org.uid"}},
    
    -- Resource mappings
    {type="direct", source="entitySnapshot.cloudProviderURL", target="resource.url"},
    {type="direct", source="entitySnapshot.externalId", target="resource.data.external_id"},
    {type="direct", source="entitySnapshot.wizResourceID.id", target="resource.data.wiz_resource_id"},
    {type="direct", source="entitySnapshot.name", target="resource.name"},
    {type="direct", source="entitySnapshot.nativeType", target="resource.type"},
    {type="direct", source="entitySnapshot.providerId", target="resource.uid"},
    {type="direct", source="entitySnapshot.resourceGroupExternalId", target="resource.group.uid"},
    {type="direct", source="entitySnapshot.status", target="resource.status"},
    {type="direct", source="entitySnapshot.type", target="resource.data.generic_type"},
    
    -- Metadata and event mappings
    {type="multi", source="id", targets={"metadata.uid", "finding.uid"}},
    {type="direct", source="event", target="event.type"},
    {type="direct", source="severity", target="unmapped.severity"},
    {type="multi", source="status", targets={"state", "status"}},
    {type="multi", source="datasource.vendor", targets={"dataSource.vendor", "metadata.product.vendor_name"}},
    {type="multi", source="datasource.name", targets={"dataSource.name", "metadata.product.name"}},
    {type="direct", source="datasource.category", target="dataSource.category"},
    {type="direct", source="ocsf_version", target="metadata.version"},
    
    -- OCSF standard fields (computed values)
    {type="computed", value="2001", target="class_uid"},
    {type="computed", value="99", target="activity_id"},
    {type="computed", value="200199", target="type_uid"},
    {type="computed", value="2", target="category_uid"},
    {type="computed", value="Security Finding", target="class_name"},
    {type="computed", value="Findings", target="category_name"},
    
    -- Additional required fields
    
    -- Computed mappings using maps
    {type="computed_map", source="severity", map="WIZ_SEVERITY_MAP", default=99, target="severity_id"},
    {type="computed_map", source="status", map="WIZ_STATE_MAP", default=99, target="state_id"},
    
    -- Cloud account type mappings
    {type="computed_cloud_type", source="entitySnapshot.cloudPlatform", target="cloud.account.type_id"},
    {type="computed_cloud_type", source="entitySnapshot.cloudPlatform", target="cloud.account.type"},
    
}


-- Field ordering is now defined by the mapping order in fieldMappings table

function getNestedField(obj, path)
    if not obj or not path or path == '' then return nil end
    local current = obj
    for key in string.gmatch(path, '[^.]+') do
        if not current or not key then return nil end
        current = current[key]
    end
    return current
end

function processEvent(event)
    if not event then return event end
    
    -- Populate event.event from _wiz_event_type if it's an issue event
    if event._wiz_event_type and string.lower(event._wiz_event_type) == "issue" then
        event.event = "Issues"
    end
    
    -- Check if this is an issue event (case-insensitive)
    local isIssueEvent = false
    if event.event and string.lower(event.event) == "issues" then
        isIssueEvent = true
    end
    
    if not isIssueEvent then
        -- Return as-is for non-issue events
        return event
    end

    -- Add datasource field to event
    if not event.datasource then
        event.datasource = {
            category = "security",
            name = "Wiz",
            vendor = "Wiz"
        }
    end
    
    -- Set event field
    event.event = "Issues"
    
    -- Add OCSF fields
    event.class_uid = "2001"
    event.activity_id = "99"
    event.type_uid = "200199"
    event.category_uid = "2"
    event.class_name = "Security Finding"
    event.category_name = "Findings"
    event.analytic_type = "Rule"
    event.analytic_type_id = 1
    
    -- Add computed fields 
    event.severity_id = WIZ_SEVERITY_MAP[event.severity] or 99
    event.state_id = WIZ_STATE_MAP[event.status] or 99
    
    
    -- Add cloud account type_id (always show) and type (only if cloudPlatform exists)
    local cloudPlatform = nil
    if event.entitySnapshot and event.entitySnapshot.cloudPlatform then
        cloudPlatform = event.entitySnapshot.cloudPlatform
    end
    
    event.cloud_account_type_id = OCSF_ACCOUNT_TYPE_ID[cloudPlatform] or 99
    
    -- Check for AWS IAM users/roles 
    if event.cloud_account_type_id == 10 and event.entitySnapshot and event.entitySnapshot.nativeType then
        local nativeType = event.entitySnapshot.nativeType
        if nativeType == "user" then
            event.cloud_account_type_id = 3  -- AWS IAM User
        elseif nativeType == "role" then
            event.cloud_account_type_id = 4  -- AWS IAM Role
        end
    end
    
    -- Only set cloud_account_type if cloudPlatform exists
    if cloudPlatform then
        event.cloud_account_type = OCSF_ACCOUNT_TYPE_NAME[event.cloud_account_type_id] or cloudPlatform or "Unknown Account Type"
    end
    -- If cloudPlatform is nil, don't set cloud_account_type but type_id still shows
    
    -- Add wizResourceID to entitySnapshot 
    if event.entitySnapshot and event.entitySnapshot.id then
        event.entitySnapshot.wizResourceID = {
            id = event.entitySnapshot.id
        }
    end
    
    -- Convert timestamps to Unix milliseconds 
    if event.createdAt then
        -- Convert createdAt to Unix milliseconds
        local createdAtStr = tostring(event.createdAt)
        -- Try to parse as ISO timestamp and convert to milliseconds
        local success, result = pcall(function()
            -- Simple conversion for ISO timestamps like "2025-10-08T22:12:42.66996Z"
            if createdAtStr:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d") then
                -- Extract the timestamp part and convert
                local year, month, day, hour, min, sec = createdAtStr:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)")
                if year and month and day and hour and min and sec then
                    -- Create a simple timestamp (this is a basic implementation)
                    -- In a real implementation, you'd use proper date parsing
                    local timestamp = os.time({
                        year = tonumber(year),
                        month = tonumber(month),
                        day = tonumber(day),
                        hour = tonumber(hour),
                        min = tonumber(min),
                        sec = tonumber(sec)
                    })
                    return timestamp * 1000  -- Convert to milliseconds
                end
            end
            -- Fallback: try to convert as number
            local num = tonumber(createdAtStr)
            if num then
                -- If it's already a timestamp, ensure it's in milliseconds
                if num > 1000000000000 then  -- Already in milliseconds
                    return num
                elseif num > 1000000000 then  -- In seconds, convert to milliseconds
                    return num * 1000
                else  -- Assume it's already in the right format
                    return num
                end
            end
            return nil
        end)
        
        if success and result then
            event.createdAt = result
        end
    end
    
    if event.updatedAt then
        -- Convert updatedAt to Unix milliseconds
        local updatedAtStr = tostring(event.updatedAt)
        local success, result = pcall(function()
            -- Simple conversion for ISO timestamps
            if updatedAtStr:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d") then
                local year, month, day, hour, min, sec = updatedAtStr:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)")
                if year and month and day and hour and min and sec then
                    local timestamp = os.time({
                        year = tonumber(year),
                        month = tonumber(month),
                        day = tonumber(day),
                        hour = tonumber(hour),
                        min = tonumber(min),
                        sec = tonumber(sec)
                    })
                    return timestamp * 1000
                end
            end
            local num = tonumber(updatedAtStr)
            if num then
                if num > 1000000000000 then
                    return num
                elseif num > 1000000000 then
                    return num * 1000
                else
                    return num
                end
            end
            return nil
        end)
        
        if success and result then
            event.updatedAt = result
        end
    end
    
    -- Set OCSF version 
    event.ocsf_version = OCSF_VERSION
    
    -- Remove tags field from entitySnapshot 
    if event.entitySnapshot then
        event.entitySnapshot.tags = nil
    end

    -- Track all fields that were added to the event as mapped
    -- so they don't appear in unmapped
    local mappedFields = {}
    mappedFields["class_uid"] = true
    mappedFields["activity_id"] = true
    mappedFields["type_uid"] = true
    mappedFields["category_uid"] = true
    mappedFields["class_name"] = true
    mappedFields["category_name"] = true
    mappedFields["analytic_type"] = true
    mappedFields["analytic_type_id"] = true
    mappedFields["severity_id"] = true
    mappedFields["state_id"] = true
    mappedFields["cloud_account_type_id"] = true
    mappedFields["cloud_account_type"] = true
    mappedFields["ocsf_version"] = true
    mappedFields["event"] = true
    mappedFields["entitySnapshot"] = true

    local result = {}
    
    -- Track field order as they're processed
    local fieldOrder = {}
    local processedFields = {}
    
    -- Helper functions
    local function getValue(priority1, priority2, priority3)
        local value = getNestedField(event, priority1)
        if value then return value end
        if priority2 then
            value = getNestedField(event, priority2)
            if value then return value end
        end
        if priority3 then
            return getNestedField(event, priority3)
        end
        return nil
    end
    
    local function setValue(targetPath, value)
        if value == "NULL_PLACEHOLDER" or value == "-" or value == "" then
            setNestedField(result, targetPath, nil)
        elseif value ~= nil then
            setNestedField(result, targetPath, value)
        end
    end
    
    local function setMultiValue(targetPaths, value)
        if value == "NULL_PLACEHOLDER" or value == "-" or value == "" then
            for _, targetPath in ipairs(targetPaths) do
                setNestedField(result, targetPath, nil)
            end
        elseif value then
            for _, targetPath in ipairs(targetPaths) do
                setNestedField(result, targetPath, value)
            end
        end
    end
    
    -- Track field order as they're processed
    local fieldOrder = {}
    local processedFields = {}
    
    -- Apply mappings
    for _, mapping in ipairs(fieldMappings) do
        local value = nil
        
        if mapping.type == "computed" then
            value = mapping.value
        elseif mapping.type == "computed_map" then
            -- Computed value from source using map
            local sourceValue = getNestedField(event, mapping.source)
            local mapTable = nil
            if mapping.map == "WIZ_SEVERITY_MAP" then
                mapTable = WIZ_SEVERITY_MAP
            elseif mapping.map == "WIZ_STATE_MAP" then
                mapTable = WIZ_STATE_MAP
            end
            value = (mapTable and mapTable[sourceValue]) or mapping.default
        elseif mapping.type == "computed_cloud_type" then
            -- Handle cloud account type logic with AWS IAM support
            local cloudPlatform = getNestedField(event, mapping.source)
            local typeId = OCSF_ACCOUNT_TYPE_ID[cloudPlatform] or 99
            
            -- Check for AWS IAM users/roles 
            if typeId == 10 and getNestedField(event, "entitySnapshot.nativeType") then
                local nativeType = getNestedField(event, "entitySnapshot.nativeType")
                if nativeType == "user" then
                    typeId = 3  -- AWS IAM User
                elseif nativeType == "role" then
                    typeId = 4  -- AWS IAM Role
                end
            end
            
            if mapping.target == "cloud.account.type_id" or mapping.target == "message.cloud_account_type_id" then
                value = typeId  -- Always show type_id
            elseif mapping.target == "cloud.account.type" or mapping.target == "message.cloud_account_type" then
                -- Only show type if cloudPlatform exists
                if cloudPlatform then
                    value = OCSF_ACCOUNT_TYPE_NAME[typeId] or cloudPlatform or "Unknown Account Type"
                end
                -- If cloudPlatform is nil, value remains nil (field will be ignored)
            end
        elseif mapping.type == "message_field" then
            value = getNestedField(event, mapping.source)
        elseif mapping.priority1 and mapping.priority2 then
            value = getValue(mapping.priority1, mapping.priority2, mapping.priority3)
        else
            value = getNestedField(event, mapping.source)
        end
        
        -- Set the value and track order
        if mapping.type == "direct" then
            setValue(mapping.target, value)
            if not processedFields[mapping.target] then
                table.insert(fieldOrder, mapping.target)
                processedFields[mapping.target] = true
            end
        elseif mapping.type == "multi" then
            setMultiValue(mapping.targets, value)
            for _, target in ipairs(mapping.targets) do
                if not processedFields[target] then
                    table.insert(fieldOrder, target)
                    processedFields[target] = true
                end
            end
        elseif mapping.type == "computed" or mapping.type == "computed_map" then
            setValue(mapping.target, value)
            if not processedFields[mapping.target] then
                table.insert(fieldOrder, mapping.target)
                processedFields[mapping.target] = true
            end
        elseif mapping.type == "computed_cloud_type" then
            if mapping.target:match("^message%.") then
                -- Handle message fields separately
                if not result["message"] then
                    result["message"] = {}
                end
                setNestedField(result["message"], mapping.target:gsub("message%.", ""), value)
            else
                setValue(mapping.target, value)
                if not processedFields[mapping.target] then
                    table.insert(fieldOrder, mapping.target)
                    processedFields[mapping.target] = true
                end
            end
        end
        
        -- Track mapped fields for unmapped processing
        if mapping.source then
            mappedFields[mapping.source] = true
        end
        if mapping.priority1 then
            mappedFields[mapping.priority1] = true
        end
        if mapping.priority2 then
            mappedFields[mapping.priority2] = true
        end
        if mapping.priority3 then
            mappedFields[mapping.priority3] = true
        end
        
        -- For computed fields, we need to track the target fields as mapped
        -- since they will be added to the event and shouldn't appear in unmapped
        if mapping.type == "computed" or mapping.type == "computed_map" or mapping.type == "computed_cloud_type" then
            if mapping.target then
                -- Extract the root field name from the target path
                local rootField = mapping.target:match("^([^%.]+)")
                if rootField then
                    mappedFields[rootField] = true
                end
            end
        end
    end
    
    -- Only include fields that are NOT mapped and NOT ignored
    for key, value in pairs(event) do
        if not IGNORE_FIELDS[key] and not mappedFields[key] then
            if type(value) == 'table' then
                local nestedObj = {}
                for nestedKey, nestedValue in pairs(value) do
                    if type(nestedValue) ~= 'function' and nestedValue ~= "-" and nestedValue ~= "" then
                        -- Check if this nested field was mapped
                        local nestedFieldKey = key .. "." .. nestedKey
                        if not mappedFields[nestedFieldKey] then
                        nestedObj[nestedKey] = nestedValue
                        end
                    end
                end
                if next(nestedObj) then
                    result["unmapped." .. key] = nestedObj
                end
            elseif value ~= "-" and value ~= "" then
                result["unmapped." .. key] = value
            end
        end
    end
    
    -- Build nested structure instead of flattening
    local nested = {}
    
    -- Add mapped fields to nested structure
    for _, fieldName in ipairs(fieldOrder) do
        local value = getNestedField(result, fieldName)
        if value ~= nil then 
            setNestedField(nested, fieldName, value)
        end
    end
    
    -- Add message field as JSON string (like AWS CloudTrail does)
    local cleanEvent = {}
    for key, value in pairs(event) do
        if key ~= "_ob" and key ~= "timestamp" and key ~= "_ts" and key ~= "_wiz_event_type" and key ~= "_wiz_query_time" and value ~= "-" and value ~= "" then
            cleanEvent[key] = value
        end
    end
    
    nested["message"] = encodeJson(cleanEvent, "message")

    -- Add missing fields that should be in the message
    if cleanEvent.readOnly == nil then
        cleanEvent.readOnly = false  -- Default for Wiz events
    end
    if cleanEvent.eventType == nil then
        cleanEvent.eventType = "Issues"  -- Default for Wiz events
    end
        
    -- Add unmapped fields as nested object (using setNestedField like AWS CloudTrail)
    for key, value in pairs(result) do
        if key:match("^unmapped%.") then
            local fieldName = key:gsub("^unmapped%.", "")
            setNestedField(nested, "unmapped." .. fieldName, value)
        end
    end

    -- Add time field
    if nested.finding and nested.finding.modified_time then
        nested["time"] = nested.finding.modified_time
    end
    
    if FEATURES.FLATTEN_EVENT_TYPE then
        if nested and nested.event then
            nested['event.type'] = nested.event.type
        end
    end
    return nested
end

