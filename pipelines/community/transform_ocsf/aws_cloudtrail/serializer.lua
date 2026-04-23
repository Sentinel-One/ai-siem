
local FEATURES = {
    IGNORE_UNKNOWN_EVENT = true,
}

-- Field ordering templates for consistent JSON serialization
local FIELD_ORDERS = {
    root = {"eventVersion", "userIdentity", "eventTime", "eventSource", "eventName", "awsRegion", "sourceIPAddress", "userAgent", "requestParameters", "responseElements", "additionalEventData", "requestID", "eventID", "readOnly", "resources", "eventType", "managementEvent", "recipientAccountId", "sharedEventID", "eventCategory", "tlsDetails", "errorCode", "errorMessage", "vpcEndpointId", "apiVersion", "message", "time", "insightDetails", "class_uid", "category_uid", "metadata", "dataSource"},
    userIdentity = {"accountId", "principalId", "accessKeyId", "userName", "type", "invokedBy", "sessionContext"},
    sessionContext = {"sessionIssuer", "attributes"},
    sessionIssuer = {"type", "principalId", "arn", "accountId", "userName"},
    attributes = {"creationDate"},
    requestParameters = {"durationSeconds", "externalId", "bucketName", "Host", "instanceId", "availabilityZone", "requestContext"},
    requestContext = {"awsAccountId"},
    responseElements = {"credentials"},
    credentials = {"accessKeyId", "expiration"},
    additionalEventData = {"SignatureVersion", "CipherSuite", "bytesTransferredIn", "AuthenticationMethod", "x-amz-id-2", "bytesTransferredOut"},
    resources = {"accountId", "type", "ARN"},
    tlsDetails = {"tlsVersion", "cipherSuite"},
    insightDetails = {"eventSource", "insightContext"},
    insightContext = {"statistics"},
    statistics = {"insightDuration"},
    metadata = {"product"},
    product = {"name", "vendor_name"},
    dataSource = {"category", "vendor", "name"}
}

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

-- Optimized JSON encoding function with predefined ordering
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
        -- Use the parent key for predefined ordering if available
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

function processEvent(event)
  
  -- Check if eventType is missing and IGNORE_UNKNOWN_EVENT is enabled
  if FEATURES.IGNORE_UNKNOWN_EVENT and (not event.eventType or event.eventType == "") then
    return nil
  end

  local result = {}
  
  -- Handle responseElements null case
  if event.responseElements == "" then
    event.responseElements = nil
  end
  
  -- Direct field mappings for better performance
  local function setField(sourcePath, targetPath)
    local value = getNestedField(event, sourcePath)
    if value ~= nil and value ~= "" then
      setNestedField(result, targetPath, value)
    end
  end
  
  -- Priority-based field mapping with fallback
  local function setFieldWithPriority(priority1, priority2, priority3, targetPath)
    local value = getNestedField(event, priority1)
    if value ~= nil and value ~= "" then
      setNestedField(result, targetPath, value)
    elseif priority2 then
      value = getNestedField(event, priority2)
      if value ~= nil and value ~= "" then
        setNestedField(result, targetPath, value)
      elseif priority3 and priority3 ~= "" then
        value = getNestedField(event, priority3)
        if value ~= nil and value ~= "" then
          setNestedField(result, targetPath, value)
        end
      end
    end
  end
  
  
  -- Field mapping table for better readability and maintainability
  local fieldMappings = {
    -- Basic CloudTrail fields
    {type = "direct", source = "awsRegion", target = "cloud.region"},
    {type = "direct", source = "eventCategory", target = "metadata.product.feature.name"},
    {type = "direct", source = "eventID", target = "metadata.uid"},
    {type = "direct", source = "eventTime", target = "metadata.original_time"},
    {type = "direct", source = "eventVersion", target = "metadata.product.version"},
    {type = "direct", source = "recipientAccountId", target = "cloud.account.uid"},
    {type = "priority", source1 = "requestID", source2 = "requestParameters.externalId", source3 = "requestParameters.requestContext.awsAccountId", target = "api.request.uid"},
    {type = "direct", source = "sourceIPAddress", target = "src_endpoint.ip"},
    {type = "direct", source = "userAgent", target = "http_request.user_agent"},
    
    -- User Identity fields
    {type = "direct", source = "userIdentity.principalId", target = "actor.user.uid"},
    {type = "direct", source = "userIdentity.accessKeyId", target = "actor.user.credential_uid"},
    {type = "direct", source = "userIdentity.type", target = "actor.user.type"},
    {type = "direct", source = "userIdentity.invokedBy", target = "actor.invoked_by"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.principalId", target = "actor.session.uid"},
    {type = "direct", source = "userIdentity.sessionContext.sessionIssuer.userName", target = "actor.session.issuer"},
    {type = "priority", source1 = "userIdentity.userName", source2 = "userIdentity.sessionContext.sessionIssuer.type", target = "actor.user.name"},
    {type = "priority", source1 = "userIdentity.accountId", source2 = "userIdentity.sessionContext.sessionIssuer.accountId", target = "actor.user.account.uid"},
    
    -- API Information
    {type = "direct", source = "errorCode", target = "api.response.error"},
    {type = "direct", source = "errorMessage", target = "api.response.error_message"},
    
    -- Request Parameters
    {type = "priority", source1 = "requestParameters.durationSeconds", source2 = "insightDetails.insightContext.statistics.insightDuration", target = "duration"},
    {type = "direct", source = "requestParameters.bucketName", target = "resources.name"},
    {type = "direct", source = "requestParameters.Host", target = "src_endpoint.hostname"},
    {type = "direct", source = "requestParameters.instanceId", target = "src_endpoint.instance_uid"},
    {type = "direct", source = "requestParameters.availabilityZone", target = "cloud.zone"},
    
    -- Response Elements
    {type = "direct", source = "responseElements.credentials.accessKeyId", target = "actor.session.credential_uid"},
    {type = "direct", source = "responseElements.credentials.expiration", target = "actor.session.expiration_time"},
    
    -- Additional Event Data
    {type = "direct", source = "additionalEventData.x-amz-id-2", target = "resources.uid"},
    {type = "direct", source = "tlsDetails.cipherSuite", target = "tls.cipher"},
    {type = "direct", source = "tlsDetails.tlsVersion", target = "tls.version"},
    
    -- Additional fields
    {type = "direct", source = "vpcEndpointId", target = "src_endpoint.uid"},
    {type = "direct", source = "apiVersion", target = "api.version"},
    {type = "direct", source = "message", target = "message"},
    {type = "priority", source1 = "eventSource", source2 = "insightDetails.eventSource", target = "api.service.name"},
    
    -- Individual resource field mappings (for single resource events)
    {type = "direct", source = "resources.accountId", target = "resource.account.uid"},
    {type = "direct", source = "resources.type", target = "resource.type"},
    {type = "direct", source = "resources.ARN", target = "resource.uid"},

    -- OCSF field mappings (direct from input)
    {type = "direct", source = "class_uid", target = "class_uid"},
    {type = "direct", source = "category_uid", target = "category_uid"}
  }
  
  -- Process all field mappings in one iteration
  for _, mapping in ipairs(fieldMappings) do
    if mapping.type == "direct" then
      setField(mapping.source, mapping.target)
    elseif mapping.type == "priority" then
      setFieldWithPriority(mapping.source1, mapping.source2, mapping.source3, mapping.target)
    end
  end
  
  -- Convert timestamps to milliseconds
  local creationDate = getNestedField(event, 'userIdentity.sessionContext.attributes.creationDate')
  if creationDate then
    local convertedTime = convertToMilliseconds(creationDate)
    if convertedTime then
      setNestedField(result, 'actor.session.created_time', convertedTime)
    end
  end
  
  local expirationDate = getNestedField(event, 'responseElements.credentials.expiration')
  if expirationDate then
    local convertedTime = convertToMilliseconds(expirationDate)
    if convertedTime then
      setNestedField(result, 'actor.session.expiration_time', convertedTime)
    end
  end
  
  -- Convert eventTime to time field
  local eventTime = getNestedField(event, 'eventTime')
  if eventTime then
    local convertedTime = convertToMilliseconds(eventTime)
    if convertedTime then
      -- we need to use milliseconds here to be compatible with S1
      setNestedField(result, 'time', convertedTime)
    end
  end
  
  -- Resources array handling
  if event.resources and type(event.resources) == "table" then
    local accountIds = {}
    local types = {}
    local arns = {}
    
    for _, resource in ipairs(event.resources) do
      if resource.accountId then table.insert(accountIds, resource.accountId) end
      if resource.type then table.insert(types, resource.type) end
      if resource.ARN then table.insert(arns, resource.ARN) end
    end
    
    if #accountIds > 0 then setNestedField(result, 'resource.account.uid', accountIds) end
    if #types > 0 then setNestedField(result, 'resource.type', types) end
    if #arns > 0 then setNestedField(result, 'resource.uid', arns) end
  end
  
  -- Priority-based default OCSF fields (only set if not already present)
  local function setDefaultIfNotExists(targetPath, defaultValue)
    local existingValue = getNestedField(result, targetPath)
    if existingValue == nil then
      setNestedField(result, targetPath, defaultValue)
    end
  end

  -- Static category mapping
  setDefaultIfNotExists('category_uid', 4)
    
  -- Static class mapping 
  setDefaultIfNotExists('class_uid', 4002)
  
  -- Set defaults only if fields don't already exist
  setDefaultIfNotExists('metadata.product.name', 'CloudTrail')
  setDefaultIfNotExists('metadata.product.vendor_name', 'AWS')
  setDefaultIfNotExists('metadata.version', '1.0.0-rc3')
  setDefaultIfNotExists('dataSource.vendor', 'AWS')
  setDefaultIfNotExists('dataSource.name', 'CloudTrail')
  setDefaultIfNotExists('dataSource.category', 'security')
  setDefaultIfNotExists('class_name', 'HTTP Activity')
  setDefaultIfNotExists('category_name', 'Network Activity')
  setDefaultIfNotExists('type_name', 'HTTP Activity: Other')
  setDefaultIfNotExists('type_uid', 400299)
  setDefaultIfNotExists('activity_id', 99)
  setDefaultIfNotExists('activity_name', event.eventName or '')
  setDefaultIfNotExists('event.type', event.eventName or '')
  setDefaultIfNotExists('severity_id', 99)
  setDefaultIfNotExists('status_id', 99)
  setDefaultIfNotExists('status', 'Other')
  
  -- Initialize observables array
  local observables = {}
  
  -- Add IP address observable
  if event.sourceIPAddress then
    table.insert(observables, {
      type_id = 2, 
      type = 'IP Address', 
      name = 'src_endpoint.ip', 
      value = event.sourceIPAddress
    })
  end
  
  -- Add ARN observable
  local arn = getNestedField(event, 'userIdentity.arn')
  if arn then
    table.insert(observables, {
      type_id = 99,
      type = 'Other',
      name = 'unmapped.userIdentity.arn',
      value = arn
    })
  end
  
  setNestedField(result, 'observables', observables)
  
  -- Add unmapped fields
  local unmapped = {}
  
  -- Add specific unmapped fields that should be preserved
  if event.eventName then unmapped.eventName = event.eventName end
  if event.readOnly ~= nil then unmapped.readOnly = event.readOnly end
  if event.resources then unmapped.resources = event.resources end
  if event.eventType then unmapped.eventType = event.eventType end
  if event.managementEvent ~= nil then unmapped.managementEvent = event.managementEvent end
  if event.sharedEventID then unmapped.sharedEventID = event.sharedEventID end
  
  -- Add additionalEventData fields as unmapped
  if event.additionalEventData then
    if event.additionalEventData.SignatureVersion then unmapped["additionalEventData.SignatureVersion"] = event.additionalEventData.SignatureVersion end
    if event.additionalEventData.CipherSuite then unmapped["additionalEventData.CipherSuite"] = event.additionalEventData.CipherSuite end
    if event.additionalEventData.bytesTransferredIn then unmapped["additionalEventData.bytesTransferredIn"] = event.additionalEventData.bytesTransferredIn end
    if event.additionalEventData.AuthenticationMethod then unmapped["additionalEventData.AuthenticationMethod"] = event.additionalEventData.AuthenticationMethod end
    if event.additionalEventData.bytesTransferredOut then unmapped["additionalEventData.bytesTransferredOut"] = event.additionalEventData.bytesTransferredOut end
  end
  
  -- Add all unmapped fields automatically
  -- Build comprehensive set of all mapped paths
  local mappedPaths = {}
  
  -- Add computed/mapped-by-logic paths
  mappedPaths['userIdentity.sessionContext.attributes.creationDate'] = true
  mappedPaths['responseElements.credentials.expiration'] = true
  
  -- Add all fieldMappings paths
  for _, mapping in ipairs(fieldMappings) do
    if mapping.type == "direct" then
      mappedPaths[mapping.source] = true
    elseif mapping.type == "priority" then
      if mapping.source1 then mappedPaths[mapping.source1] = true end
      if mapping.source2 then mappedPaths[mapping.source2] = true end
      if mapping.source3 then mappedPaths[mapping.source3] = true end
    end
  end
  
  for k, v in pairs(event) do
    -- Check if k is used as a source field in mapping
    local is_mapped = mappedPaths[k] == true
    
    -- Filter out Vector-specific fields that shouldn't be in unmapped
    local is_vector_field = (k == "_ob" or k == "site_id" or k == "timestamp")
    
    if not is_mapped and not is_vector_field then
      if type(v) == "table" then
        -- For nested objects, filter out only the mapped fields
        local function filterMappedFields(obj, prefix)
          local out = {}
          for nestedKey, nestedValue in pairs(obj) do
            local fullPath = prefix == "" and nestedKey or prefix .. "." .. nestedKey
            local isNestedMapped = mappedPaths[fullPath] == true
            
            -- Only include unmapped fields
            if not isNestedMapped then
              if type(nestedValue) == "table" then
                local child = filterMappedFields(nestedValue, fullPath)
                if next(child) then
                  out[nestedKey] = child
                end
              else
                out[nestedKey] = nestedValue
              end
            end
          end
          return out
        end
        
        local filteredObj = filterMappedFields(v, k)
        if next(filteredObj) then
          unmapped[k] = filteredObj
        end
      else
        -- Only add non-null and non-empty values
        if v ~= nil and v ~= "" then
          unmapped[k] = v
        end
      end
    end
  end
  
  
  if next(unmapped) then
    setNestedField(result, 'unmapped', unmapped)
  end
  
  -- Create message field with original event
  local cleanEvent = {}
  for key, value in pairs(event) do
    if key ~= "_ob" and key ~= "timestamp" then
      cleanEvent[key] = value
    end
  end
  
  if event.responseElements == nil then
    cleanEvent.responseElements = "NULL_PLACEHOLDER"
  end
  
  -- Add missing fields that should be in the message
  if event.readOnly == nil then
    cleanEvent.readOnly = true  -- Default for CloudTrail events
  end
  if event.eventType == nil then
    cleanEvent.eventType = "AwsApiCall"  -- Default for CloudTrail events
  end
  if event.managementEvent == nil then
    cleanEvent.managementEvent = true  -- Default for CloudTrail events
  end
  
  
         -- Flatten result
         local flattened = {}
         flattenObject(result, "", flattened)
         flattened.message = encodeJson(cleanEvent, "root")
  
  return flattened
end

-- Simplified helper functions
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
    if current == nil or current[key] == nil then
        return nil
      end
      current = current[key]
  end
  return current
end

function flattenObject(obj, prefix, result)
  prefix = prefix or ""
  if type(obj) ~= "table" then
    if prefix ~= "" then
      result[prefix] = obj
    end
    return
  end
  
  for key, value in pairs(obj) do
    local newKey = prefix == "" and key or prefix .. "." .. key
    if type(value) == "table" then
      local isArray = true
      local maxIndex = 0
      for k, v in pairs(value) do
        if type(k) ~= "number" then
          isArray = false
          break
        end
        maxIndex = math.max(maxIndex, k)
      end
      if isArray and maxIndex > 0 then
        local arrayValues = {}
        for i = 1, maxIndex do
          if value[i] ~= nil then
            table.insert(arrayValues, value[i])
          end
        end
        result[newKey] = arrayValues
      else
        flattenObject(value, newKey, result)
      end
    else
      result[newKey] = value
    end
  end
end
