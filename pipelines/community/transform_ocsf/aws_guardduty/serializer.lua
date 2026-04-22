-- AWS GuardDuty OCSF 1.0.0 parser (ported from Python)

-- Helper: split string by delimiter
local function split(str, delimiter)
    local result = {}
    local escaped = delimiter:gsub("[%.%+%*%?%^%$%(%)%[%]%%]", "%%%1")
    local pattern = "([^" .. escaped .. "]+)"
    for token in tostring(str):gmatch(pattern) do
        table.insert(result, token)
    end
    if #result == 0 and #tostring(str) > 0 then
        table.insert(result, str)
    end
    return result
end

-- Helper: safely access nested keys: keys is array, obj is table
local function getByPath(obj, keys)
    local current = obj
    for _, k in ipairs(keys) do
        if current ~= nil and type(current) == "table" then
            current = current[k]
        else
            return nil
        end
    end
    return current
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

-- Common mapping applied before specific finders
local function common_mapping(event, site_id)
    event["dataSource"] = { category = "security", name = "AWS GuardDuty", vendor = "AWS" }
    event["metadata"] = { version = "1.0.0", product = { name = "AWS GuardDuty", vendor_name = "AWS" } }
    event["cloudProvider"] = "AWS"
    event["cloudAccountType"] = "AWS Account"
    event["accountTypeId"] = 10
    if site_id ~= nil and site_id ~= "" then
        event["site"] = { id = site_id }
    end
    local sev = event["severity"]
    if type(sev) == "number" then
        if sev >= 1.0 and sev <= 2.9 then
            event["severity_id"] = 2
        elseif sev >= 4.0 and sev <= 6.9 then
            event["severity_id"] = 3
        elseif sev >= 7.0 and sev <= 8.9 then
            event["severity_id"] = 4
        else
            event["severity_id"] = 0
        end
    end
end

-- After mapping, convert lat/lon into coordinates and remove lat/lon fields based on activity_name
local function coordinates_mapping(parsed)
    local lat = parsed["lat"]
    local lon = parsed["lon"]
    if (type(lat) == "number" or type(lat) == "string") or (type(lon) == "number" or type(lon) == "string") then
        local latnum = tonumber(lat)
        local lonnum = tonumber(lon)
        if latnum and lonnum then
            local coords = { latnum, lonnum }
            local activity = parsed["activity_name"]
            if activity == "EC2 finding types" or
               activity == "EKS Runtime Monitoring finding types" or
               activity == "Kubernetes Audit Logs finding types" or
               activity == "RDS Protection finding types" or
               activity == "S3 finding types" then
                parsed["src_endpoint.location.coordinates"] = coords
                parsed["lat"], parsed["lon"] = nil, nil
            elseif activity == "IAM finding types" or activity == "Lambda Protection finding types" then
                parsed["device.location.coordinates"] = coords
                parsed["lat"], parsed["lon"] = nil, nil
            end
        end
    end
end

local function flatten_table(tbl, prefix, out)
  out = out or {}
  prefix = prefix or ""
  local hasArrayElements = false
  
  for k, v in pairs(tbl) do
    if type(k) == "number" then
      hasArrayElements = true
      break
    end
  end
  
  if hasArrayElements then
    -- This is an array, store it as-is
    if prefix ~= "" then
      out[prefix] = tbl
    end
    return out
  end
  
  for k, v in pairs(tbl) do
    local key = prefix ~= "" and (prefix .. "." .. k) or k
    if type(v) == "table" then
      flatten_table(v, key, out)
    else
      out[key] = v
    end
  end
  
  return out
end

-- Apply a mapping table of { [source_dotted] = target_dotted }
local function apply_mapping(event, mapping)
    local out = {}
    for src, dst in pairs(mapping) do
        local val = getByPath(event, split(src, "."))
        if val ~= nil then
            out[dst] = val
        end
    end

    -- NEW: auto-capture unmapped fields
    local copy = deepCopy(event)
    local flattenCopy = flatten_table(copy)
    for key, val in pairs(flattenCopy) do
        if mapping[key] == nil and val ~= nil and val ~= "" and val ~= "[]" and val ~= "()" and val ~= "{}" then
        out["unmapped." .. key] = val
        end
    end
    return out
end

local EC2_FIELD_ORDER = {
  message = {
    "schemaVersion", "accountId", "region", "partition","id", "arn", "type", "resource",
    "service", "severity", "createdAt", "updatedAt", "title", "description"
  },
  resource = {
    "resourceType", "instanceDetails"
  },
  instanceDetails = {
    "instanceId", "instanceType", "outpostArn", "launchTime", "platform", "productCodes",
    "iamInstanceProfile", "networkInterfaces", "tags", "instanceState", "availabilityZone",
    "imageId", "imageDescription"
  },
  productCodes = {
    "productCodeId", "productCodeType"
  },
  iamInstanceProfile = {
    "arn", "id"
  },
  networkInterfaces = {
    "ipv6Addresses", "networkInterfaceId", "privateDnsName", "privateIpAddress", 
    "privateIpAddresses", "subnetId", "vpcId", "securityGroups", "publicDnsName",
    "publicIp"
  },
  privateIpAddresses = {
    "privateDnsName", "privateIpAddress"
  },
  securityGroups = {
    "groupName", "groupId"
  },
  tags = {
    "key", "value"
  },
  service = {
    "serviceName", "detectorId", "action", "resourceRole", "additionalInfo", "evidence",
    "eventFirstSeen", "eventLastSeen", "archived", "count"
  },
  action = {
    "actionType", "networkConnectionAction"
  },
  networkConnectionAction = {
    "connectionDirection", "localIpDetails", "remoteIpDetails", "remotePortDetails", 
    "localPortDetails", "protocol", "blocked"
  },
  localIpDetails = {
    "ipAddressV4"
  },
  remoteIpDetails = {
    "ipAddressV4", "organization", "country", "city", "geoLocation"
  },
  organization = {
    "asn", "asnOrg", "isp", "org"
  },
  country = {
    "countryName"
  },
  city = {
    "cityName"
  },
  geoLocation = {
    "lat", "lon"
  },
  remotePortDetails = {
    "port", "portName"
  },
  localPortDetails = {
    "port", "portName"
  },
  additionalInfo = {
    "threatListName", "sample", "value", "type"
  },
  evidence = {
    "threatIntelligenceDetails"
  },
  threatIntelligenceDetails = {
    "threatListName", "threatNames"
  },
}

local EKS_RUNTIME_FIELD_ORDER = {
  message = {
    "schemaVersion", "accountId", "region", "partition", "id", "arn", "type", "resource",
    "service", "severity", "createdAt", "updatedAt", "title", "description"
  },
  resource = {
    "resourceType", "eksClusterDetails", "kubernetesDetails", "containerDetails", "instanceDetails"
  },
  eksClusterDetails = {
    "name", "arn", "createdAt", "vpcId", "status", "tags"
  },
  tags = {
    "key", "value"
  },
  kubernetesDetails = {
    "kubernetesWorkloadDetails"
  },
  kubernetesWorkloadDetails = {
    "name", "namespace", "type", "uid"
  },
  containerDetails = {
    "id", "name", "image"
  },
  instanceDetails = {
    "instanceId", "instanceType", "outpostArn", "launchTime", "platform", "productCodes",
    "iamInstanceProfile", "networkInterfaces", "tags", "instanceState", "availabilityZone",
    "imageId", "imageDescription"
  },
  productCodes = {
    "productCodeId", "productCodeType"
  },
  iamInstanceProfile = {
    "arn", "id"
  },
  networkInterfaces = {
    "ipv6Addresses", "networkInterfaceId", "privateDnsName", "privateIpAddress",
    "privateIpAddresses", "subnetId", "vpcId", "securityGroups", "publicDnsName", "publicIp"
  },
  privateIpAddresses = {
    "privateDnsName", "privateIpAddress"
  },
  securityGroups = {
    "groupName", "groupId"
  },
  service = {
    "serviceName", "detectorId", "action", "runtimeDetails", "featureName", "resourceRole",
    "additionalInfo", "evidence", "eventFirstSeen", "eventLastSeen", "archived", "count"
  },
  action = {
    "actionType", "dnsRequestAction"
  },
  dnsRequestAction = {
    "domain", "protocol", "blocked", "domainWithSuffix"
  },
  runtimeDetails = {
    "process"
  },
  process = {
    "pid", "name", "uuid", "executablePath", "executableSha256", "cmdLine", "user", "euid",
    "userId", "pwd", "startTime", "parentUuid", "lineage"
  },
  lineage = {
    "pid", "uuid", "executablePath", "euid", "parentUuid"
  },
  additionalInfo = {
    "threatListName", "sample", "agentDetails", "value", "type"
  },
  agentDetails = {
    "agentVersion", "agentId"
  },
  evidence = {
    "threatIntelligenceDetails"
  },
  threatIntelligenceDetails = {
    "threatListName", "threatNames"
  },
}

local IAM_FIELD_ORDER = {
  message = {
    "schemaVersion", "accountId", "region", "partition", "id", "arn", "type", "resource",
    "service", "severity", "createdAt", "updatedAt", "title", "description"
  },
  resource = {
    "resourceType", "accessKeyDetails", "instanceDetails"
  },
  accessKeyDetails = {
    "accessKeyId", "principalId", "userType", "userName"
  },
  instanceDetails = {
    "instanceId", "instanceType", "outpostArn", "launchTime", "platform", "productCodes",
    "iamInstanceProfile", "networkInterfaces", "tags", "instanceState", "availabilityZone",
    "imageId", "imageDescription"
  },
  productCodes = {
    "productCodeId", "productCodeType"
  },
  iamInstanceProfile = {
    "arn", "id"
  },
  networkInterfaces = {
    "ipv6Addresses", "networkInterfaceId", "privateDnsName", "privateIpAddress",
    "privateIpAddresses", "subnetId", "vpcId", "securityGroups", "publicDnsName", "publicIp"
  },
  privateIpAddresses = {
    "privateDnsName", "privateIpAddress"
  },
  securityGroups = {
    "groupName", "groupId"
  },
  tags = {
    "key", "value"
  },
  service = {
    "serviceName", "detectorId", "action", "resourceRole", "additionalInfo", "evidence",
    "eventFirstSeen", "eventLastSeen", "archived", "count"
  },
  action = {
    "actionType", "awsApiCallAction"
  },
  awsApiCallAction = {
    "api", "serviceName", "callerType", "errorCode", "remoteIpDetails", "affectedResources"
  },
  remoteIpDetails = {
    "ipAddressV4", "organization", "country", "city", "geoLocation"
  },
  organization = {
    "asn", "asnOrg", "isp", "org"
  },
  country = {
    "countryName"
  },
  city = {
    "cityName"
  },
  geoLocation = {
    "lat", "lon"
  },
  additionalInfo = {
    "userAgent", "anomalies", "profiledBehavior", "unusualBehavior", "sample", "value", "type"
  },
  userAgent = {
    "fullUserAgent", "userAgentCategory"
  },
  anomalies = {
    "anomalousAPIs"
  },
  profiledBehavior = {
    "rareProfiledAPIsAccountProfiling", "infrequentProfiledAPIsAccountProfiling",
    "frequentProfiledAPIsAccountProfiling", "rareProfiledAPIsUserIdentityProfiling",
    "infrequentProfiledAPIsUserIdentityProfiling", "frequentProfiledAPIsUserIdentityProfiling",
    "rareProfiledUserTypesAccountProfiling", "infrequentProfiledUserTypesAccountProfiling",
    "frequentProfiledUserTypesAccountProfiling", "rareProfiledUserNamesAccountProfiling",
    "infrequentProfiledUserNamesAccountProfiling", "frequentProfiledUserNamesAccountProfiling",
    "rareProfiledASNsAccountProfiling", "infrequentProfiledASNsAccountProfiling",
    "frequentProfiledASNsAccountProfiling", "rareProfiledASNsUserIdentityProfiling",
    "infrequentProfiledASNsUserIdentityProfiling", "frequentProfiledASNsUserIdentityProfiling",
    "rareProfiledUserAgentsAccountProfiling", "infrequentProfiledUserAgentsAccountProfiling",
    "frequentProfiledUserAgentsAccountProfiling", "rareProfiledUserAgentsUserIdentityProfiling",
    "infrequentProfiledUserAgentsUserIdentityProfiling", "frequentProfiledUserAgentsUserIdentityProfiling"
  },
  unusualBehavior = {
    "unusualAPIsAccountProfiling", "unusualAPIsUserIdentityProfiling",
    "unusualUserTypesAccountProfiling", "unusualUserNamesAccountProfiling",
    "unusualASNsAccountProfiling", "unusualASNsUserIdentityProfiling",
    "unusualUserAgentsAccountProfiling", "unusualUserAgentsUserIdentityProfiling",
    "isUnusualUserIdentity"
  },
}

local KUBERNETES_AUDIT_LOGS_FIELD_ORDER = {
  message = {
    "schemaVersion", "accountId", "region", "partition", "id", "arn", "type", "resource",
    "service", "severity", "createdAt", "updatedAt", "title", "description"
  },
  resource = {
    "resourceType", "eksClusterDetails", "kubernetesDetails", "accessKeyDetails"
  },
  eksClusterDetails = {
    "name", "arn", "createdAt", "vpcId", "status", "tags"
  },
  tags = {
    "key", "value"
  },
  kubernetesDetails = {
    "kubernetesWorkloadDetails", "kubernetesUserDetails"
  },
  kubernetesWorkloadDetails = {
    "name", "namespace", "type", "uid"
  },
  kubernetesUserDetails = {
    "username", "uid", "groups", "sessionName"
  },
  accessKeyDetails = {
    "accessKeyId", "principalId", "userType", "userName"
  },
  service = {
    "serviceName", "detectorId", "action", "resourceRole", "additionalInfo", "evidence",
    "eventFirstSeen", "eventLastSeen", "archived", "count"
  },
  action = {
    "actionType", "kubernetesApiCallAction"
  },
  kubernetesApiCallAction = {
    "requestUri", "verb", "sourceIPs", "userAgent", "remoteIpDetails", "statusCode"
  },
  remoteIpDetails = {
    "ipAddressV4", "organization", "country", "city", "geoLocation"
  },
  organization = {
    "asn", "asnOrg", "isp", "org"
  },
  country = {
    "countryName"
  },
  city = {
    "cityName"
  },
  geoLocation = {
    "lat", "lon"
  },
  additionalInfo = {
    "threatName", "threatListName", "sample", "value", "type"
  },
  evidence = {
    "threatIntelligenceDetails"
  },
  threatIntelligenceDetails = {
    "threatListName", "threatNames"
  },
}

local LAMBDA_PROTECTION_FIELD_ORDER = {
  message = {
    "schemaVersion", "accountId", "region", "partition", "id", "arn", "type", "resource",
    "service", "severity", "createdAt", "updatedAt", "title", "description"
  },
  resource = {
    "resourceType", "lambdaDetails"
  },
  lambdaDetails = {
    "functionArn", "functionName", "description", "lastModifiedAt", "revisionId",
    "functionVersion", "role", "vpcConfig", "tags"
  },
  vpcConfig = {
    "vpcId", "securityGroups", "subnetIds"
  },
  securityGroups = {
    "groupName", "groupId"
  },
  tags = {
    "key", "value"
  },
  service = {
    "serviceName", "detectorId", "action", "resourceRole", "additionalInfo", "evidence",
    "eventFirstSeen", "eventLastSeen", "archived", "count"
  },
  action = {
    "actionType", "networkConnectionAction"
  },
  networkConnectionAction = {
    "connectionDirection", "remoteIpDetails", "remotePortDetails", "protocol", "blocked"
  },
  remoteIpDetails = {
    "ipAddressV4", "organization", "country", "city", "geoLocation"
  },
  organization = {
    "asn", "asnOrg", "isp", "org"
  },
  country = {
    "countryName"
  },
  city = {
    "cityName"
  },
  geoLocation = {
    "lat", "lon"
  },
  remotePortDetails = {
    "port", "portName"
  },
  additionalInfo = {
    "unusualProtocol", "threatListName", "unusual", "sample", "value", "type"
  },
  evidence = {
    "threatIntelligenceDetails"
  },
  threatIntelligenceDetails = {
    "threatListName", "threatNames"
  },
}

local MALWARE_PROTECTION_FIELD_ORDER = {
  message = {
    "schemaVersion", "accountId", "region", "partition", "id", "arn", "type", "resource",
    "service", "severity", "createdAt", "updatedAt", "title", "description"
  },
  resource = {
    "resourceType", "instanceDetails", "ebsVolumeDetails"
  },
  instanceDetails = {
    "instanceId", "instanceType", "outpostArn", "launchTime", "platform", "productCodes",
    "iamInstanceProfile", "networkInterfaces", "tags", "instanceState", "availabilityZone",
    "imageId", "imageDescription"
  },
  productCodes = {
    "productCodeId", "productCodeType"
  },
  iamInstanceProfile = {
    "arn", "id"
  },
  networkInterfaces = {
    "ipv6Addresses", "networkInterfaceId", "privateDnsName", "privateIpAddress",
    "privateIpAddresses", "subnetId", "vpcId", "securityGroups", "publicDnsName", "publicIp"
  },
  privateIpAddresses = {
    "privateDnsName", "privateIpAddress"
  },
  securityGroups = {
    "groupName", "groupId"
  },
  tags = {
    "key", "value"
  },
  ebsVolumeDetails = {
    "scannedVolumeDetails", "skippedVolumeDetails"
  },
  scannedVolumeDetails = {
    "volumeArn", "volumeType", "deviceName", "volumeSizeInGB", "encryptionType", "snapshotArn", "kmsKeyArn"
  },
  service = {
    "serviceName", "detectorId", "featureName", "ebsVolumeScanDetails", "additionalInfo", "evidence",
    "eventFirstSeen", "eventLastSeen", "archived", "count"
  },
  ebsVolumeScanDetails = {
    "scanId", "scanStartedAt", "scanCompletedAt", "scanType", "triggerFindingId", "sources", "scanDetections"
  },
  scanDetections = {
    "scannedItemCount", "threatsDetectedItemCount", "highestSeverityThreatDetails", "threatDetectedByName"
  },
  scannedItemCount = {
    "totalGb", "files", "volumes"
  },
  threatsDetectedItemCount = {
    "files"
  },
  highestSeverityThreatDetails = {
    "severity", "threatName", "count"
  },
  threatDetectedByName = {
    "itemCount", "uniqueThreatNameCount", "shortened", "threatNames"
  },
  threatNames = {
    "name", "severity", "itemCount", "filePaths"
  },
  filePaths = {
    "filePath", "fileName", "volumeArn", "hash"
  },
  additionalInfo = {
    "sample", "value", "type"
  },
}

local RDS_PROTECTION_FIELD_ORDER = {
  message = {
    "schemaVersion", "accountId", "region", "partition", "id", "arn", "type", "resource",
    "service", "severity", "createdAt", "updatedAt", "title", "description"
  },
  resource = {
    "resourceType", "rdsDbInstanceDetails", "rdsDbUserDetails"
  },
  rdsDbInstanceDetails = {
    "dbInstanceIdentifier", "engine", "engineVersion", "dbClusterIdentifier", "dbInstanceArn", "tags"
  },
  tags = {
    "key", "value"
  },
  rdsDbUserDetails = {
    "user", "application", "database", "ssl", "authMethod"
  },
  service = {
    "action", "additionalInfo", "resourceRole", "evidence", "count", "detectorId",
    "eventFirstSeen", "eventLastSeen", "serviceName", "archived"
  },
  action = {
    "actionType", "rdsLoginAttemptAction"
  },
  rdsLoginAttemptAction = {
    "remoteIpDetails"
  },
  remoteIpDetails = {
    "ipAddressV4", "organization", "country", "city", "geoLocation"
  },
  organization = {
    "asn", "asnOrg", "isp", "org"
  },
  country = {
    "countryName"
  },
  city = {
    "cityName"
  },
  geoLocation = {
    "lat", "lon"
  },
  additionalInfo = {
    "sample", "value", "type"
  },
  evidence = {
    "threatIntelligenceDetails"
  },
  threatIntelligenceDetails = {
    "threatListName", "threatNames"
  },
}

local S3_FIELD_ORDER = {
  message = {
    "schemaVersion", "accountId", "region", "partition", "id", "arn", "type", "resource",
    "service", "severity", "createdAt", "updatedAt", "title", "description"
  },
  resource = {
    "resourceType", "accessKeyDetails", "s3BucketDetails", "instanceDetails"
  },
  accessKeyDetails = {
    "accessKeyId", "principalId", "userType", "userName"
  },
  s3BucketDetails = {
    "arn", "name", "type", "createdAt", "owner", "tags", "defaultServerSideEncryption", "publicAccess"
  },
  owner = {
    "id"
  },
  tags = {
    "key", "value"
  },
  defaultServerSideEncryption = {
    "encryptionType", "kmsMasterKeyArn"
  },
  publicAccess = {
    "permissionConfiguration", "effectivePermission"
  },
  permissionConfiguration = {
    "bucketLevelPermissions", "accountLevelPermissions"
  },
  bucketLevelPermissions = {
    "accessControlList", "bucketPolicy", "blockPublicAccess"
  },
  accessControlList = {
    "allowsPublicReadAccess", "allowsPublicWriteAccess"
  },
  bucketPolicy = {
    "allowsPublicReadAccess", "allowsPublicWriteAccess"
  },
  blockPublicAccess = {
    "ignorePublicAcls", "restrictPublicBuckets", "blockPublicAcls", "blockPublicPolicy"
  },
  accountLevelPermissions = {
    "blockPublicAccess"
  },
  instanceDetails = {
    "instanceId", "instanceType", "outpostArn", "launchTime", "platform", "productCodes",
    "iamInstanceProfile", "networkInterfaces", "tags", "instanceState", "availabilityZone",
    "imageId", "imageDescription"
  },
  productCodes = {
    "productCodeId", "productCodeType"
  },
  iamInstanceProfile = {
    "arn", "id"
  },
  networkInterfaces = {
    "ipv6Addresses", "networkInterfaceId", "privateDnsName", "privateIpAddress",
    "privateIpAddresses", "subnetId", "vpcId", "securityGroups", "publicDnsName", "publicIp"
  },
  privateIpAddresses = {
    "privateDnsName", "privateIpAddress"
  },
  securityGroups = {
    "groupName", "groupId"
  },
  service = {
    "serviceName", "detectorId", "action", "resourceRole", "additionalInfo",
    "eventFirstSeen", "eventLastSeen", "archived", "count"
  },
  action = {
    "actionType", "awsApiCallAction"
  },
  awsApiCallAction = {
    "api", "serviceName", "callerType", "errorCode", "remoteIpDetails", "affectedResources"
  },
  remoteIpDetails = {
    "ipAddressV4", "organization", "country", "city", "geoLocation"
  },
  organization = {
    "asn", "asnOrg", "isp", "org"
  },
  country = {
    "countryName"
  },
  city = {
    "cityName"
  },
  geoLocation = {
    "lat", "lon"
  },
  additionalInfo = {
    "unusual", "sample", "value", "type"
  },
  unusual = {
    "hoursOfDay", "userNames"
  },
}

local function get_msg_field_ordering(family)
    if family == "ec2" then return EC2_FIELD_ORDER end
    if family == "runtime" or family == "eks_runtime" or family == "runtime_monitoring" then return EKS_RUNTIME_FIELD_ORDER end
    if family == "iam" then return IAM_FIELD_ORDER end
    if family == "kubernetes" or family == "k8s" then return KUBERNETES_AUDIT_LOGS_FIELD_ORDER end
    if family == "lambda" then return LAMBDA_PROTECTION_FIELD_ORDER end
    if family == "malware" then return MALWARE_PROTECTION_FIELD_ORDER end
    if family == "rds" then return RDS_PROTECTION_FIELD_ORDER end
    if family == "s3" then return S3_FIELD_ORDER end
    return {}
end

-- OCSF Mappings (ported 1:1 from Python)
local function ec2_findings_ocsf_mapping()
    return {
        ["schemaVersion"] = "metadata.log_version",
        ["accountId"] = "cloud.account.uid",
        ["region"] = "cloud.region",
        ["id"] = "metadata.uid",
        ["type"] = "metadata.log_name",
        ["resource.resourceType"] = "metadata.log_provider",
        ["resource.instanceDetails.instanceId"] = "device.instance_uid",
        ["resource.instanceDetails.networkInterfaces"] = "device.network_interfaces",
        ["resource.instanceDetails.imageId"] = "device.image.uid",
        ["service.serviceName"] = "src_endpoint.svc_name",
        ["service.detectorId"] = "src_endpoint.uid",
        ["service.action.networkConnectionAction.localIpDetails.ipAddressV4"] = "src_endpoint.ip",
        ["service.action.networkConnectionAction.remoteIpDetails.organization.isp"] = "src_endpoint.location.isp",
        ["service.action.networkConnectionAction.remoteIpDetails.country.countryName"] = "src_endpoint.location.country",
        ["service.action.networkConnectionAction.remoteIpDetails.city.cityName"] = "src_endpoint.location.city",
        ["service.action.networkConnectionAction.remoteIpDetails.geoLocation.lat"] = "lat",
        ["service.action.networkConnectionAction.remoteIpDetails.geoLocation.lon"] = "lon",
        ["service.action.networkConnectionAction.localPortDetails.port"] = "src_endpoint.port",
        ["service.action.networkConnectionAction.protocol"] = "connection_info.protocol_name",
        ["service.eventFirstSeen"] = "start_time",
        ["service.eventLastSeen"] = "end_time",
        ["createdAt"] = "metadata.original_time",
        ["updatedAt"] = "metadata.modified_time",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

local function runtime_monitoring_findings_ocsf_mapping()
    return {
        ["schemaVersion"] = "metadata.log_version",
        ["accountId"] = "cloud.account.uid",
        ["region"] = "cloud.region",
        ["id"] = "metadata.uid",
        ["type"] = "metadata.log_name",
        ["resource.resourceType"] = "metadata.log_provider",
        ["resource.instanceDetails.instanceId"] = "device.instance_uid",
        ["resource.instanceDetails.networkInterfaces"] = "device.network_interfaces",
        ["resource.instanceDetails.imageId"] = "device.image.uid",
        ["service.runtimeDetails.process.pid"] = "actor.process.uid",
        ["service.runtimeDetails.process.name"] = "actor.process.name",
        ["service.runtimeDetails.process.user"] = "actor.user.name",
        ["service.runtimeDetails.process.userId"] = "actor.user.uid",
        ["service.runtimeDetails.process.parentUuid"] = "actor.process.parent_process.uid",
        ["service.action.networkConnectionAction.remoteIpDetails.geoLocation.lat"] = "lat",
        ["service.action.networkConnectionAction.remoteIpDetails.geoLocation.lon"] = "lon",
        ["service.featureName"] = "api.service.name",
        ["service.eventFirstSeen"] = "start_time",
        ["service.eventLastSeen"] = "end_time",
        ["createdAt"] = "metadata.original_time",
        ["updatedAt"] = "metadata.modified_time",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

local function iam_findings_ocsf_mapping()
    return {
        ["schemaVersion"] = "metadata.log_version",
        ["accountId"] = "cloud.account.uid",
        ["region"] = "cloud.region",
        ["id"] = "metadata.uid",
        ["type"] = "metadata.log_name",
        ["resource.resourceType"] = "metadata.log_provider",
        ["resource.accessKeyDetails.accessKeyId"] = "actor.session.credential_uid",
        ["resource.accessKeyDetails.principalId"] = "actor.session.uid",
        ["resource.accessKeyDetails.userName"] = "actor.user.name",
        ["resource.instanceDetails.instanceId"] = "device.instance_uid",
        ["resource.instanceDetails.networkInterfaces"] = "device.network_interfaces",
        ["resource.instanceDetails.imageId"] = "device.image.uid",
        ["service.action.awsApiCallAction.serviceName"] = "api.service.name",
        ["service.action.awsApiCallAction.remoteIpDetails.organization.isp"] = "device.location.isp",
        ["service.action.awsApiCallAction.remoteIpDetails.country.countryName"] = "device.location.country",
        ["service.action.awsApiCallAction.remoteIpDetails.city.cityName"] = "device.location.city",
        ["service.action.awsApiCallAction.remoteIpDetails.geoLocation.lat"] = "lat",
        ["service.action.awsApiCallAction.remoteIpDetails.geoLocation.lon"] = "lon",
        ["service.eventFirstSeen"] = "start_time",
        ["service.eventLastSeen"] = "end_time",
        ["createdAt"] = "metadata.original_time",
        ["updatedAt"] = "metadata.modified_time",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

local function kubernetes_audit_log_findings_ocsf_mapping()
    return {
        ["schemaVersion"] = "metadata.log_version",
        ["accountId"] = "cloud.account.uid",
        ["region"] = "cloud.region",
        ["id"] = "metadata.uid",
        ["type"] = "metadata.log_name",
        ["resource.resourceType"] = "metadata.log_provider",
        ["resource.kubernetesDetails.kubernetesUserDetails.username"] = "actor.user.name",
        ["resource.kubernetesDetails.kubernetesUserDetails.uid"] = "actor.user.uid",
        ["resource.kubernetesDetails.kubernetesUserDetails.groups"] = "actor.user.groups",
        ["resource.accessKeyDetails.accessKeyId"] = "actor.session.credential_uid",
        ["resource.accessKeyDetails.principalId"] = "actor.session.uid",
        ["service.serviceName"] = "src_endpoint.svc_name",
        ["service.detectorId"] = "src_endpoint.uid",
        ["service.action.kubernetesApiCallAction.requestUri"] = "http_request.url.url_string",
        ["service.action.kubernetesApiCallAction.verb"] = "http_request.http_method",
        ["service.action.kubernetesApiCallAction.remoteIpDetails.organization.isp"] = "src_endpoint.location.isp",
        ["service.action.kubernetesApiCallAction.remoteIpDetails.country.countryName"] = "src_endpoint.location.country",
        ["service.action.kubernetesApiCallAction.remoteIpDetails.city.cityName"] = "src_endpoint.location.city",
        ["service.action.kubernetesApiCallAction.remoteIpDetails.geoLocation.lat"] = "lat",
        ["service.action.kubernetesApiCallAction.remoteIpDetails.geoLocation.lon"] = "lon",
        ["service.action.kubernetesApiCallAction.statusCode"] = "status_code",
        ["service.eventFirstSeen"] = "start_time",
        ["service.eventLastSeen"] = "end_time",
        ["createdAt"] = "metadata.original_time",
        ["updatedAt"] = "metadata.modified_time",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

local function lambda_findings_ocsf_mapping()
    return {
        ["schemaVersion"] = "metadata.log_version",
        ["accountId"] = "cloud.account.uid",
        ["region"] = "cloud.region",
        ["id"] = "metadata.uid",
        ["type"] = "metadata.log_name",
        ["resource.resourceType"] = "metadata.log_provider",
        ["service.action.networkConnectionAction.remoteIpDetails.organization.isp"] = "device.location.isp",
        ["service.action.networkConnectionAction.remoteIpDetails.country.countryName"] = "device.location.country",
        ["service.action.networkConnectionAction.remoteIpDetails.city.cityName"] = "device.location.city",
        ["service.action.networkConnectionAction.remoteIpDetails.geoLocation.lat"] = "lat",
        ["service.action.networkConnectionAction.remoteIpDetails.geoLocation.lon"] = "lon",
        ["service.eventFirstSeen"] = "start_time",
        ["service.eventLastSeen"] = "end_time",
        ["createdAt"] = "metadata.original_time",
        ["updatedAt"] = "metadata.modified_time",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

local function malware_findings_ocsf_mapping()
    return {
        ["schemaVersion"] = "metadata.log_version",
        ["accountId"] = "cloud.account.uid",
        ["region"] = "cloud.region",
        ["partition"] = "resources.cloud_partition",
        ["id"] = "metadata.uid",
        ["type"] = "metadata.log_name",
        ["resource.resourceType"] = "metadata.log_provider",
        ["service.featureName"] = "api.service.name",
        ["service.ebsVolumeScanDetails.scanId"] = "api.service.uid",
        ["service.ebsVolumeScanDetails.scanStartedAt"] = "finding.first_seen_time",
        ["service.ebsVolumeScanDetails.scanCompletedAt"] = "finding.last_seen_time",
        ["service.ebsVolumeScanDetails.triggerFindingId"] = "finding.uid",
        ["service.eventFirstSeen"] = "start_time",
        ["service.eventLastSeen"] = "end_time",
        ["createdAt"] = "metadata.original_time",
        ["updatedAt"] = "metadata.modified_time",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

local function rds_findings_ocsf_mapping()
    return {
        ["schemaVersion"] = "metadata.log_version",
        ["accountId"] = "cloud.account.uid",
        ["region"] = "cloud.region",
        ["id"] = "metadata.uid",
        ["type"] = "metadata.log_name",
        ["resource.resourceType"] = "metadata.log_provider",
        ["service.action.rdsLoginAttemptAction.remoteIpDetails.organization.isp"] = "src_endpoint.location.isp",
        ["service.action.rdsLoginAttemptAction.remoteIpDetails.country.countryName"] = "src_endpoint.location.country",
        ["service.action.rdsLoginAttemptAction.remoteIpDetails.city.cityName"] = "src_endpoint.location.city",
        ["service.action.rdsLoginAttemptAction.remoteIpDetails.geoLocation.lat"] = "lat",
        ["service.action.rdsLoginAttemptAction.remoteIpDetails.geoLocation.lon"] = "lon",
        ["service.detectorId"] = "src_endpoint.uid",
        ["service.eventFirstSeen"] = "start_time",
        ["service.eventLastSeen"] = "end_time",
        ["service.serviceName"] = "src_endpoint.svc_name",
        ["createdAt"] = "metadata.original_time",
        ["updatedAt"] = "metadata.modified_time",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

local function s3_findings_ocsf_mapping()
    return {
        ["schemaVersion"] = "metadata.log_version",
        ["accountId"] = "cloud.account.uid",
        ["region"] = "cloud.region",
        ["partition"] = "resources.cloud_partition",
        ["id"] = "metadata.uid",
        ["type"] = "metadata.log_name",
        ["resource.resourceType"] = "metadata.log_provider",
        ["resource.accessKeyDetails.accessKeyId"] = "resources.user.credential_uid",
        ["resource.accessKeyDetails.userType"] = "resources.user.type",
        ["resource.accessKeyDetails.userName"] = "resources.user.name",
        ["service.serviceName"] = "src_endpoint.svc_name",
        ["service.detectorId"] = "src_endpoint.uid",
        ["service.action.awsApiCallAction.serviceName"] = "api.service.name",
        ["service.action.awsApiCallAction.remoteIpDetails.organization.isp"] = "src_endpoint.location.isp",
        ["service.action.awsApiCallAction.remoteIpDetails.country.countryName"] = "src_endpoint.location.country",
        ["service.action.awsApiCallAction.remoteIpDetails.city.cityName"] = "src_endpoint.location.city",
        ["service.action.awsApiCallAction.remoteIpDetails.geoLocation.lat"] = "lat",
        ["service.action.awsApiCallAction.remoteIpDetails.geoLocation.lon"] = "lon",
        ["service.eventFirstSeen"] = "start_time",
        ["service.eventLastSeen"] = "end_time",
        ["createdAt"] = "metadata.original_time",
        ["updatedAt"] = "metadata.modified_time",
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

local function unknown_findings_ocsf_mapping()
    return {
        ["class_uid"] = "class_uid",
        ["class_name"] = "class_name",
        ["category_uid"] = "category_uid",
        ["category_name"] = "category_name",
        ["activity_id"] = "activity_id",
        ["activity_name"] = "activity_name",
        ["type_uid"] = "type_uid",
        ["type_name"] = "type_name",
        ["eventId"] = "event.type",
        ["severity_id"] = "severity_id",
        ["metadata.version"] = "metadata.version",
        ["metadata.product.name"] = "metadata.product.name",
        ["metadata.product.vendor_name"] = "metadata.product.vendor_name",
        ["dataSource.vendor"] = "dataSource.vendor",
        ["dataSource.name"] = "dataSource.name",
        ["dataSource.category"] = "dataSource.category",
        ["site.id"] = "site.id",
        ["cloudProvider"] = "cloud.provider",
        ["accountTypeId"] = "cloud.account.type_id",
        ["cloudAccountType"] = "cloud.account.type",
        ["message"] = "message",
    }
end

-- Finding types constants
local ec2_finding_types = {
    ["Backdoor:EC2/C&CActivity.B"] = true,
    ["Backdoor:EC2/C&CActivity.B!DNS"] = true,
    ["Backdoor:EC2/DenialOfService.Dns"] = true,
    ["Backdoor:EC2/DenialOfService.Tcp"] = true,
    ["Backdoor:EC2/DenialOfService.Udp"] = true,
    ["Backdoor:EC2/DenialOfService.UdpOnTcpPorts"] = true,
    ["Backdoor:EC2/DenialOfService.UnusualProtocol"] = true,
    ["Backdoor:EC2/Spambot"] = true,
    ["Behavior:EC2/NetworkPortUnusual"] = true,
    ["Behavior:EC2/TrafficVolumeUnusual"] = true,
    ["CryptoCurrency:EC2/BitcoinTool.B"] = true,
    ["CryptoCurrency:EC2/BitcoinTool.B!DNS"] = true,
    ["DefenseEvasion:EC2/UnusualDNSResolver"] = true,
    ["DefenseEvasion:EC2/UnusualDoHActivity"] = true,
    ["DefenseEvasion:EC2/UnusualDoTActivity"] = true,
    ["Impact:EC2/AbusedDomainRequest.Reputation"] = true,
    ["Impact:EC2/BitcoinDomainRequest.Reputation"] = true,
    ["Impact:EC2/MaliciousDomainRequest.Reputation"] = true,
    ["Impact:EC2/PortSweep"] = true,
    ["Impact:EC2/SuspiciousDomainRequest.Reputation"] = true,
    ["Impact:EC2/WinRMBruteForce"] = true,
    ["Recon:EC2/PortProbeEMRUnprotectedPort"] = true,
    ["Recon:EC2/PortProbeUnprotectedPort"] = true,
    ["Recon:EC2/Portscan"] = true,
    ["Trojan:EC2/BlackholeTraffic"] = true,
    ["Trojan:EC2/BlackholeTraffic!DNS"] = true,
    ["Trojan:EC2/DGADomainRequest.B"] = true,
    ["Trojan:EC2/DGADomainRequest.C!DNS"] = true,
    ["Trojan:EC2/DNSDataExfiltration"] = true,
    ["Trojan:EC2/DriveBySourceTraffic!DNS"] = true,
    ["Trojan:EC2/DropPoint"] = true,
    ["Trojan:EC2/DropPoint!DNS"] = true,
    ["Trojan:EC2/PhishingDomainRequest!DNS"] = true,
    ["UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"] = true,
    ["UnauthorizedAccess:EC2/MetadataDNSRebind"] = true,
    ["UnauthorizedAccess:EC2/RDPBruteForce"] = true,
    ["UnauthorizedAccess:EC2/SSHBruteForce"] = true,
    ["UnauthorizedAccess:EC2/TorClient"] = true,
    ["UnauthorizedAccess:EC2/TorRelay"] = true
}

local runtime_monitoring_finding_types = {
    ["CryptoCurrency:Runtime/BitcoinTool.B"] = true,
    ["Backdoor:Runtime/C&CActivity.B"] = true,
    ["UnauthorizedAccess:Runtime/TorRelay"] = true,
    ["UnauthorizedAccess:Runtime/TorClient"] = true,
    ["Trojan:Runtime/BlackholeTraffic"] = true,
    ["Trojan:Runtime/DropPoint"] = true,
    ["CryptoCurrency:Runtime/BitcoinTool.B!DNS"] = true,
    ["Backdoor:Runtime/C&CActivity.B!DNS"] = true,
    ["Trojan:Runtime/BlackholeTraffic!DNS"] = true,
    ["Trojan:Runtime/DropPoint!DNS"] = true,
    ["Trojan:Runtime/DGADomainRequest.C!DNS"] = true,
    ["Trojan:Runtime/DriveBySourceTraffic!DNS"] = true,
    ["Trojan:Runtime/PhishingDomainRequest!DNS"] = true,
    ["Impact:Runtime/AbusedDomainRequest.Reputation"] = true,
    ["Impact:Runtime/BitcoinDomainRequest.Reputation"] = true,
    ["Impact:Runtime/MaliciousDomainRequest.Reputation"] = true,
    ["Impact:Runtime/SuspiciousDomainRequest.Reputation"] = true,
    ["UnauthorizedAccess:Runtime/MetadataDNSRebind"] = true,
    ["Execution:Runtime/NewBinaryExecuted"] = true,
    ["PrivilegeEscalation:Runtime/DockerSocketAccessed"] = true,
    ["PrivilegeEscalation:Runtime/RuncContainerEscape"] = true,
    ["PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified"] = true,
    ["DefenseEvasion:Runtime/ProcessInjection.Proc"] = true,
    ["DefenseEvasion:Runtime/ProcessInjection.Ptrace"] = true,
    ["DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite"] = true,
    ["Execution:Runtime/ReverseShell"] = true,
    ["DefenseEvasion:Runtime/FilelessExecution"] = true,
    ["Impact:Runtime/CryptoMinerExecuted"] = true,
    ["Execution:Runtime/NewLibraryLoaded"] = true,
    ["PrivilegeEscalation:Runtime/ContainerMountsHostDirectory"] = true,
    ["PrivilegeEscalation:Runtime/UserfaultfdUsage"] = true
}

local iam_finding_types = {
    ["CredentialAccess:IAMUser/AnomalousBehavior"] = true,
    ["DefenseEvasion:IAMUser/AnomalousBehavior"] = true,
    ["Discovery:IAMUser/AnomalousBehavior"] = true,
    ["Exfiltration:IAMUser/AnomalousBehavior"] = true,
    ["Impact:IAMUser/AnomalousBehavior"] = true,
    ["InitialAccess:IAMUser/AnomalousBehavior"] = true,
    ["PenTest:IAMUser/KaliLinux"] = true,
    ["PenTest:IAMUser/ParrotLinux"] = true,
    ["PenTest:IAMUser/PentooLinux"] = true,
    ["Persistence:IAMUser/AnomalousBehavior"] = true,
    ["Policy:IAMUser/RootCredentialUsage"] = true,
    ["PrivilegeEscalation:IAMUser/AnomalousBehavior"] = true,
    ["Recon:IAMUser/MaliciousIPCaller"] = true,
    ["Recon:IAMUser/MaliciousIPCaller.Custom"] = true,
    ["Recon:IAMUser/TorIPCaller"] = true,
    ["Stealth:IAMUser/CloudTrailLoggingDisabled"] = true,
    ["Stealth:IAMUser/PasswordPolicyChange"] = true,
    ["UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B"] = true,
    ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"] = true,
    ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"] = true,
    ["UnauthorizedAccess:IAMUser/MaliciousIPCaller"] = true,
    ["UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"] = true,
    ["UnauthorizedAccess:IAMUser/TorIPCaller"] = true
}

local kubernetes_audit_logs_finding_types = {
    ["CredentialAccess:Kubernetes/MaliciousIPCaller"] = true,
    ["CredentialAccess:Kubernetes/MaliciousIPCaller.Custom"] = true,
    ["CredentialAccess:Kubernetes/SuccessfulAnonymousAccess"] = true,
    ["CredentialAccess:Kubernetes/TorIPCaller"] = true,
    ["DefenseEvasion:Kubernetes/MaliciousIPCaller"] = true,
    ["DefenseEvasion:Kubernetes/MaliciousIPCaller.Custom"] = true,
    ["DefenseEvasion:Kubernetes/SuccessfulAnonymousAccess"] = true,
    ["DefenseEvasion:Kubernetes/TorIPCaller"] = true,
    ["Discovery:Kubernetes/MaliciousIPCaller"] = true,
    ["Discovery:Kubernetes/MaliciousIPCaller.Custom"] = true,
    ["Discovery:Kubernetes/SuccessfulAnonymousAccess"] = true,
    ["Discovery:Kubernetes/TorIPCaller"] = true,
    ["Execution:Kubernetes/ExecInKubeSystemPod"] = true,
    ["Impact:Kubernetes/MaliciousIPCaller"] = true,
    ["Impact:Kubernetes/MaliciousIPCaller.Custom"] = true,
    ["Impact:Kubernetes/SuccessfulAnonymousAccess"] = true,
    ["Impact:Kubernetes/TorIPCaller"] = true,
    ["Persistence:Kubernetes/ContainerWithSensitiveMount"] = true,
    ["Persistence:Kubernetes/MaliciousIPCaller"] = true,
    ["Persistence:Kubernetes/MaliciousIPCaller.Custom"] = true,
    ["Persistence:Kubernetes/SuccessfulAnonymousAccess"] = true,
    ["Persistence:Kubernetes/TorIPCaller"] = true,
    ["Policy:Kubernetes/AdminAccessToDefaultServiceAccount"] = true,
    ["Policy:Kubernetes/AnonymousAccessGranted"] = true,
    ["Policy:Kubernetes/ExposedDashboard"] = true,
    ["Policy:Kubernetes/KubeflowDashboardExposed"] = true,
    ["PrivilegeEscalation:Kubernetes/PrivilegedContainer"] = true,
    ["CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed"] = true,
    ["PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated"] = true,
    ["Execution:Kubernetes/AnomalousBehavior.ExecInPod"] = true,
    ["PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed!PrivilegedContainer"] = true,
    ["PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed!ContainerWithSensitiveMount"] = true,
    ["Execution:Kubernetes/AnomalousBehavior.WorkloadDeployed"] = true,
    ["PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleCreated"] = true,
    ["Discovery:Kubernetes/AnomalousBehavior.PermissionChecked"] = true
}

local lambda_protection_finding_types = {
    ["Backdoor:Lambda/C&CActivity.B"] = true,
    ["CryptoCurrency:Lambda/BitcoinTool.B"] = true,
    ["Trojan:Lambda/BlackholeTraffic"] = true,
    ["Trojan:Lambda/DropPoint"] = true,
    ["UnauthorizedAccess:Lambda/MaliciousIPCaller.Custom"] = true,
    ["UnauthorizedAccess:Lambda/TorClient"] = true,
    ["UnauthorizedAccess:Lambda/TorRelay"] = true
}

local malware_protection_finding_types = {
    ["Execution:EC2/MaliciousFile"] = true,
    ["Execution:ECS/MaliciousFile"] = true,
    ["Execution:Kubernetes/MaliciousFile"] = true,
    ["Execution:Container/MaliciousFile"] = true,
    ["Execution:EC2/SuspiciousFile"] = true,
    ["Execution:ECS/SuspiciousFile"] = true,
    ["Execution:Kubernetes/SuspiciousFile"] = true,
    ["Execution:Container/SuspiciousFile"] = true
}

local rds_protection_finding_types = {
    ["CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin"] = true,
    ["CredentialAccess:RDS/AnomalousBehavior.FailedLogin"] = true,
    ["CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce"] = true,
    ["CredentialAccess:RDS/MaliciousIPCaller.SuccessfulLogin"] = true,
    ["CredentialAccess:RDS/MaliciousIPCaller.FailedLogin"] = true,
    ["Discovery:RDS/MaliciousIPCaller"] = true,
    ["CredentialAccess:RDS/TorIPCaller.SuccessfulLogin"] = true,
    ["CredentialAccess:RDS/TorIPCaller.FailedLogin"] = true,
    ["Discovery:RDS/TorIPCaller"] = true
}

local s3_finding_types = {
    ["Discovery:S3/AnomalousBehavior"] = true,
    ["Discovery:S3/MaliciousIPCaller"] = true,
    ["Discovery:S3/MaliciousIPCaller.Custom"] = true,
    ["Discovery:S3/TorIPCaller"] = true,
    ["Exfiltration:S3/AnomalousBehavior"] = true,
    ["Exfiltration:S3/MaliciousIPCaller"] = true,
    ["Impact:S3/AnomalousBehavior.Delete"] = true,
    ["Impact:S3/AnomalousBehavior.Permission"] = true,
    ["Impact:S3/AnomalousBehavior.Write"] = true,
    ["Impact:S3/MaliciousIPCaller"] = true,
    ["PenTest:S3/KaliLinux"] = true,
    ["PenTest:S3/ParrotLinux"] = true,
    ["PenTest:S3/PentooLinux"] = true,
    ["Policy:S3/AccountBlockPublicAccessDisabled"] = true,
    ["Policy:S3/BucketAnonymousAccessGranted"] = true,
    ["Policy:S3/BucketBlockPublicAccessDisabled"] = true,
    ["Policy:S3/BucketPublicAccessGranted"] = true,
    ["Stealth:S3/ServerAccessLoggingDisabled"] = true,
    ["UnauthorizedAccess:S3/MaliciousIPCaller.Custom"] = true,
    ["UnauthorizedAccess:S3/TorIPCaller"] = true
}


-- Per-category helpers (mirroring Python OCSFMapperHelper)
local function ec2_findings(event, site_id)
    event["class_uid"] = 4001
    event["class_name"] = "Network Activity"
    event["category_uid"] = 4
    event["category_name"] = "Network Activity"
    event["activity_id"] = "99"
    event["activity_name"] = "EC2 finding types"
    event["type_uid"] = 400199
    event["type_name"] = "EC2 finding types"
    event["eventId"] = "EC2 finding types"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, ec2_findings_ocsf_mapping())
    -- enrich with fields that were set directly on event
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    coordinates_mapping(flat)
    return flat
end

local function runtime_monitoring_findings(event, site_id)
    event["class_uid"] = 6003
    event["class_name"] = "API Activity"
    event["category_uid"] = 6
    event["category_name"] = "Application Activity"
    event["activity_id"] = "99"
    event["activity_name"] = "EKS Runtime Monitoring finding types"
    event["type_uid"] = 600399
    event["type_name"] = "EKS Runtime Monitoring finding types"
    event["eventId"] = "EKS Runtime Monitoring finding types"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, runtime_monitoring_findings_ocsf_mapping())
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    coordinates_mapping(flat)
    return flat
end

local function iam_findings(event, site_id)
    event["class_uid"] = 3004
    event["class_name"] = "Entity Management"
    event["category_uid"] = 3
    event["category_name"] = "Identity & Access Management"
    event["activity_id"] = "99"
    event["activity_name"] = "IAM finding types"
    event["type_uid"] = 300499
    event["type_name"] = "IAM finding types"
    event["eventId"] = "IAM finding types"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, iam_findings_ocsf_mapping())
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    coordinates_mapping(flat)
    return flat
end

local function kubernetes_audit_log_findings(event, site_id)
    event["class_uid"] = 6003
    event["class_name"] = "API Activity"
    event["category_uid"] = 6
    event["category_name"] = "Application Activity"
    event["activity_id"] = "99"
    event["activity_name"] = "Kubernetes Audit Logs finding types"
    event["type_uid"] = 600399
    event["type_name"] = "Kubernetes Audit Logs finding types"
    event["eventId"] = "Kubernetes Audit Logs finding types"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, kubernetes_audit_log_findings_ocsf_mapping())
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    coordinates_mapping(flat)
    return flat
end

local function lambda_findings(event, site_id)
    event["class_uid"] = 6002
    event["class_name"] = "Application Lifecycle"
    event["category_uid"] = 6
    event["category_name"] = "Application Activity"
    event["activity_id"] = "99"
    event["activity_name"] = "Lambda Protection finding types"
    event["type_uid"] = 600299
    event["type_name"] = "Lambda Protection finding types"
    event["eventId"] = "Lambda Protection finding types"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, lambda_findings_ocsf_mapping())
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    coordinates_mapping(flat)
    return flat
end

local function malware_findings(event, site_id)
    event["class_uid"] = 2001
    event["class_name"] = "Security Finding"
    event["category_uid"] = 2
    event["category_name"] = "Findings"
    event["activity_id"] = "99"
    event["activity_name"] = "Malware Protection finding types"
    event["type_uid"] = 200199
    event["type_name"] = "Malware Protection finding types"
    event["eventId"] = "Malware Protection finding types"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, malware_findings_ocsf_mapping())
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    return flat
end

local function rds_findings(event, site_id)
    event["class_uid"] = 3002
    event["class_name"] = "Authentication"
    event["category_uid"] = 3
    event["category_name"] = "Identity & Access Management"
    event["activity_id"] = "99"
    event["activity_name"] = "RDS Protection finding types"
    event["type_uid"] = 300299
    event["type_name"] = "RDS Protection finding types"
    event["eventId"] = "RDS Protection finding types"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, rds_findings_ocsf_mapping())
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    coordinates_mapping(flat)
    return flat
end

local function s3_findings(event, site_id)
    event["class_uid"] = 6003
    event["class_name"] = "API Activity"
    event["category_uid"] = 6
    event["category_name"] = "Application Activity"
    event["activity_id"] = "99"
    event["activity_name"] = "S3 finding types"
    event["type_uid"] = 600399
    event["type_name"] = "S3 finding types"
    event["eventId"] = "S3 finding types"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, s3_findings_ocsf_mapping())
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    coordinates_mapping(flat)
    return flat
end

local function unknown_findings(event, site_id)
    event["class_uid"] = 0
    event["class_name"] = "Base Event"
    event["category_uid"] = 0
    event["category_name"] = "Uncategorized"
    event["activity_id"] = 0
    event["activity_name"] = "Unknown"
    event["type_uid"] = 0
    event["type_name"] = "Unknown"
    event["eventId"] = "Unknown"
    common_mapping(event, site_id)
    local flat = apply_mapping(event, unknown_findings_ocsf_mapping())
    flat["activity_name"] = event["activity_name"]
    flat["activity_id"] = event["activity_id"]
    flat["class_uid"] = event["class_uid"]
    flat["class_name"] = event["class_name"]
    flat["category_uid"] = event["category_uid"]
    flat["category_name"] = event["category_name"]
    flat["type_uid"] = event["type_uid"]
    flat["type_name"] = event["type_name"]
    flat["severity_id"] = event["severity_id"]
    return flat
end

-- Dispatcher. family one of: "ec2","runtime","iam","kubernetes","lambda","malware","rds","s3","unknown"
local function processGuardDutyEvent(event, site_id, family)
    local fam = tostring(family or "unknown"):lower()
    if fam == "ec2" then return ec2_findings(deepCopy(event), site_id) end
    if fam == "runtime" or fam == "eks_runtime" or fam == "runtime_monitoring" then return runtime_monitoring_findings(deepCopy(event), site_id) end
    if fam == "iam" then return iam_findings(deepCopy(event), site_id) end
    if fam == "kubernetes" or fam == "k8s" then return kubernetes_audit_log_findings(deepCopy(event), site_id) end
    if fam == "lambda" then return lambda_findings(deepCopy(event), site_id) end
    if fam == "malware" then return malware_findings(deepCopy(event), site_id) end
    if fam == "rds" then return rds_findings(deepCopy(event), site_id) end
    if fam == "s3" then return s3_findings(deepCopy(event), site_id) end
    return unknown_findings(deepCopy(event), site_id)
end

-- Best-effort automatic family detection from GuardDuty event structure
local function detect_family(event)
    local type = getByPath(event, {"type"})
    if ec2_finding_types[type] then return "ec2" end
    if runtime_monitoring_finding_types[type] then return "runtime" end
    if iam_finding_types[type] then return "iam" end
    if kubernetes_audit_logs_finding_types[type] then return "kubernetes" end
    if lambda_protection_finding_types[type] then return "lambda" end
    if malware_protection_finding_types[type] then return "malware" end
    if rds_protection_finding_types[type] then return "rds" end
    if s3_finding_types[type] then return "s3" end
    return "unknown"
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

local IGNORE_KEYS = {
  _ob = true,
  timestamp = true,  -- Ignore timestamp as we use start_time/end_time
}

-- Global entry point expected by transform runners
function processEvent(event)
    local site_id = nil
    local site_tbl = event and event["site"]
    if type(site_tbl) == "table" and site_tbl["id"] then
        site_id = site_tbl["id"]
    elseif event and event["site_id"] then
        site_id = event["site_id"]
    end
    local fam = detect_family(event or {})
    local copy = deepCopy(event, IGNORE_KEYS)
    local result = processGuardDutyEvent(copy, site_id, fam)
    result.time = convertUtcToMilliseconds(copy["createdAt"])
    result.message = encodeJson(copy, get_msg_field_ordering(fam), "message")
    return result
end

