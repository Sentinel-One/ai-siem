-- OCSF Vulnerability Finding (2002) serializer for Snyk project_snapshot webhook events.
-- Remediation per 2026-04-19 Orion: class kept at 2002; add defensive empty-input skeleton.

local CLASS_UID = 2002
local CATEGORY_UID = 2

-- Safe millisecond clock (pcall-guarded per Observo sandbox rules)
function safeTimeMs()
    local ok, secs = pcall(os.time)
    if ok and secs then return secs * 1000 end
    return 0
end

function getNestedField(obj, path)
    if obj == nil or path == nil or path == '' then return nil end
    local cursor = obj
    for key in string.gmatch(path, '[^.]+') do
        if type(cursor) ~= 'table' then return nil end
        if cursor[key] == nil then return nil end
        cursor = cursor[key]
    end
    return cursor
end
function setNestedField(obj, path, value)
    if obj == nil or value == nil or path == nil or path == '' then return end
    if type(obj) ~= 'table' then return end
    local keys = {}
    for key in string.gmatch(path, '[^.]+') do table.insert(keys, key) end
    if #keys == 0 then return end
    local cursor = obj
    local limit = #keys - 1
    for i = 1, limit do
        if cursor[keys[i]] == nil then cursor[keys[i]] = {} end
        cursor = cursor[keys[i]]
    end
    cursor[keys[#keys]] = value
end
function getValue(tbl, key, default)
    if tbl == nil then return default end
    local v = tbl[key]
    if v == nil then return default end
    return v
end
function no_nulls(d)
    if type(d) == 'table' then
        for k, v in pairs(d) do
            if type(v) == 'userdata' then d[k] = nil
            elseif type(v) == 'table' then no_nulls(v) end
        end
    end
    return d
end

function parseIsoMs(s)
    if s == nil then return nil end
    if type(s) ~= 'string' then s = tostring(s) end
    if type(s) ~= 'string' then return nil end
    local y, mo, d, h, mi, se = s:match("(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
    if not y then return nil end
    local ok, v = pcall(function() return os.time({year=tonumber(y), month=tonumber(mo), day=tonumber(d), hour=tonumber(h), min=tonumber(mi), sec=tonumber(se)}) * 1000 end)
    if ok then return v end
    return nil
end

function severityId(s)
    if s == nil then return 1 end
    local v = string.lower(tostring(s))
    if v == "low" then return 2 end
    if v == "medium" then return 3 end
    if v == "high" then return 4 end
    if v == "critical" then return 5 end
    return 1
end

-- Always return a valid OCSF skeleton, even when event is nil/empty.
function buildSkeleton(t, title, uid)
    local ts = t or safeTimeMs()
    return {
        class_uid = CLASS_UID,
        category_uid = CATEGORY_UID,
        type_uid = 200201,
        activity_id = 1,
        severity_id = 1,
        status_id = 1,
        time = ts,
        metadata = { version = "1.1.0", product = { name = "Snyk", vendor_name = "Snyk" } },
        finding_info = {
            uid = uid or "snyk-empty-event",
            title = title or "Snyk project snapshot (empty)",
            created_time = ts,
        },
        vulnerabilities = {},
        resources = {},
        unmapped = {}
    }
end

function processEvent(event)
    if type(event) ~= 'table' then return buildSkeleton() end
    no_nulls(event)

    local ts_raw = getValue(event, "X-Snyk-Timestamp") or getNestedField(event, "project.lastTestedDate")
    local ts = parseIsoMs(ts_raw) or safeTimeMs()

    local newIssues = getValue(event, "newIssues") or {}
    -- For empty input path, return a clean skeleton without pretending issues exist.
    if #newIssues == 0 then
        local skel = buildSkeleton(ts,
            "Snyk project snapshot (no new issues)",
            (getNestedField(event, "X-Snyk-Transport-ID") or getNestedField(event, "project.id") or "snyk-snapshot"))
        -- Attach project/org/group context if present
        local proj = getValue(event, "project") or {}
        if proj.id or proj.name then
            table.insert(skel.resources,
                { uid = proj.id, name = proj.name, type = "project", cloud_partition = "Snyk" })
        end
        setNestedField(skel, "metadata.log_name", getValue(event, "X-Snyk-Event") or "snyk.project_snapshot")
        setNestedField(skel, "metadata.correlation_uid", getValue(event, "X-Snyk-Transport-ID"))
        setNestedField(skel, "cloud.provider", "Snyk")
        setNestedField(skel, "raw_data", event)
        return skel
    end

    -- Populate from first new issue; attach all vulnerabilities into vulnerabilities[]
    local primary = newIssues[1] or {}
    local primaryIssueData = getValue(primary, "issueData") or {}

    local result = buildSkeleton(ts,
        getValue(primaryIssueData, "title") or "Snyk vulnerability finding",
        getValue(primary, "id") or (getValue(event, "X-Snyk-Transport-ID") or "snyk-finding"))

    -- finding_info enrichment
    setNestedField(result, "finding_info.desc", getValue(primaryIssueData, "description"))
    setNestedField(result, "finding_info.first_seen_time", parseIsoMs(getValue(primaryIssueData, "disclosureTime")))
    setNestedField(result, "finding_info.src_url", getValue(primaryIssueData, "url"))
    setNestedField(result, "finding_info.types", { getValue(primary, "issueType") or "vuln" })

    -- Vulnerabilities list (all new issues)
    for _, iss in ipairs(newIssues) do
        local id = getValue(iss, "issueData") or {}
        local cves = getNestedField(id, "identifiers.CVE") or {}
        local cve_uid = (type(cves) == 'table' and cves[1]) or nil
        local sev_str = getValue(id, "severity") or "medium"
        local vuln = {
            title = getValue(id, "title"),
            desc = getValue(id, "description"),
            severity = sev_str,
            vendor_name = "Snyk",
            affected_packages = {
                {
                    name = getValue(iss, "pkgName"),
                    version = (getValue(iss, "pkgVersions") or {})[1],
                    package_manager = getValue(iss, "pkgName") and getValue(iss, "issueType") or nil,
                }
            },
            cve = cve_uid and {
                uid = cve_uid,
                cvss = {
                    { version = "3.1", base_score = tonumber(getValue(id, "cvssScore")), vector_string = getValue(id, "CVSSv3") }
                }
            } or nil,
            references = { getValue(id, "url") },
            is_fix_available = (getNestedField(iss, "fixInfo.isUpgradable") == true)
        }
        table.insert(result.vulnerabilities, vuln)
    end

    result.severity_id = severityId(getValue(primaryIssueData, "severity"))

    -- Project / org context
    local proj = getValue(event, "project") or {}
    table.insert(result.resources, {
        uid = proj.id, name = proj.name, type = proj.type or "project", cloud_partition = "Snyk",
        labels = { "origin:" .. tostring(proj.origin or "unknown") }
    })
    setNestedField(result, "cloud.account.uid", getNestedField(event, "org.id"))
    setNestedField(result, "cloud.account.name", getNestedField(event, "org.name"))
    setNestedField(result, "cloud.provider", "Snyk")

    -- Metadata
    setNestedField(result, "metadata.uid", getValue(event, "X-Snyk-Transport-ID"))
    setNestedField(result, "metadata.log_name", getValue(event, "X-Snyk-Event") or "snyk.project_snapshot")
    setNestedField(result, "metadata.correlation_uid", getValue(event, "X-Snyk-Transport-ID"))

    -- Observables
    result.observables = {}
    for _, v in ipairs(result.vulnerabilities) do
        if v.cve and v.cve.uid then
            table.insert(result.observables,
                { name = "vulnerabilities.cve.uid", type = "Other UID", type_id = 40, value = v.cve.uid })
        end
    end

    result.message = string.format("%d Snyk finding%s in project %s",
        #result.vulnerabilities,
        #result.vulnerabilities == 1 and "" or "s",
        tostring(proj.name or "unknown"))
    setNestedField(result, "raw_data", event)
    return result
end
