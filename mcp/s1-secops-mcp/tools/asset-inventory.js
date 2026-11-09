/**
 * Asset Inventory GraphQL tools (1.6.1). Read-only: every document sent is a GraphQL `query`.
 *
 *   asset_inventory_counts         assetInventoryAssetCounts: totals per category and per surface
 *   asset_inventory_search         assetInventoryAssets: list, filter, sort and page assets
 *   asset_inventory_get            assetInventoryAssetOverview: one asset by resourceId or agentUuid
 *   asset_inventory_filter_values  assetInventoryFiltersCount: the values that exist for fields, with counts
 *
 * Endpoint: POST /web/api/v2.1/graphql (ApiToken auth, the same endpoint Purple AI uses).
 *
 * Injection safety: every argument value (filters, sort, scope, surface, category, subCategory,
 * first, after, fieldIds, resourceId, agentUuid) is sent as a GraphQL VARIABLE, never written into
 * the document. The only text built into the document is the selection set, and it is assembled
 * from identifiers that match ^[A-Za-z][A-Za-z0-9_]*$ plus fixed, verified sub-selections.
 *
 * Variable type names were found by trial against a live console (introspection is disabled):
 *   [AssetInventoryFilterInput!]!, AssetInventorySortInput, AssetInventoryScopeSelectorInput,
 *   AssetInventorySurfaceInput, AssetInventoryCategoryInput, AssetInventorySubCategoryInput,
 *   Int (first), String (after, resourceId, agentUuid), [String!]! (fieldIds).
 *
 * Arguments that are not set are left out of the document entirely: an explicit null for an
 * optional argument (scope, surface, sort, ...) returns "Internal server error".
 *
 * Failure shapes:
 *   - HTTP 400 {"message":"invalid query"} with no detail for any document the gateway cannot
 *     validate, for example an unknown name in `fields`.
 *   - HTTP 200 with an `errors` array (and often null data) for request errors such as an unknown
 *     filter fieldId, two operators in one filter, a page size outside 1..1000 or a bad cursor.
 *     Both become tool errors here; partial data, when present, is included in the message.
 */

import { apiPost } from '../lib/s1.js';
import { graphqlOperation } from '../lib/access.js';
import { writeOutput, resolveOutputPath, serialiseRows } from '../lib/output.js';

export const GRAPHQL_PATH = '/web/api/v2.1/graphql';

export const SURFACES = Object.freeze(['ENDPOINT', 'CLOUD', 'IDENTITY', 'NETWORK_DISCOVERY', 'AI_SECURITY']);
export const SCOPE_TYPES = Object.freeze(['TENANT', 'ACCOUNT', 'SITE', 'GROUP']);
export const FILTER_OPERATORS = Object.freeze(['match', 'stringEqual', 'stringIn', 'dateTimeRange']);

export const MAX_PAGE_SIZE = 1000;      // the API refuses more: "Maximum page size is 1000"
export const MAX_PAGES = 50;
export const INLINE_MAX_ROWS = 1000;    // larger result sets must go to outputFile
const MAX_FILTERS = 50;
const MAX_FILTER_VALUES = 1000;
const MAX_FIELD_IDS = 50;
const MAX_FIELDS = 120;

const IDENT = /^[A-Za-z][A-Za-z0-9_]*$/;
const ENUM_VALUE = /^[A-Z][A-Z0-9_]*$/;
const SCOPE_ID = /^[A-Za-z0-9_-]{1,64}$/;

// Variable types, verified live (see header).
const VAR_TYPES = Object.freeze({
  first: 'Int',
  after: 'String',
  surface: 'AssetInventorySurfaceInput',
  category: 'AssetInventoryCategoryInput',
  subCategory: 'AssetInventorySubCategoryInput',
  scope: 'AssetInventoryScopeSelectorInput',
  filters: '[AssetInventoryFilterInput!]!',
  sort: 'AssetInventorySortInput',
  fieldIds: '[String!]!',
  resourceId: 'String',
  agentUuid: 'String',
});

// Subfields of `agent` that the API accepts (each selected alone on a live console).
// diskMetrics and vssVolumes are objects with unverified subfields and are not offered.
export const AGENT_FIELDS = Object.freeze([
  'uuid', 'id', 'agentVersion', 'operationalState', 'operationalStateTitle', 'operatingMode',
  'consoleConnectivity', 'consoleMigrationStatus', 'networkStatus', 'networkStatusTitle',
  'configurableNetworkQuarantine', 'decommissioned', 'uninstalled', 'upToDate', 'isInfected',
  'detectionState', 'antiTamperingStatus', 'firewallStatus', 'diskEncryption', 'dvConnectivity',
  'dvConnectivityLastUpdatedDt', 'hasLocalConfig', 'installerType', 'customerIdentifier',
  'lastLoggedInUser', 'lastReportedIp', 'location', 'missingPermissions', 'pendingActions',
  'pendingUninstall', 'pendingUpgrade', 'rangerStatus', 'rangerVersion', 'remoteProfilingState',
  'scanStatus', 'subscribeOnDt', 'threatRebootRequired', 'vssLastSnapshotDt',
  'vssProtectionStatus', 'vssRollbackStatus', 'vssServiceStatus',
]);
export const DEFAULT_AGENT_FIELDS = Object.freeze([
  'uuid', 'agentVersion', 'consoleConnectivity', 'operationalStateTitle', 'networkStatus',
  'isInfected', 'decommissioned', 'upToDate',
]);

// Object fields with a fixed, verified sub-selection. Requesting the bare name selects these.
const OBJECT_FIELDS = Object.freeze({
  tags: 'key value source readOnly',
  alertsCount: 'severity count alertIds',
});
// Object fields whose subfields are not verified: refused with a clear message.
const UNSUPPORTED_OBJECT_FIELDS = new Set(['alerts', 'applications', 'cloudTags', 'deviceReviewLog', 'networkInterfaces', 'notes']);

// Scalar fields confirmed selectable on AssetInventoryAsset (listing and overview share the type).
// Other identifiers are passed through; an unknown one makes the API answer HTTP 400 "invalid query".
export const KNOWN_FIELDS = Object.freeze([
  'id', 'name', 'hostname', 'category', 'subCategory', 'resourceType', 'assetStatus', 'assetCriticality',
  'assetEnvironment', 'assetContactEmail', 'surfaces', 'riskFactors', 'infectionStatus',
  'activeCoverage', 'missingCoverage', 'managedState', 'eppUnsupportedUnknown', 'deviceReview',
  'discoveryMethods', 'osFamily', 'os', 'osVersion', 'osNameVersion', 'architecture', 'cpu', 'coreCount',
  'memory', 'memoryReadable', 'isVm', 'manufacturer', 'modelName', 'serialNumber', 'domain',
  'ipAddress', 'internalIps', 'internalIpsV6', 'macAddresses', 'gatewayIps', 'gatewayMacs', 'subnets',
  'networkNames', 'tcpPorts', 'udpPorts', 'firstSeenDt', 'lastActiveDt', 'lastUpdateDt', 'lastRebootDt',
  'lastApplicationScanTimeDt', 's1UpdatedAt', 'region', 'cloudProviderName', 'cloudProviderAccountId',
  'cloudProviderAccountName', 'cloudProviderOrganization', 'cloudProviderProjectId', 'cloudResourceId',
  'cloudResourceUid', 's1AccountId', 's1AccountName', 's1SiteId', 's1SiteName', 's1GroupId', 's1GroupName',
  's1ScopeId', 's1ScopeLevel', 's1ScopePath', 's1ScopeType', 's1ManagementId', 's1ActiveProtection',
  's1OnboardedAccountId', 's1OnboardedAccountName', 's1OnboardedScopeId', 's1OnboardedScopeLevel',
  's1OnboardedScopePath', 's1OnboardedSiteId', 's1OnboardedSiteName', 'idSecondary', 'hasUserLabel',
  'detectedFromSite', 'adsEnabled', 'isAdConnector', 'isDcServer', 'k8sCnsEnabled', 'k8sCwsEnabled',
  'k8sHelperAgentDeployed',
]);

export const DEFAULT_SEARCH_FIELDS = Object.freeze([
  'id', 'name', 'category', 'subCategory', 'resourceType', 'assetStatus', 'assetCriticality', 'surfaces',
  'osFamily', 'ipAddress', 'lastActiveDt', 'activeCoverage', 'missingCoverage',
]);
export const DEFAULT_GET_FIELDS = Object.freeze([
  'id', 'name', 'category', 'subCategory', 'resourceType', 'assetStatus', 'assetCriticality',
  'infectionStatus', 'riskFactors', 'surfaces', 'activeCoverage', 'missingCoverage', 'osFamily',
  'osNameVersion', 'ipAddress', 'internalIps', 'lastActiveDt', 's1ScopePath', 's1AccountId', 's1SiteId',
  's1GroupId', 'alertsCount', 'tags', 'agent',
]);

// ─── Builders (exported for tests) ───────────────────────────────────────────

function fail(msg) { throw new Error(msg); }

function checkIdent(name, what) {
  if (typeof name !== 'string' || !IDENT.test(name)) {
    fail(`${what} ${JSON.stringify(name)?.slice(0, 80)} is not a plain field name (letters, digits and _, starting with a letter).`);
  }
  return name;
}

function agentSelection(subs) {
  const list = subs.length ? subs : DEFAULT_AGENT_FIELDS;
  for (const s of list) {
    if (!AGENT_FIELDS.includes(s)) fail(`agent subfield ${JSON.stringify(s).slice(0, 60)} is not allowed. Allowed: ${AGENT_FIELDS.join(', ')}.`);
  }
  return `agent { ${[...new Set(list)].join(' ')} }`;
}

/**
 * Selection set for AssetInventoryAsset from a `fields` list. Entries:
 *   "name"                     a scalar field
 *   "tags", "alertsCount"      object fields, expanded to a fixed sub-selection
 *   "agent"                    agent with the default subfields
 *   "agent.uuid"               one agent subfield (repeat for more)
 *   "agent { uuid agentVersion }"  several agent subfields
 * Anything else is refused before a request is made.
 */
export function buildSelection(fields, defaults = DEFAULT_SEARCH_FIELDS, { alwaysId = true } = {}) {
  let list = fields === undefined || fields === null ? [...defaults] : fields;
  if (!Array.isArray(list)) fail('fields must be an array of field names.');
  if (list.length === 0) list = [...defaults];
  if (list.length > MAX_FIELDS) fail(`fields: at most ${MAX_FIELDS} entries.`);
  const scalars = [];
  const objects = [];
  const agentSubs = [];
  let agentWanted = false;
  for (const raw of list) {
    if (typeof raw !== 'string') fail('fields entries must be strings.');
    const f = raw.trim();
    const block = /^agent\s*\{([A-Za-z0-9_\s]*)\}$/.exec(f);
    if (block) {
      agentWanted = true;
      agentSubs.push(...block[1].trim().split(/\s+/).filter(Boolean).map(s => checkIdent(s, 'agent subfield')));
      continue;
    }
    const dotted = /^agent\.(.+)$/.exec(f);
    if (dotted) { agentWanted = true; agentSubs.push(checkIdent(dotted[1], 'agent subfield')); continue; }
    checkIdent(f, 'Field');
    if (f === 'agent') { agentWanted = true; continue; }
    if (OBJECT_FIELDS[f]) { if (!objects.includes(f)) objects.push(f); continue; }
    if (UNSUPPORTED_OBJECT_FIELDS.has(f)) fail(`Field ${f} is an object whose subfields are not supported by this tool. Supported object fields: agent, ${Object.keys(OBJECT_FIELDS).join(', ')}.`);
    if (!scalars.includes(f)) scalars.push(f);
  }
  if (alwaysId && !scalars.includes('id')) scalars.unshift('id');
  const parts = [...scalars, ...objects.map(o => `${o} { ${OBJECT_FIELDS[o]} }`)];
  if (agentWanted) parts.push(agentSelection(agentSubs));
  return parts.join(' ');
}

function stringList(v, where) {
  if (!Array.isArray(v) || v.length === 0) fail(`${where}.values must be a non-empty array of strings.`);
  if (v.length > MAX_FILTER_VALUES) fail(`${where}.values: at most ${MAX_FILTER_VALUES} values.`);
  return v.map((x) => {
    if (typeof x === 'number' || typeof x === 'boolean') return String(x);
    if (typeof x !== 'string') fail(`${where}.values must contain strings.`);
    return x;
  });
}

function epochMs(v, where) {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === 'string' && v.trim()) {
    if (/^\d+$/.test(v.trim())) return Number(v.trim());
    const t = Date.parse(v);
    if (Number.isFinite(t)) return t;
  }
  fail(`${where} must be epoch milliseconds or an ISO-8601 date.`);
}

/**
 * Normalise caller filters into fresh objects that carry only the allowed keys. The result is sent
 * as the $filters variable, so the server's input type validates it as data, never as document text.
 */
export function buildFilters(filters) {
  if (filters === undefined || filters === null) return [];
  if (!Array.isArray(filters)) fail('filters must be an array.');
  if (filters.length > MAX_FILTERS) fail(`filters: at most ${MAX_FILTERS} entries.`);
  return filters.map((f, i) => {
    const where = `filters[${i}]`;
    if (!f || typeof f !== 'object' || Array.isArray(f)) fail(`${where} must be an object {fieldId, <operator>}.`);
    const extra = Object.keys(f).filter(k => k !== 'fieldId' && !FILTER_OPERATORS.includes(k));
    if (extra.length) fail(`${where}: unknown key(s) ${extra.join(', ')}. Use fieldId plus exactly one of ${FILTER_OPERATORS.join(', ')}.`);
    const ops = FILTER_OPERATORS.filter(k => f[k] !== undefined && f[k] !== null);
    if (ops.length !== 1) fail(`${where}: exactly one of ${FILTER_OPERATORS.join(', ')} is required (found ${ops.length}).`);
    const fieldId = checkIdent(f.fieldId, `${where}.fieldId`);
    const op = ops[0];
    const v = f[op];
    if (typeof v !== 'object' || Array.isArray(v)) fail(`${where}.${op} must be an object.`);
    if (op === 'match' || op === 'stringIn') return { fieldId, [op]: { values: stringList(v.values, `${where}.${op}`) } };
    if (op === 'stringEqual') {
      if (typeof v.value !== 'string') fail(`${where}.stringEqual.value must be a string.`);
      return { fieldId, stringEqual: { value: v.value } };
    }
    const r = { start: epochMs(v.start, `${where}.dateTimeRange.start`) };
    if (v.end !== undefined && v.end !== null) r.end = epochMs(v.end, `${where}.dateTimeRange.end`);   // end is optional
    if (v.startInclusive !== undefined) r.startInclusive = v.startInclusive === true;
    if (v.endInclusive !== undefined) r.endInclusive = v.endInclusive === true;
    return { fieldId, dateTimeRange: r };
  });
}

export function buildSort(sort) {
  if (sort === undefined || sort === null) return undefined;
  if (typeof sort !== 'object' || Array.isArray(sort)) fail('sort must be an object {by, order}.');
  const out = { by: checkIdent(sort.by, 'sort.by') };
  if (sort.order !== undefined && sort.order !== null) {
    const o = String(sort.order).toUpperCase();
    if (o !== 'ASC' && o !== 'DESC') fail('sort.order must be ASC or DESC.');
    out.order = o;
  }
  return out;
}

export function buildScope(scope) {
  if (scope === undefined || scope === null) return undefined;
  if (typeof scope !== 'object' || Array.isArray(scope)) fail('scope must be an object {scopeType, scopeIds}.');
  const t = String(scope.scopeType || '').toUpperCase();
  if (!SCOPE_TYPES.includes(t)) fail(`scope.scopeType must be one of ${SCOPE_TYPES.join(', ')}.`);
  const ids = scope.scopeIds === undefined || scope.scopeIds === null ? [] : scope.scopeIds;
  if (!Array.isArray(ids)) fail('scope.scopeIds must be an array of ids.');
  const scopeIds = ids.map((id) => {
    const s = String(id);
    if (!SCOPE_ID.test(s)) fail(`scope.scopeIds entry ${JSON.stringify(s).slice(0, 40)} is not a valid id.`);
    return s;
  });
  if (t !== 'TENANT' && scopeIds.length === 0) fail(`scope.scopeIds is required for scopeType ${t}.`);
  return { scopeType: t, scopeIds };
}

function buildSurface(surface) {
  if (surface === undefined || surface === null || surface === '') return undefined;
  const s = String(surface).toUpperCase();
  if (!SURFACES.includes(s)) fail(`surface must be one of ${SURFACES.join(', ')}.`);
  return s;
}

function buildEnum(v, name) {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v !== 'string' || !ENUM_VALUE.test(v)) {
    fail(`${name} takes the enum form (for example SERVER, WORKSTATION, VIRTUAL_MACHINE, LAPTOP), not a display label. To filter by a display label use filters: [{fieldId: "${name}", stringIn: {values: ["Workstation"]}}].`);
  }
  return v;
}

/** Operation text with only the variables that are set. Unset arguments are left out entirely. */
function operation(opName, field, vars, selection) {
  const keys = Object.keys(vars).filter(k => vars[k] !== undefined);
  const decl = keys.length ? `(${keys.map(k => `$${k}: ${VAR_TYPES[k]}`).join(', ')})` : '';
  const args = keys.length ? `(${keys.map(k => `${k}: $${k}`).join(', ')})` : '';
  const variables = Object.fromEntries(keys.map(k => [k, vars[k]]));
  return { query: `query ${opName}${decl} { ${field}${args} { ${selection} } }`, variables, operationName: opName };
}

export function buildCountsQuery({ scope } = {}) {
  return operation('AssetInventoryCounts', 'assetInventoryAssetCounts', { scope: buildScope(scope) },
    'categories { category count subCategories { subCategory count } } surfaces { surface count }');
}

export function buildSearchQuery({ first = 50, after, surface, category, subCategory, scope, filters, sort, fields, countOnly = false } = {}) {
  const n = Number(first);
  if (!Number.isInteger(n) || n < 1 || n > MAX_PAGE_SIZE) fail(`first must be an integer from 1 to ${MAX_PAGE_SIZE}.`);
  if (after !== undefined && after !== null && typeof after !== 'string') fail('after must be the endCursor string from a previous page.');
  const selection = countOnly
    ? 'totalCount pageInfo { hasNextPage endCursor }'
    : `totalCount pageInfo { hasNextPage endCursor } edges { node { ${buildSelection(fields, DEFAULT_SEARCH_FIELDS)} } }`;
  return operation('AssetInventorySearch', 'assetInventoryAssets', {
    first: n,
    after: after || undefined,
    surface: buildSurface(surface),
    category: buildEnum(category, 'category'),
    subCategory: buildEnum(subCategory, 'subCategory'),
    scope: buildScope(scope),
    filters: buildFilters(filters),
    sort: buildSort(sort),
  }, selection);
}

export function buildGetQuery({ resourceId, agentUuid, scope, fields } = {}) {
  const has = v => typeof v === 'string' && v.trim() !== '';
  if (has(resourceId) === has(agentUuid)) fail('Pass exactly one of resourceId (the asset id) or agentUuid.');
  return operation('AssetInventoryGet', 'assetInventoryAssetOverview', {
    resourceId: has(resourceId) ? resourceId.trim() : undefined,
    agentUuid: has(agentUuid) ? agentUuid.trim() : undefined,
    scope: buildScope(scope),
  }, buildSelection(fields, DEFAULT_GET_FIELDS));
}

export function buildFilterValuesQuery({ fieldIds, surface, filters, scope } = {}) {
  if (!Array.isArray(fieldIds) || fieldIds.length === 0) fail('fieldIds is required: a non-empty array of field ids.');
  if (fieldIds.length > MAX_FIELD_IDS) fail(`fieldIds: at most ${MAX_FIELD_IDS} entries.`);
  return operation('AssetInventoryFilterValues', 'assetInventoryFiltersCount', {
    surface: buildSurface(surface),
    filters: buildFilters(filters),
    fieldIds: [...new Set(fieldIds.map(f => checkIdent(f, 'fieldIds entry')))],
    scope: buildScope(scope),
  }, 'data { fieldId values { label value count } }');
}

// ─── Transport ───────────────────────────────────────────────────────────────

const INVALID_QUERY_HINT = ' The GraphQL gateway answers HTTP 400 "invalid query", with no detail, when the document does not validate: '
  + `most often a name in fields that the asset type does not have. Field names confirmed to work: ${KNOWN_FIELDS.slice(0, 40).join(', ')}, ...; `
  + 'object fields: agent, tags, alertsCount.';

/** Run one Asset Inventory document. Returns `data`. Throws on HTTP errors and on `errors` with HTTP 200. */
export async function assetGraphql({ query, variables, operationName }) {
  if (graphqlOperation(query) !== 'query') fail('Internal error: an Asset Inventory document must be a GraphQL query.');
  const body = { query, variables, operationName };
  let res;
  try {
    res = await apiPost(GRAPHQL_PATH, body, { allowRetry: true });     // a query: safe to retry
  } catch (e) {
    if (/→ 400: invalid query/.test(e.message)) throw new Error(e.message + INVALID_QUERY_HINT);
    throw e;
  }
  if (!res || typeof res !== 'object') fail(`Asset Inventory GraphQL returned a non-JSON response: ${String(res).slice(0, 300)}`);
  if (Array.isArray(res.errors) && res.errors.length) {
    const msgs = res.errors.map((er) => {
      const ext = er?.extensions || {};
      const tag = [ext.errorType, ext.code, ext.service].filter(Boolean).join('/');
      return `${er?.message || 'unknown error'}${tag ? ` (${tag})` : ''}`;
    });
    let partial = '';
    const d = res.data && typeof res.data === 'object' ? res.data : null;
    if (d && Object.values(d).some(v => v !== null && v !== undefined)) {
      partial = ` Partial data: ${JSON.stringify(d).slice(0, 4000)}`;
    }
    let hint = '';
    if (msgs.some(m => /\b401\b|Unauthorized/i.test(m))) {
      hint = ' The Asset Inventory service refused the token (401). Check that the token authenticates at all (for example s1_api_get /web/api/v2.1/system/info) before assuming a missing permission: a revoked or invalid token fails here the same way.';
    } else if (msgs.some(m => /Internal server error/i.test(m)) && variables && variables.sort) {
      hint = ` "Internal server error" is what the API returns for a sort.by field it cannot sort on (${JSON.stringify(variables.sort.by)}); try lastActiveDt, name or s1UpdatedAt.`;
    }
    throw new Error(`Asset Inventory GraphQL error (HTTP 200 with errors): ${msgs.join('; ')}.${partial}${hint}`);
  }
  return res.data;
}

// ─── Handlers ────────────────────────────────────────────────────────────────

const out = v => JSON.stringify(v, null, 2);

export async function searchAssets(args = {}) {
  const maxPages = args.maxPages === undefined || args.maxPages === null ? 1 : Number(args.maxPages);
  if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > MAX_PAGES) fail(`maxPages must be an integer from 1 to ${MAX_PAGES}.`);
  const first = args.first === undefined || args.first === null ? 50 : Number(args.first);
  const overwrite = args.overwrite === true;
  if (args.outputFile) resolveOutputPath(args.outputFile, { overwrite });    // refuse a bad path before any request
  else if (!args.countOnly && first * maxPages > INLINE_MAX_ROWS) {
    fail(`first x maxPages can return up to ${first * maxPages} rows; inline results are limited to ${INLINE_MAX_ROWS}. Pass outputFile (.json, .jsonl or .csv) to fetch more.`);
  }
  // Validate everything once, before the first request.
  buildSearchQuery({ ...args, first });

  const rows = [];
  let after = args.after || undefined;
  let pages = 0;
  let totalCount = null;
  let pageInfo = { hasNextPage: false, endCursor: null };
  while (pages < maxPages) {
    const data = await assetGraphql(buildSearchQuery({ ...args, first, after }));
    const conn = data?.assetInventoryAssets;
    if (!conn) fail('Asset Inventory GraphQL returned no assetInventoryAssets data.');
    pages += 1;
    if (totalCount === null) totalCount = conn.totalCount ?? null;
    for (const e of conn.edges || []) rows.push(e?.node ?? null);
    pageInfo = conn.pageInfo || { hasNextPage: false, endCursor: null };
    if (args.countOnly || !pageInfo.hasNextPage || !pageInfo.endCursor) break;
    after = pageInfo.endCursor;
  }
  const meta = {
    totalCount,
    pagesFetched: pages,
    rowsReturned: rows.length,
    hasNextPage: !!pageInfo.hasNextPage,
    endCursor: pageInfo.endCursor ?? null,
    view: args.surface ? `surface: ${String(args.surface).toUpperCase()} (curated console view)` : 'all surfaces (no surface argument)',
  };
  if (args.countOnly) return { totalCount, view: meta.view };
  if (args.outputFile) {
    const full = { ...meta, rows };
    const written = writeOutput(args.outputFile, serialiseRows(args.outputFile, rows, full), { overwrite });
    return { outputFile: written.path, bytesWritten: written.bytes, sha256: written.sha256, ...meta, preview: rows.slice(0, 5) };
  }
  return { ...meta, rows };
}

// ─── Tool definitions ────────────────────────────────────────────────────────

const VIEW_RULES = 'View rules: the surface argument is the curated console view (NETWORK_DISCOVERY returns assetStatus Active only, as on the console Network Discovery page; ENDPOINT returns agent-backed assets only). '
  + 'The "surfaces" filter ({fieldId: "surfaces", stringIn: {values: ["Endpoint"]}}) is the raw surface tag and also returns Inactive and agentless records, so its totals are higher. '
  + 'For Network Discovery and Endpoint questions use the surface argument. ';
const ENUM_RULES = 'category and subCategory ARGUMENTS take enums (SERVER, WORKSTATION, VIRTUAL_MACHINE, LAPTOP); FILTER values take display labels (Workstation, Endpoint, Network Discovery, EPP). '
  + 'Discover the exact filter values with asset_inventory_filter_values first: stringEqual and stringIn are exact and case-sensitive (match is a case-insensitive contains). '
  + 'managedState and s1SiteId can be returned but not filtered; use scope SITE for one site. ';
const MIX_RULE = 'Do not mix asset_inventory_counts totals with filtered or surface totals from this tool: they are different views. ';

const SCOPE_SCHEMA = {
  type: 'object',
  description: 'Optional scope. Default: everything the token can see. {scopeType: "ACCOUNT"|"SITE"|"GROUP", scopeIds: ["<id>"]} or {scopeType: "TENANT", scopeIds: []}.',
  properties: {
    scopeType: { type: 'string', enum: [...SCOPE_TYPES] },
    scopeIds: { type: 'array', items: { type: 'string' } },
  },
  required: ['scopeType'],
};
const SURFACE_SCHEMA = {
  type: 'string',
  enum: [...SURFACES],
  description: 'Curated console view of one surface. NETWORK_DISCOVERY = Active assets only (matches the console page); ENDPOINT = agent-backed assets. Omit for all assets.',
};
const FILTERS_SCHEMA = {
  type: 'array',
  description: 'Filters, combined with AND. Each item is {fieldId, <one operator>}: match {values: [..]} (contains, case-insensitive), stringEqual {value} (exact, case-sensitive), stringIn {values: [..]} (any of, exact, case-sensitive), dateTimeRange {start, end?, startInclusive?, endInclusive?} (epoch ms or ISO-8601; end optional). Values are display labels (Workstation, EPP, Active, Supported). Sent as GraphQL variables. Example, unprotected endpoints: surface NETWORK_DISCOVERY with [{fieldId: "missingCoverage", stringIn: {values: ["EPP"]}}]. managedState and s1SiteId can be returned but not filtered (every operator is refused; use scope SITE for one site, and asset_inventory_filter_values to count managedState). Filterable: eppUnsupportedUnknown (Supported, Unsupported, Unknown), deviceReview, discoveryMethods, resourceType, osFamily, surfaces, assetStatus, category, activeCoverage, missingCoverage, name, lastActiveDt.',
  items: {
    type: 'object',
    properties: {
      fieldId: { type: 'string' },
      match: { type: 'object', properties: { values: { type: 'array', items: { type: 'string' } } } },
      stringEqual: { type: 'object', properties: { value: { type: 'string' } } },
      stringIn: { type: 'object', properties: { values: { type: 'array', items: { type: 'string' } } } },
      dateTimeRange: {
        type: 'object',
        properties: {
          start: { type: ['number', 'string'] }, end: { type: ['number', 'string'] },
          startInclusive: { type: 'boolean' }, endInclusive: { type: 'boolean' },
        },
      },
    },
    required: ['fieldId'],
  },
};
const FIELDS_DESC = `Fields to return per asset (default: ${DEFAULT_SEARCH_FIELDS.join(', ')}). Plain names such as ${KNOWN_FIELDS.slice(0, 30).join(', ')}, managedState, eppUnsupportedUnknown, deviceReview, discoveryMethods, gatewayIps, subnets, macAddresses, manufacturer. `
  + `Object fields: "tags" (key, value, source, readOnly), "alertsCount" (severity, count, alertIds), "agent" (default ${DEFAULT_AGENT_FIELDS.join(', ')}), or chosen agent subfields as "agent.<name>" or "agent { a b }" from: ${AGENT_FIELDS.join(', ')}. `
  + 'Names must match ^[A-Za-z][A-Za-z0-9_]*$. An unknown name makes the API answer HTTP 400 "invalid query".';

export const tools = [
  {
    name: 'asset_inventory_counts',
    description: 'Asset Inventory totals per category (with subcategories) and per surface, from the Asset Inventory GraphQL API (assetInventoryAssetCounts). Use it for a quick overview only. Its NETWORK_DISCOVERY surface total is higher than the console Network Discovery view (asset_inventory_search with surface NETWORK_DISCOVERY), and its Device category total is unreliable (it can read 0 while the inventory holds agentless Unknown Device records). For Network Discovery and Device numbers use asset_inventory_search totalCount (countOnly). '
      + MIX_RULE + 'For a filtered or exact count use asset_inventory_search with countOnly. Read-only.',
    inputSchema: {
      type: 'object',
      properties: { scope: SCOPE_SCHEMA },
    },
    async handler({ scope } = {}) {
      const data = await assetGraphql(buildCountsQuery({ scope }));
      return out(data?.assetInventoryAssetCounts ?? null);
    },
  },
  {
    name: 'asset_inventory_search',
    description: 'List, filter, sort and page assets from the Asset Inventory GraphQL API (assetInventoryAssets), across Endpoint, Cloud, Identity, Network Discovery and AI Security. Returns totalCount, page info and one row per asset with the requested fields. '
      + VIEW_RULES + ENUM_RULES + MIX_RULE
      + `Paging: first is the page size (1 to ${MAX_PAGE_SIZE}, default 50); maxPages (default 1, up to ${MAX_PAGES}) follows endCursor automatically and stops when hasNextPage is false; to continue later pass endCursor as after with the same filters and sort. `
      + `Inline results are limited to ${INLINE_MAX_ROWS} rows; pass outputFile (.json, .jsonl or .csv) to write the full result to a local file and get a summary plus a 5-row preview. countOnly returns only totalCount (one cheap call). Read-only.`,
    inputSchema: {
      type: 'object',
      properties: {
        surface: SURFACE_SCHEMA,
        category: { type: 'string', description: 'Category enum, e.g. SERVER, WORKSTATION. Not a display label (use a "category" filter for labels).' },
        subCategory: { type: 'string', description: 'Subcategory enum, e.g. VIRTUAL_MACHINE, LAPTOP, DESKTOP.' },
        filters: FILTERS_SCHEMA,
        sort: {
          type: 'object',
          description: 'Sort {by: "<field>", order: "ASC"|"DESC"}, e.g. {by: "lastActiveDt", order: "DESC"}. Keep it fixed while paging. A field the API cannot sort on returns "Internal server error".',
          properties: { by: { type: 'string' }, order: { type: 'string', enum: ['ASC', 'DESC'] } },
          required: ['by'],
        },
        fields: { type: 'array', items: { type: 'string' }, description: FIELDS_DESC },
        first: { type: 'number', description: `Page size, 1 to ${MAX_PAGE_SIZE} (default 50).` },
        after: { type: 'string', description: 'endCursor from a previous page.' },
        maxPages: { type: 'number', description: `Pages to fetch automatically, 1 to ${MAX_PAGES} (default 1).` },
        countOnly: { type: 'boolean', description: 'Return only totalCount for this view and filter set.' },
        scope: SCOPE_SCHEMA,
        outputFile: { type: 'string', description: 'Optional absolute path on the machine running this MCP server (.json full result, .jsonl one asset per line, .csv). Returns a summary and a 5-row preview. Must be inside S1_OUTPUT_DIRS (default: home and temp). Under the Docker launcher only the folder set with `install --output-dir` is shared with the host.' },
        overwrite: { type: 'boolean', description: 'Allow outputFile to replace an existing file.' },
      },
    },
    async handler(args = {}) { return out(await searchAssets(args)); },
  },
  {
    name: 'asset_inventory_get',
    description: 'One asset from the Asset Inventory GraphQL API (assetInventoryAssetOverview), by resourceId (the asset id from asset_inventory_search) or, for Endpoint assets, by agentUuid. '
      + `Default fields: ${DEFAULT_GET_FIELDS.join(', ')} (alertsCount lists count and alert ids per severity and is null when the asset has no alerts; tags include S1_Asset_criticality). `
      + 'Use it in triage for criticality, tags, infection status, coverage and alert counts. A missing asset returns an error ("Asset with identifier ... not found"). Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        resourceId: { type: 'string', description: 'Asset id (the id field from asset_inventory_search).' },
        agentUuid: { type: 'string', description: 'Agent UUID, for Endpoint assets.' },
        fields: { type: 'array', items: { type: 'string' }, description: 'Override the default field set. Same rules as asset_inventory_search fields.' },
        scope: SCOPE_SCHEMA,
      },
    },
    async handler(args = {}) {
      const data = await assetGraphql(buildGetQuery(args));
      return out(data?.assetInventoryAssetOverview ?? null);
    },
  },
  {
    name: 'asset_inventory_filter_values',
    description: 'The values that exist for one or more Asset Inventory fields, with the number of assets for each (assetInventoryFiltersCount). Use it before filtering to get the exact display labels (for example missingCoverage, managedState, resourceType, deviceReview, discoveryMethods, osFamily, assetStatus, surfaces, infectionStatus, riskFactors), and as a fast group-by for coverage questions. fieldIds is required. '
      + VIEW_RULES + 'Pass the same surface and filters as the search they describe. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        fieldIds: { type: 'array', items: { type: 'string' }, description: 'Field ids to list values for, e.g. ["missingCoverage", "managedState"].' },
        surface: SURFACE_SCHEMA,
        filters: FILTERS_SCHEMA,
        scope: SCOPE_SCHEMA,
      },
      required: ['fieldIds'],
    },
    async handler(args = {}) {
      const data = await assetGraphql(buildFilterValuesQuery(args));
      return out(data?.assetInventoryFiltersCount?.data ?? []);
    },
  },
];
