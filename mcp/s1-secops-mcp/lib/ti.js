/**
 * Built-in threat intelligence (1.6.0): VirusTotal API v3 and Shodan, called directly with the
 * operator's own keys. No third-party MCP server or package: Node's fetch only.
 *
 * Every request is pinned to its service origin, built from validated indicators, and read-only
 * (GET). Keys come from the environment or the OS keychain (VIRUSTOTAL_API_KEY, SHODAN_API_KEY) and
 * are never echoed: error messages carry the request path without its query string, and the server
 * redacts configured secret values from all output (lib/redact.js).
 */

import { isIP } from 'net';
import { getCreds, setupHint } from './credentials.js';
import { parseJsonExact } from './json.js';

export const VT_ORIGIN = 'https://www.virustotal.com';
export const SHODAN_ORIGIN = 'https://api.shodan.io';
const TIMEOUT_MS = Math.max(1000, Number(process.env.S1_TI_TIMEOUT_MS) || 30000);

export function hasVtKey() { return !!getCreds().VIRUSTOTAL_API_KEY; }
export function hasShodanKey() { return !!getCreds().SHODAN_API_KEY; }

function vtKey() {
  const k = getCreds().VIRUSTOTAL_API_KEY;
  if (!k) throw new Error(`VIRUSTOTAL_API_KEY is not configured. ${setupHint()}`);
  return k;
}
function shodanKey() {
  const k = getCreds().SHODAN_API_KEY;
  if (!k) throw new Error(`SHODAN_API_KEY is not configured. ${setupHint()}`);
  return k;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── Indicators ───────────────────────────────────────────────────────────────

const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const DOMAIN_RE = /^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;

/** Undo common defanging: hxxp, [.], (.), {.}, [:]. */
export function refang(value) {
  return String(value ?? '').trim()
    .replace(/^hxxp(s?):\/\//i, 'http$1://')
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[:\]/g, ':');
}

export const VT_COLLECTION = Object.freeze({ file: 'files', ip: 'ip_addresses', domain: 'domains', url: 'urls' });
const VT_GUI = Object.freeze({ file: 'file', ip: 'ip-address', domain: 'domain', url: 'url' });

function vtUrlId(url) {
  return Buffer.from(url, 'utf-8').toString('base64url').replace(/=+$/, '');
}

/**
 * Classify and normalize an indicator. type is auto | file | hash | ip | domain | url.
 * Returns { type, value, id } where id is the VirusTotal object id. Throws on anything invalid.
 */
export function classifyIndicator(raw, type = 'auto') {
  const v = refang(raw);
  if (!v) throw new Error('indicator is required.');
  if (v.length > 2048) throw new Error('indicator is longer than 2048 characters.');
  const t = String(type || 'auto').toLowerCase();
  const want = t === 'hash' ? 'file' : t;
  if (!['auto', 'file', 'ip', 'domain', 'url'].includes(want)) {
    throw new Error(`type must be auto, file (hash), ip, domain or url (got ${JSON.stringify(type)}).`);
  }
  const asFile = () => { if (!HASH_RE.test(v)) throw new Error('not an MD5, SHA-1 or SHA-256 hash.'); const h = v.toLowerCase(); return { type: 'file', value: h, id: h }; };
  const asIp = () => { if (!isIP(v)) throw new Error('not a valid IPv4 or IPv6 address.'); return { type: 'ip', value: v, id: v }; };
  const asUrl = () => {
    let u;
    try { u = new URL(v); } catch { throw new Error('not a valid URL.'); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('URL must use http or https.');
    return { type: 'url', value: v, id: vtUrlId(v) };
  };
  const asDomain = () => {
    const d = v.toLowerCase().replace(/\.$/, '');
    if (!DOMAIN_RE.test(d)) throw new Error('not a valid domain name.');
    return { type: 'domain', value: d, id: d };
  };
  if (want === 'file') return asFile();
  if (want === 'ip') return asIp();
  if (want === 'url') return asUrl();
  if (want === 'domain') return asDomain();
  if (HASH_RE.test(v)) return asFile();
  if (isIP(v)) return asIp();
  if (/^https?:\/\//i.test(v)) return asUrl();
  if (DOMAIN_RE.test(v.replace(/\.$/, ''))) return asDomain();
  throw new Error(`could not tell what ${JSON.stringify(v.slice(0, 80))} is: pass type (file, ip, domain or url).`);
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────

/**
 * GET origin+path. path is built by this module from encoded parts; the resolved origin must equal
 * the pinned one. Returns parsed JSON, or { __notFound: true } on 404.
 */
async function tiGet(origin, path, { headers = {}, query = {}, service, retries = 2, wait429Ms = 15000 } = {}) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) throw new Error(`${service}: bad request path.`);
  const u = new URL(path, origin);
  if (u.origin !== origin) throw new Error(`${service}: request path may not change the origin.`);
  for (const [k, val] of Object.entries(query)) if (val !== undefined && val !== null && val !== '') u.searchParams.set(k, String(val));
  const label = `${service} GET ${u.pathname}`;   // never the query string: Shodan's key travels there
  // S1_TI_RETRY_WAIT_MS overrides every retry wait (tests set it to 0).
  const ov = Number(process.env.S1_TI_RETRY_WAIT_MS);
  const waitFor = ms => (process.env.S1_TI_RETRY_WAIT_MS !== undefined && Number.isFinite(ov) && ov >= 0 ? ov : ms);
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetch(u, { method: 'GET', headers: { Accept: 'application/json', ...headers }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (e) {
      const why = e?.name === 'TimeoutError' ? `timed out after ${TIMEOUT_MS} ms` : 'network error';
      if (attempt < retries) { await sleep(waitFor(1000 * (attempt + 1))); continue; }
      throw new Error(`${label} failed: ${why}.`);
    }
    if (res.status === 429 && attempt < retries) {
      const ra = Number(res.headers.get('Retry-After'));
      await sleep(waitFor(Number.isFinite(ra) && ra > 0 ? Math.min(ra * 1000, 60000) : wait429Ms));
      continue;
    }
    const text = await res.text();
    let data;
    try { data = parseJsonExact(text); } catch { data = null; }
    if (res.status === 404) return { __notFound: true, detail: errDetail(data) };
    if (!res.ok) {
      const detail = errDetail(data) || String(text || '').slice(0, 200);
      throw new Error(`${label} → ${res.status}${detail ? `: ${detail}` : ''}${statusHint(service, res.status)}`);
    }
    if (data === null) throw new Error(`${label}: response was not JSON.`);
    return data;
  }
}

function errDetail(data) {
  if (!data || typeof data !== 'object') return '';
  if (data.error && typeof data.error === 'object') return [data.error.code, data.error.message].filter(Boolean).join(': ');
  if (typeof data.error === 'string') return data.error;
  return '';
}

function statusHint(service, status) {
  if (status === 429) {
    return service === 'VirusTotal'
      ? ' (quota exceeded: a free VirusTotal key allows 4 lookups per minute and 500 per day)'
      : ' (rate limited: Shodan allows about 1 request per second)';
  }
  if (status === 401) return ` (the ${service} key was rejected: check it with setup)`;
  if (status === 403) return ` (the ${service} key's plan does not include this data)`;
  return '';
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────

const iso = s => (typeof s === 'number' && s > 0 ? new Date(s * 1000).toISOString() : undefined);
const take = (a, n) => (Array.isArray(a) ? a.slice(0, n) : undefined);
function prune(o) {
  if (Array.isArray(o)) return o.map(prune);
  if (!o || typeof o !== 'object') return o;
  const out = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)
      || (typeof v === 'object' && !Array.isArray(v) && !Object.keys(prune(v)).length)) continue;
    out[k] = prune(v);
  }
  return out;
}

function engineHits(results, n = 15) {
  if (!results || typeof results !== 'object') return undefined;
  return Object.entries(results)
    .filter(([, r]) => r && (r.category === 'malicious' || r.category === 'suspicious'))
    .slice(0, n)
    .map(([engine, r]) => ({ engine, category: r.category, result: r.result || null }));
}

function vtGui(type, id) { return `${VT_ORIGIN}/gui/${VT_GUI[type]}/${encodeURIComponent(id)}`; }

/** Trim a VirusTotal object report to the fields an analyst uses for a verdict. */
export function summarizeVtObject(ind, data) {
  const a = data?.attributes || {};
  const common = {
    indicator: ind.value,
    type: ind.type,
    lastAnalysisStats: a.last_analysis_stats,
    detections: engineHits(a.last_analysis_results),
    reputation: a.reputation,
    communityVotes: a.total_votes,
    tags: take(a.tags, 20),
    lastAnalysisDate: iso(a.last_analysis_date),
    link: vtGui(ind.type, ind.id),
  };
  let specific = {};
  if (ind.type === 'file') {
    const ptc = a.popular_threat_classification || {};
    specific = {
      sha256: a.sha256, sha1: a.sha1, md5: a.md5,
      meaningfulName: a.meaningful_name,
      names: take(a.names, 10),
      typeDescription: a.type_description,
      size: a.size,
      threatLabel: ptc.suggested_threat_label,
      threatCategories: take(ptc.popular_threat_category, 3)?.map(x => x.value),
      threatNames: take(ptc.popular_threat_name, 3)?.map(x => x.value),
      sandboxVerdicts: a.sandbox_verdicts
        ? Object.entries(a.sandbox_verdicts).slice(0, 6).map(([sandbox, s]) => ({ sandbox, category: s?.category, malwareNames: take(s?.malware_names, 3) }))
        : undefined,
      signature: a.signature_info ? { product: a.signature_info.product, signers: a.signature_info.signers, verified: a.signature_info.verified } : undefined,
      yaraRules: take(a.crowdsourced_yara_results, 5)?.map(y => y.rule_name),
      sigmaStats: a.sigma_analysis_stats,
      firstSubmission: iso(a.first_submission_date),
      lastSubmission: iso(a.last_submission_date),
      timesSubmitted: a.times_submitted,
    };
  } else if (ind.type === 'ip') {
    specific = {
      asOwner: a.as_owner, asn: a.asn, country: a.country, continent: a.continent,
      network: a.network, rir: a.regional_internet_registry,
      httpsCertificateSubject: a.last_https_certificate?.subject?.CN,
      jarm: a.jarm,
    };
  } else if (ind.type === 'domain') {
    specific = {
      registrar: a.registrar,
      creationDate: iso(a.creation_date),
      categories: a.categories,
      lastDnsRecords: take(a.last_dns_records, 12)?.map(r => ({ type: r.type, value: r.value })),
      httpsCertificateIssuer: a.last_https_certificate?.issuer?.CN,
      popularityRanks: a.popularity_ranks ? Object.fromEntries(Object.entries(a.popularity_ranks).slice(0, 4).map(([k, v]) => [k, v?.rank])) : undefined,
    };
  } else if (ind.type === 'url') {
    specific = {
      url: a.url,
      finalUrl: a.last_final_url,
      title: a.title,
      httpResponseCode: a.last_http_response_code,
      categories: a.categories,
      redirectionChain: take(a.redirection_chain, 5),
      firstSubmission: iso(a.first_submission_date),
    };
  }
  return prune({ ...common, ...specific });
}

/** Look up a file hash, IP, domain or URL in VirusTotal. */
export async function vtLookup(indicator, type = 'auto') {
  const ind = classifyIndicator(indicator, type);
  const data = await tiGet(VT_ORIGIN, `/api/v3/${VT_COLLECTION[ind.type]}/${encodeURIComponent(ind.id)}`, {
    headers: { 'x-apikey': vtKey() }, service: 'VirusTotal',
  });
  if (data.__notFound) {
    return { indicator: ind.value, type: ind.type, found: false, note: 'VirusTotal has no record of this indicator. Absence is not a benign verdict.' };
  }
  return { found: true, ...summarizeVtObject(ind, data.data) };
}

/** Relationships offered per indicator type. Kept to the ones playbooks use. */
export const VT_RELATIONSHIPS = Object.freeze({
  file: ['contacted_domains', 'contacted_ips', 'contacted_urls', 'dropped_files', 'execution_parents', 'bundled_files',
    'embedded_domains', 'embedded_ips', 'embedded_urls', 'itw_urls', 'related_threat_actors', 'similar_files', 'comments'],
  ip: ['communicating_files', 'downloaded_files', 'referrer_files', 'resolutions', 'urls', 'related_threat_actors',
    'historical_ssl_certificates', 'comments'],
  domain: ['communicating_files', 'downloaded_files', 'referrer_files', 'resolutions', 'subdomains', 'siblings', 'urls',
    'related_threat_actors', 'historical_ssl_certificates', 'comments'],
  url: ['contacted_domains', 'contacted_ips', 'downloaded_files', 'communicating_files', 'redirects_to', 'redirecting_urls',
    'last_serving_ip_address', 'related_threat_actors', 'comments'],
});

const stats = a => (a?.last_analysis_stats ? { malicious: a.last_analysis_stats.malicious, suspicious: a.last_analysis_stats.suspicious } : undefined);

function summarizeRelated(o) {
  const a = o?.attributes || {};
  switch (o?.type) {
    case 'file': return prune({ type: 'file', sha256: o.id, name: a.meaningful_name || take(a.names, 1)?.[0], fileType: a.type_description, detections: stats(a), reputation: a.reputation });
    case 'domain': return prune({ type: 'domain', domain: o.id, detections: stats(a), reputation: a.reputation, registrar: a.registrar });
    case 'ip_address': return prune({ type: 'ip', ip: o.id, country: a.country, asOwner: a.as_owner, detections: stats(a) });
    case 'url': return prune({ type: 'url', url: a.url || o.context_attributes?.url || o.id, detections: stats(a), title: a.title });
    case 'resolution': return prune({ type: 'resolution', date: iso(a.date), hostName: a.host_name, ipAddress: a.ip_address, hostDetections: a.host_name_last_analysis_stats?.malicious, ipDetections: a.ip_address_last_analysis_stats?.malicious });
    case 'collection': return prune({ type: 'collection', id: o.id, name: a.name, aliases: take(a.alt_names, 8), collectionType: a.collection_type, sourceRegion: a.source_region, targetedIndustries: take(a.targeted_industries, 6), description: a.description ? String(a.description).slice(0, 400) : undefined });
    case 'ssl_cert': return prune({ type: 'certificate', thumbprint: o.id, subject: a.subject?.CN, issuer: a.issuer?.CN, validFrom: a.validity?.not_before, validTo: a.validity?.not_after });
    case 'comment': return prune({ type: 'comment', date: iso(a.date), text: a.text ? String(a.text).slice(0, 400) : undefined, votes: a.votes });
    default: return prune({ type: o?.type, id: o?.id });
  }
}

/** One relationship page for an indicator. limit 1..40, cursor from a previous page. */
export async function vtRelationship(indicator, relationship, { type = 'auto', limit = 10, cursor } = {}) {
  const ind = classifyIndicator(indicator, type);
  const allowed = VT_RELATIONSHIPS[ind.type];
  if (!allowed.includes(relationship)) {
    throw new Error(`relationship ${JSON.stringify(relationship)} is not available for a ${ind.type}. Use one of: ${allowed.join(', ')}.`);
  }
  const n = Math.min(40, Math.max(1, Math.floor(Number(limit) || 10)));
  const data = await tiGet(VT_ORIGIN, `/api/v3/${VT_COLLECTION[ind.type]}/${encodeURIComponent(ind.id)}/${relationship}`, {
    headers: { 'x-apikey': vtKey() }, query: { limit: n, cursor }, service: 'VirusTotal',
  });
  if (data.__notFound) {
    return { indicator: ind.value, type: ind.type, relationship, found: false, items: [], note: 'VirusTotal has no record of this indicator.' };
  }
  const raw = Array.isArray(data.data) ? data.data : (data.data ? [data.data] : []);
  return prune({
    indicator: ind.value, type: ind.type, relationship, found: true,
    count: raw.length,
    total: data.meta?.count,
    items: raw.map(summarizeRelated),
    nextCursor: data.meta?.cursor,
  });
}

// ─── Shodan ───────────────────────────────────────────────────────────────────

/** Shodan host information for one IP: open ports, services, CVEs, owner. */
export async function shodanHost(ip) {
  const v = refang(ip);
  if (!isIP(v)) throw new Error('ip must be a valid IPv4 or IPv6 address.');
  const data = await tiGet(SHODAN_ORIGIN, `/shodan/host/${encodeURIComponent(v)}`, {
    query: { key: shodanKey() }, service: 'Shodan', wait429Ms: 1100,
  });
  if (data.__notFound) {
    return { ip: v, found: false, note: 'Shodan has no information for this IP (not scanned or nothing exposed). Absence is not a benign verdict.' };
  }
  const services = (Array.isArray(data.data) ? data.data : []).slice(0, 25).map(s => prune({
    port: s.port,
    transport: s.transport,
    product: s.product,
    version: s.version,
    module: s._shodan?.module,
    seen: s.timestamp,
    cpe: take(s.cpe23 || s.cpe, 4),
    http: s.http ? { title: s.http.title ? String(s.http.title).slice(0, 200) : undefined, server: s.http.server, status: s.http.status } : undefined,
    tls: s.ssl ? { subject: s.ssl.cert?.subject?.CN, issuer: s.ssl.cert?.issuer?.CN, expires: s.ssl.cert?.expires, jarm: s.ssl.jarm } : undefined,
    vulns: s.vulns ? Object.keys(s.vulns).slice(0, 20) : undefined,
  }));
  const vulns = Array.isArray(data.vulns) ? data.vulns : (data.vulns ? Object.keys(data.vulns) : []);
  return prune({
    ip: data.ip_str || v,
    found: true,
    org: data.org, isp: data.isp, asn: data.asn,
    country: data.country_name, city: data.city,
    os: data.os,
    hostnames: take(data.hostnames, 20),
    domains: take(data.domains, 20),
    tags: data.tags,
    ports: data.ports,
    vulnCount: vulns.length || undefined,
    vulns: vulns.slice().sort().slice(0, 50),
    lastUpdate: data.last_update,
    services,
    link: `https://www.shodan.io/host/${encodeURIComponent(v)}`,
  });
}

/** Resolve hostnames to IPs, or IPs to hostnames, with Shodan DNS (no query credits). */
export async function shodanDns({ hostnames, ips } = {}) {
  const hs = (Array.isArray(hostnames) ? hostnames : []).map(h => refang(h).toLowerCase().replace(/\.$/, '')).filter(Boolean);
  const is = (Array.isArray(ips) ? ips : []).map(refang).filter(Boolean);
  if (!hs.length === !is.length) throw new Error('pass either hostnames or ips (not both, not neither).');
  const list = hs.length ? hs : is;
  if (list.length > 25) throw new Error('at most 25 values per call.');
  for (const x of list) {
    if (hs.length ? !DOMAIN_RE.test(x) : !isIP(x)) throw new Error(`${JSON.stringify(x.slice(0, 80))} is not a valid ${hs.length ? 'hostname' : 'IP address'}.`);
  }
  const path = hs.length ? '/dns/resolve' : '/dns/reverse';
  const data = await tiGet(SHODAN_ORIGIN, path, {
    query: { [hs.length ? 'hostnames' : 'ips']: list.join(','), key: shodanKey() }, service: 'Shodan', wait429Ms: 1100,
  });
  if (data.__notFound) return { mode: hs.length ? 'resolve' : 'reverse', results: {} };
  return { mode: hs.length ? 'resolve' : 'reverse', results: data };
}
