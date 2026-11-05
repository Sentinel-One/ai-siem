/**
 * Built-in threat-intelligence tools (1.6.0). Read-only, our own code, the operator's own keys.
 *
 *   ti_vt_lookup        VirusTotal report for a file hash, IP, domain or URL
 *   ti_vt_relationship  One VirusTotal relationship page (contacted IPs, resolutions, threat actors, ...)
 *   ti_shodan_host      Shodan host information for an IP
 *   ti_shodan_dns       Shodan DNS resolve / reverse
 *
 * Each tool is listed only when its key is configured (`available`), so a client never sees a tool
 * it cannot use. Keys: VIRUSTOTAL_API_KEY, SHODAN_API_KEY (environment or OS keychain, via setup).
 */

import {
  vtLookup, vtRelationship, shodanHost, shodanDns, hasVtKey, hasShodanKey, VT_RELATIONSHIPS,
} from '../lib/ti.js';

const ALL_RELS = [...new Set(Object.values(VT_RELATIONSHIPS).flat())].sort();
const out = v => JSON.stringify(v, null, 2);

export const tools = [
  {
    name: 'ti_vt_lookup',
    available: hasVtKey,
    description: 'VirusTotal report for one indicator: a file hash (MD5, SHA-1 or SHA-256), IP address, domain or URL. Defanged input (hxxp, [.]) is accepted. Returns detection stats (malicious, suspicious, harmless, undetected), the engines that flagged it, reputation, community votes, tags and type-specific context: for files the threat label, names, sandbox verdicts, signature and YARA hits; for IPs the ASN, owner and country; for domains the registrar, creation date, DNS records and categories; for URLs the final URL, title and redirects. found:false means VirusTotal has no record, which is not a benign verdict. Uses the operator\'s VIRUSTOTAL_API_KEY: a free key allows 4 lookups per minute. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        indicator: { type: 'string', description: 'The hash, IP, domain or URL to look up.' },
        type: { type: 'string', enum: ['auto', 'file', 'hash', 'ip', 'domain', 'url'], description: 'Indicator type. Default auto (detected from the value).' },
      },
      required: ['indicator'],
    },
    async handler({ indicator, type }) { return out(await vtLookup(indicator, type || 'auto')); },
  },
  {
    name: 'ti_vt_relationship',
    available: hasVtKey,
    description: `One page of a VirusTotal relationship for an indicator, to pivot from it: what a file contacts or drops, which files talk to an IP or domain, DNS resolutions, subdomains, related threat actors, certificates. Relationships by type: file: ${VT_RELATIONSHIPS.file.join(', ')}. ip: ${VT_RELATIONSHIPS.ip.join(', ')}. domain: ${VT_RELATIONSHIPS.domain.join(', ')}. url: ${VT_RELATIONSHIPS.url.join(', ')}. Some (e.g. related_threat_actors, similar_files) need a premium key; a 403 says so. Items are trimmed to the fields used for pivoting (ids, names, detection counts). Page with nextCursor. Read-only.`,
    inputSchema: {
      type: 'object',
      properties: {
        indicator: { type: 'string', description: 'The hash, IP, domain or URL.' },
        relationship: { type: 'string', enum: ALL_RELS, description: 'Relationship name, valid for the indicator type.' },
        type: { type: 'string', enum: ['auto', 'file', 'hash', 'ip', 'domain', 'url'], description: 'Indicator type. Default auto.' },
        limit: { type: 'number', description: 'Items per page, 1 to 40 (default 10).' },
        cursor: { type: 'string', description: 'nextCursor from a previous page.' },
      },
      required: ['indicator', 'relationship'],
    },
    async handler({ indicator, relationship, type, limit, cursor }) {
      return out(await vtRelationship(indicator, relationship, { type: type || 'auto', limit, cursor }));
    },
  },
  {
    name: 'ti_shodan_host',
    available: hasShodanKey,
    description: 'Shodan host information for one IP address: owner (org, ISP, ASN), location, OS, hostnames, open ports, known CVEs, tags (e.g. vpn, tor, honeypot) and up to 25 services with product, version, HTTP title and TLS certificate. found:false means Shodan has not seen the IP, which is not a benign verdict. A host lookup does not spend query credits. Uses the operator\'s SHODAN_API_KEY. Read-only.',
    inputSchema: {
      type: 'object',
      properties: { ip: { type: 'string', description: 'IPv4 or IPv6 address (defanged accepted).' } },
      required: ['ip'],
    },
    async handler({ ip }) { return out(await shodanHost(ip)); },
  },
  {
    name: 'ti_shodan_dns',
    available: hasShodanKey,
    description: 'Shodan DNS: resolve up to 25 hostnames to IP addresses, or reverse-resolve up to 25 IP addresses to hostnames. Pass hostnames or ips, not both. Does not spend query credits. Uses the operator\'s SHODAN_API_KEY. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        hostnames: { type: 'array', items: { type: 'string' }, description: 'Hostnames to resolve.' },
        ips: { type: 'array', items: { type: 'string' }, description: 'IP addresses to reverse-resolve.' },
      },
    },
    async handler({ hostnames, ips }) { return out(await shodanDns({ hostnames, ips })); },
  },
];
