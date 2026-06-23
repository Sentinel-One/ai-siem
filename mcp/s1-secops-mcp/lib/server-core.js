/**
 * MCP server core: transport-agnostic.
 *
 * Exports:
 *   - dispatch(method, params, id):    JSON-RPC method dispatcher
 *   - SERVER_INFO, PROTOCOL_VERSION:    server identity
 *   - TOOL_DEFS:                        for diagnostics / introspection
 *   - ALL_TOOLS:                        for tests
 *
 * Both stdio-transport and http-transport import dispatch() and feed it
 * parsed JSON-RPC envelopes. They are responsible for serialization,
 * framing, and any transport-specific concerns (auth, sessions, headers).
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import { tools as pqTools }        from '../tools/powerquery.js';
import { tools as mgmtTools }       from '../tools/mgmt-console.js';
import { tools as sdlTools }        from '../tools/sdl-api.js';
import { tools as haTools }         from '../tools/hyperautomation.js';
import { tools as uamIngestTools }  from '../tools/uam-ingest.js';
import { getCreds, hasS1Creds, hasSdlCreds } from './credentials.js';
import { hasHecCreds } from './uam-ingest.js';

const __dir = dirname(fileURLToPath(import.meta.url));

// ─── SOC context (CLAUDE.md) ──────────────────────────────────────────────────

function loadSocContext() {
  const candidates = [
    process.env.S1_CLAUDE_MD_PATH,
    process.cwd() ? join(process.cwd(), 'CLAUDE.md') : null,
    join(__dir, '..', '..', '..', 'plugins', 's1-secops-skills', 'CLAUDE.md'), // ai-siem layout
    join(__dir, '..', '..', 'CLAUDE.md'),    // legacy monorepo layout
    join(__dir, '..', '..', '..', 'CLAUDE.md'),
    join(__dir, '..', 'CLAUDE.md'),
  ].filter(Boolean);
  for (const p of candidates) {
    if (existsSync(p)) {
      try { return readFileSync(p, 'utf-8'); } catch { /* skip */ }
    }
  }
  return '# SentinelOne SOC Analyst Context\n\n_CLAUDE.md not found. Place it in your Cowork project folder, or set S1_CLAUDE_MD_PATH to an absolute path._';
}

const SOC_CONTEXT = loadSocContext();

// ─── Tool registry ────────────────────────────────────────────────────────────

export const ALL_TOOLS = [...pqTools, ...mgmtTools, ...sdlTools, ...haTools, ...uamIngestTools];

export const TOOL_DEFS = ALL_TOOLS.map(t => ({
  name: t.name,
  description: t.description,
  inputSchema: t.inputSchema,
}));

const HANDLERS = Object.fromEntries(ALL_TOOLS.map(t => [t.name, t.handler]));

// ─── Resources ────────────────────────────────────────────────────────────────

const RESOURCES = [
  {
    uri: 'sentinelone://soc-context',
    name: 'SOC Analyst Operating Instructions',
    description: 'CLAUDE.md — Principal SOC Analyst operating instructions including investigation workflow, evidence discipline, anomaly detection playbook, MITRE ATT&CK mapping, and tool usage priorities.',
    mimeType: 'text/markdown',
  },
  {
    uri: 'sentinelone://credentials-status',
    name: 'Credential Configuration Status',
    description: 'Reports which credentials are configured and which API surfaces are available.',
    mimeType: 'application/json',
  },
];

// ─── Prompts ──────────────────────────────────────────────────────────────────

const PROMPTS = [
  {
    name: 'soc_analyst',
    description: 'Load the Principal SOC Analyst system context from CLAUDE.md. Call at the start of every security investigation session to prime the operating instructions, evidence discipline rules, investigation workflow, and tool usage priorities.',
    arguments: [],
  },
  {
    name: 'session_init',
    description: 'Structured session initialization prompt. Triggers mandatory data-source enumeration, alert triage, and schema discovery in parallel, mirroring the standard engagement workflow from the SOC playbook.',
    arguments: [],
  },
];

// ─── MCP envelope helpers ─────────────────────────────────────────────────────

export const SERVER_INFO = {
  name: 's1-secops-mcp-server',
  version: '1.2.2',
};

export const PROTOCOL_VERSION = '2024-11-05';

export function ok(id, result) {
  return { jsonrpc: '2.0', id, result };
}

export function err(id, code, message, data) {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data ? { data } : {}) } };
}

function log(...args) {
  process.stderr.write('[s1-secops-mcp] ' + args.join(' ') + '\n');
}

// ─── dispatch ────────────────────────────────────────────────────────────────

export async function dispatch(method, params, id) {
  switch (method) {

    case 'initialize': {
      return ok(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          resources: { subscribe: false, listChanged: false },
          tools: { listChanged: false },
          prompts: { listChanged: false },
        },
        serverInfo: SERVER_INFO,
        instructions: 'SentinelOne MCP server providing PowerQuery, Mgmt Console API, SDL API, and Hyperautomation tools. Load the "soc_analyst" prompt at session start for full operating context.',
      });
    }

    case 'ping': {
      return ok(id, {});
    }

    case 'resources/list': {
      return ok(id, { resources: RESOURCES });
    }

    case 'resources/read': {
      const uri = params?.uri;
      if (uri === 'sentinelone://soc-context') {
        return ok(id, {
          contents: [{ uri, mimeType: 'text/markdown', text: SOC_CONTEXT }],
        });
      }
      if (uri === 'sentinelone://credentials-status') {
        const c = getCreds();
        const status = {
          s1MgmtApi: {
            configured: hasS1Creds(),
            consoleUrl: c.S1_CONSOLE_URL ? c.S1_CONSOLE_URL.replace(/https?:\/\//, '').split('.')[0] + '...' : 'NOT SET',
            tokenPresent: !!c.S1_CONSOLE_API_TOKEN,
          },
          sdlApi: {
            configured: hasSdlCreds(),
            xdrUrl: c.SDL_XDR_URL || 'NOT SET',
            configWriteKey: !!c.SDL_CONFIG_WRITE_KEY,
          },
          uamIngestApi: {
            configured: hasHecCreds(),
            hecUrl: c.S1_HEC_INGEST_URL || 'NOT SET (add S1_HEC_INGEST_URL to credentials.json)',
            tokenPresent: !!c.S1_CONSOLE_API_TOKEN,
          },
        };
        return ok(id, {
          contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(status, null, 2) }],
        });
      }
      return err(id, -32002, `Resource not found: ${uri}`);
    }

    case 'prompts/list': {
      return ok(id, { prompts: PROMPTS });
    }

    case 'prompts/get': {
      const name = params?.name;

      if (name === 'soc_analyst') {
        return ok(id, {
          description: 'Principal SOC Analyst operating instructions from CLAUDE.md',
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: `You are operating as a Principal SOC Analyst. Load and follow the instructions below precisely.\n\n${SOC_CONTEXT}`,
              },
            },
          ],
        });
      }

      if (name === 'session_init') {
        return ok(id, {
          description: 'Structured session initialization',
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: `Begin a new SOC analyst session. Follow this initialization sequence:

1. Call \`powerquery_enumerate_sources\` to discover active SDL data sources (MANDATORY, never assume sources from prior sessions).
2. In parallel, call \`uam_list_alerts\` with status="NEW" to pull untriaged active alerts. Valid status values are "NEW", "IN_PROGRESS", or "RESOLVED" (there is no "OPEN" status; it silently returns 0 results). Omit the status argument to pull the most recent alerts across all states.
3. For each discovered data source not already in the schema registry, plan schema discovery via \`powerquery_schema_discover\`.
4. Report: (a) active data sources list, (b) untriaged (NEW) alert count and top 5 by severity, (c) which sources need schema discovery.

Apply the SOC analyst context from the soc_analyst prompt throughout.`,
              },
            },
          ],
        });
      }

      return err(id, -32002, `Prompt not found: ${name}`);
    }

    case 'tools/list': {
      return ok(id, { tools: TOOL_DEFS });
    }

    case 'tools/call': {
      const toolName = params?.name;
      const args = params?.arguments || {};

      if (!toolName) {
        return err(id, -32602, 'Missing tool name');
      }

      const handler = HANDLERS[toolName];
      if (!handler) {
        return err(id, -32602, `Tool not found: ${toolName}`);
      }

      try {
        const output = await handler(args);
        const text = typeof output === 'string' ? output : JSON.stringify(output, null, 2);
        return ok(id, {
          content: [{ type: 'text', text }],
          isError: false,
        });
      } catch (e) {
        log(`Tool error [${toolName}]:`, e.message);
        return ok(id, {
          content: [{ type: 'text', text: `Error: ${e.message}` }],
          isError: true,
        });
      }
    }

    case 'notifications/initialized':
    case 'initialized':
      return null;

    default: {
      if (id !== undefined) {
        return err(id, -32601, `Method not found: ${method}`);
      }
      return null;
    }
  }
}
