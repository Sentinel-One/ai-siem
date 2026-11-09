/**
 * Detection as Code tools: native custom-rule management through the console's VCS endpoints.
 *
 *   dac_export  GET  /web/api/v2.1/cloud-detection/rules/export-vcs           (read)
 *   dac_diff    POST /web/api/v2.1/cloud-detection/rules/parse-vcs?mode=diff  (read: the diff writes nothing)
 *   dac_apply   POST /web/api/v2.1/cloud-detection/rules/parse-vcs?mode=apply (write)
 *
 * The bundle matches the reference CI script: the deployments file is stored as
 * `deployments.yaml` at the zip root and every rule file (.yaml / .yml) at its path relative to
 * the detections root. The backend applies the deploy globs from deployments.yaml.
 *
 * Local file access goes through the output-folder policy (lib/output.js): repoDir and
 * deploymentsFile must resolve inside an allowed root, are not followed through symlinks, and
 * hidden (dot) paths are skipped. Archives from the console are read with lib/zip.js, which
 * refuses unsafe entry names and caps size and entry count.
 */

import { createHash } from 'node:crypto';
import {
  lstatSync, realpathSync, readdirSync, openSync, readFileSync, closeSync, constants as fsConstants,
} from 'node:fs';
import { isAbsolute, join, relative, resolve, sep, dirname, basename, extname } from 'node:path';
import { base, jwt, apiGetBinary } from '../lib/s1.js';
import { allowedRoots, inContainer, resolveOutputPath, writeOutput } from '../lib/output.js';
import { parseJsonExact } from '../lib/json.js';
import { writeZip, readZip, checkEntryName } from '../lib/zip.js';

const EXPORT_PATH = '/web/api/v2.1/cloud-detection/rules/export-vcs';
const PARSE_PATH = '/web/api/v2.1/cloud-detection/rules/parse-vcs';
const DEPLOYMENTS = 'deployments.yaml';
const RULE_EXT = new Set(['.yaml', '.yml']);
const CHANGE_LISTS = ['creates', 'updates', 'deletes', 'imports', 'retains'];

const MAX_BUNDLE_FILES = 5000;
const MAX_BUNDLE_BYTES = 50 * 1024 * 1024;
const MAX_EXPORT_PAGES = 100;
const PARSE_TIMEOUT_MS = 120 * 1000;
const ERROR_BODY_MAX = 20000;
/** Retry timing; tests shorten it. */
export const retryTiming = { baseMs: 2000 };

const out = v => JSON.stringify(v, null, 2);

// ─── local input: path policy ─────────────────────────────────────────────────

function within(child, root) {
  return child === root || child.startsWith(root.endsWith(sep) ? root : root + sep);
}

/**
 * Validate a local input path (directory or file) against the output-folder policy:
 * absolute, not a symlink, of the expected kind, real path inside an allowed root, and no hidden
 * (dot) segment below that root. Returns the real path.
 */
export function resolveInputPath(p, kind, label) {
  if (typeof p !== 'string' || !p.trim()) throw new Error(`${label} must be a non-empty string`);
  if (!isAbsolute(p)) throw new Error(`${label} must be an absolute path (got ${p})`);
  const target = resolve(p);
  const roots = allowedRoots();
  if (roots.length === 0) {
    throw new Error(`${label} ${target} refused: no folder is shared with this container. Ask the user to run `
      + '"s1-secops-mcp-launch.sh install --output-dir <folder>" (Windows: -OutputDir), restart Claude Desktop, and put the '
      + 'repository inside that folder (Windows: under /output). Or pass the rule files inline with `files`.');
  }
  let st;
  try { st = lstatSync(target); } catch (e) {
    if (e.code === 'ENOENT') throw new Error(`${label} ${target} does not exist`);
    throw e;
  }
  if (st.isSymbolicLink()) throw new Error(`${label} ${target} is a symlink; refusing to follow it`);
  if (kind === 'dir' && !st.isDirectory()) throw new Error(`${label} ${target} is not a directory`);
  if (kind === 'file' && !st.isFile()) throw new Error(`${label} ${target} is not a regular file`);
  const real = realpathSync(target);
  const root = roots.filter(r => within(real, r)).sort((a, b) => b.length - a.length)[0];
  if (!root) {
    throw new Error(inContainer()
      ? `${label} ${target} is outside the folder shared with this container (${roots.join(', ')}).`
      : `${label} ${target} is outside the allowed directories (${roots.join(', ')}). Set S1_OUTPUT_DIRS to allow another directory.`);
  }
  const rel = relative(root, real).replace(/\\/g, '/');
  if (rel.split('/').filter(Boolean).some(s => s.startsWith('.'))) {
    throw new Error(`${label} ${target} is a hidden (dot) path below ${root}, which the file policy refuses.`);
  }
  return real;
}

function readNoFollow(p) {
  const fd = openSync(p, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
  try { return readFileSync(fd); } finally { closeSync(fd); }
}

/** Every .yaml/.yml file below dir, sorted, skipping hidden entries and symlinks. */
function listRuleFiles(dir) {
  const found = [];
  const skipped = { symlinks: 0, hidden: 0 };
  const walk = (abs, depth) => {
    if (depth > 32) throw new Error(`repoDir is nested more than 32 levels deep at ${abs}`);
    for (const d of readdirSync(abs, { withFileTypes: true })) {
      if (d.name.startsWith('.')) { skipped.hidden++; continue; }   // .git, .github, editor files
      const full = join(abs, d.name);
      if (d.isSymbolicLink()) { skipped.symlinks++; continue; }
      if (d.isDirectory()) { walk(full, depth + 1); continue; }
      if (d.isFile() && RULE_EXT.has(extname(d.name).toLowerCase())) {
        found.push(full);
        if (found.length > MAX_BUNDLE_FILES) throw new Error(`repoDir holds more than ${MAX_BUNDLE_FILES} rule files`);
      }
    }
  };
  walk(dir, 0);
  found.sort();
  return { found, skipped };
}

/**
 * Build the bundle entries from either `files` (inline map) or `repoDir` (+ optional deploymentsFile).
 * Returns { entries: [{name, data}], ruleFiles: [names], notes: [] }.
 */
export function collectBundle({ files, repoDir, deploymentsFile } = {}) {
  const hasFiles = files !== undefined && files !== null;
  if (hasFiles === Boolean(repoDir)) throw new Error('Pass exactly one of `files` or `repoDir`.');
  const notes = [];
  let total = 0;
  const add = (entries, name, data) => {
    total += data.length;
    if (total > MAX_BUNDLE_BYTES) throw new Error(`bundle exceeds ${MAX_BUNDLE_BYTES} bytes`);
    entries.push({ name, data });
  };

  if (hasFiles) {
    if (typeof files !== 'object' || Array.isArray(files)) throw new Error('`files` must be an object mapping relative path to YAML text');
    const keys = Object.keys(files);
    if (!keys.includes(DEPLOYMENTS)) throw new Error('`files` must contain "deployments.yaml" (the deployments manifest, at the bundle root)');
    if (keys.length > MAX_BUNDLE_FILES + 1) throw new Error(`\`files\` holds more than ${MAX_BUNDLE_FILES} rule files`);
    const entries = [];
    if (typeof files[DEPLOYMENTS] !== 'string') throw new Error('files["deployments.yaml"] must be a string');
    add(entries, DEPLOYMENTS, Buffer.from(files[DEPLOYMENTS], 'utf-8'));
    const rules = keys.filter(k => k !== DEPLOYMENTS).sort();
    for (const k of rules) {
      checkEntryName(k);
      if (k.endsWith('/')) throw new Error(`files key ${JSON.stringify(k)} is a directory, not a file`);
      if (!RULE_EXT.has(extname(k).toLowerCase())) throw new Error(`files key ${JSON.stringify(k)} is not a .yaml or .yml rule file`);
      if (typeof files[k] !== 'string') throw new Error(`files[${JSON.stringify(k)}] must be a string`);
      add(entries, k, Buffer.from(files[k], 'utf-8'));
    }
    return { entries, ruleFiles: rules, notes };
  }

  const root = resolveInputPath(repoDir, 'dir', 'repoDir');
  let depPath;
  if (deploymentsFile) {
    const candidate = isAbsolute(deploymentsFile) ? deploymentsFile : join(root, deploymentsFile);
    depPath = resolveInputPath(candidate, 'file', 'deploymentsFile');
  } else {
    depPath = resolveInputPath(join(root, DEPLOYMENTS), 'file', 'deploymentsFile (default <repoDir>/deployments.yaml)');
  }
  const entries = [];
  add(entries, DEPLOYMENTS, readNoFollow(depPath));
  const { found, skipped } = listRuleFiles(root);
  const ruleFiles = [];
  for (const abs of found) {
    const real = realpathSync(abs);
    if (real === depPath) continue;                        // the manifest itself is not a rule file
    const rel = relative(root, abs).split(sep).join('/');
    if (rel === DEPLOYMENTS) {
      notes.push(`Skipped ${DEPLOYMENTS} at the repoDir root: the bundle root name is reserved for the deployments manifest.`);
      continue;
    }
    checkEntryName(rel);
    add(entries, rel, readNoFollow(abs));
    ruleFiles.push(rel);
  }
  if (skipped.symlinks) notes.push(`Skipped ${skipped.symlinks} symlink(s): links are not followed.`);
  if (skipped.hidden) notes.push(`Skipped ${skipped.hidden} hidden entr${skipped.hidden === 1 ? 'y' : 'ies'} (names starting with ".", such as .git).`);
  return { entries, ruleFiles, notes };
}

// ─── parse-vcs ────────────────────────────────────────────────────────────────

function vcsField(v, name) {
  if (typeof v === 'number' && Number.isFinite(v)) v = String(v);
  if (typeof v !== 'string' || !v.trim()) throw new Error(`${name} is required (a non-empty string)`);
  if (v.length > 512 || /[\u0000-\u001f]/.test(v)) throw new Error(`${name} must be at most 512 printable characters`);
  return v;
}

export function vcsFields({ vcsRepoId, vcsRepoName, vcsCommitId } = {}) {
  return {
    vcsRepoId: vcsField(vcsRepoId, 'vcsRepoId'),
    vcsRepoName: vcsField(vcsRepoName, 'vcsRepoName'),
    vcsCommitId: vcsField(vcsCommitId, 'vcsCommitId'),
  };
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/**
 * POST the bundle to parse-vcs as multipart/form-data. mode is "diff" or "apply".
 * Diff is retried on 429/5xx (it writes nothing); apply is sent once.
 * Returns the response's `data` object. A non-2xx response throws with the body verbatim.
 */
export async function postParseVcs(mode, zip, fields) {
  if (mode !== 'diff' && mode !== 'apply') throw new Error(`mode must be diff or apply (got ${mode})`);
  const origin = new URL(base()).origin;
  const u = new URL(PARSE_PATH, origin);
  u.searchParams.set('mode', mode);
  // The endpoint rate-limits bursts with HTTP 429 (no Retry-After observed). A 429 is a refusal
  // before processing, so it is retried for both modes; a 5xx or network error is retried for diff
  // only, because an apply may have been committed.
  const retries = 4;
  let delay = retryTiming.baseMs;
  for (let attempt = 0; ; attempt++) {
    const fd = new FormData();
    fd.append('file', new Blob([zip], { type: 'application/zip' }), 'detections.zip');
    fd.append('vcsRepoId', fields.vcsRepoId);
    fd.append('vcsRepoName', fields.vcsRepoName);
    fd.append('vcsCommitId', fields.vcsCommitId);
    let res;
    try {
      res = await fetch(u.toString(), {
        method: 'POST',
        headers: { Authorization: `ApiToken ${jwt()}` },
        body: fd,
        signal: AbortSignal.timeout(PARSE_TIMEOUT_MS),
      });
    } catch (e) {
      if (e?.name === 'TimeoutError') throw new Error(`parse-vcs mode=${mode} timed out after ${PARSE_TIMEOUT_MS / 1000} s`);
      if (mode !== 'diff' || attempt >= retries) throw e;
      await sleep(delay); delay *= 2; continue;
    }
    if (attempt < retries && (res.status === 429 || (mode === 'diff' && res.status >= 500))) {
      const ra = Number(res.headers.get('Retry-After'));
      await res.text().catch(() => {});
      await sleep(Number.isFinite(ra) && ra > 0 ? Math.min(ra * 1000, 60000) : delay);
      delay *= 2;
      continue;
    }
    const text = await res.text();
    let body;
    try { body = parseJsonExact(text); } catch { body = null; }
    if (!res.ok) {
      const shown = text.length > ERROR_BODY_MAX ? `${text.slice(0, ERROR_BODY_MAX)}... [${text.length - ERROR_BODY_MAX} more characters]` : text;
      throw new Error(`parse-vcs mode=${mode} → HTTP ${res.status}: ${shown}`);
    }
    if (!body || typeof body !== 'object') throw new Error(`parse-vcs mode=${mode} returned a non-JSON body: ${text.slice(0, 2000)}`);
    if (Array.isArray(body.errors) && body.errors.length && !body.data) {
      throw new Error(`parse-vcs mode=${mode} → HTTP ${res.status} with errors: ${text.slice(0, ERROR_BODY_MAX)}`);
    }
    return body.data ?? body;
  }
}

/** The response with each change list trimmed to maxItems, plus counts. */
function trimResult(data, maxItems) {
  const res = { summary: data?.summary ?? null, vcsRepoId: data?.vcsRepoId };
  const counts = {};
  let trimmed = false;
  for (const k of CHANGE_LISTS) {
    const list = Array.isArray(data?.[k]) ? data[k] : [];
    counts[k] = list.length;
    res[k] = list.slice(0, maxItems);
    if (list.length > maxItems) trimmed = true;
  }
  res.listCounts = counts;
  if (trimmed) res.trimmed = `Each change list is cut to ${maxItems} item(s); pass outputFile (or a larger maxItems) for the full response.`;
  for (const [k, v] of Object.entries(data || {})) {
    if (!(k in res) && !CHANGE_LISTS.includes(k)) res[k] = v;
  }
  return res;
}

function bundleInfo(zip, ruleFiles, notes, cap = 100) {
  return {
    ruleFiles: ruleFiles.length,
    files: ruleFiles.slice(0, cap),
    ...(ruleFiles.length > cap ? { filesTrimmed: `${ruleFiles.length - cap} more not shown` } : {}),
    zipBytes: zip.length,
    zipSha256: createHash('sha256').update(zip).digest('hex'),
    ...(notes.length ? { notes } : {}),
  };
}

const TOTAL_KEYS_HINT = ['totalChanges', 'totalCreates', 'totalUpdates', 'totalDeletes', 'totalImports', 'totalRetains'];

/** Every total* field that differs between two summaries (missing on one side counts). */
export function summaryMismatches(expected, fresh) {
  const keys = new Set([...Object.keys(expected || {}), ...Object.keys(fresh || {})].filter(k => /^total/i.test(k)));
  const diffs = [];
  for (const k of [...keys].sort()) {
    const a = expected?.[k];
    const b = fresh?.[k];
    if (a === undefined || b === undefined || Number(a) !== Number(b)) diffs.push({ field: k, expected: a ?? null, fresh: b ?? null });
  }
  return diffs;
}

async function runDiff(args) {
  const fields = vcsFields(args);
  const { entries, ruleFiles, notes } = collectBundle(args);
  const zip = writeZip(entries);
  const data = await postParseVcs('diff', zip, fields);
  return { fields, zip, ruleFiles, notes, data };
}

function maxItemsOf(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.min(Math.floor(n), 1000) : 25;
}

// ─── export-vcs ───────────────────────────────────────────────────────────────

/** queryType from a rule YAML, reading only a top-level `queryType:` line. */
export function queryTypeOf(text) {
  const m = /^queryType:[ \t]*['"]?([A-Za-z_]+)['"]?[ \t]*(#.*)?$/m.exec(text);
  return m ? m[1] : 'unknown';
}

/** Scope folder of an exported rule path rules/<scopeLevel>-<scopeId>/..., else null. */
export function scopeOf(name) {
  const m = /^rules\/([^/]+)\//.exec(name);
  return m ? m[1] : null;
}

function decodeCursor(c) {
  if (typeof c !== 'string' || !c) return null;
  if (!/%[0-9A-Fa-f]{2}/.test(c)) return c;
  try { return decodeURIComponent(c); } catch { return c; }
}

function pageFileName(file, page) {
  if (page === 1) return file;
  const ext = extname(file);
  return join(dirname(file), `${basename(file, ext)}-page${page}${ext || '.zip'}`);
}

// ─── tool definitions ─────────────────────────────────────────────────────────

const OWNERSHIP_NOTE = 'vcsRepoId must be the same id the CI pipeline uses for this repository (for GitHub, the numeric repository id): the console keys rule ownership on it, so a different id is treated as a different repository.';
const MANAGED_NOTE = 'Rules managed this way cannot be edited on the console Detections page or through the custom-rule API; change them in the repository. Only queryLang "2.0" rules can be managed. Managed rules list with source "DAC" and editable false. A rule removed from the repository follows its deletePolicy: Retain (the default) releases it as a normal, editable console rule; Delete removes it, which takes two applies (set deletePolicy: Delete and apply, then remove the file and apply). A different vcsRepoId cannot take over rules another repository owns: the diff fails with "already claimed by another repository", and an empty bundle under another id changes nothing.';
const BUNDLE_NOTE = 'Input is either `files` (an object mapping relative path to YAML text; must contain "deployments.yaml", which holds `targets.<name>.{scopeId, scopeLevel: global|account|site}` and `deploy.<name>: [globs]`; rule paths are relative to the detections root that the globs match) or `repoDir` (an absolute path to the detections root inside the allowed folders, S1_OUTPUT_DIRS or by default home and temp; under the Docker launcher only the `install --output-dir` folder). With repoDir the manifest is `deploymentsFile` (absolute, or relative to repoDir; default <repoDir>/deployments.yaml), it is stored as deployments.yaml at the bundle root, and every .yaml/.yml below repoDir is bundled at its relative path. Symlinks and hidden entries such as .git are skipped.';

const BUNDLE_PROPS = {
  files: {
    type: 'object',
    additionalProperties: { type: 'string' },
    description: 'Inline bundle: relative path to YAML text. Must include "deployments.yaml". Use this or repoDir.',
  },
  repoDir: { type: 'string', description: 'Absolute path to the detections root on the machine running this server. Use this or files.' },
  deploymentsFile: { type: 'string', description: 'With repoDir: the deployments manifest (absolute, or relative to repoDir). Default <repoDir>/deployments.yaml.' },
  vcsRepoId: { type: 'string', description: 'Required. Repository id; must equal the id the CI pipeline uses for this repository, because it keys rule ownership.' },
  vcsRepoName: { type: 'string', description: 'Required. Repository name, e.g. <org>/<repo>.' },
  vcsCommitId: { type: 'string', description: 'Required. Commit id the bundle represents.' },
  maxItems: { type: 'number', description: 'Items shown per change list (default 25, max 1000).' },
  outputFile: { type: 'string', description: 'Optional absolute path; the full JSON response is written there (mode 0600). Same folder rules as other outputFile options.' },
  overwrite: { type: 'boolean', description: 'Allow outputFile to replace an existing file.' },
};

export const tools = [
  {
    name: 'dac_export',
    description: 'Export every custom detection rule this token can see as Detection as Code YAML (GET /web/api/v2.1/cloud-detection/rules/export-vcs). The console returns a ZIP per page of up to 500 rules: export-summary.json (exported, limit, nextCursor, totalItems) plus rules/<scopeLevel>-<scopeId>/exported-rule-<id>.yaml; this tool follows nextCursor. Each exported rule carries importCustomRuleId (the id of the existing console rule). Returns counts by scope folder and by queryType and the number of pages. With outputFile the raw ZIP is written (page 2 onward as <name>-page<N>.zip); with outputDir the archive is extracted there (unsafe entry names refused, files mode 0600). Without either, a short listing is returned. Read-only: writes only to the local machine.',
    inputSchema: {
      type: 'object',
      properties: {
        outputFile: { type: 'string', description: 'Optional absolute path for the raw ZIP. Inside S1_OUTPUT_DIRS (default home and temp; under the Docker launcher only the `install --output-dir` folder).' },
        outputDir: { type: 'string', description: 'Optional absolute directory to extract the export into (same folder rules). Existing files are not replaced unless overwrite is true.' },
        overwrite: { type: 'boolean', description: 'Allow replacing existing files.' },
        maxPages: { type: 'number', description: `Pages to fetch, 500 rules each (default and max ${MAX_EXPORT_PAGES}).` },
        listLimit: { type: 'number', description: 'Rule paths listed when no output path is given (default 50, max 500).' },
      },
    },
    async handler({ outputFile, outputDir, overwrite, maxPages, listLimit } = {}) {
      if (outputFile && outputDir) throw new Error('Pass outputFile or outputDir, not both.');
      const ow = overwrite === true;
      const pagesCap = Math.max(1, Math.min(MAX_EXPORT_PAGES, Math.floor(Number(maxPages) || MAX_EXPORT_PAGES)));
      // Validate the destination before any network call.
      if (outputFile) resolveOutputPath(outputFile, { overwrite: ow });
      let dirReal = null;
      if (outputDir) {
        if (typeof outputDir !== 'string' || !isAbsolute(outputDir)) throw new Error('outputDir must be an absolute path');
        resolveOutputPath(join(outputDir, 'export-summary.json'), { overwrite: ow });
        dirReal = resolve(outputDir);
      }

      const byScope = {};
      const byQueryType = {};
      const listing = [];
      const written = [];
      const summaries = [];
      const seenNames = new Set();
      const seenCursors = new Set();
      let cursor = null;
      let pages = 0;
      let rules = 0;
      let stopReason = 'no nextCursor';
      const cap = listLimit === undefined || listLimit === null || !Number.isFinite(Number(listLimit))
        ? 50 : Math.max(0, Math.min(500, Math.floor(Number(listLimit))));

      while (pages < pagesCap) {
        const r = await apiGetBinary(EXPORT_PATH, cursor ? { cursor } : {});
        pages++;
        const entries = readZip(r.buffer);
        const sumEntry = entries.find(e => e.name === 'export-summary.json');
        let summary = null;
        if (sumEntry) { try { summary = JSON.parse(sumEntry.data.toString('utf-8')); } catch { summary = null; } }
        summaries.push(summary ? { exported: summary.exported, limit: summary.limit, totalItems: summary.totalItems, hasNextCursor: Boolean(summary.nextCursor) } : null);

        if (outputFile) {
          written.push(writeOutput(pageFileName(resolve(outputFile), pages), r.buffer, { overwrite: ow }));
        }
        for (const e of entries) {
          if (e.directory) continue;
          if (e.name === 'export-summary.json') {
            if (dirReal) {
              const name = pages === 1 ? e.name : `export-summary-page${pages}.json`;
              written.push(writeOutput(join(dirReal, name), e.data, { overwrite: ow }));
            }
            continue;
          }
          const scope = scopeOf(e.name);
          if (!scope || !/\.ya?ml$/i.test(e.name)) continue;
          if (seenNames.has(e.name)) continue;            // repeated across pages: keep the first
          seenNames.add(e.name);
          rules++;
          const qt = queryTypeOf(e.data.toString('utf-8'));
          byScope[scope] = (byScope[scope] || 0) + 1;
          byQueryType[qt] = (byQueryType[qt] || 0) + 1;
          if (dirReal) {
            const target = resolve(dirReal, e.name);
            if (!within(target, dirReal)) throw new Error(`export entry ${e.name} resolves outside outputDir`);
            written.push(writeOutput(target, e.data, { overwrite: ow }));
          } else if (!outputFile && listing.length < cap) {
            listing.push({ path: e.name, queryType: qt });
          }
        }

        const next = decodeCursor(summary?.nextCursor);
        if (!next) { stopReason = 'no nextCursor'; break; }
        if (seenCursors.has(next)) { stopReason = 'nextCursor repeated'; break; }
        if (summary && Number(summary.exported) === 0) { stopReason = 'empty page'; break; }
        seenCursors.add(next);
        cursor = next;
        if (pages >= pagesCap) stopReason = `maxPages (${pagesCap}) reached; more rules remain`;
      }

      const result = {
        pages,
        rules,
        totalItems: summaries.find(s => s && s.totalItems !== undefined)?.totalItems ?? null,
        complete: stopReason === 'no nextCursor' || stopReason === 'empty page',
        stopReason,
        byScope,
        byQueryType,
        pageSummaries: summaries,
      };
      if (outputFile) result.outputFiles = written.map(w => ({ path: w.path, bytes: w.bytes, sha256: w.sha256 }));
      if (dirReal) { result.outputDir = dirReal; result.filesWritten = written.length; }
      if (!outputFile && !dirReal) {
        result.listing = listing;
        if (rules > listing.length) result.listingTrimmed = `${rules - listing.length} more not listed; pass outputDir to extract all.`;
      }
      return out(result);
    },
  },
  {
    name: 'dac_diff',
    description: `Preview a Detection as Code deployment: bundle the rule YAML and POST it to /web/api/v2.1/cloud-detection/rules/parse-vcs?mode=diff. The console validates every rule and returns what an apply would do (creates, updates, deletes, imports, retains, summary.total*) without changing anything. Validation errors from the console are returned verbatim. Use the returned summary as expectedSummary for dac_apply. ${BUNDLE_NOTE} ${OWNERSHIP_NOTE} ${MANAGED_NOTE} Read-only.`,
    inputSchema: {
      type: 'object',
      properties: BUNDLE_PROPS,
      required: ['vcsRepoId', 'vcsRepoName', 'vcsCommitId'],
    },
    async handler(args = {}) {
      const ow = args.overwrite === true;
      if (args.outputFile) resolveOutputPath(args.outputFile, { overwrite: ow });
      const { fields, zip, ruleFiles, notes, data } = await runDiff(args);
      const result = { mode: 'diff', vcsRepoId: fields.vcsRepoId, bundle: bundleInfo(zip, ruleFiles, notes), ...trimResult(data, maxItemsOf(args.maxItems)) };
      if (args.outputFile) {
        const w = writeOutput(args.outputFile, JSON.stringify(data, null, 2), { overwrite: ow });
        result.outputFile = { path: w.path, bytes: w.bytes, sha256: w.sha256 };
      }
      return out(result);
    },
  },
  {
    name: 'dac_apply',
    description: `Apply a Detection as Code deployment (POST parse-vcs?mode=apply). Intended for repositories without a CI pipeline, or to bootstrap one; when CI owns the repository, let CI apply. It first runs a fresh diff of the same bundle and refuses, showing both, unless every summary total equals expectedSummary (the summary from a diff the user reviewed); only then does it send mode=apply. Apply creates, updates and, for rules with deletePolicy: Delete whose files were removed, deletes rules. ${BUNDLE_NOTE} ${OWNERSHIP_NOTE} ${MANAGED_NOTE} Changes the tenant.`,
    inputSchema: {
      type: 'object',
      properties: {
        ...BUNDLE_PROPS,
        expectedSummary: {
          type: 'object',
          description: `Required. The summary object from the reviewed dac_diff (${TOTAL_KEYS_HINT.join(', ')}).`,
        },
      },
      required: ['vcsRepoId', 'vcsRepoName', 'vcsCommitId', 'expectedSummary'],
    },
    async handler(args = {}) {
      const exp = args.expectedSummary;
      if (!exp || typeof exp !== 'object' || Array.isArray(exp) || !Object.keys(exp).some(k => /^total/i.test(k))) {
        throw new Error(`expectedSummary is required: pass the summary object from a reviewed dac_diff (fields ${TOTAL_KEYS_HINT.join(', ')}).`);
      }
      const ow = args.overwrite === true;
      if (args.outputFile) resolveOutputPath(args.outputFile, { overwrite: ow });
      const { fields, zip, ruleFiles, notes, data: diff } = await runDiff(args);
      const mismatches = summaryMismatches(exp, diff?.summary);
      if (mismatches.length) {
        throw new Error(`dac_apply refused: the fresh diff does not match expectedSummary, so the tenant or the bundle changed since the review. Nothing was applied. Review the new diff and call again with its summary.\n${out({ expectedSummary: exp, freshSummary: diff?.summary ?? null, mismatches })}`);
      }
      const data = await postParseVcs('apply', zip, fields);
      const result = {
        mode: 'apply',
        vcsRepoId: fields.vcsRepoId,
        bundle: bundleInfo(zip, ruleFiles, notes),
        diffSummary: diff?.summary ?? null,
        ...trimResult(data, maxItemsOf(args.maxItems)),
      };
      if (args.outputFile) {
        const w = writeOutput(args.outputFile, JSON.stringify(data, null, 2), { overwrite: ow });
        result.outputFile = { path: w.path, bytes: w.bytes, sha256: w.sha256 };
      }
      return out(result);
    },
  },
];
