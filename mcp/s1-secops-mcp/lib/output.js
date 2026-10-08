/**
 * Write tool results to a file on the machine running the MCP server, so bulk
 * data (query results, exports, downloads) does not have to pass through the
 * model's context window.
 *
 * Safety rules:
 *   - The path must be absolute and resolve (after symlinks) inside one of the
 *     allowed roots: S1_OUTPUT_DIRS (path-delimiter separated) or, when unset,
 *     the user's home directory and the OS temp directory.
 *   - Existing files are never overwritten unless overwrite is true.
 *   - Files are created with mode 0600 (results can hold sensitive telemetry).
 *   - Under Docker the path is inside the container unless the launcher mounted
 *     the host directory at the same path (see docker/s1-secops-mcp-launch.sh).
 */

import { createHash } from 'crypto';
import { existsSync, mkdirSync, realpathSync, lstatSync, openSync, writeSync, closeSync, constants as fsConstants } from 'fs';
import { homedir, tmpdir } from 'os';
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep, extname } from 'path';

export function allowedRoots() {
  const raw = process.env.S1_OUTPUT_DIRS;
  const roots = raw ? raw.split(delimiter).filter(Boolean) : [homedir(), tmpdir()];
  return roots.map(r => { try { return realpathSync(resolve(r)); } catch { return resolve(r); } });
}

function within(child, root) {
  return child === root || child.startsWith(root.endsWith(sep) ? root : root + sep);
}

/** Validate and normalise an output path. Throws with a clear reason. */
export function resolveOutputPath(p, { overwrite = false } = {}) {
  if (typeof p !== 'string' || !p.trim()) throw new Error('outputFile must be a non-empty string');
  if (!isAbsolute(p)) throw new Error(`outputFile must be an absolute path (got ${p})`);
  const target = resolve(p);
  const roots = allowedRoots();

  // Resolve the deepest existing ancestor through symlinks, so a symlinked
  // directory cannot be used to escape the allowed roots.
  let probe = dirname(target);
  while (!existsSync(probe)) { const up = dirname(probe); if (up === probe) break; probe = up; }
  const realTarget = join(realpathSync(probe), relative(probe, target));
  if (!roots.some(r => within(realTarget, r))) {
    throw new Error(`outputFile ${target} is outside the allowed output directories (${roots.join(', ')}). Set S1_OUTPUT_DIRS to allow another directory.`);
  }
  // Below the allowed root, refuse places where a written file changes what runs
  // or who can log in: any dot-file or dot-directory (.ssh/authorized_keys,
  // .zshrc, .config/autostart), macOS LaunchAgents/LaunchDaemons, and the Windows
  // Startup folder. Content can come from the tenant (s1_api_download), so a
  // steered model must not be able to plant it. This applies under every root,
  // including an explicit S1_OUTPUT_DIRS such as the whole home folder; the root
  // itself may be a dot directory (S1_OUTPUT_DIRS=~/.cache/s1 is fine).
  const root = roots.filter(r => within(realTarget, r)).sort((a, b) => b.length - a.length)[0];
  const rel = relative(root, realTarget).replace(/\\/g, '/');
  const segs = rel.split('/').filter(Boolean);
  if (segs.some(seg => seg.startsWith('.'))
    || /(^|\/)Library\/Launch(Agents|Daemons)(\/|$)/i.test(rel)
    || /(^|\/)Start Menu\/Programs\/Startup(\/|$)/i.test(rel)) {
    throw new Error(`outputFile ${target} is a hidden (dot) path or an autostart location below ${root}, which the output policy refuses. Write to a normal folder.`);
  }
  // lstat, not exists: existsSync follows links and reports a DANGLING symlink as
  // absent, which would let a write through it land outside the allowed roots.
  let st = null;
  try { st = lstatSync(target); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (st) {
    if (st.isSymbolicLink()) throw new Error(`outputFile ${target} is a symlink; refusing to write through it`);
    if (!st.isFile()) throw new Error(`outputFile ${target} exists and is not a regular file`);
    if (!overwrite) throw new Error(`outputFile ${target} already exists; pass overwrite: true to replace it`);
  }
  return target;
}

/** Write bytes or text. Returns { path, bytes, sha256 }. */
export function writeOutput(p, data, { overwrite = false } = {}) {
  const target = resolveOutputPath(p, { overwrite });
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf-8');
  // O_NOFOLLOW closes the race between the check above and the open: if a
  // symlink appears at the path in between, the open fails instead of following it.
  const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | (fsConstants.O_NOFOLLOW || 0)
    | (overwrite ? fsConstants.O_TRUNC : fsConstants.O_EXCL);
  const fd = openSync(target, flags, 0o600);
  try { writeSync(fd, buf, 0, buf.length, 0); } finally { closeSync(fd); }
  return { path: target, bytes: buf.length, sha256: createHash('sha256').update(buf).digest('hex') };
}

function csvCell(v) {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Rows (array of objects) to CSV text, header from the union of keys in order seen. */
export function rowsToCsv(rows) {
  const cols = [];
  const seen = new Set();
  for (const r of rows) for (const k of Object.keys(r || {})) if (!seen.has(k)) { seen.add(k); cols.push(k); }
  const lines = [cols.map(csvCell).join(',')];
  for (const r of rows) lines.push(cols.map(c => csvCell(r?.[c])).join(','));
  return lines.join('\n') + '\n';
}

/** Format for a query result based on the file extension (.csv, .jsonl, else JSON). */
export function serialiseRows(path, rows, fullResult) {
  const ext = extname(path).toLowerCase();
  if (ext === '.csv') return rowsToCsv(rows);
  if (ext === '.jsonl' || ext === '.ndjson') return rows.map(r => JSON.stringify(r)).join('\n') + '\n';
  return JSON.stringify(fullResult, null, 2);
}
