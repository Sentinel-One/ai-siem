/**
 * Minimal ZIP writer and reader on node:zlib, with no dependencies.
 *
 * Scope: what the Detection as Code endpoints need. The writer produces a plain ZIP (deflate,
 * UTF-8 names, fixed 1980-01-01 timestamps so the same input gives the same bytes). The reader
 * handles stored and deflate entries from a single-disk archive without ZIP64 or encryption, and
 * refuses anything else rather than guessing.
 *
 * Reader safety, because archives come from the network:
 *   - every entry name is checked: no absolute path, no drive letter, no backslash, no NUL,
 *     no "." or ".." segment, no empty segment
 *   - entry count and total uncompressed size are capped before anything is inflated, and the
 *     inflate itself is bounded by the declared size, so a header that lies cannot exhaust memory
 *   - each entry's size and CRC-32 are verified after inflating
 */

import { deflateRawSync, inflateRawSync, crc32 } from 'node:zlib';

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const FLAG_ENCRYPTED = 0x0001;
const FLAG_UTF8 = 0x0800;
const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;
const DOS_DATE_1980_01_01 = (0 << 9) | (1 << 5) | 1;

export const DEFAULT_MAX_ENTRIES = 20000;
export const DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024;

/**
 * Throws unless name is a safe relative archive path. Directory entries end in "/".
 * Returns the name unchanged.
 */
export function checkEntryName(name) {
  if (typeof name !== 'string' || name.length === 0) throw new Error('zip entry name must be a non-empty string');
  if (name.length > 1024) throw new Error(`zip entry name is too long (${name.length} characters)`);
  if (name.includes('\0')) throw new Error(`zip entry name contains a NUL byte: ${JSON.stringify(name.slice(0, 80))}`);
  if (name.includes('\\')) throw new Error(`zip entry name contains a backslash: ${JSON.stringify(name.slice(0, 200))}`);
  if (name.startsWith('/')) throw new Error(`zip entry name is an absolute path: ${JSON.stringify(name.slice(0, 200))}`);
  if (/^[A-Za-z]:/.test(name)) throw new Error(`zip entry name starts with a drive letter: ${JSON.stringify(name.slice(0, 200))}`);
  const segs = name.endsWith('/') ? name.slice(0, -1).split('/') : name.split('/');
  for (const s of segs) {
    if (s === '' || s === '.' || s === '..') {
      throw new Error(`zip entry name has an empty, "." or ".." segment: ${JSON.stringify(name.slice(0, 200))}`);
    }
  }
  return name;
}

/**
 * Build a ZIP from [{ name, data }] (data: Buffer, Uint8Array or string, UTF-8).
 * Entries are deflated and written in the order given. Duplicate names are refused.
 */
export function writeZip(entries) {
  if (!Array.isArray(entries)) throw new Error('writeZip expects an array of { name, data }');
  const locals = [];
  const centrals = [];
  const seen = new Set();
  let offset = 0;
  for (const e of entries) {
    const name = checkEntryName(e?.name);
    if (seen.has(name)) throw new Error(`duplicate zip entry name: ${name}`);
    seen.add(name);
    const raw = Buffer.isBuffer(e.data) ? e.data
      : e.data instanceof Uint8Array ? Buffer.from(e.data)
        : Buffer.from(String(e.data ?? ''), 'utf-8');
    const nameBuf = Buffer.from(name, 'utf-8');
    const comp = deflateRawSync(raw);
    const crc = crc32(raw) >>> 0;
    if (raw.length > 0xfffffffe || comp.length > 0xfffffffe || offset > 0xfffffffe) {
      throw new Error('zip entry or archive too large for this writer (ZIP64 is not supported)');
    }

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(SIG_LOCAL, 0);
    lh.writeUInt16LE(20, 4);                 // version needed
    lh.writeUInt16LE(FLAG_UTF8, 6);
    lh.writeUInt16LE(METHOD_DEFLATE, 8);
    lh.writeUInt16LE(0, 10);                 // time 00:00:00
    lh.writeUInt16LE(DOS_DATE_1980_01_01, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(raw.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);                 // extra length
    locals.push(lh, nameBuf, comp);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(SIG_CENTRAL, 0);
    ch.writeUInt16LE((3 << 8) | 20, 4);      // made by: unix, 2.0
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(FLAG_UTF8, 8);
    ch.writeUInt16LE(METHOD_DEFLATE, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(DOS_DATE_1980_01_01, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(comp.length, 20);
    ch.writeUInt32LE(raw.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);                 // extra
    ch.writeUInt16LE(0, 32);                 // comment
    ch.writeUInt16LE(0, 34);                 // disk
    ch.writeUInt16LE(0, 36);                 // internal attrs
    ch.writeUInt32LE((0o100644 << 16) >>> 0, 38); // external attrs: regular file 0644
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, nameBuf);

    offset += lh.length + nameBuf.length + comp.length;
  }
  if (seen.size > 0xfffe) throw new Error('too many zip entries for this writer (ZIP64 is not supported)');
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(seen.size, 8);
  eocd.writeUInt16LE(seen.size, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, cd, eocd]);
}

function findEocd(buf) {
  const min = Math.max(0, buf.length - (22 + 0xffff));
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  return -1;
}

/**
 * Read a ZIP into [{ name, data: Buffer, directory: boolean }], in central-directory order.
 * Options: maxEntries, maxTotalBytes (sum of uncompressed sizes).
 */
export function readZip(input, { maxEntries = DEFAULT_MAX_ENTRIES, maxTotalBytes = DEFAULT_MAX_TOTAL_BYTES } = {}) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (buf.length < 22) throw new Error('not a zip archive (too short)');
  const e = findEocd(buf);
  if (e < 0) throw new Error('not a zip archive (no end-of-central-directory record)');
  const disk = buf.readUInt16LE(e + 4);
  const cdDisk = buf.readUInt16LE(e + 6);
  const countDisk = buf.readUInt16LE(e + 8);
  const count = buf.readUInt16LE(e + 10);
  const cdSize = buf.readUInt32LE(e + 12);
  const cdOffset = buf.readUInt32LE(e + 16);
  if (disk !== 0 || cdDisk !== 0 || countDisk !== count) throw new Error('multi-disk zip archives are not supported');
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw new Error('ZIP64 archives are not supported');
  if (count > maxEntries) throw new Error(`zip has ${count} entries, over the limit of ${maxEntries}`);
  if (cdOffset + cdSize > e) throw new Error('corrupt zip: central directory lies outside the archive');

  // Pass 1: read and check every header before inflating anything.
  const metas = [];
  const names = new Set();
  let total = 0;
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (p + 46 > e || buf.readUInt32LE(p) !== SIG_CENTRAL) throw new Error(`corrupt zip: bad central directory entry ${i}`);
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const compSize = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    if (p + 46 + nameLen > e) throw new Error(`corrupt zip: entry ${i} name runs past the central directory`);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString((flags & FLAG_UTF8) ? 'utf-8' : 'latin1');
    p += 46 + nameLen + extraLen + commentLen;

    checkEntryName(name);
    if (names.has(name)) throw new Error(`zip has a duplicate entry: ${name}`);
    names.add(name);
    if (flags & FLAG_ENCRYPTED) throw new Error(`zip entry ${name} is encrypted, which is not supported`);
    if (method !== METHOD_STORED && method !== METHOD_DEFLATE) {
      throw new Error(`zip entry ${name} uses compression method ${method}; only stored (0) and deflate (8) are supported`);
    }
    if (size === 0xffffffff || compSize === 0xffffffff || localOffset === 0xffffffff) {
      throw new Error(`zip entry ${name} needs ZIP64, which is not supported`);
    }
    if (method === METHOD_STORED && compSize !== size) throw new Error(`corrupt zip: stored entry ${name} has different sizes`);
    total += size;
    if (total > maxTotalBytes) {
      throw new Error(`zip uncompressed size exceeds the limit of ${maxTotalBytes} bytes (at entry ${name})`);
    }
    metas.push({ name, method, crc, compSize, size, localOffset });
  }

  // Pass 2: locate and inflate each entry, bounded by its declared size.
  const out = [];
  for (const m of metas) {
    const lo = m.localOffset;
    if (lo + 30 > cdOffset || buf.readUInt32LE(lo) !== SIG_LOCAL) throw new Error(`corrupt zip: bad local header for ${m.name}`);
    const start = lo + 30 + buf.readUInt16LE(lo + 26) + buf.readUInt16LE(lo + 28);
    const end = start + m.compSize;
    if (end > cdOffset) throw new Error(`corrupt zip: data for ${m.name} runs past the central directory`);
    const comp = buf.subarray(start, end);
    const directory = m.name.endsWith('/');
    let data;
    if (m.method === METHOD_STORED) {
      data = Buffer.from(comp);
    } else {
      try {
        data = inflateRawSync(comp, { maxOutputLength: Math.max(1, m.size) });
      } catch (err) {
        throw new Error(`zip entry ${m.name} failed to inflate within its declared size of ${m.size} bytes: ${err.message}`);
      }
    }
    if (data.length !== m.size) throw new Error(`zip entry ${m.name} is ${data.length} bytes, header says ${m.size}`);
    if ((crc32(data) >>> 0) !== m.crc) throw new Error(`zip entry ${m.name} failed its CRC-32 check`);
    out.push({ name: m.name, data, directory });
  }
  return out;
}
