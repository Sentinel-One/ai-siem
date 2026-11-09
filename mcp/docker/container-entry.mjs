// Dispatcher for the SentinelOne SecOps MCP image (1.6.3).
//
// The image is distroless: no shell, no package manager, no init. This script replaces the
// former sh entrypoint and is run by the image's node (ENTRYPOINT /nodejs/bin/node).
//
//   s1-secops-mcp | s1    run the MCP server on stdio (secrets preamble: S1_SECRETS_STDIN=1,
//                         read by the server itself, see lib/stdio-transport.js)
//   versions              print /etc/sentinelone/versions.json
//   notices               print the third-party notices
//   help                  usage
//   __image_setup         build time only: normalise file modes, remove base packages Node never
//                         loads, write versions.json
//   __image_verify        build time only: prove crypto, TLS and zlib still work
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// Debian packages in the distroless base that Node never loads. The official Node binary
// compiles in its own OpenSSL and zlib (process.versions.openssl / .zlib), and at runtime maps
// only libc, libpthread, libdl, libm, libgcc_s, libstdc++ and the loader (checked with
// /proc/self/maps after exercising crypto, TLS and zlib). These four carry the image's only
// scanner findings (zlib1g CVE-2026-85091 HIGH, unfixed in Debian; an OpenSSL LOW), so they are
// removed, files and dpkg records both, and __image_verify proves Node still works without them.
const UNUSED_PACKAGES = ['libssl3t64', 'zlib1g', 'libzstd1', 'libgomp1'];
const DPKG_STATUS_D = '/var/lib/dpkg/status.d';

function removeUnusedPackages() {
  const removed = [];
  for (const pkg of UNUSED_PACKAGES) {
    const sums = join(DPKG_STATUS_D, `${pkg}.md5sums`);
    if (!existsSync(join(DPKG_STATUS_D, pkg))) continue;
    if (existsSync(sums)) {
      for (const line of readFileSync(sums, 'utf-8').split('\n')) {
        const rel = line.trim().split(/\s+/).slice(1).join(' ');
        if (rel) rmSync(join('/', rel), { force: true });
      }
    }
    rmSync(join(DPKG_STATUS_D, pkg), { force: true });
    rmSync(sums, { force: true });
    rmSync(join('/usr/share/doc', pkg), { recursive: true, force: true });   // now-empty doc dir
    removed.push(pkg);
  }
  return removed;
}

/** Build time, after setup: Node's crypto, TLS and zlib work, and the removed libraries are not mapped. */
async function imageVerify() {
  const zlib = await import('node:zlib');
  const crypto = await import('node:crypto');
  const tls = await import('node:tls');
  await import('node:https');
  if (zlib.gunzipSync(zlib.gzipSync('ok')).toString() !== 'ok') throw new Error('zlib round trip failed');
  crypto.createHash('sha256').update('x').digest('hex');
  crypto.randomUUID();
  tls.createSecureContext();
  if (tls.rootCertificates.length < 50) throw new Error('bundled root certificates missing');
  const maps = readFileSync('/proc/self/maps', 'utf-8');
  const hit = ['libssl', 'libcrypto', 'libz.so', 'libzstd', 'libgomp'].filter(n => maps.includes(n));
  if (hit.length) throw new Error(`removed libraries are still mapped: ${hit.join(', ')}`);
  for (const pkg of UNUSED_PACKAGES) {
    if (existsSync(join(DPKG_STATUS_D, pkg))) throw new Error(`${pkg} is still recorded in ${DPKG_STATUS_D}`);
  }
  process.stdout.write(`image verify ok: node ${process.version}, openssl ${process.versions.openssl} and zlib ${process.versions.zlib} built in; removed ${UNUSED_PACKAGES.join(', ')}\n`);
}

const SERVER = '/opt/s1-secops-mcp/index.js';
const VERSIONS = '/etc/sentinelone/versions.json';
const NOTICES = '/usr/share/doc/secops-mcps/THIRD_PARTY_NOTICES.md';

const HELP = `SentinelOne SecOps MCP

Server:
  s1-secops-mcp     PowerQuery, SDL, Mgmt Console REST, UAM, Hyperautomation,
                    Purple AI (purple_ai_query), and built-in threat intelligence:
                    VirusTotal (ti_vt_*) and Shodan (ti_shodan_*), each listed
                    only when its API key is stored

Other commands:
  versions          Print what is inside this image as JSON
  notices           Print third-party notices, licenses and service terms

Read-only by default: s1-secops-mcp refuses tools that change the tenant
(create, update, delete, ingest, alert status or verdict changes) unless
S1_READ_ONLY=false is set. Launcher: \`install --read-write\`. Write actions
run as the API token's user; the server logs each one to its own log.

VirusTotal and Shodan lookups go directly to those services under your own
API keys and are subject to their terms. See \`notices\`.

Usage (recommended): run through the host launcher, which reads the OS
keychain and passes secrets over stdin so they never appear in
\`docker inspect\`:
  s1-secops-mcp-launch.sh setup            # once: store values in the keychain
  s1-secops-mcp-launch.sh s1-secops-mcp    # what the MCP client runs

Manual equivalent (secrets as the first stdin lines, then an empty line):
  docker run -i --rm -e S1_SECRETS_STDIN=1 sentinelone/secops-mcps:<version> s1-secops-mcp

Environment variables (-e S1_CONSOLE_URL -e S1_CONSOLE_API_TOKEN ...) still
work but are readable by anyone who can run \`docker inspect\`.

The image is distroless: no shell, no package manager, no npm, and no
third-party MCP server.

Reference:
  https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/docs/docker.md
`;

const LEGACY = new Set(['purple-mcp', 'purple', 'virustotal-mcp', 'virustotal', 'vt', 'shodan-mcp', 'shodan']);

/** Build time: a+rX on the server tree and the docs, then the version manifest. */
function imageSetup() {
  const fix = (p) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      chmodSync(p, 0o755);
      for (const e of readdirSync(p)) fix(join(p, e));
    } else {
      // Read for all; keep execute only where the source had it (the server's index.js).
      chmodSync(p, (st.mode & 0o111) ? 0o755 : 0o644);
    }
  };
  for (const p of ['/opt/s1-secops-mcp', '/usr/share/doc/secops-mcps', '/etc/sentinelone', '/usr/local/lib/s1-secops']) fix(p);
  chmodSync(SERVER, 0o755);
  const removed = removeUnusedPackages();
  const env = process.env;
  if (!env.IMAGE_VERSION) throw new Error('IMAGE_VERSION build-arg is required');
  const manifest = {
    image_version: env.IMAGE_VERSION,
    build_date: env.BUILD_DATE || '',
    vcs_ref: env.VCS_REF || '',
    node: process.version,
    base: 'gcr.io/distroless/nodejs24-debian13',
    servers: {
      's1-secops-mcp': {
        source: 'git',
        repo: 'https://github.com/Sentinel-One/ai-siem',
        ref: env.VCS_REF || '',
        path: 'mcp/s1-secops-mcp',
        version: env.S1_MCP_VERSION || '',
      },
    },
    builtin_tools: ['purple_ai_query', 'ti_vt_lookup', 'ti_vt_relationship', 'ti_shodan_host', 'ti_shodan_dns'],
    removed_base_packages: removed,
    shell: false,
    npm: false,
  };
  mkdirSync('/etc/sentinelone', { recursive: true });
  writeFileSync(VERSIONS, JSON.stringify(manifest, null, 2) + '\n', { mode: 0o644 });
  const pkg = JSON.parse(readFileSync('/opt/s1-secops-mcp/package.json', 'utf-8'));
  if (env.S1_MCP_VERSION && pkg.version !== env.S1_MCP_VERSION) {
    throw new Error(`S1_MCP_VERSION ${env.S1_MCP_VERSION} does not match package.json ${pkg.version}`);
  }
  if (!process.version.startsWith('v24.')) throw new Error(`base image runs ${process.version}, expected Node 24`);
  process.stdout.write(`image setup ok: ${env.IMAGE_VERSION}, server ${pkg.version}, node ${process.version}\n`);
}

const [cmd = 'help', ...rest] = process.argv.slice(2);

switch (cmd) {
  case 's1-secops-mcp':
  case 's1':
    // index.js reads process.argv.slice(2) for its own flags (e.g. --version).
    process.argv = [process.argv[0], SERVER, ...rest];
    await import(SERVER);
    break;
  case 'versions':
  case 'version':
    process.stdout.write(readFileSync(VERSIONS, 'utf-8'));
    break;
  case 'notices':
  case 'licenses':
  case 'license':
    process.stdout.write(readFileSync(NOTICES, 'utf-8'));
    break;
  case 'help':
  case '--help':
  case '-h':
    process.stdout.write(HELP);
    break;
  case '__image_setup':
    imageSetup();
    break;
  case '__image_verify':
    await imageVerify();
    break;
  default:
    if (LEGACY.has(cmd)) {
      // Removed in 1.6.0. One clear line for an MCP client still configured for the old server.
      process.stderr.write(`entrypoint: '${cmd}' was removed from this image in 1.6.0. Purple AI (purple_ai_query), VirusTotal (ti_vt_*) and Shodan (ti_shodan_*) are now built-in tools of s1-secops-mcp. Run 's1-secops-mcp-launch.sh install' again to update your MCP client config, then restart the client. To run another MCP server, install it from its official source: see docs/connect-optional-tools.md.\n`);
      process.exit(78);
    }
    process.stderr.write(`entrypoint: unknown command '${cmd}'\nvalid: s1-secops-mcp, versions, notices, help\n`);
    process.exit(64);
}
