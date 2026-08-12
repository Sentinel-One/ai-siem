## s1-secops-mcp 1.3.1

Credential simplification and a naming realignment. One console API token now
authorises every SentinelOne API surface this project touches, the SDL base URL
is derived from the console URL, and every identity in the repo matches the
`ai-siem` monorepo. Tool count unchanged at 26.

Versioning: npm package **@pmoses-s1/s1-secops-mcp 1.3.3**. Docker bundle image
**1.3.1**, pinning `S1_MCP_VERSION=1.3.3`. Plugin **1.3.1**. The image version and
the npm version are independent: the image version tracks the Dockerfile, the
dispatcher and the bundled `CLAUDE.md`; the npm version tracks the server itself.

### Breaking

- **npm package renamed.** `@pmoses-s1/s1-secops-mcp` is superseded by
  `@pmoses-s1/s1-secops-mcp`. The binary is `s1-secops-mcp`, and the Docker
  entrypoint dispatcher name changes to match.
- **Plugin renamed** from `sentinelone-skills` to `s1-secops-skills`. The plugin
  name is its installed identity, so existing installs see this as a different
  plugin and must be reinstalled.
- **Skill directories dropped the `sentinelone-` prefix**: `sdl-api`,
  `powerquery`, `mgmt-console-api`, `sdl-dashboard`, `sdl-log-parser`,
  `sdl-solutions`, `hyperautomation`. Bundled `.skill` artifacts are named to
  match.
  `SDL_LOG_READ_KEY` and `SDL_LOG_WRITE_KEY` are no longer read. Configurations
  that still define them are unaffected; the values are simply ignored.
  `<console>/sdl`.
- **`SDLClient.keys` removed.** Code that force-cleared scoped keys, the
  `c.keys["log_read_key"] = ""` idiom, now raises `AttributeError`. Delete those
  lines; nothing replaces them.

### Changed

- **One credential for all SDL operations.** The console API token authorises
  config read, config write and log read. Verified live against a production
  tenant with only the reduced credential set exposed: `getFile`, `putFile`,
  `listFiles`, `/api/query` and HEC ingest all pass, and the scoped keys pass
  on exactly the same calls, so they add nothing but rotation overhead.
- **SDL reaches the console host.** `POST <console>/sdl/api/*` returns results
  identical to the regional XDR host (1,914 config paths either way), so the
  separate host is redundant.
- **Auth is a single credential, not a chain.** `keyCandidates()` and the
  per-chain 401/403 fallthrough in `lib/sdl.js` are replaced by `sdlToken()`;
  `sdlFetch` no longer takes a `chain` argument. The Python client loses
  `KEY_CHAINS`, `_candidate_keys()` and `_pick_key()`; `_auth_headers()` builds
  one Bearer header and the client fails fast at construction when the token is
  absent. A 403 is now raised on the first request rather than retried against
  a second credential.
- **One set of variable names for all three servers.** The image entrypoint
  derives `PURPLEMCP_CONSOLE_BASE_URL`, `PURPLEMCP_CONSOLE_TOKEN` and
  `VIRUSTOTAL_API_KEY` from `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN` and
  `VT_API_KEY`, so purple-mcp and virustotal are configured with the same names
  as `s1-secops-mcp`. A server-specific variable that is already set always
  wins. Seven variable names reduce to three.
- **Minimum credential set** is `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN` and,
  for ingest, `S1_HEC_INGEST_URL`.

### Fixed

- **1.3.0 shipped a stale bridge filename.** Its tarball contained
  `deploy/bridge/s1-secops-mcp-bridge.mjs` while the README beside it
  referenced `s1-secops-mcp-bridge.mjs`. File contents were correct and the
  server ran, but the deploy helper pointed at a file that was not in the
  package. 1.3.0 is deprecated on npm.
- Four documentation links and the `.windsurf` workflow filenames that the
  directory rename left behind.

### Migration

Delete the four scoped SDL keys and `SDL_XDR_URL`; nothing replaces them.
Rename the server key and the dispatcher argument, and point purple-mcp at the
canonical variable names:

```json
"s1-secops-mcp": {
  "command": "docker",
  "args": ["run", "-i", "--rm", "--pull=missing",
           "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN", "-e", "S1_HEC_INGEST_URL",
           "ghcr.io/pmoses-s1/s1-mcps:1.3.1", "s1-secops-mcp"],
  "env": {
    "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
    "S1_CONSOLE_API_TOKEN": "eyJ...",
    "S1_HEC_INGEST_URL":    "https://ingest.us1.sentinelone.net"
  }
},
"purple-mcp": {
  "command": "docker",
  "args": ["run", "-i", "--rm", "--pull=missing",
           "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN",
           "ghcr.io/pmoses-s1/s1-mcps:1.3.1", "purple-mcp"],
  "env": {
    "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
    "S1_CONSOLE_API_TOKEN": "eyJ..."
  }
}
```

`PURPLEMCP_CONSOLE_BASE_URL` and `PURPLEMCP_CONSOLE_TOKEN` are no longer needed
in the config; the entrypoint supplies them.

If you install from npm rather than Docker:

```bash
npm uninstall -g @pmoses-s1/s1-secops-mcp
npm install -g @pmoses-s1/s1-secops-mcp@1.3.1
```

Reinstall the plugin under its new name, `s1-secops-skills`.

### Verification

Live against a production tenant with only `S1_CONSOLE_URL` and
`S1_CONSOLE_API_TOKEN` exposed:

- data source enumeration: 27 sources
- per-source attribute discovery: 27/27 sources, 843 distinct fields
- parser lifecycle 12/12: create, read, list, update with `expectedVersion`,
  stale-version rejection, delete, verify absent
- `sdl-api/tests/smoke_test.py` 12/12
- config-file CRUD and MCP `tools/list` over stdio

Unit suite 57/57. Install-from-tarball smoke: `initialize` reports
`s1-secops-mcp-server` 1.3.1 and `tools/list` returns 26 tools. markdownlint,
shellcheck and shfmt clean.
