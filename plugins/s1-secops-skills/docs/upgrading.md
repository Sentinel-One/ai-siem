# Upgrading to 1.3.x

Three things move independently: the **MCP image**, the **skills plugin**, and your
**Claude Desktop config**. Do them in that order. Budget five minutes.

Nothing here needs a credential you do not already have. The upgrade removes
five environment variables and adds none.

---

## Before you start

Note your console URL and API token from the current config, you will reuse both:

```bash
python3 -c "
import json, pathlib
p = pathlib.Path.home()/'Library/Application Support/Claude/claude_desktop_config.json'
s = json.load(open(p))['mcpServers']
for name, body in s.items():
    print(name, sorted((body.get('env') or {}).keys()))
"
```

Back the file up:

```bash
cd ~/Library/Application\ Support/Claude
cp claude_desktop_config.json claude_desktop_config.json.pre-1.3.1
```

---

## Step 1: the MCP

**Docker (default).** Nothing to install. Bump the tag in your config (step 3);
`--pull=missing` fetches the image on next start.

**npm.** The package was renamed, so the old one must be removed explicitly or
you will have two binaries on `PATH`:

```bash
npm uninstall -g @pmoses-s1/sentinelone-mcp
npm install  -g @pmoses-s1/s1-secops-mcp@1.3.3
s1-secops-mcp --version     # expect 1.3.3
```

---

## Step 2: the skills plugin

The plugin was renamed from `sentinelone-skills` to `s1-secops-skills`. A
plugin's name is its installed identity, so this reads as a **different plugin**:
the old one will not update in place.

1. Remove the old `sentinelone-skills` plugin.
2. Install `s1-secops-skills` from the marketplace.

Confirm afterwards that the skills are the new ones, not a stale cache:

```bash
for f in /var/folders/*/*/T/claude-hostloop-plugins/*/skills/sdl-api/SKILL.md; do
  [ -f "$f" ] || continue
  printf 'stale-markers=%s  %s\n' \
    "$(grep -c 'SDL_XDR_URL\|c\.keys\[' "$f")" "${f##*hostloop-plugins/}"
done
```

`stale-markers=0` means you are on the new skills. Anything above zero is an old
cache still in place.

---

## Step 3: the config

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`.

### What changes

| Change | From | To |
|---|---|---|
| Server key | `"sentinelone-mcp"` | `"s1-secops-mcp"` |
| Dispatcher argument | `sentinelone-mcp` | `s1-secops-mcp` |
| Image tag | `s1-mcps:1.2.x` | `s1-mcps:1.3.1` |
| purple-mcp variables | `PURPLEMCP_CONSOLE_BASE_URL`, `PURPLEMCP_CONSOLE_TOKEN` | `S1_CONSOLE_URL`, `S1_CONSOLE_API_TOKEN` |

### What to delete outright

`SDL_XDR_URL`, `SDL_CONFIG_READ_KEY`, `SDL_CONFIG_WRITE_KEY`, `SDL_LOG_READ_KEY`,
`SDL_LOG_WRITE_KEY`. Nothing replaces them. The console API token authorises
every SDL operation, and the SDL base is derived from `S1_CONSOLE_URL` as
`<console>/sdl`.

### Result

```json
{
  "mcpServers": {
    "s1-secops-mcp": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--pull=missing",
               "-e", "S1_CONSOLE_URL", "-e", "S1_CONSOLE_API_TOKEN", "-e", "S1_HEC_INGEST_URL",
               "ghcr.io/pmoses-s1/s1-mcps:1.3.1", "s1-secops-mcp"],
      "env": {
        "S1_CONSOLE_URL":       "https://usea1-yourorg.sentinelone.net",
        "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token...",
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
        "S1_CONSOLE_API_TOKEN": "eyJ...your-api-token..."
      }
    },
    "virustotal": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--pull=missing",
               "-e", "VIRUSTOTAL_API_KEY",
               "ghcr.io/pmoses-s1/s1-mcps:1.3.1", "virustotal-mcp"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-key"
      }
    }
  }
}
```

purple-mcp takes the same two variables as `s1-secops-mcp`: the image entrypoint
derives `PURPLEMCP_CONSOLE_BASE_URL` and `PURPLEMCP_CONSOLE_TOKEN` from them. A
`PURPLEMCP_*` variable you set explicitly still wins, so leaving them in place
also works.

> Running purple-mcp directly via `uvx` bypasses the entrypoint. That path still
> needs `PURPLEMCP_CONSOLE_BASE_URL` and `PURPLEMCP_CONSOLE_TOKEN`.

Then **restart Claude Desktop**.

---

## Step 4: verify

In a Claude session:

```
smoke test secops skills
```

Or from a terminal, without Claude Desktop:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  | docker run -i --rm ghcr.io/pmoses-s1/s1-mcps:1.3.1 s1-secops-mcp
```

Expect `serverInfo.name = "s1-secops-mcp-server"`, `version = "1.3.3"`, and
`Tools: 26 registered` on stderr.

---

## If you have scripts of your own

One change breaks copied snippets. `SDLClient.keys` no longer exists, so this
raises `AttributeError`:

```python
c = SDLClient()
c.keys["log_read_key"] = ""        # remove
c.keys["config_read_key"] = ""     # remove
c.keys["config_write_key"] = ""    # remove
```

Delete those lines. Nothing replaces them; the client uses the console token for
every method.

`SDLClient` now also fails fast at construction when `S1_CONSOLE_API_TOKEN` is
absent, rather than failing later on the first request.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `manifest unknown` / image pull fails | Tag typo. The tag is `1.3.1`, not `1.3.0`. |
| `entrypoint: unknown command 'sentinelone-mcp'` | The dispatcher argument still says the old name. Change it to `s1-secops-mcp`. |
| MCP red in Cowork, `Cannot connect to the Docker daemon` | Docker Desktop is not running. |
| Skills still mention `SDL_XDR_URL` or `c.keys[...]` | An old plugin cache. Re-check with the command in step 2. |
| `S1 Mgmt API: NOT configured` | No console token reached the container. Each `-e VAR` needs a matching key in that block's `env`. |
| `AttributeError: 'SDLClient' object has no attribute 'keys'` | A script still force-clears scoped keys. See above. |
| purple-mcp fails to start | If you run it via `uvx` rather than Docker, set `PURPLEMCP_*` explicitly. |

Per-MCP logs: `~/Library/Logs/Claude/mcp-server-<name>.log`.

---

## Rolling back

```bash
cd ~/Library/Application\ Support/Claude
cp claude_desktop_config.json.pre-1.3.1 claude_desktop_config.json
```

Then reinstall the old plugin and restart. The 1.2.x images remain on ghcr.io;
npm `@pmoses-s1/sentinelone-mcp@1.2.4` is still published.
