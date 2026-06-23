# Docker image: SentinelOne Claude Skills MCP Stack

Single image bundling all three MCPs (`sentinelone-mcp`, `purple-mcp`, `virustotal-mcp`) so end users only need Docker installed. No Node, no Python, no `uv`, no `npm install`. Alternative to the npx/uvx install path.

End-user reference: [`docs/docker.md`](../docs/docker.md). This file is for image maintainers.

## Layout

```
docker/
├── Dockerfile         # multi-arch, all 3 MCPs at pinned versions
├── entrypoint.sh      # dispatcher: argv[1] selects which MCP to run
├── build.sh           # local + push build wrapper
├── .dockerignore      # keep build context lean
└── README.md          # this file
```

The image is published to `ghcr.io/pmoses-s1/s1-mcps`. Tags follow semver plus `:latest` and `:sha-<short>`. The matching CI workflow is at [`.github/workflows/docker-publish.yml`](../.github/workflows/docker-publish.yml).

## Pinned versions

All three MCPs are pinned at build time. The pins live in two places that must stay in sync:

1. `docker/build.sh` for local builds and manual pushes
2. `.github/workflows/docker-publish.yml` env block for CI builds

When bumping a pin, edit both. They are checked once via `grep` in CI; a mismatch fails the build.

| What | Source | Current pin |
|---|---|---|
| Image version (`IMAGE_VERSION`) | this repo | `1.2.2` |
| `@pmoses-s1/sentinelone-mcp` | npm | `1.2.2` |
| `@burtthecoder/mcp-virustotal` | npm | `1.0.21` |
| `purple-mcp` | git | `1582c094` (Sentinel-One/purple-mcp main) |

`IMAGE_VERSION` is the tag the image is published under (`ghcr.io/pmoses-s1/s1-mcps:1.2.2`). It is independent of the underlying MCP versions: bump it when the Dockerfile, dispatcher, or bundled CLAUDE.md changes, even if all three MCP pins stay the same.

## Build locally

```bash
# Single-arch (matches your machine), tags s1-mcps:<version> and s1-mcps:latest
docker/build.sh

# Smoke test
docker run -i --rm s1-mcps:1.2.2 help
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}}}' \
  | docker run -i --rm s1-mcps:1.2.2 sentinelone-mcp
```

The dispatcher accepts `sentinelone-mcp`, `purple-mcp`, `virustotal-mcp`, or `help`.

## Push manually

```bash
# Multi-arch (linux/amd64 + linux/arm64) and push to ghcr.io
PUSH=true docker/build.sh

# Override registry/tag
PUSH=true REGISTRY=ghcr.io/your-org TAG=dev docker/build.sh
```

You need `docker login ghcr.io` first. Use a personal access token with `write:packages` scope.

## Bump a pin

```bash
# Edit docker/build.sh: change S1_MCP_VERSION (or VT_MCP_VERSION, PURPLE_MCP_REF)
# Edit .github/workflows/docker-publish.yml: same change in env block
# Then:
docker/build.sh                                  # verify locally
git tag -a v1.0.1 -m "..." && git push --tags    # CI builds and pushes :1.0.1
```

## Why one image with three entrypoints?

Three entries in `claude_desktop_config.json` (one per MCP) all reference the same image and tag, so a single `docker pull` covers all three MCPs and the versions stay in lockstep. A "router" MCP that exposes all bundled tools through one process was rejected because the MCP spec has no tool-namespacing convention; tool name collisions across `sentinelone-mcp` and `purple-mcp` would force ad-hoc renaming.

## Why install pip-style for purple-mcp instead of via uv?

`uv tool install` puts the binary at a path that depends on internal layout decisions and varies by uv version. A simple `python3 -m venv /opt/purple-mcp && pip install` gives a deterministic binary location at `/opt/purple-mcp/bin/purple-mcp` and the venv is fully self-contained. End users who run `purple-mcp` outside the container still get the uvx path documented in [`docs/installation.md`](../docs/installation.md).
