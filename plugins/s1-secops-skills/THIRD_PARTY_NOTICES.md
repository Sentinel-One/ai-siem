# Third-Party Notices and Attributions

**Product:** SentinelOne SecOps MCP container image (`sentinelone/secops-mcps`), the s1-secops-mcp server, and the s1-secops-skills plugin
**Applies to:** image 1.6.0 and later, s1-secops-mcp 1.6.0 and later, plugin 1.4.0 and later
**Last reviewed:** 2026-11-05

This document identifies the third-party software bundled with this product, the license that governs each component, and the third-party services the product can connect to. It is provided to satisfy the attribution requirements of those licenses and to inform users of the terms that apply when they use those services.

From 1.6.0 the image bundles no third-party MCP server. Purple AI, VirusTotal and Shodan are reached by tools that are part of s1-secops-mcp itself.

---

## 1. Important notices

### 1.1 Third-party services

s1-secops-mcp includes optional built-in tools that send queries to services operated by third parties. Each tool is listed only when the user has stored the key for that service.

| Service | Tools | What is sent | Credential |
|---|---|---|---|
| VirusTotal | `ti_vt_lookup`, `ti_vt_relationship` | File hashes, IP addresses, domains and URLs that the user or the AI assistant submits for enrichment | `VIRUSTOTAL_API_KEY`, supplied by the user |
| Shodan | `ti_shodan_host`, `ti_shodan_dns` | IP addresses and hostnames | `SHODAN_API_KEY`, supplied by the user |

When you use these tools:

- Requests are made directly from your environment to the service provider under **your own API key and account**. SentinelOne does not proxy, store, or receive these requests or their results.
- Your use of each service is governed by **that provider's terms of service, acceptable-use policy, and privacy policy**, including any limits on commercial use, rate limits, attribution, and redistribution of results. You are responsible for holding a valid subscription appropriate to your use and for complying with those terms.
  - VirusTotal terms of service: <https://docs.virustotal.com/docs/terms-of-service>
  - Shodan terms of service: <https://static.shodan.io/legal/terms.html>
- Indicators submitted to a public threat-intelligence service may become visible to that provider and, depending on the provider's policies and your subscription, to its other users. Do not submit confidential data (internal hostnames, private file contents, personal data) unless your agreement with the provider and your organisation's policies permit it.
- Results returned by these services are third-party data. SentinelOne makes no representation as to their accuracy, completeness, or fitness for any purpose.

`purple_ai_query` and the other s1-secops-mcp tools call your own SentinelOne console with your console API token.

### 1.2 Non-affiliation

The built-in VirusTotal and Shodan tools call those services' public APIs. Their inclusion does not imply that VirusTotal, Shodan, or their respective owners sponsor, endorse, or are affiliated with SentinelOne or this product, nor that SentinelOne is a reseller of or partner for those services.

### 1.3 Trademarks

SentinelOne®, Singularity™ and Purple AI™ are trademarks or registered trademarks of SentinelOne, Inc. in the United States and other countries. VirusTotal® and Shodan® are registered trademarks of their respective owners. All other product names, logos, and brands are the property of their respective owners. Use of these names is for identification purposes only and does not imply endorsement.

### 1.4 No warranty

Third-party components are provided by their authors "AS IS", without warranty of any kind, as stated in their licenses below. Nothing in this document modifies the terms of your agreement with SentinelOne.

---

## 2. Bundled components

What the image you are running contains is printed by `docker run --rm sentinelone/secops-mcps:<version> versions`.

| Component | Version / source | License | Copyright | Location in the image |
|---|---|---|---|---|
| s1-secops-mcp | This repository, `s1-secops-mcp/`. No runtime dependencies. | GNU AGPL-3.0 | SentinelOne, Inc. and contributors | `/opt/s1-secops-mcp/` (license: `/opt/s1-secops-mcp/LICENSE`) |
| Node.js runtime | `gcr.io/distroless/nodejs24-debian13` base image, pinned digest | MIT and bundled third-party licenses (<https://github.com/nodejs/node/blob/v24.x/LICENSE>) | Node.js contributors | `/nodejs/` |
| Debian packages | From the distroless base: base-files, ca-certificates, glibc (libc6), libgcc, libstdc++, media-types, netbase, tzdata | Various (GPL, LGPL, MIT, MPL-2.0 for the CA bundle, public domain for tzdata, and others) | Their respective authors | `/usr/share/doc/<package>/copyright` |

The image is distroless: it has no shell and no package manager. Four base packages that Node never loads (libssl3t64, zlib1g, libzstd1, libgomp1) are removed at build time, because Node compiles in its own OpenSSL and zlib.

A complete, machine-readable inventory of every package in the image, with its version and declared license, is attached to each published image as an SPDX SBOM attestation:

```
docker buildx imagetools inspect sentinelone/secops-mcps:<version> --format '{{ json .SBOM }}'
```

### 2.1 Source code availability (AGPL-3.0)

s1-secops-mcp is licensed under the GNU Affero General Public License v3.0. Its complete corresponding source is published in the public SentinelOne AI SIEM repository at <https://github.com/Sentinel-One/ai-siem/tree/main/mcp/s1-secops-mcp>, with the release matching the version printed by the image's `versions` command. The full license text is in `LICENSE` at the root of that repository and at `/opt/s1-secops-mcp/LICENSE` in the image.

---

## 3. License texts

### 3.1 s1-secops-mcp

GNU Affero General Public License, version 3. See `LICENSE` at the repository root or `/opt/s1-secops-mcp/LICENSE` in the image.

### 3.2 Node.js and Debian packages

The Node.js license, with the licenses of the components Node.js bundles, is at <https://github.com/nodejs/node/blob/v24.x/LICENSE>. Each Debian package's copyright and license text is in `/usr/share/doc/<package>/copyright` in the image.

---

Questions about this notice: open an issue at <https://github.com/Sentinel-One/ai-siem/issues>.
