# Third-Party Notices and Attributions

**Product:** SentinelOne SecOps MCP container image (`sentinelone/secops-mcps`), the s1-secops-mcp server, and the s1-secops-skills plugin
**Applies to:** image 1.5.5 and later, s1-secops-mcp 1.5.5 and later, plugin 1.3.16 and later
**Last reviewed:** 2026-10-14

This document identifies the third-party software bundled with this product, the license that governs each component, and the third-party services the product can connect to. It is provided to satisfy the attribution requirements of those licenses and to inform users of the terms that apply when they use those services.

---

## 1. Important notices

### 1.1 Third-party services

This product includes optional MCP servers that send queries to services operated by third parties:

| Service | Bundled server | What is sent | Credential |
|---|---|---|---|
| VirusTotal | `virustotal-mcp` (and the `threat_intel_*` tools of `purple-mcp`) | File hashes, IP addresses, domains, URLs and search strings that the user or the AI assistant submits for enrichment | `VIRUSTOTAL_API_KEY`, supplied by the user |
| Shodan | `shodan-mcp` (optional, off unless a key is stored) | IP addresses, hostnames, domains, search queries, CVE and CPE identifiers | `SHODAN_API_KEY`, supplied by the user |

When you enable these servers:

- Requests are made directly from your environment to the service provider under **your own API key and account**. SentinelOne does not proxy, store, or receive these requests or their results.
- Your use of each service is governed by **that provider's terms of service, acceptable-use policy, and privacy policy**, including any limits on commercial use, rate limits, attribution, and redistribution of results. You are responsible for holding a valid subscription appropriate to your use and for complying with those terms.
  - VirusTotal terms of service: <https://docs.virustotal.com/docs/terms-of-service>
  - Shodan terms of service: <https://static.shodan.io/legal/terms.html>
- Indicators submitted to a public threat-intelligence service may become visible to that provider and, depending on the provider's policies and your subscription, to its other users. Do not submit confidential data (internal hostnames, private file contents, personal data) unless your agreement with the provider and your organisation's policies permit it.
- Results returned by these services are third-party data. SentinelOne makes no representation as to their accuracy, completeness, or fitness for any purpose.

### 1.2 Non-affiliation

The VirusTotal and Shodan MCP servers in this image are independently maintained open-source projects, vendored from pinned forks. Their inclusion does not imply that VirusTotal, Shodan, or their respective owners sponsor, endorse, or are affiliated with SentinelOne or this product, nor that SentinelOne is a reseller of or partner for those services.

### 1.3 Trademarks

SentinelOne®, Singularity™ and Purple AI™ are trademarks or registered trademarks of SentinelOne, Inc. in the United States and other countries. VirusTotal® and Shodan® are registered trademarks of their respective owners. All other product names, logos, and brands are the property of their respective owners. Use of these names is for identification purposes only and does not imply endorsement.

### 1.4 No warranty

Third-party components are provided by their authors "AS IS", without warranty of any kind, as stated in their licenses below. Nothing in this document modifies the terms of your agreement with SentinelOne.

---

## 2. Bundled components

Each server is built from a pinned git commit. The exact sources of the image you are running are printed by `docker run --rm sentinelone/secops-mcps:<version> versions`.

| Component | Version / source | License | Copyright | Location in the image |
|---|---|---|---|---|
| s1-secops-mcp | This repository, `s1-secops-mcp/` | GNU AGPL-3.0 | SentinelOne, Inc. and contributors | `/opt/s1-secops-mcp/` (license: `/opt/s1-secops-mcp/LICENSE`) |
| purple-mcp | Fork of the SentinelOne purple-mcp project, pinned commit | MIT | Copyright (c) 2025 SentinelOne, Inc. | `/opt/purple-mcp/` (license: `site-packages/purple_mcp-*.dist-info/licenses/LICENSE`) |
| mcp-virustotal (`@burtthecoder/mcp-virustotal`) | Fork of BurtTheCoder/mcp-virustotal, pinned commit | MIT | Copyright (c) 2024 Burt | `/opt/mcp-virustotal/` (license: `/opt/mcp-virustotal/LICENSE`) |
| mcp-shodan (`@burtthecoder/mcp-shodan`) | Fork of BurtTheCoder/mcp-shodan, pinned commit | MIT | Copyright (c) 2024 Burt | `/opt/mcp-shodan/` (license: `/opt/mcp-shodan/LICENSE`) |
| Node.js runtime | Official `node:24-trixie-slim` base image, pinned digest | MIT and bundled third-party licenses (<https://github.com/nodejs/node/blob/v24.x/LICENSE>) | Node.js contributors | `/usr/local/bin/node` |
| Python runtime and Debian packages | Debian 13 (trixie) packages from the base image and `apt-get` | Various (PSF, GPL, LGPL, BSD, MIT and others) | Their respective authors | `/usr/share/doc/<package>/copyright` |
| tini | Debian package | MIT | Thomas Orozco | `/usr/share/doc/tini/copyright` |

### 2.1 Transitive dependencies

The Node.js servers ship their production dependencies in `node_modules/`, and purple-mcp ships its Python dependencies in a virtual environment. Every package declares its license in its own metadata (`package.json` for Node.js packages, `*.dist-info/METADATA` for Python packages), and the license files that packages distribute are kept in place in the image (`/opt/mcp-virustotal/node_modules/`, `/opt/mcp-shodan/node_modules/`, `/opt/purple-mcp/lib/python3*/site-packages/`).

A complete, machine-readable inventory of every package in the image, with its version and declared license, is attached to each published image from 1.5.5 as an SPDX SBOM attestation:

```
docker buildx imagetools inspect sentinelone/secops-mcps:<version> --format '{{ json .SBOM }}'
```

### 2.2 Source code availability (AGPL-3.0)

s1-secops-mcp is licensed under the GNU Affero General Public License v3.0. Its complete corresponding source is published in the public SentinelOne AI SIEM repository at <https://github.com/Sentinel-One/ai-siem/tree/main/mcp/s1-secops-mcp>, with the release matching the version printed by the image's `versions` command. The full license text is in `LICENSE` at the root of that repository and at `/opt/s1-secops-mcp/LICENSE` in the image.

---

## 3. License texts

### 3.1 mcp-virustotal

```
MIT License

Copyright (c) 2024 Burt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 3.2 mcp-shodan

```
MIT License

Copyright (c) 2024 Burt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 3.3 purple-mcp

```
MIT License

Copyright (c) 2025 SentinelOne, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 3.4 s1-secops-mcp

GNU Affero General Public License, version 3. See `LICENSE` at the repository root or `/opt/s1-secops-mcp/LICENSE` in the image.

---

Questions about this notice: open an issue at <https://github.com/Sentinel-One/ai-siem/issues>.
