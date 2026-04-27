# pipelines/community/

Community-contributed Observo pipeline templates for SentinelOne AI SIEM.

This directory holds parser/transform pipelines that bridge a vendor's log
format to OCSF and the AI SIEM HEC endpoint.

---

## Layout

```
pipelines/
├── push/                                    # vendor pushes events to us
│   ├── syslog/<vendor>/<product>/           # vendor-specific syslog/CEF/LEEF/KV
│   └── hec/<vendor>/<product>/              # vendors that POST direct to HEC
├── pull/                                    # we fetch events from the vendor
│   ├── api/<vendor>/<product>/              # REST/HTTP API polling
│   └── object_store/<vendor>/<product>/     # S3 / GCS / Azure Blob
├── community/
│   └── transform_ocsf/<vendor>/<product>/   # OCSF normalization overlays
```

Each leaf (`<product>/`) contains a `metadata.yaml` and (for ingestion
templates) one Observo pipeline export JSON, or (for `transform_ocsf/`
overlays) the serializer Lua plus metadata.

---

## What this directory accepts

1. **Ingestion templates** — pipelines that get a vendor's events into the
   AI SIEM. Belongs under `push/` or `pull/` based on which side initiates
   the connection.

2. **OCSF transform overlays** — Lua serializers that normalize already-
   ingested data into OCSF. Belongs under `community/transform_ocsf/`.

3. **Vendor-specific HEC shaping** — pipelines for vendors POSTing to HEC
   that need vendor-specific batch/retry/field-handling logic. Belongs
   under `push/hec/`.

---

## `metadata.yaml` schema

> **New fields (`ingest_mode`, `auth_type`) apply to new pipelines added
> after this PR.** Existing entries in `transform_ocsf/` will be backfilled
> in a follow-up sweep — they should not be considered out of compliance
> until then.

In addition to the existing top-level `grade:` block (produced by the
automated grader; do not author by hand), each pipeline declares:

```yaml
metadata_details:
  vendor: "<canonical_vendor_key>"      # lowercase, underscored
  product: "<canonical_product_key>"    # lowercase, underscored

  ingest_mode: "..."                    # see enum below
  auth_type: "..."                      # see enum below

  # Optional, only when relevant
  syslog_format: "CEF | LEEF | RFC5424 | RFC3164 | Vendor KV"

  # Plus the standard pipeline narrative fields
  purpose: ...
  source_template: ...
  source_vendor: ...
  destination_template: "SentinelOne AI SIEM"
  destination_type: "SPLUNK_HEC_LOGS"
  transform_templates: ...
  input_schema: ...
  output_schema: ...
  scheduling: ...
  retry_behavior: ...
  dependencies: ...
  performance_impact: ...
  tags: [...]
  version: "v1.0"
```

### `ingest_mode` enum

The directory the pipeline lives in encodes push-vs-pull; `ingest_mode`
records the protocol/mechanism.

| Value                          | Meaning                                              |
|--------------------------------|------------------------------------------------------|
| `HEC`                          | HTTP Event Collector                                 |
| `Syslog`                       | Vendor syslog (RFC5424/3164, CEF, LEEF, vendor KV)   |
| `API Call`                     | REST/HTTP API                                        |
| `Other - {Explain: ...}`       | Anything else — e.g. websocket, object store (S3/GCS/Azure Blob), gRPC. Spell out the mechanism in the braces. |

### `auth_type` enum

| Value                          | Meaning                                              |
|--------------------------------|------------------------------------------------------|
| `N/A`                          | No auth on the wire (raw syslog over UDP, etc.)      |
| `HEC Token`                    | Splunk-style HEC bearer                              |
| `OAuth`                        | OAuth 2.0 client credentials / authorization code    |
| `API Key & Secret`             | Two-part credential (key + shared secret)            |
| `Bearer Token`                 | Static bearer token (non-HEC)                        |
| `Basic`                        | HTTP Basic auth                                      |
| `mTLS`                         | Mutual TLS (client cert)                             |
| `IAM Role`                     | AWS-style assume-role (typical for object stores)    |
| `Other - {Explain: ...}`       | Anything else — spell out the mechanism in braces    |

---

## Naming conventions

- Vendor and product directories: lowercase, underscored, no spaces
  (`palo_alto/panos/`, never `Palo Alto Networks/PANOS/`)
- File names: snake_case
- One vendor's pipelines may live under multiple subtrees (e.g.,
  `push/syslog/palo_alto/panos/` for firewall syslog and
  `pull/api/palo_alto/cortex_xdr/` for the Cortex XDR API)
