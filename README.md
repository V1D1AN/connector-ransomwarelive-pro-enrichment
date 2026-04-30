# OpenCTI — Ransomware.live PRO Internal-Enrichment Connector

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-%E2%89%A56.4-orange)](https://www.opencti.io/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)

Internal-enrichment connector for [OpenCTI](https://www.opencti.io/) that
enriches `IntrusionSet` and `Threat Actor Group` entities on demand by
querying the **Ransomware.live PRO API**
(`https://api-pro.ransomware.live`).

> **Looking for scheduled bulk imports?** This project is the on-demand
> per-entity enrichment variant. For full feed ingestion (groups, victims,
> press, 8-K filings, negotiations…), see the companion project
> [`connector-ransomwarelive-pro-import`](https://github.com/V1D1AN/connector-ransomwarelive-pro-import).

## What it does

When an analyst right-clicks an `IntrusionSet` (e.g. `LockBit`) in the
OpenCTI UI and selects **Enrichment → Ransomware.live PRO (enrichment)**,
this connector:

1. Reads the entity name and all known aliases (`aliases`,
   `x_mitre_aliases`, `x_opencti_aliases`).
2. Tries to resolve a matching ransomware group on the PRO API
   (`/groups/{name}`), with case-insensitive and space-stripped variants.
3. On a match, pulls **IOCs**, **YARA rules** and **ransom notes** for that
   one specific group.
4. Returns a STIX 2.1 bundle that gets merged into the existing entity.

This is faster and cheaper (in API quota) than running a full external
import when an analyst only needs deep enrichment on one specific group.

The same connector can also run in **auto mode** (`CONNECTOR_AUTO=true`):
it then enriches every newly-created or updated `IntrusionSet`
automatically, without manual click. Useful when other connectors (MISP,
Mandiant, ATT&CK…) regularly create new ransomware groups in your platform.

## What gets added to the enriched entity

| Source | STIX entities produced |
| --- | --- |
| **IOCs** | `Observable` (+ optional `Indicator` with `pattern_type=stix`), with `based-on` and `indicates` relationships. |
| **YARA rules** | `Indicator` with `pattern_type=yara`, linked to the IntrusionSet via `indicates`. |
| **Ransom notes** | `Note` attached to the IntrusionSet (content truncated at 5 KB). |

Relationships emitted:

```
IntrusionSet (existing)
   ├── indicated-by ─► Indicator (yara | stix pattern)
   │                       └── based-on ► Observable (ipv4/domain/file/url/wallet/...)
   └── object_ref of ─► Note (ransom note text)
```

## Why this connector

The official upstream connector
([`OpenCTI-Platform/connectors/external-import/ransomwarelive`](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/ransomwarelive))
only exposes scheduled bulk import using the anonymous v2 API. There is no
on-demand path, no IOC enrichment, no YARA rules, no ransom notes. This
connector fills that gap by targeting the PRO API
(`api-pro.ransomware.live`), which:

- requires an `X-API-KEY` header (free key from [my.ransomware.live](https://my.ransomware.live)),
- allows up to **3,000 calls/day** with burst tolerance,
- exposes per-group IOC, YARA and ransom-note endpoints.

## Requirements

- OpenCTI ≥ **6.4** (tested with 6.8.x)
- A free API key from [my.ransomware.live](https://my.ransomware.live)
- Docker + Docker Compose, **or** Python 3.11+

## Quickstart with Docker

```bash
git clone https://github.com/V1D1AN/connector-ransomwarelive-pro-enrichment.git
cd connector-ransomwarelive-pro-enrichment

# Build the image
docker build -t opencti/connector-ransomwarelive-pro-enrichment:1.0.0 .

# Set secrets
cat >> .env <<EOF
OPENCTI_ADMIN_TOKEN=xxxx
RANSOMWARELIVE_PRO_API_KEY=xxxx
EOF

# Generate a unique connector ID
echo "CONNECTOR_ID: $(uuidgen)"
# Paste it into docker-compose.yml

# Start the connector
docker compose up -d
```

## Triggering an enrichment from the UI

1. In OpenCTI, navigate to an `IntrusionSet` or `Threat Actor Group`
   (e.g. `LockBit`).
2. Click the rocket icon in the top right → **Enrichment**.
3. Select **Ransomware.live PRO (enrichment)**.
4. Refresh after a few seconds — IOCs, YARA rules and notes appear under
   the **Knowledge** tab and as related observables.

## Local development

```bash
cd src/
cp config.yml.sample config.yml
# Edit config.yml with your tokens
pip install -r requirements.txt
python main.py
```

## Configuration reference

### OpenCTI core

| Variable | Default | Description |
| --- | --- | --- |
| `OPENCTI_URL` | _(required)_ | OpenCTI internal URL. |
| `OPENCTI_TOKEN` | _(required)_ | OpenCTI admin / connector token. |

### Connector core

| Variable | Default | Description |
| --- | --- | --- |
| `CONNECTOR_ID` | _(required)_ | UUID v4, unique per connector instance. |
| `CONNECTOR_TYPE` | `INTERNAL_ENRICHMENT` | Connector type (do not change). |
| `CONNECTOR_NAME` | `Ransomware.live PRO (enrichment)` | Display name in the OpenCTI UI. |
| `CONNECTOR_SCOPE` | `Intrusion-Set,Threat-Actor-Group` | Comma-separated entity types that can trigger this connector. |
| `CONNECTOR_AUTO` | `false` | If `true`, auto-enrich every new IntrusionSet without manual click. |
| `CONNECTOR_LOG_LEVEL` | `info` | One of `debug`, `info`, `warning`, `error`. |

### Ransomware.live PRO

| Variable | Default | Description |
| --- | --- | --- |
| `RANSOMWARELIVEPRO_API_BASE_URL` | `https://api-pro.ransomware.live` | Override only for a self-hosted mirror. |
| `RANSOMWARELIVEPRO_API_KEY` | _(required)_ | Your PRO API key. |
| `RANSOMWARELIVEPRO_COLLECT_IOCS` | `true` | Enable IOC enrichment. |
| `RANSOMWARELIVEPRO_COLLECT_YARA` | `true` | Enable YARA rule enrichment. |
| `RANSOMWARELIVEPRO_COLLECT_RANSOMNOTES` | `true` | Enable ransom note enrichment. |
| `RANSOMWARELIVEPRO_IOC_TYPE_FILTER` | `` (all) | Comma-separated IOC types to keep, e.g. `ipv4,domain,sha256`. |
| `RANSOMWARELIVEPRO_CREATE_INDICATORS` | `true` | If `false`, only Observables are created (no Indicators). |
| `RANSOMWARELIVEPRO_TLP_LEVEL` | `green` | One of `white`, `green`, `amber`, `red`. |
| `RANSOMWARELIVEPRO_CONFIDENCE_LEVEL` | `75` | 0–100. |
| `RANSOMWARELIVEPRO_UPDATE_EXISTING` | `update` | One of `skip`, `update`, `force`. |

## Group resolution heuristics

When an analyst enriches `LockBit 3.0`, Ransomware.live may know it as
`lockbit3` or `lockbit`. To handle these mismatches, the connector tries
each candidate name in this order:

1. The primary entity name (`name`).
2. Each entry in `aliases`.
3. Each entry in `x_mitre_aliases` (some platforms store ATT&CK names there).
4. Each entry in `x_opencti_aliases`.

For each candidate, three variants are tried:

1. As-is.
2. Lowercase.
3. Lowercase with all spaces removed.

The first hit wins. If no variant matches, the enrichment returns a
non-fatal "no matching group" message and no objects are created.

## Known limitations

1. PRO API endpoint paths are derived from the public Swagger and from the
   community [`Jacox98/n8n-nodes-ransomware-live`](https://github.com/Jacox98/n8n-nodes-ransomware-live)
   node. If Filigran or JMousqueton renames anything, edit the `_ENDPOINTS`
   table in `api_client.py` — it is the single source of truth.
2. Cryptocurrency wallet observables are emitted as raw STIX dicts;
   OpenCTI custom observable plugin support depends on your platform version.
3. Group resolution depends on the entity having useful aliases. Adding
   `aliases` to your IntrusionSets in OpenCTI improves match rates.

## Contributing

See [CONTRIBUTORS.md](CONTRIBUTORS.md) and [CHANGELOG.md](CHANGELOG.md).

## License

[Apache 2.0](LICENSE).
