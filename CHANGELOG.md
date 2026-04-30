# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-04-29

### Added

- Initial release of `connector-ransomwarelive-pro-enrichment`.
- Internal-enrichment connector subscribed to `Intrusion-Set` and `Threat-Actor-Group` scopes, triggered manually from the OpenCTI UI or automatically via `CONNECTOR_AUTO=true`.
- Group-name resolution heuristics: tries the primary entity name, all aliases, `x_mitre_aliases`, `x_opencti_aliases`, plus lowercase and space-stripped variants — handles canonical-name mismatches between OpenCTI and Ransomware.live.
- Toggleable enrichment sources: IOCs (`COLLECT_IOCS`), YARA rules (`COLLECT_YARA`), ransom notes (`COLLECT_RANSOMNOTES`).
- IOC promotion to STIX `Indicator` with proper `based-on` (Indicator → Observable) and `indicates` (Indicator → IntrusionSet) relationships.
- YARA rules ingested as STIX `Indicator` with `pattern_type=yara`.
- Apache 2.0 license, contributors list, contribution guide.

### Configuration

- Default `RANSOMWARELIVEPRO_UPDATE_EXISTING=update` so re-enriching an existing entity refreshes its data instead of skipping.
- Default `CONNECTOR_AUTO=false` — opt in to automatic enrichment only when desired.
