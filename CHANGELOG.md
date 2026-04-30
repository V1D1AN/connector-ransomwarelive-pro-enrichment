# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- API client now strips leading/trailing whitespace and newlines from `RANSOMWARELIVEPRO_API_KEY` and `RANSOMWARELIVEPRO_API_BASE_URL`. Previously, a stray space after `=` in `.env` files caused the connector to fail at startup with `requests.exceptions.InvalidHeader`. Embedded whitespace is now rejected at construction time with a clear error message.
- `validate()` no longer fails silently when the API does not expose a `/validate` endpoint. It now falls back to a `/groups` probe, distinguishes auth errors (401/403) from missing-endpoint errors (404), and surfaces the actual HTTP status and response body in error messages.
- `validate()` now accepts the actual upstream response shape (`{"status": "valid", "client": "<email>"}`) in addition to other common variants (`{"valid": true}`, `{"status": "ok"}`, `{"ok": true}`, `{"authenticated": true}`). The authenticated client email is logged for confirmation.
- `_ensure_list()` now flattens the dict-of-records payload returned by `/groups` (e.g. `{"LockBit": {…}, "Akira": {…}}`), folding the dict key into each record as a `name` field. Previously this 18 KB payload was treated as a single record, breaking the validation probe.
- Dockerfile now installs `libmagic1` (kept at runtime) and `libmagic-dev` (purged after build), required by `python-magic` — a transitive dependency of `pycti` used for file type detection.

### Changed

- HTTP layer: every request now logs `URL → HTTP status (bytes)` at debug level. 401/403 errors include the response body (truncated to 200 chars) for easier diagnostics.

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
