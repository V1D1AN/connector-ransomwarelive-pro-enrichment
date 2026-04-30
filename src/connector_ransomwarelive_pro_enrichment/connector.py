"""Internal-enrichment connector for Ransomware.live PRO.

Triggered manually (or via playbook) when an analyst right-clicks an
IntrusionSet (or ThreatActor) in OpenCTI and selects this enrichment.

Behaviour:
  1. Receives a STIX IntrusionSet / ThreatActor entity from OpenCTI.
  2. Looks up the group name + aliases against ransomware.live PRO.
  3. If found, pulls IOCs, YARA rules and ransom notes for that specific
     group only.
  4. Returns a STIX bundle that gets merged into the existing entity.

This avoids a full external import when an analyst only needs deep enrichment
on one specific group (faster, less noise, less API quota consumed).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pycti import OpenCTIConnectorHelper

from connector_ransomwarelive_pro_enrichment.api_client import (
    RansomwareLiveProAPIError,
    RansomwareLiveProClient,
)
from connector_ransomwarelive_pro_enrichment.config_loader import ConfigConnector
from connector_ransomwarelive_pro_enrichment.converter_to_stix import StixConverter


class RansomwareLiveProConnector:
    """Internal-enrichment connector for IntrusionSet / ThreatActor entities."""

    def __init__(self) -> None:
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.helper.connector_logger.info(
            "[ransomwarelive-pro-enrich] Booting enrichment connector",
        )
        self.client = RansomwareLiveProClient(
            api_key=self.config.api_key,
            base_url=self.config.api_base_url,
            logger=self.helper.connector_logger,
        )
        self.converter = StixConverter(
            confidence=self.config.confidence_level,
            tlp_level=self.config.tlp_level,
            create_indicators=self.config.create_indicators,
            logger=self.helper.connector_logger,
        )

        self.ioc_type_filter: Optional[set[str]] = None
        if self.config.ioc_type_filter:
            self.ioc_type_filter = {
                t.strip().lower()
                for t in self.config.ioc_type_filter.split(",")
                if t.strip()
            }

    # ---------------------------------------------------------------- run
    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)

    # ----------------------------------------------------- process_message
    def process_message(self, data: Dict[str, Any]) -> str:
        """Called by the helper for each enrichment request.

        Args:
            data: dict containing {'enrichment_entity': <stix dict>, 'stix_objects': [...]}.
        """
        log = self.helper.connector_logger

        entity = data.get("enrichment_entity") or {}
        entity_type = entity.get("entity_type") or entity.get("type") or ""

        if entity_type.lower() not in ("intrusion-set", "threat-actor", "threat-actor-group"):
            return (
                f"[ransomwarelive-pro-enrich] Skipped: unsupported entity "
                f"type {entity_type}"
            )

        candidate_names = self._candidate_names(entity)
        log.info(
            f"[ransomwarelive-pro-enrich] Looking up: {candidate_names}",
        )

        # Resolve the group name on the API side. We try the entity name then
        # each alias, stopping at the first match.
        api_group_name, api_group_payload = self._resolve_group(candidate_names)
        if not api_group_name:
            return (
                f"[ransomwarelive-pro-enrich] No matching group on "
                f"ransomware.live for {candidate_names}"
            )

        log.info(f"[ransomwarelive-pro-enrich] Matched group: {api_group_name}")

        # Build (or rebuild) the IntrusionSet so we have a stable id locally
        # for the relationships. OpenCTI will dedupe against the existing
        # entity by canonical name.
        intrusion_set = self.converter.build_intrusion_set(
            api_group_payload or {"name": api_group_name}
        )
        all_objects: List[Any] = [intrusion_set]

        # IOCs
        if self.config.collect_iocs:
            try:
                iocs = self.client.iocs_for_group(api_group_name)
                for ioc in iocs:
                    all_objects.extend(
                        self.converter.build_ioc_objects(
                            ioc, intrusion_set.id, self.ioc_type_filter
                        )
                    )
                log.info(f"[ransomwarelive-pro-enrich] +{len(iocs)} IOCs")
            except RansomwareLiveProAPIError as exc:
                log.warning(f"[ransomwarelive-pro-enrich] IOC fetch failed: {exc}")

        # YARA rules
        if self.config.collect_yara:
            try:
                rules = self.client.yara_for_group(api_group_name)
                for rule in rules:
                    all_objects.extend(
                        self.converter.build_yara_indicator(rule, intrusion_set.id)
                    )
                log.info(f"[ransomwarelive-pro-enrich] +{len(rules)} YARA rules")
            except RansomwareLiveProAPIError as exc:
                log.warning(f"[ransomwarelive-pro-enrich] YARA fetch failed: {exc}")

        # Ransom notes
        if self.config.collect_ransomnotes:
            try:
                files = self.client.ransomnotes_files(api_group_name)
                for f in files:
                    filename = (
                        (f.get("filename") or f.get("name"))
                        if isinstance(f, dict)
                        else f
                    )
                    if not filename:
                        continue
                    content_payload = self.client.ransomnote(api_group_name, filename)
                    if isinstance(content_payload, dict):
                        content = (
                            content_payload.get("content")
                            or content_payload.get("text")
                            or content_payload.get("_raw", "")
                        )
                    else:
                        content = content_payload or ""
                    all_objects.extend(
                        self.converter.build_ransomnote_note(
                            api_group_name, filename, content, intrusion_set.id
                        )
                    )
                log.info(f"[ransomwarelive-pro-enrich] +{len(files)} ransom notes")
            except RansomwareLiveProAPIError as exc:
                log.warning(f"[ransomwarelive-pro-enrich] notes fetch failed: {exc}")

        if len(all_objects) <= 1:
            return (
                f"[ransomwarelive-pro-enrich] No enrichable data found "
                f"for group {api_group_name}"
            )

        bundle = self.converter.build_bundle(all_objects)
        bundle_str = bundle.serialize()
        update = self.config.update_existing in ("update", "force")
        self.helper.send_stix2_bundle(bundle_str, update=update)

        return (
            f"[ransomwarelive-pro-enrich] Sent bundle of {len(all_objects)} "
            f"objects for group {api_group_name}"
        )

    # ----------------------------------------------------------------- utils
    @staticmethod
    def _candidate_names(entity: Dict[str, Any]) -> List[str]:
        """Build a deduplicated list of names to try against the API.

        Order of priority: primary name, then aliases, then x_mitre_aliases
        (some platforms store ATT&CK names there).
        """
        names: List[str] = []
        seen: set[str] = set()
        for raw in (
            [entity.get("name")]
            + list(entity.get("aliases") or [])
            + list(entity.get("x_mitre_aliases") or [])
            + list(entity.get("x_opencti_aliases") or [])
        ):
            if not raw:
                continue
            cleaned = str(raw).strip()
            if not cleaned:
                continue
            key = cleaned.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(cleaned)
        return names

    def _resolve_group(
        self, candidate_names: List[str]
    ) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Try each candidate name against /groups/{name}.

        Returns (api_name, payload) of the first hit, or (None, None) on miss.
        We also try a normalized variant (lowercased, spaces removed) which
        matches Ransomware.live's URL-style group identifiers.
        """
        tried: set[str] = set()
        for name in candidate_names:
            for variant in (name, name.lower(), name.lower().replace(" ", "")):
                if variant in tried:
                    continue
                tried.add(variant)
                try:
                    payload = self.client.group(variant)
                except RansomwareLiveProAPIError:
                    continue
                if payload:
                    # API may return the canonical name in a different field.
                    canonical = (
                        payload.get("name") if isinstance(payload, dict) else None
                    ) or variant
                    return canonical, payload if isinstance(payload, dict) else None
        return None, None
