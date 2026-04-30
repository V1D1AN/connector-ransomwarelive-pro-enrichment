"""STIX 2.1 converter for Ransomware.live PRO data.

Maps API payloads to STIX SDO/SCO/SRO compatible with OpenCTI 6.x.

Design choices (informed by issues observed on the official connector):

* Ransomware groups are modelled as **IntrusionSet** (not ThreatActor).
  Refs: https://github.com/OpenCTI-Platform/connectors/issues/2351
* IOCs become Observables, and optionally Indicators (STIX patterns) when
  CREATE_INDICATORS=true. Indicators get `based-on` relationships to the
  observable and `indicates` to the IntrusionSet.
* Victims become Identity (organization) entities, linked to the IntrusionSet
  via a `targets` relationship. Each victim claim is wrapped in a Report so
  analysts can pivot on the original publication date.
* Sectors are created as Identity (class=class) entities via a `part-of`
  relationship. We do NOT search OpenCTI before creating — we let OpenCTI's
  upsert logic deduplicate by canonical name. This avoids the "wrong sector
  matching" bug from issue #3506.
* All objects carry the configured TLP marking, the Ransomware.live identity
  as `created_by_ref`, and a `confidence` value.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import stix2
from pycti import (
    Identity,
    Incident,
    IntrusionSet,
    Indicator,
    Location,
    Note,
    Report,
    StixCoreRelationship,
)


# Map Ransomware.live IOC type strings to STIX observable / pattern types.
_IOC_TYPE_MAP: Dict[str, Tuple[str, str]] = {
    # ransomware.live -> (stix observable type, pattern path)
    "ipv4": ("IPv4-Addr", "ipv4-addr:value"),
    "ipv6": ("IPv6-Addr", "ipv6-addr:value"),
    "ip": ("IPv4-Addr", "ipv4-addr:value"),
    "domain": ("Domain-Name", "domain-name:value"),
    "fqdn": ("Domain-Name", "domain-name:value"),
    "url": ("Url", "url:value"),
    "md5": ("File", "file:hashes.MD5"),
    "sha1": ("File", "file:hashes.'SHA-1'"),
    "sha256": ("File", "file:hashes.'SHA-256'"),
    "sha512": ("File", "file:hashes.'SHA-512'"),
    "email": ("Email-Addr", "email-addr:value"),
    "btc": ("Cryptocurrency-Wallet", "cryptocurrency-wallet:value"),
    "monero": ("Cryptocurrency-Wallet", "cryptocurrency-wallet:value"),
}

_TLP_MAP = {
    "white": stix2.TLP_WHITE,
    "clear": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}


class StixConverter:
    """Build STIX bundles from Ransomware.live PRO payloads."""

    def __init__(
        self,
        confidence: int = 75,
        tlp_level: str = "green",
        create_indicators: bool = True,
        logger=None,
    ) -> None:
        self.confidence = confidence
        self.tlp = _TLP_MAP.get(tlp_level, stix2.TLP_GREEN)
        self.create_indicators = create_indicators
        self.logger = logger

        # Persistent author identity (Ransomware.live).
        self.author = stix2.Identity(
            id=Identity.generate_id("Ransomware.live", "organization"),
            name="Ransomware.live",
            identity_class="organization",
            description=(
                "Ransomware.live tracks ransomware groups and their public "
                "victim claims via DLS scraping. Maintained by Julien Mousqueton."
            ),
            confidence=self.confidence,
            object_marking_refs=[self.tlp],
        )

    # ------------------------------------------------------------------ utils
    def _common_meta(self) -> Dict[str, Any]:
        return {
            "created_by_ref": self.author.id,
            "object_marking_refs": [self.tlp],
            "confidence": self.confidence,
        }

    @staticmethod
    def _parse_date(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
        return None

    # ------------------------------------------------------- intrusion sets
    def build_intrusion_set(self, group: Dict[str, Any]) -> stix2.IntrusionSet:
        """Build an IntrusionSet from a /groups payload."""
        name = group.get("name") or group.get("group") or "unknown-group"
        aliases = group.get("aliases") or group.get("meta") or []
        if isinstance(aliases, str):
            aliases = [a.strip() for a in aliases.split(",") if a.strip()]

        description = group.get("description") or group.get("profile") or ""
        first_seen = self._parse_date(group.get("firstseen") or group.get("first_seen"))
        last_seen = self._parse_date(group.get("lastseen") or group.get("last_seen"))

        return stix2.IntrusionSet(
            id=IntrusionSet.generate_id(name),
            name=name,
            description=description or None,
            aliases=aliases or None,
            first_seen=first_seen,
            last_seen=last_seen,
            labels=["ransomware"],
            **self._common_meta(),
        )

    # ------------------------------------------------------------- victims
    def build_victim_objects(
        self, victim: Dict[str, Any], intrusion_set_id: Optional[str] = None
    ) -> List[Any]:
        """Convert a victim record into Identity + Sector + Location + Report
        + relationships."""
        objects: List[Any] = []

        victim_name = victim.get("victim") or victim.get("name") or victim.get("post_title")
        if not victim_name:
            return []

        # Victim Identity
        victim_identity = stix2.Identity(
            id=Identity.generate_id(victim_name, "organization"),
            name=victim_name,
            identity_class="organization",
            description=victim.get("description") or None,
            **self._common_meta(),
        )
        objects.append(victim_identity)

        # Sector
        sector_obj = None
        sector_name = victim.get("sector") or victim.get("activity")
        if sector_name:
            sector_obj = stix2.Identity(
                id=Identity.generate_id(sector_name, "class"),
                name=sector_name,
                identity_class="class",
                **self._common_meta(),
            )
            objects.append(sector_obj)
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "part-of", victim_identity.id, sector_obj.id
                    ),
                    relationship_type="part-of",
                    source_ref=victim_identity.id,
                    target_ref=sector_obj.id,
                    **self._common_meta(),
                )
            )

        # Country
        country_code = victim.get("country") or victim.get("country_code")
        country_obj = None
        if country_code:
            country_name = _country_name(country_code)
            country_obj = stix2.Location(
                id=Location.generate_id(country_name, "Country"),
                name=country_name,
                country=country_code.upper()[:2],
                **self._common_meta(),
            )
            objects.append(country_obj)
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "located-at", victim_identity.id, country_obj.id
                    ),
                    relationship_type="located-at",
                    source_ref=victim_identity.id,
                    target_ref=country_obj.id,
                    **self._common_meta(),
                )
            )

        # Relationship Intrusion Set -> Victim
        if intrusion_set_id:
            published = self._parse_date(
                victim.get("attackdate")
                or victim.get("discovered")
                or victim.get("published")
            )
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "targets", intrusion_set_id, victim_identity.id
                    ),
                    relationship_type="targets",
                    source_ref=intrusion_set_id,
                    target_ref=victim_identity.id,
                    start_time=published,
                    description=victim.get("description") or None,
                    **self._common_meta(),
                )
            )

        # Wrap in a Report so analysts can pivot per claim.
        published = (
            self._parse_date(
                victim.get("discovered")
                or victim.get("published")
                or victim.get("attackdate")
            )
            or datetime.now(tz=timezone.utc)
        )
        group_label = victim.get("group") or "unknown-group"
        report_name = f"[Ransomware.live] {group_label} → {victim_name}"
        report_refs = [victim_identity.id]
        if sector_obj:
            report_refs.append(sector_obj.id)
        if country_obj:
            report_refs.append(country_obj.id)
        if intrusion_set_id:
            report_refs.append(intrusion_set_id)

        report = stix2.Report(
            id=Report.generate_id(report_name, published),
            name=report_name,
            published=published,
            description=victim.get("description") or f"Public claim by {group_label}.",
            report_types=["threat-report"],
            object_refs=report_refs,
            external_references=_external_refs(victim),
            **self._common_meta(),
        )
        objects.append(report)

        return objects

    # --------------------------------------------------------------- IOCs
    def build_ioc_objects(
        self,
        ioc: Dict[str, Any],
        intrusion_set_id: str,
        type_filter: Optional[Iterable[str]] = None,
    ) -> List[Any]:
        """Convert one IOC record into Observable (+ Indicator) + relationships."""
        raw_type = (ioc.get("type") or "").lower().strip()
        value = ioc.get("value") or ioc.get("ioc")
        if not raw_type or not value:
            return []
        if type_filter and raw_type not in type_filter:
            return []
        if raw_type not in _IOC_TYPE_MAP:
            if self.logger:
                self.logger.debug(
                    f"[ransomwarelive-pro] Skipping unsupported IOC type: {raw_type}"
                )
            return []

        observable_type, pattern_path = _IOC_TYPE_MAP[raw_type]
        objects: List[Any] = []

        # Build observable
        observable = _build_observable(
            observable_type, value, self.author.id, self.tlp
        )
        if observable is None:
            return []
        objects.append(observable)

        # Optional indicator
        if self.create_indicators:
            pattern = f"[{pattern_path} = '{value}']"
            valid_from = (
                self._parse_date(ioc.get("date") or ioc.get("first_seen"))
                or datetime.now(tz=timezone.utc)
            )
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=value,
                pattern=pattern,
                pattern_type="stix",
                valid_from=valid_from,
                indicator_types=["malicious-activity"],
                labels=["ransomware", raw_type],
                **self._common_meta(),
            )
            objects.append(indicator)

            # indicator -> based-on -> observable
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "based-on", indicator.id, observable.id
                    ),
                    relationship_type="based-on",
                    source_ref=indicator.id,
                    target_ref=observable.id,
                    **self._common_meta(),
                )
            )
            # indicator -> indicates -> intrusion set
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", indicator.id, intrusion_set_id
                    ),
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=intrusion_set_id,
                    **self._common_meta(),
                )
            )
        else:
            # observable -> related-to -> intrusion set
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", observable.id, intrusion_set_id
                    ),
                    relationship_type="related-to",
                    source_ref=observable.id,
                    target_ref=intrusion_set_id,
                    **self._common_meta(),
                )
            )

        return objects

    # ---------------------------------------------------------------- YARA
    def build_yara_indicator(
        self, yara_rule: Dict[str, Any], intrusion_set_id: str
    ) -> List[Any]:
        """Build a YARA-typed Indicator from a yara rule entry."""
        rule_text = yara_rule.get("rule") or yara_rule.get("content")
        rule_name = yara_rule.get("name") or yara_rule.get("rule_name")
        if not rule_text or not rule_name:
            return []

        # OpenCTI/STIX 2.1 supports pattern_type='yara'.
        # Use a stable hash to seed the indicator id.
        rule_hash = hashlib.sha256(rule_text.encode("utf-8")).hexdigest()
        indicator = stix2.Indicator(
            id=Indicator.generate_id(f"yara-{rule_hash}"),
            name=rule_name,
            pattern=rule_text,
            pattern_type="yara",
            valid_from=datetime.now(tz=timezone.utc),
            indicator_types=["malicious-activity"],
            labels=["ransomware", "yara"],
            **self._common_meta(),
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "indicates", indicator.id, intrusion_set_id
            ),
            relationship_type="indicates",
            source_ref=indicator.id,
            target_ref=intrusion_set_id,
            **self._common_meta(),
        )
        return [indicator, relationship]

    # -------------------------------------------------------- Ransom notes
    def build_ransomnote_note(
        self, group_name: str, filename: str, content: str, intrusion_set_id: str
    ) -> List[Any]:
        if not content:
            return []
        # Cap note content to keep payload manageable.
        truncated = content[:5000]
        note = stix2.Note(
            id=Note.generate_id(
                created=datetime.now(tz=timezone.utc),
                content=truncated,
            ),
            abstract=f"Ransom note ({group_name} / {filename})",
            content=truncated,
            object_refs=[intrusion_set_id],
            **self._common_meta(),
        )
        return [note]

    # --------------------------------------------------------------- Press
    def build_press_objects(
        self, press: Dict[str, Any], intrusion_set_index: Dict[str, str]
    ) -> List[Any]:
        """Convert a press / cyberattack record into a Report.

        Press entries are journalistic coverage of incidents. They reference
        a victim and (optionally) an attributed group. We model them as a
        Report with `report_types=['threat-report']` and external_references
        pointing to the actual article URL(s).
        """
        title = press.get("title") or press.get("name")
        url = press.get("url") or press.get("link")
        if not title:
            return []

        objects: List[Any] = []
        published = (
            self._parse_date(
                press.get("date") or press.get("published") or press.get("discovered")
            )
            or datetime.now(tz=timezone.utc)
        )

        report_refs: List[str] = []

        # Optional victim
        victim_name = press.get("victim") or press.get("target")
        if victim_name:
            victim = stix2.Identity(
                id=Identity.generate_id(victim_name, "organization"),
                name=victim_name,
                identity_class="organization",
                **self._common_meta(),
            )
            objects.append(victim)
            report_refs.append(victim.id)

        # Optional group attribution
        group_name = (press.get("group") or "").lower().strip()
        if group_name and group_name in intrusion_set_index:
            report_refs.append(intrusion_set_index[group_name])

        # Optional country
        country_code = press.get("country")
        if country_code:
            country_name = _country_name(country_code)
            country = stix2.Location(
                id=Location.generate_id(country_name, "Country"),
                name=country_name,
                country=country_code.upper()[:2],
                **self._common_meta(),
            )
            objects.append(country)
            report_refs.append(country.id)

        external_refs = []
        if url:
            external_refs.append(
                stix2.ExternalReference(
                    source_name=press.get("source") or "press",
                    url=str(url),
                )
            )

        if not report_refs:
            # A Report with no object_refs is meaningless in OpenCTI.
            return objects

        report = stix2.Report(
            id=Report.generate_id(title, published),
            name=f"[Press] {title}",
            published=published,
            description=press.get("summary") or press.get("description") or title,
            report_types=["threat-report"],
            object_refs=report_refs,
            external_references=external_refs or None,
            **self._common_meta(),
        )
        objects.append(report)
        return objects

    # --------------------------------------------------------- Negotiations
    def build_negotiation_note(
        self,
        group_name: str,
        chat_id: str,
        chat_payload: Dict[str, Any],
        intrusion_set_id: str,
    ) -> List[Any]:
        """Convert a negotiation chat transcript into a Note attached to the
        IntrusionSet. Transcripts can be huge — we cap at ~20 KB and add an
        external_references entry if the original URL is present."""
        if not chat_payload:
            return []

        # The API returns either a transcript string or a list of message dicts.
        transcript_raw = (
            chat_payload.get("transcript")
            or chat_payload.get("messages")
            or chat_payload.get("chat")
            or chat_payload
        )
        if isinstance(transcript_raw, list):
            lines: List[str] = []
            for msg in transcript_raw:
                if not isinstance(msg, dict):
                    continue
                ts = msg.get("timestamp") or msg.get("date") or ""
                author = msg.get("author") or msg.get("from") or "?"
                text = msg.get("text") or msg.get("message") or ""
                lines.append(f"[{ts}] {author}: {text}")
            transcript = "\n".join(lines)
        else:
            transcript = str(transcript_raw)

        # Cap to keep payload sane.
        truncated = transcript[:20000]
        if len(transcript) > 20000:
            truncated += "\n\n[...transcript truncated...]"

        victim_name = chat_payload.get("victim") or chat_payload.get("target")
        abstract = f"Negotiation chat — {group_name} / {chat_id}"
        if victim_name:
            abstract += f" with {victim_name}"

        note = stix2.Note(
            id=Note.generate_id(
                created=datetime.now(tz=timezone.utc),
                content=truncated,
            ),
            abstract=abstract,
            content=truncated,
            object_refs=[intrusion_set_id],
            **self._common_meta(),
        )
        return [note]

    # ----------------------------------------------------------- 8-K filing
    def build_filing_objects(
        self, filing: Dict[str, Any], intrusion_set_index: Dict[str, str]
    ) -> List[Any]:
        """Convert an SEC 8-K filing into Identity (victim) + Incident + Report."""
        company = filing.get("company") or filing.get("name") or filing.get("ticker")
        ticker = filing.get("ticker")
        cik = filing.get("cik")
        url = filing.get("url") or filing.get("link")
        filed_at = self._parse_date(
            filing.get("date") or filing.get("filed") or filing.get("published")
        ) or datetime.now(tz=timezone.utc)

        if not company:
            return []

        objects: List[Any] = []

        # Victim org
        victim = stix2.Identity(
            id=Identity.generate_id(company, "organization"),
            name=company,
            identity_class="organization",
            description=(
                f"SEC registrant. Ticker: {ticker or 'n/a'}, CIK: {cik or 'n/a'}."
            ),
            external_references=[
                stix2.ExternalReference(source_name="SEC", url=str(url))
            ]
            if url
            else None,
            **self._common_meta(),
        )
        objects.append(victim)

        # Incident
        item = filing.get("item") or "1.05"
        incident_name = f"[8-K Item {item}] {company}"
        incident = stix2.Incident(
            id=Incident.generate_id(incident_name, filed_at),
            name=incident_name,
            description=(
                filing.get("summary")
                or filing.get("description")
                or f"SEC 8-K cybersecurity incident disclosure for {company}."
            ),
            custom_properties={
                "first_seen": filed_at,
                "incident_type": "data-breach",
                "severity": "high",
            },
            **self._common_meta(),
        )
        objects.append(incident)
        objects.append(
            stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", incident.id, victim.id
                ),
                relationship_type="related-to",
                source_ref=incident.id,
                target_ref=victim.id,
                **self._common_meta(),
            )
        )

        # Optional group attribution
        group_name = (filing.get("group") or "").lower().strip()
        if group_name and group_name in intrusion_set_index:
            objects.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "attributed-to",
                        incident.id,
                        intrusion_set_index[group_name],
                    ),
                    relationship_type="attributed-to",
                    source_ref=incident.id,
                    target_ref=intrusion_set_index[group_name],
                    **self._common_meta(),
                )
            )

        # Wrap in a Report
        report_refs = [victim.id, incident.id]
        if group_name and group_name in intrusion_set_index:
            report_refs.append(intrusion_set_index[group_name])

        report = stix2.Report(
            id=Report.generate_id(incident_name, filed_at),
            name=incident_name,
            published=filed_at,
            description=incident.description,
            report_types=["threat-report", "incident-report"],
            object_refs=report_refs,
            external_references=[
                stix2.ExternalReference(source_name="SEC EDGAR 8-K", url=str(url))
            ]
            if url
            else None,
            **self._common_meta(),
        )
        objects.append(report)
        return objects

    # -------------------------------------------------------------- bundle
    def build_bundle(self, objects: List[Any]) -> stix2.Bundle:
        """Wrap objects in a bundle, deduplicating by id and ensuring author."""
        deduped: Dict[str, Any] = {self.author.id: self.author}
        for obj in objects:
            if obj is None:
                continue
            obj_id = getattr(obj, "id", None) or obj.get("id")
            if obj_id and obj_id not in deduped:
                deduped[obj_id] = obj
        return stix2.Bundle(objects=list(deduped.values()), allow_custom=True)


# ---------------------------------------------------------------- helpers
def _build_observable(
    obs_type: str, value: str, author_id: str, tlp: stix2.MarkingDefinition
) -> Optional[Any]:
    """Instantiate the appropriate stix2 observable. Returns None on failure."""
    try:
        common = {
            "object_marking_refs": [tlp],
            "custom_properties": {
                "x_opencti_created_by_ref": author_id,
                "x_opencti_score": 75,
            },
        }
        if obs_type == "IPv4-Addr":
            return stix2.IPv4Address(value=value, **common)
        if obs_type == "IPv6-Addr":
            return stix2.IPv6Address(value=value, **common)
        if obs_type == "Domain-Name":
            return stix2.DomainName(value=value, **common)
        if obs_type == "Url":
            return stix2.URL(value=value, **common)
        if obs_type == "Email-Addr":
            return stix2.EmailAddress(value=value, **common)
        if obs_type == "File":
            algo = _detect_hash_algo(value)
            if not algo:
                return None
            return stix2.File(hashes={algo: value}, **common)
        if obs_type == "Cryptocurrency-Wallet":
            # OpenCTI custom obs — fall back to generic dict.
            return {
                "type": "cryptocurrency-wallet",
                "spec_version": "2.1",
                "id": f"cryptocurrency-wallet--{_uuid_from(value)}",
                "value": value,
                "object_marking_refs": [tlp.id],
                "x_opencti_created_by_ref": author_id,
            }
    except Exception:
        return None
    return None


def _detect_hash_algo(value: str) -> Optional[str]:
    cleaned = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", cleaned):
        return None
    length = len(cleaned)
    return {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(length)


def _uuid_from(value: str) -> str:
    """Deterministic UUID v5 from value."""
    import uuid
    return str(uuid.uuid5(uuid.NAMESPACE_URL, value))


def _external_refs(victim: Dict[str, Any]) -> List[stix2.ExternalReference]:
    refs: List[stix2.ExternalReference] = []
    website = victim.get("website")
    if website:
        refs.append(
            stix2.ExternalReference(source_name="victim-website", url=str(website))
        )
    screenshot = victim.get("screenshot") or victim.get("post_url")
    if screenshot:
        refs.append(
            stix2.ExternalReference(source_name="ransomware.live", url=str(screenshot))
        )
    return refs


# Tiny ISO 3166 helper — country code -> human-readable name. Falls back to
# the original code if unknown (keeps OpenCTI happy via Location upsert).
_COUNTRY_NAMES = {
    "US": "United States", "FR": "France", "DE": "Germany", "GB": "United Kingdom",
    "UK": "United Kingdom", "CA": "Canada", "JP": "Japan", "IN": "India",
    "BR": "Brazil", "IT": "Italy", "ES": "Spain", "NL": "Netherlands",
    "AU": "Australia", "CN": "China", "RU": "Russia", "BE": "Belgium",
    "CH": "Switzerland", "SE": "Sweden", "NO": "Norway", "FI": "Finland",
    "DK": "Denmark", "PL": "Poland", "MX": "Mexico", "AR": "Argentina",
    "ZA": "South Africa", "AE": "United Arab Emirates", "SG": "Singapore",
    "KR": "South Korea", "TW": "Taiwan", "TR": "Turkey",
}


def _country_name(code: str) -> str:
    code = (code or "").upper().strip()
    return _COUNTRY_NAMES.get(code[:2], code or "Unknown")
