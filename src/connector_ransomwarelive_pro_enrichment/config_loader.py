"""Configuration loader for the Ransomware.live PRO enrichment connector.

The enrichment connector is triggered on demand by an analyst (or auto on
entity creation when CONNECTOR_AUTO=true). It pulls per-group intel only,
so it has fewer knobs than the import connector.
"""

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pycti import get_config_variable


class ConfigConnector:
    """Read configuration once and expose it as typed attributes."""

    def __init__(self) -> None:
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.load = config
        self._initialize_configurations()

    def _initialize_configurations(self) -> None:
        # ---- OpenCTI core ---------------------------------------------------
        self.opencti_url: str = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], self.load
        )
        self.opencti_token: str = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], self.load
        )

        # ---- Connector core -------------------------------------------------
        self.connector_id: str = get_config_variable(
            "CONNECTOR_ID", ["connector", "id"], self.load
        )
        self.connector_name: str = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            self.load,
            default="Ransomware.live PRO (enrichment)",
        )
        # Comma-separated entity types this connector accepts.
        self.connector_scope: str = get_config_variable(
            "CONNECTOR_SCOPE",
            ["connector", "scope"],
            self.load,
            default="Intrusion-Set,Threat-Actor-Group",
        )
        self.connector_type: str = get_config_variable(
            "CONNECTOR_TYPE",
            ["connector", "type"],
            self.load,
            default="INTERNAL_ENRICHMENT",
        )
        self.connector_log_level: str = get_config_variable(
            "CONNECTOR_LOG_LEVEL",
            ["connector", "log_level"],
            self.load,
            default="info",
        )
        # If true, the connector triggers automatically when an IntrusionSet
        # is created or updated, without an analyst clicking "Enrich".
        self.connector_auto: bool = get_config_variable(
            "CONNECTOR_AUTO",
            ["connector", "auto"],
            self.load,
            default=False,
        )

        # ---- Ransomware.live PRO specific ----------------------------------
        self.api_base_url: str = get_config_variable(
            "RANSOMWARELIVEPRO_API_BASE_URL",
            ["ransomwareliveepro", "api_base_url"],
            self.load,
            default="https://api-pro.ransomware.live",
        )
        self.api_key: str = get_config_variable(
            "RANSOMWARELIVEPRO_API_KEY",
            ["ransomwareliveepro", "api_key"],
            self.load,
            required=True,
        )
        # Sources to enrich with — narrower than the import connector.
        self.collect_iocs: bool = get_config_variable(
            "RANSOMWARELIVEPRO_COLLECT_IOCS",
            ["ransomwareliveepro", "collect_iocs"],
            self.load,
            default=True,
        )
        self.collect_yara: bool = get_config_variable(
            "RANSOMWARELIVEPRO_COLLECT_YARA",
            ["ransomwareliveepro", "collect_yara"],
            self.load,
            default=True,
        )
        self.collect_ransomnotes: bool = get_config_variable(
            "RANSOMWARELIVEPRO_COLLECT_RANSOMNOTES",
            ["ransomwareliveepro", "collect_ransomnotes"],
            self.load,
            default=True,
        )

        self.ioc_type_filter: str = get_config_variable(
            "RANSOMWARELIVEPRO_IOC_TYPE_FILTER",
            ["ransomwareliveepro", "ioc_type_filter"],
            self.load,
            default="",
        )
        self.create_indicators: bool = get_config_variable(
            "RANSOMWARELIVEPRO_CREATE_INDICATORS",
            ["ransomwareliveepro", "create_indicators"],
            self.load,
            default=True,
        )
        self.tlp_level: str = get_config_variable(
            "RANSOMWARELIVEPRO_TLP_LEVEL",
            ["ransomwareliveepro", "tlp_level"],
            self.load,
            default="green",
        ).lower()
        self.confidence_level: int = int(
            get_config_variable(
                "RANSOMWARELIVEPRO_CONFIDENCE_LEVEL",
                ["ransomwareliveepro", "confidence_level"],
                self.load,
                default=75,
                isNumber=True,
            )
        )
        self.update_existing: str = get_config_variable(
            "RANSOMWARELIVEPRO_UPDATE_EXISTING",
            ["ransomwareliveepro", "update_existing"],
            self.load,
            default="update",
        ).lower()

    def get(self, name: str, default: Optional[Any] = None) -> Any:
        return getattr(self, name, default)
