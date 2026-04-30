"""Entry point for the Ransomware.live PRO internal-enrichment connector."""

import traceback

from connector_ransomwarelive_pro_enrichment.connector import (
    RansomwareLiveProConnector,
)


if __name__ == "__main__":
    try:
        connector = RansomwareLiveProConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
