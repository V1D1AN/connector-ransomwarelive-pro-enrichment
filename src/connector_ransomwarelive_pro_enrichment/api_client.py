"""HTTP client for the Ransomware.live PRO API.

Wraps `requests.Session` with:
  * `X-API-KEY` header injection
  * exponential back-off + Retry on 429 / 5xx
  * helper methods per documented endpoint
  * defensive JSON decoding (the API occasionally returns plain text on 5xx)

Endpoint paths are derived from the public swagger of api-pro.ransomware.live
and the community n8n node (Jacox98/n8n-nodes-ransomware-live). Wrong paths can
be overridden centrally below — `_ENDPOINTS` is the only source of truth.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# -----------------------------------------------------------------------------
# Centralised endpoint table — adjust here if the upstream API ever moves.
# -----------------------------------------------------------------------------
_ENDPOINTS: Dict[str, str] = {
    "validate": "/validate",
    "stats": "/stats",
    # Victims
    "victims_recent": "/victims/recent",
    "victims_list": "/victims",
    "victim_get": "/victims/{victim_id}",
    "victims_search": "/victims/search",
    # Groups
    "groups_list": "/groups",
    "group_get": "/groups/{group}",
    # IOCs
    "iocs_groups": "/iocs/groups",
    "iocs_for_group": "/iocs/{group}",
    # YARA
    "yara_groups": "/yara/groups",
    "yara_for_group": "/yara/{group}",
    # Ransom notes
    "ransomnotes_groups": "/ransomnotes/groups",
    "ransomnotes_files_for_group": "/ransomnotes/{group}",
    "ransomnote_file": "/ransomnotes/{group}/{filename}",
    # Press
    "press_recent": "/press/recent",
    "press_list": "/press",
    # Negotiations
    "negotiations_groups": "/negotiations/groups",
    "negotiations_for_group": "/negotiations/{group}",
    "negotiation_chat": "/negotiations/{group}/{chat_id}",
    # 8-K filings
    "filings_8k": "/8k",
    # Sectors / CSIRT
    "sectors_list": "/sectors",
    "csirt_list": "/csirt",
    "csirt_for_country": "/csirt/{country_code}",
}


class RansomwareLiveProAPIError(Exception):
    """Wrapper for any API-side error."""


class RansomwareLiveProClient:
    """Thin client around api-pro.ransomware.live."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api-pro.ransomware.live",
        timeout: int = 30,
        max_retries: int = 5,
        backoff_factor: float = 1.5,
        logger=None,
    ) -> None:
        if not api_key:
            raise ValueError("Ransomware.live PRO API key is required.")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.logger = logger

        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-API-KEY": api_key,
                "Accept": "application/json",
                "User-Agent": "OpenCTI-connector-ransomwarelive-pro/1.0",
            }
        )

        retry = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    # ------------------------------------------------------------------ core
    def _get(
        self,
        endpoint_key: str,
        path_params: Optional[Dict[str, Any]] = None,
        query_params: Optional[Dict[str, Any]] = None,
    ) -> Union[Dict[str, Any], List[Any], None]:
        """Perform a GET on a named endpoint and return parsed JSON."""
        if endpoint_key not in _ENDPOINTS:
            raise ValueError(f"Unknown endpoint key: {endpoint_key}")

        path_template = _ENDPOINTS[endpoint_key]
        try:
            path = path_template.format(**(path_params or {}))
        except KeyError as exc:
            raise ValueError(
                f"Missing path parameter for {endpoint_key}: {exc}"
            ) from exc

        url = f"{self.base_url}{path}"

        try:
            response = self.session.get(
                url, params=query_params or {}, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise RansomwareLiveProAPIError(
                f"Network error calling {url}: {exc}"
            ) from exc

        if response.status_code == 401:
            raise RansomwareLiveProAPIError(
                "API key rejected (HTTP 401). Check RANSOMWARELIVEPRO_API_KEY."
            )
        if response.status_code == 403:
            raise RansomwareLiveProAPIError(
                f"Access forbidden (HTTP 403) for {url}. "
                "Your key may not have the required entitlements."
            )
        if response.status_code == 404:
            # Many endpoints return 404 when no data exists for a group; treat
            # as empty rather than fatal.
            if self.logger:
                self.logger.debug(f"[ransomwarelive-pro] 404 on {url}, returning None")
            return None
        if response.status_code >= 400:
            raise RansomwareLiveProAPIError(
                f"HTTP {response.status_code} on {url}: {response.text[:300]}"
            )

        # Defensive JSON parsing
        try:
            return response.json()
        except ValueError:
            text = response.text.strip()
            if not text:
                return None
            if self.logger:
                self.logger.warning(
                    f"[ransomwarelive-pro] Non-JSON response from {url}: {text[:200]}"
                )
            return {"_raw": text}

    # ------------------------------------------------------------ public API
    def validate(self) -> bool:
        """Confirm the API key is active. Returns True on success."""
        result = self._get("validate")
        if result is None:
            return False
        # Tolerate either {"valid": true} or {"status": "ok"} shapes.
        if isinstance(result, dict):
            return bool(
                result.get("valid")
                or result.get("status") == "ok"
                or result.get("ok") is True
            )
        return True

    def stats(self) -> Optional[Dict[str, Any]]:
        return self._get("stats")  # type: ignore[return-value]

    # ---- Victims --------------------------------------------------------
    def victims_recent(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        params = {"limit": limit} if limit else None
        data = self._get("victims_recent", query_params=params)
        return _ensure_list(data)

    def victims_list(
        self,
        year: Optional[int] = None,
        country: Optional[str] = None,
        group: Optional[str] = None,
        sector: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = _drop_none(
            {
                "year": year,
                "country": country,
                "group": group,
                "sector": sector,
                "from": date_from,
                "to": date_to,
            }
        )
        data = self._get("victims_list", query_params=params)
        return _ensure_list(data)

    def victim(self, victim_id: str) -> Optional[Dict[str, Any]]:
        return self._get("victim_get", path_params={"victim_id": victim_id})  # type: ignore[return-value]

    def victims_search(self, query: str) -> List[Dict[str, Any]]:
        data = self._get("victims_search", query_params={"q": query})
        return _ensure_list(data)

    # ---- Groups ---------------------------------------------------------
    def groups(self) -> List[Dict[str, Any]]:
        return _ensure_list(self._get("groups_list"))

    def group(self, name: str) -> Optional[Dict[str, Any]]:
        return self._get("group_get", path_params={"group": name})  # type: ignore[return-value]

    # ---- IOCs -----------------------------------------------------------
    def groups_with_iocs(self) -> List[Dict[str, Any]]:
        return _ensure_list(self._get("iocs_groups"))

    def iocs_for_group(
        self, group: str, ioc_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        params = {"type": ioc_type} if ioc_type else None
        data = self._get(
            "iocs_for_group", path_params={"group": group}, query_params=params
        )
        return _ensure_list(data)

    # ---- YARA -----------------------------------------------------------
    def groups_with_yara(self) -> List[Dict[str, Any]]:
        return _ensure_list(self._get("yara_groups"))

    def yara_for_group(self, group: str) -> List[Dict[str, Any]]:
        return _ensure_list(
            self._get("yara_for_group", path_params={"group": group})
        )

    # ---- Ransom notes ---------------------------------------------------
    def groups_with_ransomnotes(self) -> List[Dict[str, Any]]:
        return _ensure_list(self._get("ransomnotes_groups"))

    def ransomnotes_files(self, group: str) -> List[Dict[str, Any]]:
        return _ensure_list(
            self._get("ransomnotes_files_for_group", path_params={"group": group})
        )

    def ransomnote(
        self, group: str, filename: str
    ) -> Optional[Union[Dict[str, Any], str]]:
        return self._get(
            "ransomnote_file",
            path_params={"group": group, "filename": filename},
        )  # type: ignore[return-value]

    # ---- Press ----------------------------------------------------------
    def press_recent(
        self, country: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        params = {"country": country} if country else None
        return _ensure_list(self._get("press_recent", query_params=params))

    def press_list(self) -> List[Dict[str, Any]]:
        return _ensure_list(self._get("press_list"))

    # ---- Negotiations ---------------------------------------------------
    def groups_with_negotiations(self) -> List[Dict[str, Any]]:
        return _ensure_list(self._get("negotiations_groups"))

    def negotiations_for_group(self, group: str) -> List[Dict[str, Any]]:
        return _ensure_list(
            self._get("negotiations_for_group", path_params={"group": group})
        )

    def negotiation_chat(self, group: str, chat_id: str) -> Optional[Dict[str, Any]]:
        return self._get(
            "negotiation_chat",
            path_params={"group": group, "chat_id": chat_id},
        )  # type: ignore[return-value]

    # ---- 8-K filings ----------------------------------------------------
    def filings_8k(
        self,
        ticker: Optional[str] = None,
        cik: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = _drop_none(
            {
                "ticker": ticker,
                "cik": cik,
                "from": date_from,
                "to": date_to,
            }
        )
        return _ensure_list(self._get("filings_8k", query_params=params))


# ----------------------------------------------------------------- helpers
def _ensure_list(payload: Any) -> List[Any]:
    """Coerce API responses to a list. PRO API mixes list/dict shapes."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        # Common patterns: {"data": [...]}, {"results": [...]}, {"items": [...]}
        for key in ("data", "results", "items", "victims", "groups"):
            if key in payload and isinstance(payload[key], list):
                return payload[key]
        # Fallback: wrap the dict in a single-element list.
        return [payload]
    return []


def _drop_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None and v != ""}
