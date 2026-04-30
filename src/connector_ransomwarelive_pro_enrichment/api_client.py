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
        # Strip whitespace defensively — .env files and YAML often introduce
        # leading/trailing spaces or stray newlines that break HTTP headers.
        api_key = (api_key or "").strip()
        base_url = (base_url or "").strip()

        if not api_key:
            raise ValueError("Ransomware.live PRO API key is required.")
        # Reject keys that contain whitespace anywhere — they will be silently
        # rejected by `requests`' header validator otherwise.
        if any(c.isspace() for c in api_key):
            raise ValueError(
                "Ransomware.live PRO API key contains whitespace. "
                "Check your .env or config.yml — there must be no space "
                "around the '=' sign and no embedded newlines."
            )

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

        if self.logger:
            self.logger.debug(
                f"[ransomwarelive-pro] GET {url} -> "
                f"HTTP {response.status_code} "
                f"({len(response.content)} bytes)"
            )

        if response.status_code == 401:
            raise RansomwareLiveProAPIError(
                f"API key rejected (HTTP 401) on {url}. "
                f"Check RANSOMWARELIVEPRO_API_KEY at https://my.ransomware.live. "
                f"Body: {response.text[:200]}"
            )
        if response.status_code == 403:
            raise RansomwareLiveProAPIError(
                f"Access forbidden (HTTP 403) for {url}. "
                f"Your key may not have the required entitlements. "
                f"Body: {response.text[:200]}"
            )
        if response.status_code == 404:
            # Many endpoints return 404 when no data exists for a group; treat
            # as empty rather than fatal.
            if self.logger:
                self.logger.debug(
                    f"[ransomwarelive-pro] 404 on {url}, returning None"
                )
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
        """Confirm the API key is active.

        Strategy: try /validate first (cheap, dedicated endpoint). If the API
        does not expose it (404) or returns an unexpected shape, fall back to
        a lightweight call on /groups which we KNOW exists. The fallback
        succeeds as long as we get a 2xx with a list-shaped payload.

        Raises RansomwareLiveProAPIError on auth errors (401/403) so the
        caller can surface the real reason instead of a vague "failed".
        """
        # ---- Attempt 1: dedicated /validate endpoint ------------------
        try:
            result = self._get("validate")
            if isinstance(result, dict):
                # Accept any of these auth-ok shapes:
                #   {"valid": true}
                #   {"status": "ok"} | {"status": "valid"} | {"status": "active"}
                #   {"ok": true}
                #   {"authenticated": true}
                status = str(result.get("status") or "").lower()
                if (
                    result.get("valid") is True
                    or status in ("ok", "valid", "active", "authenticated")
                    or result.get("ok") is True
                    or result.get("authenticated") is True
                ):
                    if self.logger:
                        client_id = result.get("client") or result.get("user") or ""
                        suffix = f" (client: {client_id})" if client_id else ""
                        self.logger.info(
                            f"[ransomwarelive-pro] /validate confirms key{suffix}"
                        )
                    return True
                # Endpoint replied but not in a shape we recognise — log it
                # and fall through to the fallback so we don't false-negative.
                if self.logger:
                    self.logger.warning(
                        "[ransomwarelive-pro] /validate returned unexpected "
                        f"shape, falling back to /groups probe: {result!r}"
                    )
            elif result is None:
                # 404 — endpoint not exposed on this tier. Fall through.
                if self.logger:
                    self.logger.info(
                        "[ransomwarelive-pro] /validate not available, "
                        "probing /groups instead"
                    )
        except RansomwareLiveProAPIError as exc:
            # Auth errors are fatal; bubble them up.
            msg = str(exc)
            if "401" in msg or "403" in msg or "rejected" in msg:
                raise
            # Other errors — log and fall through to the probe.
            if self.logger:
                self.logger.warning(
                    f"[ransomwarelive-pro] /validate errored, "
                    f"falling back to /groups probe: {exc}"
                )

        # ---- Attempt 2: probe /groups ---------------------------------
        # Use _ensure_list to coerce dict-wrapped payloads (e.g. {"groups":
        # [...]}) into a list — same logic as everywhere else in the client.
        try:
            raw = self._get("groups_list")
        except RansomwareLiveProAPIError:
            raise
        if raw is None:
            if self.logger:
                self.logger.error(
                    "[ransomwarelive-pro] /groups returned no data (404 or "
                    "empty). Verify RANSOMWARELIVEPRO_API_BASE_URL."
                )
            return False
        groups = _ensure_list(raw)
        if groups:
            if self.logger:
                self.logger.info(
                    f"[ransomwarelive-pro] /groups probe OK "
                    f"({len(groups)} groups visible)"
                )
            return True
        # Empty list is suspicious but not fatal — could be a transient empty
        # response. Treat as success so the connector continues; collectors
        # will handle empty data downstream.
        if self.logger:
            self.logger.warning(
                f"[ransomwarelive-pro] /groups returned empty payload "
                f"(raw type: {type(raw).__name__}). Continuing anyway."
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
    """Coerce API responses to a list. The PRO API mixes shapes:

    * `[...]`                          → returned as-is
    * `{"data": [...]}`                → unwrapped to inner list
    * `{"results": [...]}`             → unwrapped
    * `{"items": [...]}` / `{"victims": [...]}` / `{"groups": [...]}` → unwrapped
    * `{"LockBit": {...}, "Akira": {...}}` → values flattened, name folded in
    * Single record dict                → wrapped in a one-element list
    """
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if not payload:
            return []
        # Common wrappers
        for key in ("data", "results", "items", "victims", "groups"):
            if key in payload and isinstance(payload[key], list):
                return payload[key]

        # Dict-of-records pattern (e.g. /groups returning
        # {"LockBit": {profile…}, "Akira": {profile…}}). Detect by checking
        # all values are dicts and none of the recognized scalar metadata
        # keys are present at the top level.
        values = list(payload.values())
        if values and all(isinstance(v, dict) for v in values):
            # Likely indexed-by-name. Fold the key into each record under
            # `name` so downstream converters work uniformly.
            flattened: List[Dict[str, Any]] = []
            for name, record in payload.items():
                merged = dict(record)
                merged.setdefault("name", name)
                flattened.append(merged)
            return flattened

        # Fallback: treat the dict as a single record.
        return [payload]
    return []


def _drop_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None and v != ""}
