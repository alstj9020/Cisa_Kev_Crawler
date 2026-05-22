from __future__ import annotations

from typing import Any

import httpx

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class CrawlerError(Exception):
    pass


class NetworkError(CrawlerError):
    pass


class CisaKevClient:
    def __init__(self, timeout: int = 30) -> None:
        self._timeout = timeout

    def fetch(self) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.get(CISA_KEV_URL)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            raise NetworkError(f"HTTP {exc.response.status_code}: {CISA_KEV_URL}") from exc
        except httpx.RequestError as exc:
            raise NetworkError(str(exc)) from exc
