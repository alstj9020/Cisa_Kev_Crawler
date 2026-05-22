from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CvssResult:
    label: str
    score: float | None
    vector: str | None
    cpe_products: list[tuple[str, str]] = field(default_factory=list)


class NvdClient:
    def __init__(self, api_key: str | None = None, timeout: int = 30) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._delay = 0.6 if api_key else 6.0

    def lookup(self, cve_id: str) -> CvssResult:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(NVD_BASE_URL, params={"cveId": cve_id}, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            time.sleep(self._delay)
            return self._parse(data)
        except (httpx.RequestError, httpx.HTTPStatusError):
            time.sleep(self._delay)
            return CvssResult(label="unknown", score=None, vector=None)

    def _parse(self, data: dict) -> CvssResult:
        label, score, vector = "unknown", None, None
        try:
            vuln = data["vulnerabilities"][0]["cve"]
            metrics = vuln.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if key in metrics:
                    cvss_data = metrics[key][0]["cvssData"]
                    score = float(cvss_data["baseScore"])
                    vector = cvss_data["vectorString"]
                    label = self._score_to_label(score)
                    break
        except (KeyError, IndexError, TypeError, ValueError):
            pass
        return CvssResult(
            label=label, score=score, vector=vector, cpe_products=self._parse_cpe(data)
        )

    def _parse_cpe(self, data: dict) -> list[tuple[str, str]]:
        seen: set[tuple[str, str]] = set()
        result: list[tuple[str, str]] = []
        try:
            configs = data["vulnerabilities"][0]["cve"].get("configurations", [])
            for config in configs:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable", False):
                            continue
                        parts = match.get("criteria", "").split(":")
                        if len(parts) < 5:
                            continue
                        vendor = parts[3].replace("_", " ")
                        product = parts[4].replace("_", " ")
                        if vendor in ("*", "-") or product in ("*", "-"):
                            continue
                        key = (vendor, product)
                        if key not in seen:
                            seen.add(key)
                            result.append(key)
        except (KeyError, IndexError, TypeError):
            pass
        return result

    @staticmethod
    def _score_to_label(score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "info"
