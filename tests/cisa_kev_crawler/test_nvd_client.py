import httpx
import pytest
import respx

from cisa_kev_crawler.nvd_client import NVD_BASE_URL, NvdClient

NVD_RESPONSE_CRITICAL = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ]
                }
            }
        }
    ]
}

_CPE_A = "cpe:2.3:a:vendor_a:product_x:1.0:*:*:*:*:*:*:*"
_CPE_B = "cpe:2.3:a:vendor_b:product_y:2.0:*:*:*:*:*:*:*"
_CPE_C = "cpe:2.3:a:vendor_c:product_z:*:*:*:*:*:*:*:*"

NVD_RESPONSE_WITH_CPE = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"vulnerable": True, "criteria": _CPE_A},
                                    {"vulnerable": True, "criteria": _CPE_B},
                                    {"vulnerable": True, "criteria": _CPE_A},  # 중복
                                    {"vulnerable": False, "criteria": _CPE_C},  # 비취약
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
}

NVD_RESPONSE_HIGH_V30 = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            }
                        }
                    ]
                }
            }
        }
    ]
}


@respx.mock
def test_lookup_critical(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE_CRITICAL))
    client = NvdClient()
    result = client.lookup("CVE-2026-1234")
    assert result.label == "critical"
    assert result.score == 9.8
    assert "CVSS:3.1" in result.vector


@respx.mock
def test_lookup_high_from_v30(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE_HIGH_V30))
    client = NvdClient()
    result = client.lookup("CVE-2026-5678")
    assert result.label == "high"
    assert result.score == 7.5


@respx.mock
def test_lookup_returns_unknown_on_http_error(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(403))
    client = NvdClient()
    result = client.lookup("CVE-2026-9999")
    assert result.label == "unknown"
    assert result.score is None
    assert result.vector is None


@respx.mock
def test_lookup_returns_unknown_on_empty_response(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))
    client = NvdClient()
    result = client.lookup("CVE-2026-0000")
    assert result.label == "unknown"


@respx.mock
def test_lookup_extracts_cpe_products(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE_WITH_CPE))
    client = NvdClient()
    result = client.lookup("CVE-2026-1234")
    assert ("vendor a", "product x") in result.cpe_products
    assert ("vendor b", "product y") in result.cpe_products
    assert ("vendor c", "product z") not in result.cpe_products  # vulnerable=False
    assert len(result.cpe_products) == 2  # 중복 제거


@respx.mock
def test_lookup_cpe_empty_when_no_configurations(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE_CRITICAL))
    client = NvdClient()
    result = client.lookup("CVE-2026-1234")
    assert result.cpe_products == []


@respx.mock
def test_lookup_cpe_empty_on_error(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    respx.get(NVD_BASE_URL).mock(return_value=httpx.Response(403))
    client = NvdClient()
    result = client.lookup("CVE-2026-9999")
    assert result.cpe_products == []


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.8, "critical"),
        (9.0, "critical"),
        (8.9, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (0.1, "low"),
        (0.0, "info"),
    ],
)
def test_score_to_label(score, expected):
    assert NvdClient._score_to_label(score) == expected
