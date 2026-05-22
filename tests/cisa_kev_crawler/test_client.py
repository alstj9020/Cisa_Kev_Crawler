import httpx
import pytest
import respx

from cisa_kev_crawler.client import CISA_KEV_URL, CisaKevClient, NetworkError

SAMPLE_RESPONSE = {
    "title": "CISA Catalog",
    "count": 1,
    "vulnerabilities": [{"cveID": "CVE-2026-1234"}],
}


@respx.mock
def test_fetch_returns_vulnerabilities():
    respx.get(CISA_KEV_URL).mock(return_value=httpx.Response(200, json=SAMPLE_RESPONSE))
    client = CisaKevClient()
    result = client.fetch()
    assert result["count"] == 1
    assert result["vulnerabilities"][0]["cveID"] == "CVE-2026-1234"


@respx.mock
def test_fetch_raises_network_error_on_500():
    respx.get(CISA_KEV_URL).mock(return_value=httpx.Response(500))
    client = CisaKevClient()
    with pytest.raises(NetworkError):
        client.fetch()


@respx.mock
def test_fetch_raises_network_error_on_connection_failure():
    respx.get(CISA_KEV_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    client = CisaKevClient()
    with pytest.raises(NetworkError):
        client.fetch()
