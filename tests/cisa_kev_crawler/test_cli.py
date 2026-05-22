from pathlib import Path
from unittest.mock import patch

from cisa_kev_crawler.cli import run_crawl
from cisa_kev_crawler.config import CrawlerConfig
from cisa_kev_crawler.nvd_client import CvssResult

SAMPLE_ENTRY = {
    "cveID": "CVE-2026-9999",
    "vulnerabilityName": "Integration Test Vuln",
    "shortDescription": "Test description.",
    "dateAdded": "2026-05-20",
    "dueDate": "2026-06-04",
    "vendorProject": "TestVendor",
    "product": "TestProduct",
    "requiredAction": "Apply patch.",
    "knownRansomwareCampaignUse": "Unknown",
    "cwes": [],
    "notes": "",
}

CISA_RESPONSE = {"count": 1, "vulnerabilities": [SAMPLE_ENTRY]}


def test_run_crawl_returns_path_string(tmp_path):
    config = CrawlerConfig(output_dir=str(tmp_path), nvd_api_key=None, request_timeout=30)
    with (
        patch("cisa_kev_crawler.cli.load_config", return_value=config),
        patch("cisa_kev_crawler.cli.CisaKevClient") as MockClient,
        patch("cisa_kev_crawler.cli.NvdClient") as MockNvd,
    ):
        MockClient.return_value.fetch.return_value = CISA_RESPONSE
        MockNvd.return_value.lookup.return_value = CvssResult(
            label="unknown", score=None, vector=None
        )
        path = run_crawl(days=30, output_dir=str(tmp_path))
    assert "cisa_kev" in path
    assert Path(path).exists()


def test_run_crawl_creates_latest_json(tmp_path):
    config = CrawlerConfig(output_dir=str(tmp_path), nvd_api_key=None, request_timeout=30)
    with (
        patch("cisa_kev_crawler.cli.load_config", return_value=config),
        patch("cisa_kev_crawler.cli.CisaKevClient") as MockClient,
        patch("cisa_kev_crawler.cli.NvdClient") as MockNvd,
    ):
        MockClient.return_value.fetch.return_value = CISA_RESPONSE
        MockNvd.return_value.lookup.return_value = CvssResult(
            label="unknown", score=None, vector=None
        )
        run_crawl(days=30, output_dir=str(tmp_path))
    assert (tmp_path / "latest.json").exists()


def test_run_crawl_output_dir_overrides_config(tmp_path):
    override_dir = str(tmp_path / "custom")
    config = CrawlerConfig(output_dir="original", nvd_api_key=None, request_timeout=30)
    with (
        patch("cisa_kev_crawler.cli.load_config", return_value=config),
        patch("cisa_kev_crawler.cli.CisaKevClient") as MockClient,
        patch("cisa_kev_crawler.cli.NvdClient") as MockNvd,
    ):
        MockClient.return_value.fetch.return_value = {"count": 0, "vulnerabilities": []}
        MockNvd.return_value.lookup.return_value = CvssResult(
            label="unknown", score=None, vector=None
        )
        path = run_crawl(days=7, output_dir=override_dir)
    assert "custom" in path
