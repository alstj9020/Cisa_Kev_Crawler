from cisa_kev_crawler.normalizer import _make_id, normalize_batch, normalize_entry
from cisa_kev_crawler.nvd_client import CvssResult

SAMPLE_ENTRY = {
    "cveID": "CVE-2026-1234",
    "vulnerabilityName": "Test Vuln RCE",
    "shortDescription": "A critical RCE vulnerability in TestProduct.",
    "dateAdded": "2026-05-20",
    "dueDate": "2026-06-04",
    "vendorProject": "TestVendor",
    "product": "TestProduct",
    "requiredAction": "Apply vendor patch immediately.",
    "knownRansomwareCampaignUse": "Known",
    "cwes": ["CWE-79", "CWE-23"],
    "notes": "More info at https://example.com/advisory and https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
}

CVSS_CRITICAL = CvssResult(
    label="critical",
    score=9.8,
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
)
CVSS_UNKNOWN = CvssResult(label="unknown", score=None, vector=None)
CVSS_WITH_CPE = CvssResult(
    label="critical",
    score=9.8,
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cpe_products=[("vendor a", "product x"), ("vendor b", "product y")],
)

MULTIPLE_PRODUCTS_ENTRY = {**SAMPLE_ENTRY, "product": "Multiple Products"}


def test_make_id_is_deterministic():
    assert _make_id("CVE-2026-1234") == _make_id("CVE-2026-1234")
    assert len(_make_id("CVE-2026-1234")) == 32


def test_normalize_entry_source_fields():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert record.source == "cisa_kev"
    assert record.source_id == "CVE-2026-1234"
    assert "known-exploited-vulnerabilities-catalog" in record.source_url


def test_normalize_entry_id_matches_make_id():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert record.id == _make_id("CVE-2026-1234")


def test_normalize_entry_title_and_content():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert record.title == "Test Vuln RCE"
    assert "RCE vulnerability" in record.content_raw
    assert record.summary is None


def test_normalize_entry_dates():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert record.published_at == "2026-05-20T00:00:00Z"
    assert record.due_date == "2026-06-04T00:00:00Z"
    assert record.updated_at is None


def test_normalize_entry_severity_from_nvd():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert record.severity.label == "critical"
    assert record.severity.cvss_score == 9.8
    assert record.severity.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert record.severity.epss_score is None


def test_normalize_entry_severity_unknown_when_nvd_fails():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_UNKNOWN)
    assert record.severity.label == "unknown"
    assert record.severity.cvss_score is None


def test_normalize_entry_affected():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert len(record.affected) == 1
    assert record.affected[0].vendor == "TestVendor"
    assert record.affected[0].product == "TestProduct"


def test_normalize_entry_identifiers():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert record.identifiers.cve_ids == ["CVE-2026-1234"]
    assert record.identifiers.kev_listed is True
    assert record.identifiers.ransomware_known is True
    assert record.identifiers.ghsa_id is None


def test_normalize_entry_ransomware_unknown():
    entry = {**SAMPLE_ENTRY, "knownRansomwareCampaignUse": "Unknown"}
    record = normalize_entry(entry, CVSS_UNKNOWN)
    assert record.identifiers.ransomware_known is False


def test_normalize_entry_cwe_list():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    cwe_ids = [c.id for c in record.tags.cwe]
    assert "CWE-79" in cwe_ids
    assert "CWE-23" in cwe_ids
    assert record.tags.categories == ["vulnerability"]


def test_normalize_entry_references_from_notes():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    urls = [r.url for r in record.action.references]
    assert any("example.com" in u for u in urls)
    assert any("nvd.nist.gov" in u for u in urls)


def test_normalize_entry_required_action():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert record.action.required_action == "Apply vendor patch immediately."


def test_normalize_entry_lmm_slots_empty():
    record = normalize_entry(SAMPLE_ENTRY, CVSS_CRITICAL)
    assert record.tags.tech_stack == []
    assert record.tags.topics == []
    assert record.tags.attack_vectors == []
    assert record.audience.scores.general == 0.0


def test_normalize_entry_multiple_products_uses_cpe():
    record = normalize_entry(MULTIPLE_PRODUCTS_ENTRY, CVSS_WITH_CPE)
    assert len(record.affected) == 2
    products = [a.product for a in record.affected]
    vendors = [a.vendor for a in record.affected]
    assert "product x" in products
    assert "product y" in products
    assert "vendor a" in vendors
    assert "vendor b" in vendors


def test_normalize_entry_multiple_products_falls_back_without_cpe():
    record = normalize_entry(MULTIPLE_PRODUCTS_ENTRY, CVSS_UNKNOWN)
    assert len(record.affected) == 1
    assert record.affected[0].product == "Multiple Products"


def test_normalize_batch_deduplicates_by_cve_id():
    class MockNvd:
        def lookup(self, cve_id: str) -> CvssResult:
            return CVSS_UNKNOWN

    records = normalize_batch([SAMPLE_ENTRY, SAMPLE_ENTRY], MockNvd())
    assert len(records) == 1


def test_normalize_batch_skips_missing_cve_id():
    class MockNvd:
        def lookup(self, cve_id: str) -> CvssResult:
            return CVSS_UNKNOWN

    entries = [{"dateAdded": "2026-05-20"}, SAMPLE_ENTRY]
    records = normalize_batch(entries, MockNvd())
    assert len(records) == 1
