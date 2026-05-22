from cisa_kev_crawler.schema import (
    Action,
    AdvisoryRecord,
    CrawlResult,
    Identifiers,
    Severity,
    Tags,
    make_id,
)


def test_make_id_is_deterministic():
    id1 = make_id("cisa_kev", "CVE-2026-1234")
    id2 = make_id("cisa_kev", "CVE-2026-1234")
    assert id1 == id2
    assert len(id1) == 32


def test_make_id_differs_by_source():
    id1 = make_id("cisa_kev", "CVE-2026-1234")
    id2 = make_id("github_advisory", "CVE-2026-1234")
    assert id1 != id2


def _make_minimal_record() -> AdvisoryRecord:
    return AdvisoryRecord(
        id="abc123",
        source="cisa_kev",
        source_id="CVE-2026-1234",
        source_url="https://example.com",
        title="Test Vulnerability",
        content_raw="A test vuln.",
        language="en",
        published_at="2026-05-20T00:00:00Z",
        severity=Severity(label="high"),
        identifiers=Identifiers(),
        tags=Tags(),
        action=Action(),
    )


def test_advisory_record_defaults():
    record = _make_minimal_record()
    assert record.summary is None
    assert record.updated_at is None
    assert record.due_date is None
    assert record.identifiers.kev_listed is False
    assert record.identifiers.cve_ids == []
    assert record.tags.cwe == []


def test_severity_defaults():
    s = Severity(label="unknown")
    assert s.cvss_score is None
    assert s.cvss_vector is None
    assert s.epss_score is None


def test_crawl_result_serializable():
    record = _make_minimal_record()
    result = CrawlResult(
        crawled_at="2026-05-23T10:00:00Z",
        query_from="2026-05-20",
        query_to="2026-05-20",
        source="cisa_kev",
        count=1,
        records=[record],
    )
    data = result.model_dump()
    assert data["count"] == 1
    assert data["records"][0]["source"] == "cisa_kev"
