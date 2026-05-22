import json
from datetime import UTC, datetime

from cisa_kev_crawler.schema import (
    Action,
    AdvisoryRecord,
    Identifiers,
    Severity,
    Tags,
)
from cisa_kev_crawler.storage import build_result, save_result


def _make_record() -> AdvisoryRecord:
    return AdvisoryRecord(
        id="abc123",
        source="cisa_kev",
        source_id="CVE-2026-1234",
        source_url="https://example.com",
        title="Test Vulnerability",
        content_raw="Test content.",
        language="en",
        published_at="2026-05-20T00:00:00Z",
        severity=Severity(label="high", cvss_score=7.5),
        identifiers=Identifiers(cve_ids=["CVE-2026-1234"], kev_listed=True),
        tags=Tags(categories=["vulnerability"]),
        action=Action(),
    )


def test_build_result_count_and_query_range():
    records = [_make_record()]
    now = datetime(2026, 5, 23, 10, 0, 0, tzinfo=UTC)
    result = build_result(records, crawled_at=now)
    assert result.count == 1
    assert result.query_from == "2026-05-20"
    assert result.query_to == "2026-05-20"
    assert result.source == "cisa_kev"
    assert result.crawled_at == "2026-05-23T10:00:00Z"


def test_build_result_query_range_empty_records():
    now = datetime(2026, 5, 23, 10, 0, 0, tzinfo=UTC)
    result = build_result([], crawled_at=now)
    assert result.query_from is None
    assert result.query_to is None


def test_save_result_creates_timestamped_file(tmp_path):
    now = datetime(2026, 5, 23, 10, 0, 0, tzinfo=UTC)
    result = build_result([_make_record()], crawled_at=now)
    saved = save_result(result, str(tmp_path))
    assert saved.exists()
    assert saved.name.startswith("cisa_kev_")
    assert saved.suffix == ".json"


def test_save_result_creates_latest_json(tmp_path):
    now = datetime(2026, 5, 23, 10, 0, 0, tzinfo=UTC)
    result = build_result([_make_record()], crawled_at=now)
    save_result(result, str(tmp_path))
    latest = tmp_path / "latest.json"
    assert latest.exists()


def test_save_result_json_content_is_valid(tmp_path):
    now = datetime(2026, 5, 23, 10, 0, 0, tzinfo=UTC)
    result = build_result([_make_record()], crawled_at=now)
    save_result(result, str(tmp_path))
    data = json.loads((tmp_path / "latest.json").read_text(encoding="utf-8"))
    assert data["count"] == 1
    assert data["source"] == "cisa_kev"
    assert data["query_from"] == "2026-05-20"
    assert data["query_to"] == "2026-05-20"
    assert data["records"][0]["source_id"] == "CVE-2026-1234"
    assert data["records"][0]["severity"]["cvss_score"] == 7.5


def test_save_result_creates_output_dir_if_missing(tmp_path):
    new_dir = tmp_path / "nested" / "output"
    now = datetime(2026, 5, 23, 10, 0, 0, tzinfo=UTC)
    result = build_result([], crawled_at=now)
    save_result(result, str(new_dir))
    assert new_dir.exists()
