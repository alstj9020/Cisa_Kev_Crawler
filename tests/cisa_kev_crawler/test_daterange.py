from datetime import UTC, datetime

from cisa_kev_crawler.daterange import compute_added_range, filter_by_date


def test_compute_added_range_end_is_midnight():
    now = datetime(2026, 5, 23, 15, 30, 0, tzinfo=UTC)
    start, end = compute_added_range(now, days=7)
    assert end == datetime(2026, 5, 23, 0, 0, 0, tzinfo=UTC)


def test_compute_added_range_start_is_n_days_before_end():
    now = datetime(2026, 5, 23, 15, 30, 0, tzinfo=UTC)
    start, end = compute_added_range(now, days=7)
    assert start == datetime(2026, 5, 16, 0, 0, 0, tzinfo=UTC)


def test_filter_includes_entry_on_start_date():
    entries = [{"dateAdded": "2026-05-16", "cveID": "CVE-A"}]
    start = datetime(2026, 5, 16, tzinfo=UTC)
    end = datetime(2026, 5, 23, tzinfo=UTC)
    result = filter_by_date(entries, start, end)
    assert len(result) == 1


def test_filter_excludes_entry_before_start():
    entries = [{"dateAdded": "2026-05-15", "cveID": "CVE-A"}]
    start = datetime(2026, 5, 16, tzinfo=UTC)
    end = datetime(2026, 5, 23, tzinfo=UTC)
    result = filter_by_date(entries, start, end)
    assert result == []


def test_filter_excludes_entry_on_end_date():
    entries = [{"dateAdded": "2026-05-23", "cveID": "CVE-A"}]
    start = datetime(2026, 5, 16, tzinfo=UTC)
    end = datetime(2026, 5, 23, tzinfo=UTC)
    result = filter_by_date(entries, start, end)
    assert result == []


def test_filter_returns_only_in_range():
    entries = [
        {"dateAdded": "2026-05-15", "cveID": "CVE-before"},
        {"dateAdded": "2026-05-20", "cveID": "CVE-in"},
        {"dateAdded": "2026-05-23", "cveID": "CVE-after"},
    ]
    start = datetime(2026, 5, 16, tzinfo=UTC)
    end = datetime(2026, 5, 23, tzinfo=UTC)
    result = filter_by_date(entries, start, end)
    assert len(result) == 1
    assert result[0]["cveID"] == "CVE-in"


def test_filter_skips_entry_without_date_added():
    entries = [{"cveID": "CVE-A"}, {"dateAdded": "2026-05-20", "cveID": "CVE-B"}]
    start = datetime(2026, 5, 16, tzinfo=UTC)
    end = datetime(2026, 5, 23, tzinfo=UTC)
    result = filter_by_date(entries, start, end)
    assert len(result) == 1
    assert result[0]["cveID"] == "CVE-B"
