from __future__ import annotations

from datetime import UTC, datetime, timedelta


def compute_added_range(now: datetime, days: int = 7) -> tuple[datetime, datetime]:
    end = now.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=UTC)
    start = end - timedelta(days=days)
    return start, end


def filter_by_date(entries: list[dict], start: datetime, end: datetime) -> list[dict]:
    result = []
    for entry in entries:
        date_str = entry.get("dateAdded")
        if not date_str:
            continue
        added = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=UTC)
        if start <= added < end:
            result.append(entry)
    return result
