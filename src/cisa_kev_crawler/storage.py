from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .schema import AdvisoryRecord, CrawlResult


def build_result(records: list[AdvisoryRecord], crawled_at: datetime) -> CrawlResult:
    dates = [r.published_at[:10] for r in records] if records else []
    return CrawlResult(
        crawled_at=crawled_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        query_from=min(dates) if dates else None,
        query_to=max(dates) if dates else None,
        source="cisa_kev",
        count=len(records),
        records=records,
    )


def save_result(result: CrawlResult, output_dir: str) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = result.crawled_at.replace("-", "").replace(":", "").replace("T", "_")[:15]
    fname = f"cisa_kev_{ts}.json"
    data = result.model_dump()
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    for path in [out / fname, out / "latest.json"]:
        path.write_text(payload, encoding="utf-8")
    return out / fname
