"""크롤러 진입점 — 설정 로딩부터 JSON 저장까지의 흐름을 오케스트레이션한다."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime

from .client import CisaKevClient
from .config import load_config
from .daterange import compute_added_range, filter_by_date
from .normalizer import normalize_batch
from .nvd_client import NvdClient
from .storage import build_result, save_result


def run_crawl(days: int = 7, output_dir: str | None = None) -> str:
    config = load_config()
    if output_dir:
        config.output_dir = output_dir

    now = datetime.now(tz=UTC)
    start, end = compute_added_range(now, days)

    client = CisaKevClient(timeout=config.request_timeout)
    data = client.fetch()
    entries = filter_by_date(data.get("vulnerabilities", []), start, end)

    nvd = NvdClient(api_key=config.nvd_api_key, timeout=config.request_timeout)
    records = normalize_batch(entries, nvd)

    result = build_result(records, now)
    path = save_result(result, config.output_dir)
    return str(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="CISA KEV 크롤러")
    parser.add_argument("--days", type=int, default=7, metavar="N", help="수집 기간(일수, 기본: 7)")
    parser.add_argument("--output-dir", default=None, metavar="PATH", help="결과 저장 디렉토리")
    args = parser.parse_args()
    path = run_crawl(days=args.days, output_dir=args.output_dir)
    print(f"저장 완료: {path}")
