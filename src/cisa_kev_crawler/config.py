from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass
class CrawlerConfig:
    output_dir: str
    nvd_api_key: str | None
    request_timeout: int


def _parse_timeout(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"REQUEST_TIMEOUT must be an integer, got: {value!r}") from None


def load_config() -> CrawlerConfig:
    load_dotenv()
    return CrawlerConfig(
        output_dir=os.getenv("OUTPUT_DIR", "output"),
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
        request_timeout=_parse_timeout(os.getenv("REQUEST_TIMEOUT", "30")),
    )
