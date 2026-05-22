from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from .schema import (
    Action,
    AdvisoryRecord,
    AffectedItem,
    Audience,
    Cwe,
    Identifiers,
    Reference,
    Severity,
    Tags,
    make_id,
)

if TYPE_CHECKING:
    from .nvd_client import CvssResult, NvdClient

SOURCE = "cisa_kev"
SOURCE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
_URL_RE = re.compile(r"https?://\S+")


def _make_id(cve_id: str) -> str:
    return make_id(SOURCE, cve_id)


def _to_iso(date_str: str) -> str:
    return f"{date_str}T00:00:00Z"


def _parse_references(notes: str) -> list[Reference]:
    return [
        Reference(label="CISA Notes", url=url.rstrip(".,;:)\"'"))
        for url in _URL_RE.findall(notes)
    ]


def _build_affected(entry: dict, cpe_products: list[tuple[str, str]]) -> list[AffectedItem]:
    if entry.get("product", "").strip() == "Multiple Products" and cpe_products:
        return [
            AffectedItem(
                vendor=vendor or None,
                product=product,
                ecosystem=None,
                versions_affected="",
                versions_fixed=None,
            )
            for vendor, product in cpe_products
        ]
    return [
        AffectedItem(
            vendor=entry.get("vendorProject") or None,
            product=entry.get("product", ""),
            ecosystem=None,
            versions_affected="",
            versions_fixed=None,
        )
    ]


def normalize_entry(entry: dict, cvss: CvssResult) -> AdvisoryRecord:
    cve_id: str = entry["cveID"]
    return AdvisoryRecord(
        id=_make_id(cve_id),
        source=SOURCE,
        source_id=cve_id,
        source_url=SOURCE_URL,
        title=entry.get("vulnerabilityName", ""),
        summary=None,
        content_raw=entry.get("shortDescription", ""),
        language="en",
        published_at=_to_iso(entry["dateAdded"]),
        updated_at=None,
        due_date=_to_iso(entry["dueDate"]) if entry.get("dueDate") else None,
        severity=Severity(
            label=cvss.label,
            cvss_score=cvss.score,
            cvss_vector=cvss.vector,
            epss_score=None,
        ),
        affected=_build_affected(entry, cvss.cpe_products),
        identifiers=Identifiers(
            cve_ids=[cve_id],
            ghsa_id=None,
            kev_listed=True,
            ransomware_known=entry.get("knownRansomwareCampaignUse", "") == "Known",
        ),
        tags=Tags(
            categories=["vulnerability"],
            cwe=[Cwe(id=c, name="") for c in (entry.get("cwes") or [])],
            attack_vectors=[],
            tech_stack=[],
            topics=[],
        ),
        action=Action(
            required_action=entry.get("requiredAction") or None,
            remediation=None,
            references=_parse_references(entry.get("notes", "")),
        ),
        audience=Audience(),
    )


def normalize_batch(entries: list[dict], nvd_client: NvdClient) -> list[AdvisoryRecord]:
    seen: set[str] = set()
    unique: list[dict] = []
    for entry in entries:
        cve_id = entry.get("cveID", "")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        unique.append(entry)

    workers = 50 if getattr(nvd_client, "_api_key", None) else 5
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(nvd_client.lookup, e["cveID"]) for e in unique]
        return [normalize_entry(e, f.result()) for e, f in zip(unique, futures)]
