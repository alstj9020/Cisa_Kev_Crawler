from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, Field, model_validator

SourceType = Literal["kisa_advisory", "kisa_vulnerability", "github_advisory", "cisa_kev", "reddit"]
SeverityLabel = Literal["critical", "high", "medium", "low", "info", "unknown"]
Language = Literal["ko", "en", "mixed"]
AudienceRole = Literal["general", "developer", "security"]


def make_id(source: str, source_id: str) -> str:
    return hashlib.sha256(f"{source}:{source_id}".encode()).hexdigest()[:32]


class Severity(BaseModel):
    label: SeverityLabel
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    epss_score: float | None = None


class AffectedItem(BaseModel):
    vendor: str | None = None
    product: str
    ecosystem: str | None = None
    versions_affected: str = ""
    versions_fixed: str | None = None


class Identifiers(BaseModel):
    cve_ids: list[str] = Field(default_factory=list)
    ghsa_id: str | None = None
    kev_listed: bool = False
    ransomware_known: bool = False


class Cwe(BaseModel):
    id: str
    name: str = ""


class Tags(BaseModel):
    categories: list[str] = Field(default_factory=list)
    cwe: list[Cwe] = Field(default_factory=list)
    attack_vectors: list[str] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)
    topics: list[str] = Field(default_factory=list)


class Reference(BaseModel):
    label: str
    url: str


class Action(BaseModel):
    required_action: str | None = None
    remediation: str | None = None
    references: list[Reference] = Field(default_factory=list)


class AudienceScores(BaseModel):
    general: float = Field(0.0, ge=0.0, le=100.0)
    developer: float = Field(0.0, ge=0.0, le=100.0)
    security: float = Field(0.0, ge=0.0, le=100.0)


class Audience(BaseModel):
    scores: AudienceScores = Field(default_factory=AudienceScores)
    primary: AudienceRole = "security"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    recommended_for: list[AudienceRole] = Field(default_factory=list)


class AdvisoryRecord(BaseModel):
    id: str
    source: SourceType
    source_id: str
    source_url: str
    title: str
    summary: str | None = None
    content_raw: str
    language: Language
    published_at: str
    updated_at: str | None = None
    due_date: str | None = None
    severity: Severity
    affected: list[AffectedItem] = Field(default_factory=list)
    identifiers: Identifiers
    tags: Tags
    action: Action
    audience: Audience = Field(default_factory=Audience)


class CrawlResult(BaseModel):
    crawled_at: str
    query_from: str | None
    query_to: str | None
    source: SourceType
    count: int
    records: list[AdvisoryRecord]

    @model_validator(mode="after")
    def _check_count(self) -> CrawlResult:
        if self.count != len(self.records):
            raise ValueError(f"count={self.count} but len(records)={len(self.records)}")
        return self
