"""Scan API models."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.scan import ScanStatus


class ScanSummary(BaseModel):
    files_scanned: int
    files_skipped: int
    skip_reasons: dict[str, int]
    findings: int
    high_confidence: int
    medium_confidence: int
    low_confidence: int
    algorithms: dict[str, int] = Field(default_factory=dict)
    confirmed_findings: int = 0
    probable_findings: int = 0
    weak_signal_findings: int = 0
    dependencies: int = 0
    crypto_dependencies: int = 0
    malformed_manifests: int = 0


class ScanResponse(BaseModel):
    scan_id: int
    project_id: int
    status: ScanStatus
    summary: ScanSummary


class ScanDetailResponse(BaseModel):
    scan_id: int
    project_id: int
    status: ScanStatus
    created_at: datetime
    summary: ScanSummary | None


class FindingDependencyLink(BaseModel):
    dependency_id: int
    relationship_type: str
    name: str
    ecosystem: str
    version: str | None
    version_constraint: str | None
    manifest_file: str
    source_line: int


class FindingResponse(BaseModel):
    id: int
    project_id: int
    scan_id: int
    file_path: str
    line_start: int
    line_end: int
    language: str | None
    algorithm: str | None
    algorithm_family: str | None
    library: str | None
    library_version: str | None
    usage: str
    key_size: int | None
    curve: str | None
    mode: str | None
    evidence: str
    detection_method: str
    confidence: str
    metadata: dict[str, str]
    evidence_type: str | None
    confidence_reasons: list[str]
    finding_status: str | None
    cryptographic_role: str | None
    parameter_completeness: str | None
    security_concern: str | None
    quantum_relevance: str | None
    dependencies: list[FindingDependencyLink]
    created_at: datetime


class FindingListResponse(BaseModel):
    scan_id: int
    total: int
    limit: int
    offset: int
    items: list[FindingResponse]
