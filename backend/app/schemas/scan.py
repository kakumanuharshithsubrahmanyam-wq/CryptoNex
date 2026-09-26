"""Scan API models."""

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


class ScanResponse(BaseModel):
    scan_id: int
    project_id: int
    status: ScanStatus
    summary: ScanSummary
