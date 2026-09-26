"""Security artifact API models."""

from datetime import datetime

from pydantic import BaseModel


class ArtifactResponse(BaseModel):
    id: int
    project_id: int
    scan_id: int
    artifact_type: str
    file_path: str
    line_start: int
    line_end: int
    protocol: str | None
    format: str | None
    algorithm: str | None
    key_size: int | None
    curve: str | None
    subject: str | None
    issuer: str | None
    serial_number: str | None
    validity_start: str | None
    validity_end: str | None
    cipher_suite: str | None
    evidence: str
    detection_method: str
    confidence: str
    metadata: dict[str, str]
    created_at: datetime


class ArtifactListResponse(BaseModel):
    scan_id: int
    total: int
    limit: int
    offset: int
    items: list[ArtifactResponse]
