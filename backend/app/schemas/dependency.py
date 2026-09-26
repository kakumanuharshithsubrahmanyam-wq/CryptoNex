"""Dependency inventory API models."""

from datetime import datetime

from pydantic import BaseModel


class DependencyEvidence(BaseModel):
    manifest_file: str
    source_line: int
    raw_declaration: str


class DependencyResponse(BaseModel):
    id: int
    project_id: int
    scan_id: int
    name: str
    ecosystem: str
    version: str | None
    version_constraint: str | None
    dependency_type: str
    direct_or_transitive: str
    crypto_relevance: str
    library: str | None
    manifest_file: str
    source_line: int
    evidence: DependencyEvidence
    metadata: dict[str, str]
    finding_ids: list[int]
    required_by_dependency_ids: list[int]
    created_at: datetime


class DependencyListResponse(BaseModel):
    scan_id: int
    total: int
    limit: int
    offset: int
    items: list[DependencyResponse]
