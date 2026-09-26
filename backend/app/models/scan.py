"""Persisted deterministic crypto scans and findings."""

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=ScanStatus.RUNNING.value)
    summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class CryptoFinding(Base):
    __tablename__ = "crypto_findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", name="uq_findings_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    language: Mapped[str | None] = mapped_column(String(32), nullable=True)
    algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    algorithm_family: Mapped[str | None] = mapped_column(String(32), nullable=True)
    library: Mapped[str | None] = mapped_column(String(128), nullable=True)
    library_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    usage: Mapped[str] = mapped_column(String(32), nullable=False)
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    curve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence: Mapped[str] = mapped_column(String(512), nullable=False)
    detection_method: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    # Deterministic context. Null on findings stored before these fields existed.
    evidence_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence_reasons_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cryptographic_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    parameter_completeness: Mapped[str | None] = mapped_column(String(16), nullable=True)
    security_concern: Mapped[str | None] = mapped_column(String(32), nullable=True)
    quantum_relevance: Mapped[str | None] = mapped_column(String(40), nullable=True)
