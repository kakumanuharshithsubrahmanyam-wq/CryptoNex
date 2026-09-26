"""Persisted migration patch proposals. Generating a proposal does not apply it."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MigrationPatchProposal(Base):
    __tablename__ = "migration_patch_proposals"
    __table_args__ = (UniqueConstraint("scan_id", "finding_id", name="uq_patch_scan_finding"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("crypto_findings.id"), nullable=False, index=True)
    source_file: Mapped[str] = mapped_column(String(512), nullable=False)
    migration_id: Mapped[str] = mapped_column(String(128), nullable=False)
    current_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    proposed_replacement: Mapped[str | None] = mapped_column(String(64), nullable=True)
    migration_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    patch_status: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    affected_files_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    affected_dependencies_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    warnings_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    validation_checklist_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    unified_diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_files_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    source_migrated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
