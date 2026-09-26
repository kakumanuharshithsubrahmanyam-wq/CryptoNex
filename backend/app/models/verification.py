"""Persisted isolated verification results. The original scan is not updated."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MigrationVerification(Base):
    __tablename__ = "migration_verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    original_scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    verification_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("crypto_findings.id"), nullable=False, index=True)
    patch_id: Mapped[int] = mapped_column(ForeignKey("migration_patch_proposals.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    target_status: Mapped[str] = mapped_column(String(32), nullable=False)
    original_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    replacement_algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    original_finding_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    replacement_finding_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    detail_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
