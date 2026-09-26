"""Security artifacts recorded by a scan."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.scan import utcnow


class SecurityArtifact(Base):
    __tablename__ = "security_artifacts"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", name="uq_artifacts_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    artifact_type: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    format: Mapped[str | None] = mapped_column(String(32), nullable=True)
    algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    curve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(128), nullable=True)
    validity_start: Mapped[str | None] = mapped_column(String(32), nullable=True)
    validity_end: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evidence: Mapped[str] = mapped_column(String(512), nullable=False)
    detection_method: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
