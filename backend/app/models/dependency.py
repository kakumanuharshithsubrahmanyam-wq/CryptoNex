"""Dependency inventory recorded by a scan."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.scan import utcnow


class Dependency(Base):
    __tablename__ = "dependencies"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", name="uq_dependencies_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version_constraint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    dependency_type: Mapped[str] = mapped_column(String(16), nullable=False)
    direct_or_transitive: Mapped[str] = mapped_column(String(16), nullable=False)
    crypto_relevance: Mapped[str] = mapped_column(String(32), nullable=False)
    library: Mapped[str | None] = mapped_column(String(128), nullable=True)
    manifest_file: Mapped[str] = mapped_column(String(512), nullable=False)
    source_line: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[str] = mapped_column(String(512), nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class DependencyRelationship(Base):
    """An evidence-backed edge that ends at a dependency.

    finding_uses_dependency and dependency_only start at a finding.
    transitive_dependency starts at the dependency that requires the target.
    """

    __tablename__ = "dependency_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    dependency_id: Mapped[int] = mapped_column(ForeignKey("dependencies.id"), nullable=False, index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("crypto_findings.id"), nullable=True, index=True)
    source_dependency_id: Mapped[int | None] = mapped_column(
        ForeignKey("dependencies.id"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
