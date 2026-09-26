"""Persisted CryptoNex CBOM documents."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.scan import utcnow


class Cbom(Base):
    __tablename__ = "cboms"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_cboms_scan"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class CbomComponent(Base):
    __tablename__ = "cbom_components"
    __table_args__ = (UniqueConstraint("cbom_id", "component_key", name="uq_cbom_component_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cbom_id: Mapped[int] = mapped_column(ForeignKey("cboms.id"), nullable=False, index=True)
    component_key: Mapped[str] = mapped_column(String(255), nullable=False)
    component_type: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)


class CbomRelationship(Base):
    __tablename__ = "cbom_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cbom_id: Mapped[int] = mapped_column(ForeignKey("cboms.id"), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_key: Mapped[str] = mapped_column(String(255), nullable=False)
    target_key: Mapped[str] = mapped_column(String(255), nullable=False)
