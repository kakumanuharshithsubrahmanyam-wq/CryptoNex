"""Project persistence. Workspace paths stay internal and are not API fields."""

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import CheckConstraint, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SourceType(str, Enum):
    GITHUB = "github"
    ZIP = "zip"


class ProjectStatus(str, Enum):
    CREATED = "created"
    INGESTING = "ingesting"
    READY = "ready"
    FAILED = "failed"


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("length(trim(name)) > 0", name="ck_projects_name_not_blank"),
        CheckConstraint("source_type IN ('github', 'zip')", name="ck_projects_source_type"),
        CheckConstraint(
            "status IN ('created', 'ingesting', 'ready', 'failed')",
            name="ck_projects_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    repository_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default=SourceType.GITHUB.value
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ProjectStatus.CREATED.value
    )
    workspace_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    manifest_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )
