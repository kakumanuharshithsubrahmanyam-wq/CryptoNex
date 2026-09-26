"""Project and repository manifest API models."""

from enum import Enum

from pydantic import BaseModel, Field, field_validator

from app.models.project import ProjectStatus, SourceType


class FileCategory(str, Enum):
    SOURCE = "source"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    CERTIFICATE = "certificate"
    DOCUMENTATION = "documentation"
    BINARY = "binary"
    UNKNOWN = "unknown"


class ProjectCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    repository_url: str = Field(min_length=1, max_length=512)

    @field_validator("name")
    @classmethod
    def name_must_not_be_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("name must not be blank")
        return stripped


class ManifestFileRecord(BaseModel):
    relative_path: str
    filename: str
    extension: str
    detected_language: str | None
    file_size: int
    line_count: int | None
    sha256: str
    category: FileCategory


class RepositoryManifest(BaseModel):
    file_count: int
    total_size: int
    languages: dict[str, int]
    files: list[ManifestFileRecord]


class ProjectResponse(BaseModel):
    id: int
    name: str
    repository_url: str | None
    source_type: SourceType
    status: ProjectStatus
    manifest: RepositoryManifest | None
