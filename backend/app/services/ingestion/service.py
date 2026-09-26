"""Ingest a stored project into an isolated workspace and build its manifest."""

import logging

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AppError
from app.models.project import Project, ProjectStatus, SourceType
from app.schemas.project import ProjectResponse, RepositoryManifest
from app.services.ingestion import github
from app.services.ingestion.manifest import build_manifest
from app.services.ingestion.validation import validate_github_repository_url
from app.services.ingestion.workspace import (
    archive_path,
    project_workspace,
    remove_workspace,
    source_directory,
)
from app.services.ingestion.zip import extract_zip

logger = logging.getLogger(__name__)


def project_response(project: Project) -> ProjectResponse:
    manifest = None
    if project.manifest_json:
        manifest = RepositoryManifest.model_validate_json(project.manifest_json)
    return ProjectResponse(
        id=project.id,
        name=project.name,
        repository_url=project.repository_url,
        source_type=SourceType(project.source_type),
        status=ProjectStatus(project.status),
        manifest=manifest,
    )


def ingest_project(session: Session, project: Project, settings: Settings) -> ProjectResponse:
    if project.status == ProjectStatus.READY.value and project.manifest_json:
        return project_response(project)
    if project.status == ProjectStatus.INGESTING.value:
        raise AppError(
            "INGESTION_FAILED",
            "Repository ingestion is already in progress.",
            status_code=409,
        )

    project_id = project.id
    project.status = ProjectStatus.INGESTING.value
    session.commit()

    workspace = project_workspace(settings, project_id)
    source = source_directory(workspace)
    try:
        if project.source_type == SourceType.GITHUB.value:
            repository = validate_github_repository_url(project.repository_url or "")
            github.clone_repository(repository, source, settings)
        elif project.source_type == SourceType.ZIP.value:
            archive = archive_path(workspace)
            if not archive.is_file():
                raise AppError("INVALID_ZIP", "The uploaded ZIP archive is missing.", status_code=400)
            extract_zip(archive, source, settings)
            archive.unlink(missing_ok=True)
        else:
            raise AppError("INGESTION_FAILED", "The project source is not supported.", status_code=400)

        manifest = build_manifest(source, settings)
        project.manifest_json = manifest.model_dump_json()
        project.workspace_path = str(workspace)
        project.status = ProjectStatus.READY.value
        session.commit()
        logger.info("Ingestion ready project_id=%s source_type=%s", project_id, project.source_type)
        return project_response(project)
    except AppError as exc:
        _mark_failed(session, project_id, workspace)
        raise exc
    except Exception as exc:
        _mark_failed(session, project_id, workspace)
        logger.error("Ingestion failed project_id=%s error_type=%s", project_id, type(exc).__name__)
        raise AppError(
            "INGESTION_FAILED",
            "Repository ingestion failed.",
            status_code=500,
        ) from exc


def _mark_failed(session: Session, project_id: int, workspace) -> None:
    session.rollback()
    failed = session.get(Project, project_id)
    if failed is not None:
        failed.status = ProjectStatus.FAILED.value
        failed.workspace_path = None
        failed.manifest_json = None
        session.commit()
    remove_workspace(workspace)
    logger.info("Ingestion failed project_id=%s", project_id)
