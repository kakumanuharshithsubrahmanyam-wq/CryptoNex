"""Create and load projects. Persistence stays outside route handlers."""

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AppError
from app.models.project import Project, SourceType
from app.schemas.project import ProjectCreateRequest, ProjectResponse
from app.services.ingestion.service import project_response
from app.services.ingestion.validation import validate_github_repository_url
from app.services.ingestion.workspace import archive_path, project_workspace, remove_workspace
from app.services.ingestion.zip import save_zip_upload


def create_github_project(
    session: Session,
    settings: Settings,
    body: ProjectCreateRequest,
) -> ProjectResponse:
    repository = validate_github_repository_url(body.repository_url)
    project = Project(
        name=body.name,
        repository_url=repository.display_url,
        source_type=SourceType.GITHUB.value,
    )
    session.add(project)
    session.commit()
    session.refresh(project)
    return project_response(project)


def create_zip_project(session: Session, settings: Settings, name: str, upload) -> ProjectResponse:
    cleaned = name.strip()
    if not cleaned or len(cleaned) > 255:
        raise AppError("INVALID_ZIP", "Project name must be between 1 and 255 characters.", status_code=400)
    project = Project(name=cleaned, repository_url=None, source_type=SourceType.ZIP.value)
    session.add(project)
    session.commit()
    session.refresh(project)
    workspace = project_workspace(settings, project.id)
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        save_zip_upload(upload, archive_path(workspace), settings)
    except AppError:
        remove_workspace(workspace)
        session.delete(project)
        session.commit()
        raise
    project.workspace_path = str(workspace)
    session.commit()
    return project_response(project)


def get_project(session: Session, project_id: int) -> Project:
    project = session.get(Project, project_id)
    if project is None:
        raise AppError("PROJECT_NOT_FOUND", "Project not found.", status_code=404)
    return project
