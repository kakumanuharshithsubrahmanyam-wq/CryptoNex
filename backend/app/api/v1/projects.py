"""Project creation and repository ingestion routes."""

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.project import ProjectCreateRequest, ProjectResponse
from app.services.ingestion.service import ingest_project, project_response
from app.services.projects import create_github_project, create_zip_project, get_project

router = APIRouter(prefix="/projects")


@router.post("", response_model=ProjectResponse)
def create_project(
    body: ProjectCreateRequest,
    request: Request,
    session: Session = Depends(get_db),
) -> ProjectResponse:
    return create_github_project(session, request.app.state.settings, body)


@router.post("/uploads", response_model=ProjectResponse)
def create_project_from_zip(
    request: Request,
    name: str = Form(),
    file: UploadFile = File(),
    session: Session = Depends(get_db),
) -> ProjectResponse:
    return create_zip_project(session, request.app.state.settings, name, file)


@router.get("/{project_id}", response_model=ProjectResponse)
def read_project(project_id: int, session: Session = Depends(get_db)) -> ProjectResponse:
    return project_response(get_project(session, project_id))


@router.post("/{project_id}/ingest", response_model=ProjectResponse)
def ingest(
    project_id: int,
    request: Request,
    session: Session = Depends(get_db),
) -> ProjectResponse:
    project = get_project(session, project_id)
    return ingest_project(session, project, request.app.state.settings)
