"""Database initialization and the Project model."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.models.project import Project


def test_database_initialization_creates_project_table(client: TestClient) -> None:
    engine = client.app.state.engine
    table_names = inspect(engine).get_table_names()
    assert "projects" in table_names

    columns = {column["name"] for column in inspect(engine).get_columns("projects")}
    assert columns == {
        "id",
        "name",
        "repository_url",
        "source_type",
        "status",
        "workspace_path",
        "manifest_json",
        "created_at",
        "updated_at",
    }

    session = client.app.state.session_factory()
    try:
        project = Project(name="Foundation")
        session.add(project)
        session.commit()
        session.refresh(project)
        assert project.id is not None
        assert project.created_at is not None
        assert project.updated_at is not None
        stored = session.get(Project, project.id)
        assert stored is not None
        assert stored.name == "Foundation"
    finally:
        session.close()


def test_project_name_cannot_be_blank(client: TestClient) -> None:
    session = client.app.state.session_factory()
    try:
        session.add(Project(name="   "))
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()
