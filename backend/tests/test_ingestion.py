"""Ingestion service and API, with the git process mocked."""

import io
import os
import subprocess
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.exceptions import AppError
from app.main import create_app
from app.services.ingestion.github import clone_repository
from app.services.ingestion.validation import validate_github_repository_url


def _client(tmp_path: Path, **overrides: int) -> TestClient:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        cors_origins="http://localhost:5173",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        **overrides,
    )
    application = create_app(settings)
    return TestClient(application)


def _write_sample(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "src").mkdir()
    (destination / "src" / "main.py").write_text("value = 1\n", encoding="utf-8")
    (destination / "README.md").write_text("hello\n", encoding="utf-8")


def test_git_clone_uses_argument_list_and_drops_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "super-secret")
    captured: dict = {}

    class _Process:
        pid = 424242
        returncode = 0

        def communicate(self, timeout=None):
            destination = Path(captured["args"][-1])
            _write_sample(destination)
            return b"", b""

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _Process()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        git_executable="git",
    )
    repository = validate_github_repository_url("https://github.com/octocat/Hello-World/")
    destination = tmp_path / "workspaces" / "projects" / "1" / "source"
    clone_repository(repository, destination, settings)

    assert captured["kwargs"]["shell"] is False
    assert isinstance(captured["args"], list)
    assert captured["args"][0] == "git"
    assert "https://github.com/octocat/Hello-World.git" in captured["args"]
    assert "--no-recurse-submodules" in captured["args"]
    assert "AWS_SECRET_ACCESS_KEY" not in captured["kwargs"]["env"]
    assert "super-secret" not in repr(captured["kwargs"]["env"])
    joined = " ".join(captured["args"])
    assert "shell" not in captured["kwargs"] or captured["kwargs"]["shell"] is False
    assert "Hello-World/" not in joined


def test_clone_timeout_is_sanitized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Process:
        pid = 424242

        def communicate(self, timeout=None):
            if not hasattr(self, "raised"):
                self.raised = True
                raise subprocess.TimeoutExpired(cmd="git", timeout=1)
            return b"", b""

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: _Process())
    monkeypatch.setattr(os, "killpg", lambda *args, **kwargs: None)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        clone_timeout_seconds=1,
    )
    repository = validate_github_repository_url("https://github.com/octocat/Hello-World")
    with pytest.raises(AppError) as captured:
        clone_repository(repository, tmp_path / "source", settings)
    assert captured.value.code == "REPOSITORY_CLONE_TIMEOUT"
    assert "super-secret" not in captured.value.message
    assert str(tmp_path) not in captured.value.message


def test_successful_github_ingestion_returns_manifest_without_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(args, *, timeout, env, cwd):
        _write_sample(Path(args[-1]))
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    with _client(tmp_path) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Hello", "repository_url": "https://github.com/octocat/Hello-World/"},
        )
        assert created.status_code == 200
        body = created.json()
        assert body["source_type"] == "github"
        assert body["status"] == "created"
        assert body["repository_url"] == "https://github.com/octocat/Hello-World"
        assert "workspace" not in created.text
        assert str(tmp_path) not in created.text

        ingested = client.post(f"/api/v1/projects/{body['id']}/ingest")
        assert ingested.status_code == 200
        ready = ingested.json()
        assert ready["status"] == "ready"
        assert ready["manifest"]["file_count"] == 2
        assert ready["manifest"]["languages"] == {"Python": 1}
        assert {item["relative_path"] for item in ready["manifest"]["files"]} == {
            "README.md",
            "src/main.py",
        }
        assert str(tmp_path) not in ingested.text
        assert "workspace_path" not in ingested.text


def test_clone_failure_cleans_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        Path(args[-1]).mkdir(parents=True)
        return 1

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    with _client(tmp_path) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Hello", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        failed = client.post(f"/api/v1/projects/{project_id}/ingest")
        assert failed.status_code == 502
        assert failed.json()["error"]["code"] == "REPOSITORY_CLONE_FAILED"
        assert str(tmp_path) not in failed.text
        assert "git clone" not in failed.text
        stored = client.get(f"/api/v1/projects/{project_id}")
        assert stored.json()["status"] == "failed"
        assert not (tmp_path / "workspaces" / "projects" / str(project_id)).exists()


def test_clone_timeout_cleans_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        raise subprocess.TimeoutExpired(cmd="git", timeout=timeout)

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    with _client(tmp_path) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Hello", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        failed = client.post(f"/api/v1/projects/{project_id}/ingest")
        assert failed.status_code == 504
        assert failed.json()["error"]["code"] == "REPOSITORY_CLONE_TIMEOUT"
        assert not (tmp_path / "workspaces" / "projects" / str(project_id)).exists()


def test_repository_limit_cleans_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        destination.mkdir(parents=True)
        (destination / "a.txt").write_text("a", encoding="utf-8")
        (destination / "b.txt").write_text("b", encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    with _client(tmp_path, max_file_count=1) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Hello", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        failed = client.post(f"/api/v1/projects/{project_id}/ingest")
        assert failed.status_code == 413
        assert failed.json()["error"]["code"] == "TOO_MANY_FILES"
        assert not (tmp_path / "workspaces" / "projects" / str(project_id)).exists()


def test_missing_project_uses_error_envelope(client: TestClient) -> None:
    response = client.get("/api/v1/projects/999")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "PROJECT_NOT_FOUND"


def test_zip_upload_and_ingest(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("pkg/app.py", "print('zip')\n")
        archive.writestr("README.md", "docs\n")
    with _client(tmp_path) as client:
        created = client.post(
            "/api/v1/projects/uploads",
            data={"name": "Uploaded"},
            files={"file": ("repo.zip", buffer.getvalue(), "application/zip")},
        )
        assert created.status_code == 200
        body = created.json()
        assert body["source_type"] == "zip"
        assert body["repository_url"] is None
        assert str(tmp_path) not in created.text
        ingested = client.post(f"/api/v1/projects/{body['id']}/ingest")
        assert ingested.status_code == 200
        ready = ingested.json()
        assert ready["status"] == "ready"
        assert ready["manifest"]["languages"] == {"Python": 1}
        assert str(tmp_path) not in ingested.text


def test_invalid_repository_url_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/projects",
        json={"name": "Bad", "repository_url": "https://example.com/octocat/Hello-World"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "UNSUPPORTED_REPOSITORY_HOST"
