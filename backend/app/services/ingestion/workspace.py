"""Server-controlled workspace paths.

Callers must not pass user-controlled directory names into these helpers.
"""

import shutil
from pathlib import Path

from app.core.config import Settings
from app.core.exceptions import AppError


def project_workspace(settings: Settings, project_id: int) -> Path:
    if project_id < 1:
        raise AppError("INGESTION_FAILED", "Project workspace could not be created.", status_code=500)
    root = Path(settings.workspace_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    workspace = root.joinpath("projects", str(project_id))
    resolved = workspace.resolve()
    if not resolved.is_relative_to(root):
        raise AppError("INGESTION_FAILED", "Project workspace could not be created.", status_code=500)
    return resolved


def source_directory(workspace: Path) -> Path:
    return workspace / "source"


def archive_path(workspace: Path) -> Path:
    return workspace / "archive.zip"


def remove_workspace(workspace: Path) -> None:
    if workspace.exists():
        shutil.rmtree(workspace)
