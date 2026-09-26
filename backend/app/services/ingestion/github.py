"""Clone a validated public GitHub repository.

The clone URL is data passed as one argv element. Repository code, hooks,
submodules, and dependency installers are not executed.
"""

import os
import signal
import subprocess
from pathlib import Path

from app.core.config import Settings
from app.core.exceptions import AppError
from app.services.ingestion.validation import GitHubRepository

_TRUE_EXECUTABLE = "/usr/bin/true"


def clone_repository(
    repository: GitHubRepository,
    destination: Path,
    settings: Settings,
    *,
    runner=None,
) -> None:
    """Shallow-clone repository into destination. destination is created by git."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise AppError("INGESTION_FAILED", "Repository workspace already exists.", status_code=500)

    control = destination.parent
    home = control / ".cryptonex-home"
    hooks = control / ".cryptonex-hooks"
    home.mkdir(parents=True, exist_ok=True)
    hooks.mkdir(parents=True, exist_ok=True)
    gitconfig = home / ".gitconfig"
    gitconfig.write_text("", encoding="utf-8")

    command = [
        settings.git_executable,
        "-c",
        f"core.hooksPath={hooks}",
        "-c",
        "core.symlinks=false",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "credential.helper=",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--",
        repository.clone_url,
        str(destination),
    ]
    environment = _git_environment(home, gitconfig)
    execute = runner or run_git
    try:
        return_code = execute(
            command,
            timeout=settings.clone_timeout_seconds,
            env=environment,
            cwd=str(control),
        )
    except subprocess.TimeoutExpired as exc:
        raise AppError(
            "REPOSITORY_CLONE_TIMEOUT",
            "Cloning the repository took too long.",
            status_code=504,
        ) from exc
    except OSError as exc:
        raise AppError(
            "REPOSITORY_CLONE_FAILED",
            "The repository could not be cloned.",
            status_code=502,
        ) from exc

    if return_code != 0 or not destination.is_dir():
        raise AppError(
            "REPOSITORY_CLONE_FAILED",
            "The repository could not be cloned.",
            status_code=502,
        )


def run_git(args: list[str], *, timeout: int, env: dict[str, str], cwd: str) -> int:
    """Run a fixed git argv list. stdout and stderr are discarded."""
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=env,
        cwd=cwd,
        shell=False,
        start_new_session=True,
    )
    try:
        process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate(process)
        raise
    return process.returncode


def _terminate(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        process.kill()
    process.communicate()


def _git_environment(home: Path, gitconfig: Path) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": str(gitconfig),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "LANG": "C.UTF-8",
    }
    if Path(_TRUE_EXECUTABLE).is_file():
        environment["GIT_ASKPASS"] = _TRUE_EXECUTABLE
    return environment
