"""Deterministic repository manifest from a workspace tree.

Classification uses file names and extensions only. It does not detect
cryptographic algorithms or parse file contents for security findings.
"""

import hashlib
import os
from pathlib import Path

from app.core.config import Settings
from app.core.exceptions import AppError
from app.schemas.project import FileCategory, ManifestFileRecord, RepositoryManifest
from app.services.ingestion.limits import megabytes_to_bytes

_CHUNK_SIZE = 64 * 1024

_DEPENDENCY_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
}

_SOURCE_LANGUAGES = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".c": "C",
    ".h": "C",
    ".hpp": "C++",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".scala": "Scala",
    ".sh": "Shell",
}

_CONFIGURATION_EXTENSIONS = {
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".env",
}

_CERTIFICATE_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx"}
_DOCUMENTATION_EXTENSIONS = {".md", ".txt", ".rst", ".adoc"}
_BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".jar",
    ".class",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".wasm",
    ".woff",
    ".woff2",
    ".pyc",
}


def build_manifest(root: Path, settings: Settings) -> RepositoryManifest:
    """Walk root and return a path-sorted manifest. Symlinks are not followed."""
    max_files = settings.max_file_count
    max_file_bytes = megabytes_to_bytes(settings.max_file_size_mb)
    max_repository_bytes = megabytes_to_bytes(settings.max_repository_size_mb)
    repository_bytes = _directory_size(root)
    if repository_bytes > max_repository_bytes:
        raise AppError(
            "REPOSITORY_TOO_LARGE",
            "The repository exceeds the configured size limit.",
            status_code=413,
            details={"limit_mb": settings.max_repository_size_mb},
        )

    records: list[ManifestFileRecord] = []
    for path in _iter_files(root):
        if len(records) >= max_files:
            raise AppError(
                "TOO_MANY_FILES",
                "The repository contains too many files.",
                status_code=413,
                details={"limit": max_files},
            )
        records.append(_record_file(root, path, max_file_bytes))

    records.sort(key=lambda record: record.relative_path)
    languages: dict[str, int] = {}
    for record in records:
        if record.detected_language is None:
            continue
        languages[record.detected_language] = languages.get(record.detected_language, 0) + 1
    ordered_languages = {name: languages[name] for name in sorted(languages)}
    return RepositoryManifest(
        file_count=len(records),
        total_size=sum(record.file_size for record in records),
        languages=ordered_languages,
        files=records,
    )


def classify_file(relative_path: str) -> tuple[FileCategory, str | None]:
    path = Path(relative_path)
    name = path.name.lower()
    extension = path.suffix.lower()
    if name in _DEPENDENCY_NAMES or name.endswith(".env.example") or _is_requirements_file(name):
        return FileCategory.DEPENDENCY, None
    if extension in _CERTIFICATE_EXTENSIONS:
        return FileCategory.CERTIFICATE, None
    if extension in _SOURCE_LANGUAGES:
        return FileCategory.SOURCE, _SOURCE_LANGUAGES[extension]
    if extension in _CONFIGURATION_EXTENSIONS:
        return FileCategory.CONFIGURATION, None
    if extension in _DOCUMENTATION_EXTENSIONS:
        return FileCategory.DOCUMENTATION, None
    if extension in _BINARY_EXTENSIONS:
        return FileCategory.BINARY, None
    return FileCategory.UNKNOWN, None


def _is_requirements_file(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name != ".git")
        current = Path(dirpath)
        for filename in sorted(filenames):
            path = current / filename
            if path.is_symlink():
                resolved = path.resolve()
                if not resolved.is_relative_to(root.resolve()):
                    raise AppError(
                        "INGESTION_FAILED",
                        "The repository contains a link outside the workspace.",
                        status_code=400,
                    )
                continue
            if path.is_file():
                yield path


def _directory_size(root: Path) -> int:
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if not (Path(dirpath) / name).is_symlink()]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.is_symlink():
                continue
            total += path.stat().st_size
    return total


def _record_file(root: Path, path: Path, max_file_bytes: int) -> ManifestFileRecord:
    relative = path.relative_to(root).as_posix()
    category, language = classify_file(relative)
    digest = hashlib.sha256()
    size = 0
    newlines = 0
    ends_with_newline = False
    saw_null = False
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if size > max_file_bytes:
                raise AppError(
                    "FILE_TOO_LARGE",
                    "The repository contains a file that exceeds the size limit.",
                    status_code=413,
                    details={"limit_mb": max(1, max_file_bytes // (1024 * 1024))},
                )
            digest.update(chunk)
            if b"\x00" in chunk:
                saw_null = True
            newlines += chunk.count(b"\n")
            ends_with_newline = chunk.endswith(b"\n")

    line_count: int | None
    if category is FileCategory.BINARY or saw_null:
        line_count = None
    elif size == 0:
        line_count = 0
    elif ends_with_newline:
        line_count = newlines
    else:
        line_count = newlines + 1

    return ManifestFileRecord(
        relative_path=relative,
        filename=path.name,
        extension=path.suffix.lower(),
        detected_language=language,
        file_size=size,
        line_count=line_count,
        sha256=digest.hexdigest(),
        category=category,
    )
