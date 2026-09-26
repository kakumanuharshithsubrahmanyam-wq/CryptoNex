"""Route manifest files to detectors and deduplicate findings.

The manifest decides which files are eligible. Source detectors do not run on
documentation, binaries, or dependency manifests.
"""

from pathlib import Path

from app.core.config import Settings
from app.schemas.project import FileCategory, RepositoryManifest
from app.services.scanner.detectors.cpp_detector import detect_cpp
from app.services.scanner.detectors.dependency_detector import detect_dependencies
from app.services.scanner.detectors.go_detector import detect_go
from app.services.scanner.detectors.java_detector import detect_java
from app.services.scanner.detectors.javascript_detector import detect_javascript
from app.services.scanner.detectors.python_detector import detect_python
from app.services.scanner.findings import RawFinding, prefer

_SOURCE_LANGUAGES = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".h": "C",
    ".hpp": "C++",
}
_DEPENDENCY_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "pipfile",
    "poetry.lock",
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
}


class ScanRun:
    def __init__(self) -> None:
        self.findings: list[RawFinding] = []
        self.files_scanned = 0
        self.skip_reasons: dict[str, int] = {}

    def skip(self, reason: str) -> None:
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1


def scan_manifest(source_root: Path, manifest: RepositoryManifest, settings: Settings) -> ScanRun:
    run = ScanRun()
    excluded = {
        part.strip()
        for part in settings.scan_excluded_directories.split(",")
        if part.strip()
    }
    root = source_root.resolve()
    for record in manifest.files:
        relative = record.relative_path
        if _excluded(relative, excluded):
            run.skip("excluded_directory")
            continue
        path = _safe_file(root, relative)
        if path is None:
            run.skip("unsafe_path")
            continue
        if record.category in {FileCategory.BINARY, FileCategory.DOCUMENTATION, FileCategory.CERTIFICATE}:
            run.skip(record.category.value)
            continue
        if record.file_size > settings.max_file_size_mb * 1024 * 1024:
            run.skip("file_too_large")
            continue
        filename = Path(relative).name.lower()
        is_dependency = record.category == FileCategory.DEPENDENCY or filename in _DEPENDENCY_NAMES
        language = _SOURCE_LANGUAGES.get(Path(relative).suffix.lower())
        if not is_dependency and language is None:
            run.skip("unsupported_language")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            run.skip("binary")
            continue
        except OSError:
            run.skip("unreadable")
            continue
        if "\x00" in text:
            run.skip("binary")
            continue
        run.files_scanned += 1
        if is_dependency:
            run.findings.extend(detect_dependencies(text, relative, settings))
            continue
        run.findings.extend(_detect_source(text, relative, language or "", settings))
    run.findings = dedupe(run.findings)
    return run


def dedupe(findings: list[RawFinding]) -> list[RawFinding]:
    chosen: dict[tuple, RawFinding] = {}
    loose_owner: dict[tuple, tuple] = {}
    for finding in findings:
        exact = finding.dedupe_key()
        loose = (finding.file_path, finding.line_start, finding.algorithm or "", finding.library or "")
        if exact in chosen:
            chosen[exact] = prefer(chosen[exact], finding)
            continue
        if loose in loose_owner:
            owner = loose_owner[loose]
            chosen[owner] = prefer(chosen[owner], finding)
            continue
        chosen[exact] = finding
        loose_owner[loose] = exact
    return sorted(chosen.values(), key=lambda item: (item.file_path, item.line_start, item.algorithm or ""))


def _detect_source(source: str, file_path: str, language: str, settings: Settings) -> list[RawFinding]:
    if language == "Python":
        return detect_python(source, file_path, settings)
    if language == "Java":
        return detect_java(source, file_path, settings)
    if language in {"JavaScript", "TypeScript"}:
        return detect_javascript(source, file_path, settings, language)
    if language == "Go":
        return detect_go(source, file_path, settings)
    if language in {"C", "C++"}:
        return detect_cpp(source, file_path, settings, language)
    return []


def _excluded(relative: str, excluded: set[str]) -> bool:
    return any(part in excluded for part in relative.split("/"))


def _safe_file(root: Path, relative: str) -> Path | None:
    if relative.startswith("/") or ".." in relative.split("/"):
        return None
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        return None
    if candidate.is_symlink() or not candidate.is_file():
        return None
    return candidate
