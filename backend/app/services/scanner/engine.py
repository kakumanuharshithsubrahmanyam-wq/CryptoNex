"""Route manifest files to detectors and deduplicate findings.

The manifest decides which files are eligible. Source detectors do not run on
documentation, binaries, or dependency manifests.
"""

from pathlib import Path

from app.core.config import Settings
from app.schemas.project import FileCategory, RepositoryManifest
from app.services.artifacts.detect import detect_binary_artifacts, detect_text_artifacts, is_artifact_filename
from app.services.artifacts.types import RawArtifact
from app.services.dependencies.inventory import build_inventory
from app.services.dependencies.parsers import parse_manifest
from app.services.dependencies.types import DeclaredDependency
from app.services.scanner.detectors.cpp_detector import detect_cpp
from app.services.scanner.detectors.dependency_detector import dependency_findings
from app.services.scanner.detectors.go_detector import detect_go
from app.services.scanner.detectors.java_detector import detect_java
from app.services.scanner.detectors.javascript_detector import detect_javascript
from app.services.scanner.detectors.python_detector import detect_python
from app.services.scanner.detectors.rust_detector import detect_rust
from app.services.scanner.findings import RawFinding, prefer

_SOURCE_LANGUAGES = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
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
    "cmakelists.txt",
    "vcpkg.json",
    "conanfile.txt",
    "conanfile.py",
}


class ScanRun:
    def __init__(self) -> None:
        self.findings: list[RawFinding] = []
        self.dependencies: list[DeclaredDependency] = []
        self.artifacts: list[RawArtifact] = []
        self.manifests: dict[str, dict[str, str]] = {}
        self.malformed_manifests = 0
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
        if record.category == FileCategory.DOCUMENTATION:
            run.skip(record.category.value)
            continue
        if record.file_size > settings.max_file_size_mb * 1024 * 1024:
            run.skip("file_too_large")
            continue
        filename = Path(relative).name.lower()
        is_dependency = record.category == FileCategory.DEPENDENCY or filename in _DEPENDENCY_NAMES
        language = _SOURCE_LANGUAGES.get(Path(relative).suffix.lower())
        artifact_file = record.category in {FileCategory.CERTIFICATE, FileCategory.CONFIGURATION} or is_artifact_filename(relative)
        if record.category == FileCategory.BINARY:
            if not artifact_file:
                run.skip(record.category.value)
                continue
            try:
                data = path.read_bytes()
            except OSError:
                run.skip("unreadable")
                continue
            run.files_scanned += 1
            run.artifacts.extend(detect_binary_artifacts(data, relative, settings))
            continue
        if not is_dependency and language is None and not artifact_file:
            run.skip("unsupported_language")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            if artifact_file:
                try:
                    data = path.read_bytes()
                except OSError:
                    run.skip("unreadable")
                    continue
                run.files_scanned += 1
                run.artifacts.extend(detect_binary_artifacts(data, relative, settings))
                continue
            run.skip("binary")
            continue
        except OSError:
            run.skip("unreadable")
            continue
        if "\x00" in text:
            if artifact_file:
                run.files_scanned += 1
                run.artifacts.extend(detect_binary_artifacts(path.read_bytes(), relative, settings))
                continue
            run.skip("binary")
            continue
        run.files_scanned += 1
        if is_dependency:
            parsed = parse_manifest(text, relative, settings)
            run.manifests[relative] = parsed.attributes
            run.dependencies.extend(parsed.dependencies)
            if parsed.malformed:
                run.malformed_manifests += 1
            continue
        if language:
            run.findings.extend(_detect_source(text, relative, language, settings))
        if language or artifact_file:
            run.artifacts.extend(detect_text_artifacts(text, relative, settings))
    run.dependencies = build_inventory(run.dependencies, run.manifests)
    run.findings.extend(dependency_findings(run.dependencies))
    run.findings = dedupe(run.findings)
    run.artifacts = _dedupe_artifacts(run.artifacts)
    return run


def _dedupe_artifacts(artifacts: list[RawArtifact]) -> list[RawArtifact]:
    chosen: dict[tuple, RawArtifact] = {}
    for artifact in artifacts:
        key = artifact.dedupe_key()
        if key not in chosen:
            chosen[key] = artifact
    return sorted(chosen.values(), key=lambda item: (item.file_path, item.line_start, item.artifact_type))


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
    if language == "Rust":
        return detect_rust(source, file_path, settings)
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
