"""Dependency-manifest detection.

A listed package is evidence that a cryptographic library is declared.
It is not evidence that an algorithm is used.
"""

import re

from app.core.config import Settings
from app.services.scanner.evidence import snippet
from app.services.scanner.findings import RawFinding
from app.services.scanner.registry import CRYPTO_DEPENDENCIES

_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[.*\])?\s*(?:==|>=|~=|!=|<=)?=?\s*([A-Za-z0-9.*+\-]*)")
_TOML_DEP = re.compile(r"""(?im)^\s*([A-Za-z0-9_.\-]+)\s*=\s*["']([^"']+)["']""")
_TOML_STRING = re.compile(r"""["']([A-Za-z0-9_.\-]+)(?:==|>=|~=)([^"']+)["']""")
_PACKAGE_JSON = re.compile(r"""["'](@?[A-Za-z0-9_.\-/]+)["']\s*:\s*["']([^"']+)["']""")
_GO_REQUIRE = re.compile(r"(golang\.org/x/crypto)\s+(v[A-Za-z0-9.\-+]+)")
_MAVEN_ARTIFACT = re.compile(r"<artifactId>\s*([^<]+)\s*</artifactId>")
_MAVEN_VERSION = re.compile(r"<version>\s*([^<$][^<]*)\s*</version>")
_GRADLE = re.compile(
    r"""["']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([A-Za-z0-9.+\-]+)["']"""
)


def detect_dependencies(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    name = file_path.rsplit("/", 1)[-1].lower()
    if name in {"requirements.txt", "requirements-dev.txt"} or (
        name.startswith("requirements") and name.endswith(".txt")
    ):
        return _from_requirements(source, file_path, settings)
    if name in {"pyproject.toml", "pipfile"}:
        return _from_toml(source, file_path, settings)
    if name in {"package.json", "package-lock.json"}:
        return _from_package_json(source, file_path, settings)
    if name == "go.mod":
        return _from_go_mod(source, file_path, settings)
    if name == "pom.xml":
        return _from_pom(source, file_path, settings)
    if name in {"build.gradle", "build.gradle.kts"}:
        return _from_gradle(source, file_path, settings)
    if name in {"cargo.toml", "cargo.lock", "go.sum", "poetry.lock", "yarn.lock", "pnpm-lock.yaml"}:
        return _from_loose_names(source, file_path, settings)
    return []


def _from_requirements(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = _REQUIREMENT.match(stripped)
        if not match:
            continue
        library = CRYPTO_DEPENDENCIES.get(match.group(1).lower())
        if library is None:
            continue
        version = match.group(2) or None
        findings.append(_dependency(file_path, line_number, line, settings, library, version))
    return findings


def _from_toml(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for match in _TOML_DEP.finditer(source):
        library = CRYPTO_DEPENDENCIES.get(match.group(1).lower())
        if library:
            findings.append(_at(source, file_path, settings, match.start(), library, match.group(2)))
    for match in _TOML_STRING.finditer(source):
        library = CRYPTO_DEPENDENCIES.get(match.group(1).lower())
        if library:
            findings.append(_at(source, file_path, settings, match.start(), library, match.group(2)))
    return findings


def _from_package_json(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for match in _PACKAGE_JSON.finditer(source):
        library = CRYPTO_DEPENDENCIES.get(match.group(1).lower())
        if library is None:
            continue
        version = match.group(2).lstrip("^~=v")
        findings.append(_at(source, file_path, settings, match.start(), library, version))
    return findings


def _from_go_mod(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for match in _GO_REQUIRE.finditer(source):
        findings.append(
            _at(source, file_path, settings, match.start(), CRYPTO_DEPENDENCIES[match.group(1)], match.group(2))
        )
    return findings


def _from_pom(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for match in _MAVEN_ARTIFACT.finditer(source):
        library = CRYPTO_DEPENDENCIES.get(match.group(1).strip().lower())
        if library is None:
            continue
        window = source[match.end() : match.end() + 200]
        version_match = _MAVEN_VERSION.search(window)
        version = version_match.group(1).strip() if version_match else None
        findings.append(_at(source, file_path, settings, match.start(), library, version))
    return findings


def _from_gradle(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for match in _GRADLE.finditer(source):
        library = CRYPTO_DEPENDENCIES.get(match.group(2).lower())
        if library is None and "bouncycastle" in match.group(1).lower():
            library = "Bouncy Castle"
        if library is None:
            continue
        findings.append(_at(source, file_path, settings, match.start(), library, match.group(3)))
    return findings


def _from_loose_names(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    lowered = source.lower()
    for package, library in CRYPTO_DEPENDENCIES.items():
        index = lowered.find(package)
        if index < 0:
            continue
        findings.append(_at(source, file_path, settings, index, library, None))
    return findings


def _dependency(
    file_path: str,
    line_number: int,
    line: str,
    settings: Settings,
    library: str,
    version: str | None,
) -> RawFinding:
    return RawFinding(
        file_path=file_path,
        line_start=line_number,
        line_end=line_number,
        language=None,
        algorithm=None,
        algorithm_family=None,
        library=library,
        library_version=version or None,
        usage="dependency_only",
        key_size=None,
        curve=None,
        mode=None,
        evidence=snippet(line, 1, 1, settings),
        detection_method="dependency_detection",
        confidence="low",
        metadata={},
    )


def _at(
    source: str,
    file_path: str,
    settings: Settings,
    offset: int,
    library: str,
    version: str | None,
) -> RawFinding:
    line = source.count("\n", 0, offset) + 1
    return _dependency(file_path, line, source.splitlines()[line - 1], settings, library, version)
