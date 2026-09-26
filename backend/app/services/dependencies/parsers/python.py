"""requirements*.txt, pyproject.toml, Pipfile, and poetry.lock."""

import re
from typing import Any

from app.core.config import Settings
from app.services.dependencies.parsers.common import (
    block_evidence,
    dict_items,
    line_evidence,
    line_of_token,
    load_toml,
    package_name_lines,
    section_offset,
)
from app.services.dependencies.types import (
    DeclaredDependency,
    DependencyType,
    Directness,
    Ecosystem,
    ManifestParse,
)

_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_EXACT_PEP440 = re.compile(r"^===?([A-Za-z0-9.+!_\-]+)$")
_POETRY_EXACT = re.compile(r"^=?=?(\d+(?:\.\d+)*(?:[a-zA-Z0-9.+\-]*)?)$")
_VIA_INLINE = re.compile(r"#\s*via\s+(.+)$")
_VIA_BLOCK = re.compile(r"^\s+#\s*via\s*$")
_VIA_ITEM = re.compile(r"^\s+#\s{2,}(\S.*)$")

_PYTHON = Ecosystem.PYTHON.value


def parse_requirements(text: str, file_path: str, settings: Settings) -> ManifestParse:
    lines = text.splitlines()
    result = ManifestParse()
    index = 0
    while index < len(lines):
        raw = lines[index]
        line_number = index + 1
        index += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        requirement, _, inline_comment = stripped.partition(" #")
        parsed = parse_pep508(requirement.rstrip("\\ "))
        if parsed is None:
            continue
        name, version, constraint, metadata = parsed
        via: list[str] = []
        inline = _VIA_INLINE.search("#" + inline_comment) if inline_comment else None
        if inline:
            via.append(inline.group(1).strip())
        if index < len(lines) and _VIA_BLOCK.match(lines[index]):
            index += 1
            while index < len(lines) and _VIA_ITEM.match(lines[index]):
                via.append(_VIA_ITEM.match(lines[index]).group(1).strip())
                index += 1
        elif index < len(lines):
            single = re.match(r"^\s+#\s*via\s+(\S.*)$", lines[index])
            if single:
                via.append(single.group(1).strip())
                index += 1
        directness, required_by = _pip_compile_directness(via)
        result.dependencies.append(
            DeclaredDependency(
                name=name,
                ecosystem=_PYTHON,
                manifest_file=file_path,
                source_line=line_number,
                raw_declaration=line_evidence(lines, line_number, settings),
                version=version,
                version_constraint=constraint,
                direct_or_transitive=directness,
                required_by=required_by,
                metadata=metadata,
            )
        )
    return result


def parse_pyproject(text: str, file_path: str, settings: Settings) -> ManifestParse:
    data = load_toml(text)
    if data is None:
        return ManifestParse(malformed=True)
    lines = text.splitlines()
    result = ManifestParse()
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    project_start = section_offset(text, "project")
    for spec in project.get("dependencies", []) if isinstance(project.get("dependencies"), list) else []:
        _add_pep508(result, spec, text, lines, file_path, settings, DependencyType.RUNTIME, project_start)
    optional_start = section_offset(text, "project.optional-dependencies")
    for _group, specs in dict_items(project.get("optional-dependencies")):
        for spec in specs if isinstance(specs, list) else []:
            _add_pep508(result, spec, text, lines, file_path, settings, DependencyType.OPTIONAL, optional_start)

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if not isinstance(poetry, dict):
        return result
    tables: list[tuple[str, Any, DependencyType]] = [
        ("tool.poetry.dependencies", poetry.get("dependencies"), DependencyType.RUNTIME),
        ("tool.poetry.dev-dependencies", poetry.get("dev-dependencies"), DependencyType.DEVELOPMENT),
    ]
    for group, body in dict_items(poetry.get("group")):
        if isinstance(body, dict):
            tables.append((f"tool.poetry.group.{group}.dependencies", body.get("dependencies"), DependencyType.DEVELOPMENT))
    for header, table, dependency_type in tables:
        start = section_offset(text, header)
        for name, spec in dict_items(table):
            if name.lower() == "python":
                continue
            version, constraint, metadata = _poetry_spec(spec)
            result.dependencies.append(
                _record(name, text, lines, file_path, settings, dependency_type, version, constraint, metadata, start)
            )
    return result


def parse_pipfile(text: str, file_path: str, settings: Settings) -> ManifestParse:
    data = load_toml(text)
    if data is None:
        return ManifestParse(malformed=True)
    lines = text.splitlines()
    result = ManifestParse()
    for header, dependency_type in (("packages", DependencyType.RUNTIME), ("dev-packages", DependencyType.DEVELOPMENT)):
        start = section_offset(text, header)
        for name, spec in dict_items(data.get(header)):
            version, constraint, metadata = _pipfile_spec(spec)
            result.dependencies.append(
                _record(name, text, lines, file_path, settings, dependency_type, version, constraint, metadata, start)
            )
    return result


def parse_poetry_lock(text: str, file_path: str, settings: Settings) -> ManifestParse:
    data = load_toml(text)
    if data is None or not isinstance(data.get("package", []), list):
        return ManifestParse(malformed=True)
    lines = text.splitlines()
    name_lines = package_name_lines(lines)
    result = ManifestParse()
    for position, package in enumerate(data.get("package", [])):
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue
        line = name_lines[position] if position < len(name_lines) else 1
        category = package.get("category")
        dependency_type = {
            "main": DependencyType.RUNTIME,
            "dev": DependencyType.DEVELOPMENT,
        }.get(category, DependencyType.UNKNOWN)
        version = package.get("version") if isinstance(package.get("version"), str) else None
        result.dependencies.append(
            DeclaredDependency(
                name=package["name"],
                ecosystem=_PYTHON,
                manifest_file=file_path,
                source_line=line,
                raw_declaration=block_evidence(lines, line, settings),
                version=version,
                dependency_type=dependency_type.value,
                requires=tuple(sorted(name for name, _spec in dict_items(package.get("dependencies")))),
            )
        )
    return result


def parse_pep508(requirement: str) -> tuple[str, str | None, str | None, dict[str, str]] | None:
    match = _PEP508.match(requirement)
    if not match:
        return None
    name = match.group(1)
    rest = match.group(3).split(";", 1)[0].strip()
    metadata: dict[str, str] = {}
    if rest.startswith("@"):
        metadata["source"] = "direct_reference"
        return name, None, None, metadata
    if "://" in requirement.split("@", 1)[0] or rest.startswith(("+", ":")):
        return None
    specifier = rest.strip("()").replace(" ", "")
    if not specifier:
        return name, None, None, metadata
    exact = _EXACT_PEP440.match(specifier)
    if exact and "*" not in specifier:
        return name, exact.group(1), None, metadata
    return name, None, specifier, metadata


def _pip_compile_directness(via: list[str]) -> tuple[str, tuple[str, ...]]:
    if not via:
        return Directness.UNKNOWN.value, ()
    parents = tuple(sorted(item for item in via if not item.startswith("-")))
    if any(item.startswith("-r") or item.startswith("-c") for item in via):
        return Directness.DIRECT.value, parents
    return Directness.TRANSITIVE.value, parents


def _add_pep508(
    result: ManifestParse,
    spec: Any,
    text: str,
    lines: list[str],
    file_path: str,
    settings: Settings,
    dependency_type: DependencyType,
    start: int,
) -> None:
    if not isinstance(spec, str):
        return
    parsed = parse_pep508(spec)
    if parsed is None:
        return
    name, version, constraint, metadata = parsed
    result.dependencies.append(
        _record(name, text, lines, file_path, settings, dependency_type, version, constraint, metadata, start)
    )


def _record(
    name: str,
    text: str,
    lines: list[str],
    file_path: str,
    settings: Settings,
    dependency_type: DependencyType,
    version: str | None,
    constraint: str | None,
    metadata: dict[str, str],
    start: int,
) -> DeclaredDependency:
    line = line_of_token(text, name, start)
    return DeclaredDependency(
        name=name,
        ecosystem=_PYTHON,
        manifest_file=file_path,
        source_line=line,
        raw_declaration=line_evidence(lines, line, settings),
        version=version,
        version_constraint=constraint,
        dependency_type=dependency_type.value,
        direct_or_transitive=Directness.DIRECT.value,
        metadata=metadata,
    )


def _poetry_spec(spec: Any) -> tuple[str | None, str | None, dict[str, str]]:
    if isinstance(spec, dict):
        if any(key in spec for key in ("git", "path", "url")):
            return None, None, {"source": "direct_reference"}
        spec = spec.get("version")
    if not isinstance(spec, str):
        return None, None, {}
    cleaned = spec.strip().replace(" ", "")
    if not cleaned or cleaned == "*":
        return None, None, {}
    exact = _POETRY_EXACT.match(cleaned)
    if exact:
        return exact.group(1), None, {}
    return None, cleaned, {}


def _pipfile_spec(spec: Any) -> tuple[str | None, str | None, dict[str, str]]:
    if isinstance(spec, dict):
        if any(key in spec for key in ("git", "path", "file", "ref")):
            return None, None, {"source": "direct_reference"}
        spec = spec.get("version")
    if not isinstance(spec, str):
        return None, None, {}
    cleaned = spec.strip().replace(" ", "")
    if not cleaned or cleaned == "*":
        return None, None, {}
    exact = _EXACT_PEP440.match(cleaned)
    if exact and "*" not in cleaned:
        return exact.group(1), None, {}
    return None, cleaned, {}

