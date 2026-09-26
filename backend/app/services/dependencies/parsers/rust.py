"""Cargo.toml and Cargo.lock."""

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

_RUST = Ecosystem.RUST.value
_TABLES = (
    ("dependencies", DependencyType.RUNTIME),
    ("dev-dependencies", DependencyType.DEVELOPMENT),
    ("build-dependencies", DependencyType.BUILD),
)


def parse_cargo_toml(text: str, file_path: str, settings: Settings) -> ManifestParse:
    data = load_toml(text)
    if data is None:
        return ManifestParse(malformed=True)
    lines = text.splitlines()
    result = ManifestParse()
    sources: list[tuple[str, Any, DependencyType]] = [
        (table, data.get(table), dependency_type) for table, dependency_type in _TABLES
    ]
    for target, body in dict_items(data.get("target")):
        for table, dependency_type in _TABLES:
            if isinstance(body, dict):
                sources.append((f"target.{target}.{table}", body.get(table), dependency_type))
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        sources.append(("workspace.dependencies", workspace.get("dependencies"), DependencyType.UNKNOWN))
    for header, table, dependency_type in sources:
        start = section_offset(text, header)
        for key, spec in dict_items(table):
            name = spec.get("package", key) if isinstance(spec, dict) and isinstance(spec.get("package"), str) else key
            version, constraint, metadata = _cargo_spec(spec)
            line = line_of_token(text, key, start)
            result.dependencies.append(
                DeclaredDependency(
                    name=name,
                    ecosystem=_RUST,
                    manifest_file=file_path,
                    source_line=line,
                    raw_declaration=line_evidence(lines, line, settings),
                    version=version,
                    version_constraint=constraint,
                    dependency_type=dependency_type.value,
                    direct_or_transitive=Directness.DIRECT.value,
                    metadata=metadata,
                )
            )
    return result


def parse_cargo_lock(text: str, file_path: str, settings: Settings) -> ManifestParse:
    data = load_toml(text)
    if data is None or not isinstance(data.get("package", []), list):
        return ManifestParse(malformed=True)
    lines = text.splitlines()
    name_lines = package_name_lines(lines)
    result = ManifestParse()
    for position, package in enumerate(data.get("package", [])):
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue
        # Entries without a source are the workspace's own crates or path crates.
        if "source" not in package:
            continue
        line = name_lines[position] if position < len(name_lines) else 1
        requires = tuple(
            sorted(
                str(item).split(" ", 1)[0]
                for item in package.get("dependencies", [])
                if isinstance(item, str)
            )
        )
        result.dependencies.append(
            DeclaredDependency(
                name=package["name"],
                ecosystem=_RUST,
                manifest_file=file_path,
                source_line=line,
                raw_declaration=block_evidence(lines, line, settings),
                version=package.get("version") if isinstance(package.get("version"), str) else None,
                requires=requires,
            )
        )
    return result


def _cargo_spec(spec: Any) -> tuple[str | None, str | None, dict[str, str]]:
    if isinstance(spec, dict):
        if spec.get("workspace") is True:
            return None, None, {"source": "workspace"}
        if any(key in spec for key in ("git", "path")):
            return None, None, {"source": "direct_reference"}
        spec = spec.get("version")
    if not isinstance(spec, str) or not spec.strip():
        return None, None, {}
    cleaned = spec.strip()
    exact = re.fullmatch(r"=\s*(\d+\.\d+\.\d+\S*)", cleaned)
    if exact:
        return exact.group(1), None, {}
    return None, cleaned, {}

