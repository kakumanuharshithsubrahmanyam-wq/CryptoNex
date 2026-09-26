"""package.json, package-lock.json, yarn.lock, and pnpm-lock.yaml."""

import re
from typing import Any

from app.core.config import Settings
from app.services.dependencies.parsers.common import (
    block_evidence,
    dict_items,
    find_offset,
    line_at,
    line_evidence,
    load_json,
)
from app.services.dependencies.types import (
    DeclaredDependency,
    DependencyType,
    Directness,
    Ecosystem,
    ManifestParse,
)

_JS = Ecosystem.JAVASCRIPT.value
_SECTIONS = (
    ("dependencies", DependencyType.RUNTIME),
    ("devDependencies", DependencyType.DEVELOPMENT),
    ("peerDependencies", DependencyType.PEER),
    ("optionalDependencies", DependencyType.OPTIONAL),
)
_EXACT_SEMVER = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?)$")
_NON_REGISTRY = ("git", "http:", "https:", "file:", "link:", "workspace:", "npm:", "github:", "portal:", "patch:")
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')
_YARN_DEP = re.compile(r'^\s+"?(@?[^"\s:@][^"\s:]*)"?:?\s+"?[^"\s]+"?\s*$')


def parse_package_json(text: str, file_path: str, settings: Settings) -> ManifestParse:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestParse(malformed=True)
    lines = text.splitlines()
    result = ManifestParse()
    if data.get("workspaces"):
        result.attributes["workspaces"] = "true"
    for section, dependency_type in _SECTIONS:
        start = find_offset(text, rf'"{section}"\s*:') or 0
        for name, spec in dict_items(data.get(section)):
            version, constraint, metadata = npm_spec(spec)
            offset = find_offset(text, rf'"{re.escape(name)}"\s*:', start)
            line = line_at(text, offset) if offset is not None else 1
            result.dependencies.append(
                DeclaredDependency(
                    name=name,
                    ecosystem=_JS,
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


def parse_package_lock(text: str, file_path: str, settings: Settings) -> ManifestParse:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestParse(malformed=True)
    lines = text.splitlines()
    if isinstance(data.get("packages"), dict):
        return _lock_v2(data["packages"], text, lines, file_path, settings)
    if isinstance(data.get("dependencies"), dict):
        result = ManifestParse()
        _lock_v1(data["dependencies"], text, lines, file_path, settings, result, nested=False, cursor=[0])
        return result
    return ManifestParse()


def parse_yarn_lock(text: str, file_path: str, settings: Settings) -> ManifestParse:
    lines = text.splitlines()
    result = ManifestParse()
    index = 0
    while index < len(lines):
        header = lines[index]
        index += 1
        if not header or header[0] in " \t#" or not header.rstrip().endswith(":"):
            continue
        entry = _yarn_entry_name(header.rstrip()[:-1])
        if entry is None:
            continue
        name, _range = entry
        line_number = index
        version = None
        requires: list[str] = []
        in_dependencies = False
        while index < len(lines) and (not lines[index] or lines[index][0] in " \t"):
            body = lines[index]
            index += 1
            stripped = body.strip()
            if not stripped:
                continue
            indent = len(body) - len(body.lstrip())
            if indent < 4:
                in_dependencies = False
            if not in_dependencies:
                version_match = _YARN_VERSION.match(body)
                if version_match:
                    version = version_match.group(1)
                elif stripped in {"dependencies:", "optionalDependencies:", "peerDependencies:"}:
                    in_dependencies = True
                continue
            dependency = _YARN_DEP.match(body)
            if dependency:
                requires.append(dependency.group(1))
        result.dependencies.append(
            DeclaredDependency(
                name=name,
                ecosystem=_JS,
                manifest_file=file_path,
                source_line=line_number,
                raw_declaration=block_evidence(lines, line_number, settings),
                version=version,
                requires=tuple(sorted(set(requires))),
            )
        )
    return result


def parse_pnpm_lock(text: str, file_path: str, settings: Settings) -> ManifestParse:
    lines = text.splitlines()
    result = ManifestParse()
    in_packages = False
    current: DeclaredDependency | None = None
    in_dependencies = False
    for number, line in enumerate(lines, start=1):
        if line and not line[0].isspace():
            in_packages = line.strip() == "packages:"
            current = None
            continue
        if not in_packages or not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 2 and stripped.endswith(":"):
            parsed = _pnpm_key(stripped[:-1])
            current = None
            in_dependencies = False
            if parsed is None:
                continue
            name, version = parsed
            current = DeclaredDependency(
                name=name,
                ecosystem=_JS,
                manifest_file=file_path,
                source_line=number,
                raw_declaration=line_evidence(lines, number, settings),
                version=version,
            )
            result.dependencies.append(current)
            continue
        if current is None:
            continue
        if indent == 4:
            in_dependencies = stripped in {"dependencies:", "optionalDependencies:"}
            if stripped == "dev: true":
                current.dependency_type = DependencyType.DEVELOPMENT.value
            continue
        if indent >= 6 and in_dependencies and ":" in stripped:
            dependency_name = stripped.split(":", 1)[0].strip().strip("'\"")
            current.requires = tuple(sorted(set(current.requires) | {dependency_name}))
    return result


def npm_spec(spec: Any) -> tuple[str | None, str | None, dict[str, str]]:
    if not isinstance(spec, str):
        return None, None, {}
    cleaned = spec.strip()
    if cleaned.startswith(_NON_REGISTRY) or "/" in cleaned and not cleaned.startswith((">", "<", "^", "~", "=")):
        return None, None, {"source": "non_registry"}
    exact = _EXACT_SEMVER.match(cleaned)
    if exact:
        return exact.group(1), None, {}
    if not cleaned:
        return None, None, {}
    return None, cleaned, {}


def _lock_v2(
    packages: dict[str, Any], text: str, lines: list[str], file_path: str, settings: Settings
) -> ManifestParse:
    result = ManifestParse()
    workspace_entries = [info for key, info in packages.items() if "node_modules/" not in key and isinstance(info, dict)]
    has_root = "" in packages
    direct_names: set[str] = set()
    for info in workspace_entries:
        for section, _type in _SECTIONS:
            direct_names.update(name for name, _spec in dict_items(info.get(section)))
    for key, info in packages.items():
        if "node_modules/" not in key or not isinstance(info, dict) or info.get("link"):
            continue
        name = info.get("name") if isinstance(info.get("name"), str) else key.rsplit("node_modules/", 1)[-1]
        version = info.get("version") if isinstance(info.get("version"), str) else None
        if key.count("node_modules/") > 1 or not key.startswith("node_modules/"):
            directness = Directness.TRANSITIVE if key.count("node_modules/") > 1 else Directness.UNKNOWN
        elif has_root:
            directness = Directness.DIRECT if name in direct_names else Directness.TRANSITIVE
        else:
            directness = Directness.UNKNOWN
        offset = find_offset(text, rf'"{re.escape(key)}"\s*:')
        line = line_at(text, offset) if offset is not None else 1
        requires: set[str] = set()
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            requires.update(dependency for dependency, _spec in dict_items(info.get(section)))
        result.dependencies.append(
            DeclaredDependency(
                name=name,
                ecosystem=_JS,
                manifest_file=file_path,
                source_line=line,
                raw_declaration=block_evidence(lines, line, settings),
                version=version,
                dependency_type=_lock_type(info).value,
                direct_or_transitive=directness.value,
                requires=tuple(sorted(requires)),
            )
        )
    return result


def _lock_v1(
    dependencies: dict[str, Any],
    text: str,
    lines: list[str],
    file_path: str,
    settings: Settings,
    result: ManifestParse,
    nested: bool,
    cursor: list[int],
) -> None:
    for name, info in dependencies.items():
        if not isinstance(info, dict):
            continue
        offset = find_offset(text, rf'"{re.escape(name)}"\s*:\s*\{{', cursor[0])
        if offset is not None:
            cursor[0] = offset + 1
        line = line_at(text, offset) if offset is not None else 1
        version = info.get("version") if isinstance(info.get("version"), str) else None
        result.dependencies.append(
            DeclaredDependency(
                name=name,
                ecosystem=_JS,
                manifest_file=file_path,
                source_line=line,
                raw_declaration=block_evidence(lines, line, settings),
                version=version,
                dependency_type=_lock_type(info).value,
                direct_or_transitive=(Directness.TRANSITIVE if nested else Directness.UNKNOWN).value,
                requires=tuple(sorted(name for name, _spec in dict_items(info.get("requires")))),
            )
        )
        if isinstance(info.get("dependencies"), dict):
            _lock_v1(info["dependencies"], text, lines, file_path, settings, result, nested=True, cursor=cursor)


def _lock_type(info: dict[str, Any]) -> DependencyType:
    if info.get("dev") or info.get("devOptional"):
        return DependencyType.DEVELOPMENT
    if info.get("optional"):
        return DependencyType.OPTIONAL
    if info.get("peer"):
        return DependencyType.PEER
    return DependencyType.RUNTIME


def _yarn_entry_name(header: str) -> tuple[str, str] | None:
    first = header.split(",", 1)[0].strip().strip('"')
    if first == "__metadata" or not first:
        return None
    at = first.find("@", 1) if first.startswith("@") else first.find("@")
    if at <= 0:
        return None
    name, spec = first[:at], first[at + 1 :]
    if spec.startswith(("workspace:", "patch:", "link:", "portal:")):
        return None
    return name, spec


def _pnpm_key(key: str) -> tuple[str, str] | None:
    cleaned = key.strip().strip("'\"").lstrip("/").split("(", 1)[0]
    if not cleaned:
        return None
    at = cleaned.find("@", 1) if cleaned.startswith("@") else cleaned.find("@")
    if at > 0:
        return cleaned[:at], cleaned[at + 1 :]
    if "/" not in cleaned:
        return None
    name, version = cleaned.rsplit("/", 1)
    return name, version.split("_", 1)[0]
