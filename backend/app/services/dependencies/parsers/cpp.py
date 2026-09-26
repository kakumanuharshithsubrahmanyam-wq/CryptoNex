"""Static C/C++ dependency declarations.

Parsers read CMake, Conan, and vcpkg text. They do not execute CMake, Make,
Conan, package managers, or repository code. Botan-style configure.py is not
a supported declarative manifest.
"""

from __future__ import annotations

import re

from app.core.config import Settings
from app.services.dependencies.parsers.common import line_at, line_evidence, load_json
from app.services.dependencies.types import (
    DeclaredDependency,
    DependencyType,
    Directness,
    Ecosystem,
    ManifestParse,
)

_CPP = Ecosystem.CPP.value
_FIND_PACKAGE = re.compile(r"\bfind_package\s*\(", re.IGNORECASE)
_FETCH = re.compile(r"\bFetchContent_Declare\s*\(", re.IGNORECASE)
_PKG_CHECK = re.compile(
    r"""\bpkg_check_modules\s*\(\s*[A-Za-z0-9_]+\s+(?:REQUIRED\s+)?(?P<name>[A-Za-z0-9_.+-]+)""",
    re.IGNORECASE,
)
_CONAN_TXT_REQ = re.compile(r"^\s*(?P<name>[A-Za-z0-9_.+-]+)(?P<rest>/[^\s#]+)?\s*$")
_CONAN_PY_CALL = re.compile(
    r"""self\.requires\s*\(\s*["'](?P<spec>[^"']+)["']""",
)
_CONAN_PY_ASSIGN = re.compile(
    r"""(?:^|\n)\s*requires\s*=\s*["'](?P<spec>[^"']+)["']""",
)
_CONAN_PY_LIST = re.compile(r"requires\s*=\s*\[(?P<body>.*?)]", re.DOTALL)
_CONAN_PY_ITEM = re.compile(r"""["']([^"']+)["']""")
_SKIP_CMAKE = {"pkgconfig", "threads", "gnuinstalldirs", "checkipo"}


def parse_cmake_lists(text: str, file_path: str, settings: Settings) -> ManifestParse:
    result = ManifestParse()
    lines = text.splitlines()
    for match in _FIND_PACKAGE.finditer(text):
        body = _balanced_args(text, match.end() - 1)
        if body is None:
            result.malformed = True
            continue
        tokens = _cmake_tokens(body)
        if not tokens or tokens[0].startswith("$") or tokens[0].lower() in _SKIP_CMAKE:
            continue
        name = tokens[0]
        version, constraint = _cmake_version(tokens[1:])
        line = line_at(text, match.start())
        result.dependencies.append(
            _dep(
                name,
                file_path,
                line,
                line_evidence(lines, line, settings) or match.group(0),
                version=version,
                constraint=constraint,
                extra={"declaration": "find_package"},
            )
        )
    for match in _FETCH.finditer(text):
        body = _balanced_args(text, match.end() - 1)
        if body is None:
            result.malformed = True
            continue
        tokens = _cmake_tokens(body)
        if not tokens or tokens[0].startswith("$"):
            continue
        name = tokens[0]
        tag = _cmake_named(tokens, "GIT_TAG")
        line = line_at(text, match.start())
        result.dependencies.append(
            _dep(
                name,
                file_path,
                line,
                line_evidence(lines, line, settings) or match.group(0),
                version=tag,
                extra={"declaration": "FetchContent_Declare"},
            )
        )
    for match in _PKG_CHECK.finditer(text):
        name = match.group("name")
        if name.startswith("$"):
            continue
        line = line_at(text, match.start())
        result.dependencies.append(
            _dep(
                name,
                file_path,
                line,
                line_evidence(lines, line, settings),
                extra={"declaration": "pkg_check_modules"},
            )
        )
    return result


def parse_conanfile_txt(text: str, file_path: str, settings: Settings) -> ManifestParse:
    result = ManifestParse()
    lines = text.splitlines()
    section: str | None = None
    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            continue
        if section not in {"requires", "tool_requires", "test_requires"} or not stripped or stripped.startswith("#"):
            continue
        match = _CONAN_TXT_REQ.match(stripped)
        if match is None:
            result.malformed = True
            continue
        name, version, constraint = _conan_spec(match.group("name") + (match.group("rest") or ""))
        dep_type = DependencyType.BUILD if section == "tool_requires" else (
            DependencyType.TEST if section == "test_requires" else DependencyType.RUNTIME
        )
        result.dependencies.append(
            _dep(
                name,
                file_path,
                number,
                line_evidence(lines, number, settings),
                version=version,
                constraint=constraint,
                dependency_type=dep_type,
            )
        )
    return result


def parse_conanfile_py(text: str, file_path: str, settings: Settings) -> ManifestParse:
    """Read literal Conan requires assignments. The file is never executed."""
    result = ManifestParse()
    lines = text.splitlines()
    specs: list[tuple[int, str]] = []
    for match in _CONAN_PY_CALL.finditer(text):
        specs.append((line_at(text, match.start()), match.group("spec")))
    for match in _CONAN_PY_ASSIGN.finditer(text):
        specs.append((line_at(text, match.start()), match.group("spec")))
    for match in _CONAN_PY_LIST.finditer(text):
        start = line_at(text, match.start())
        for item in _CONAN_PY_ITEM.findall(match.group("body")):
            specs.append((start, item))
    if not specs:
        return result
    for line, spec in specs:
        name, version, constraint = _conan_spec(spec)
        if not name:
            continue
        result.dependencies.append(
            _dep(name, file_path, line, line_evidence(lines, line, settings), version=version, constraint=constraint)
        )
    return result


def parse_vcpkg_json(text: str, file_path: str, settings: Settings) -> ManifestParse:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestParse(malformed=True)
    listed = data.get("dependencies", [])
    if listed is None:
        return ManifestParse()
    if not isinstance(listed, list):
        return ManifestParse(malformed=True)
    result = ManifestParse()
    lines = text.splitlines()
    for item in listed:
        name, version, constraint = _vcpkg_item(item)
        if not name:
            continue
        line = _json_name_line(text, name)
        result.dependencies.append(
            _dep(
                name,
                file_path,
                line,
                line_evidence(lines, line, settings),
                version=version,
                constraint=constraint,
                extra={"declaration": "vcpkg.json"},
            )
        )
    return result


def _dep(
    name: str,
    file_path: str,
    line: int,
    evidence: str,
    *,
    version: str | None = None,
    constraint: str | None = None,
    dependency_type: DependencyType = DependencyType.UNKNOWN,
    extra: dict[str, str] | None = None,
) -> DeclaredDependency:
    return DeclaredDependency(
        name=name,
        ecosystem=_CPP,
        manifest_file=file_path,
        source_line=line,
        raw_declaration=evidence,
        version=version,
        version_constraint=constraint,
        dependency_type=dependency_type.value,
        direct_or_transitive=Directness.DIRECT.value,
        metadata=extra or {},
    )


def _balanced_args(text: str, open_index: int) -> str | None:
    if open_index >= len(text) or text[open_index] != "(":
        return None
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index]
    return None


def _cmake_tokens(body: str) -> list[str]:
    return [token for token in re.findall(r"""[^\s"'()]+|"[^"]*"|'[^']*'""", body) if token not in {"", "(", ")"}]


def _cmake_version(tokens: list[str]) -> tuple[str | None, str | None]:
    if not tokens:
        return None, None
    first = tokens[0].strip("\"'")
    if not re.match(r"^\d", first):
        return None, None
    exact = any(token.upper() == "EXACT" for token in tokens)
    if exact:
        return first, None
    return None, first


def _cmake_named(tokens: list[str], key: str) -> str | None:
    for index, token in enumerate(tokens[:-1]):
        if token.upper() == key:
            value = tokens[index + 1].strip("\"'")
            return value or None
    return None


def _conan_spec(spec: str) -> tuple[str, str | None, str | None]:
    cleaned = spec.strip().split("@", 1)[0]
    if "/" not in cleaned:
        return cleaned, None, None
    name, rest = cleaned.split("/", 1)
    rest = rest.strip()
    if not rest:
        return name, None, None
    if rest[0] in "[<>=~^":
        return name, None, rest
    if re.match(r"^\d", rest):
        return name, rest, None
    return name, None, rest


def _vcpkg_item(item: object) -> tuple[str | None, str | None, str | None]:
    if isinstance(item, str):
        return item, None, None
    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
        return None, None, None
    name = item["name"]
    if isinstance(item.get("version"), str):
        return name, item["version"], None
    if isinstance(item.get("version>="), str):
        return name, None, f">={item['version>=']}"
    return name, None, None


def _json_name_line(text: str, name: str) -> int:
    match = re.search(rf'"{re.escape(name)}"', text)
    return line_at(text, match.start()) if match else 1
