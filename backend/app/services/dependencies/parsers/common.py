"""Helpers shared by manifest parsers.

Structured formats are read with the standard library's data parsers
(json, tomllib, ElementTree). None of them evaluate code.
"""

import json
import re
import tomllib
from typing import Any

from app.core.config import Settings
from app.services.dependencies.types import DeclaredDependency
from app.services.scanner.evidence import bounded


def load_json(text: str) -> Any | None:
    try:
        return json.loads(text)
    except ValueError:
        return None


def load_toml(text: str) -> dict[str, Any] | None:
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None


def line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def find_offset(text: str, pattern: str, start: int = 0, flags: int = 0) -> int | None:
    match = re.compile(pattern, flags).search(text, start)
    return match.start() if match else None


def token_pattern(name: str) -> str:
    return rf"(?<![A-Za-z0-9_.\-/@]){re.escape(name)}(?![A-Za-z0-9_.\-/])"


def line_of_token(text: str, name: str, start: int = 0) -> int:
    offset = find_offset(text, token_pattern(name), start, re.IGNORECASE)
    if offset is None and start:
        offset = find_offset(text, token_pattern(name), 0, re.IGNORECASE)
    return line_at(text, offset) if offset is not None else 1


def section_offset(text: str, header: str) -> int:
    offset = find_offset(text, rf"(?m)^\s*\[{re.escape(header)}\]\s*$")
    return offset or 0


def line_evidence(lines: list[str], line: int, settings: Settings) -> str:
    if 1 <= line <= len(lines):
        return bounded(lines[line - 1], settings)
    return ""


def block_evidence(lines: list[str], line: int, settings: Settings, max_lines: int = 6) -> str:
    """Evidence for a lockfile entry: its first line through the line naming its version."""
    if not 1 <= line <= len(lines):
        return ""
    end = line
    for candidate in range(line, min(len(lines), line + max_lines - 1) + 1):
        end = candidate
        if candidate > line and "version" in lines[candidate - 1].lower():
            break
    else:
        end = line
    selected = [text.strip() for text in lines[line - 1 : end] if text.strip()]
    return bounded("\n".join(selected), settings)


def package_name_lines(lines: list[str]) -> list[int]:
    """Line numbers of the name key in each [[package]] table, in file order."""
    found: list[int] = []
    waiting = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped == "[[package]]":
            waiting = True
            continue
        if waiting and re.match(r"""^name\s*=\s*["']""", stripped):
            found.append(number)
            waiting = False
    return found


def dict_items(value: Any) -> list[tuple[str, Any]]:
    if not isinstance(value, dict):
        return []
    return [(str(key), item) for key, item in value.items()]


def dedupe_in_file(dependencies: list[DeclaredDependency]) -> list[DeclaredDependency]:
    """Collapse identical declarations of one package within a single manifest."""
    chosen: dict[tuple, DeclaredDependency] = {}
    for dependency in dependencies:
        key = (
            dependency.ecosystem,
            dependency.normalized_name,
            dependency.version or "",
            dependency.version_constraint or "",
        )
        existing = chosen.get(key)
        if existing is None:
            chosen[key] = dependency
            continue
        existing.requires = tuple(sorted(set(existing.requires) | set(dependency.requires)))
        existing.required_by = tuple(sorted(set(existing.required_by) | set(dependency.required_by)))
        if dependency.source_line < existing.source_line:
            existing.source_line = dependency.source_line
            existing.raw_declaration = dependency.raw_declaration
    return sorted(chosen.values(), key=lambda item: (item.source_line, item.normalized_name))
