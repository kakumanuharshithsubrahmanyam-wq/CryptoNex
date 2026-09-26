"""Apply a stored unified diff inside an isolated snapshot.

This does not invoke the system patch command, a shell, or repository code.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import Settings
from app.services.scanner.evidence import redact_secrets

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_MAX_FILES = 32
_MAX_HUNKS = 200


class PatchApplyError(Exception):
    def __init__(self, messages: list[str]) -> None:
        super().__init__("; ".join(messages))
        self.messages = messages


def apply_unified_diff(root: Path, diff_text: str | None, settings: Settings) -> None:
    errors = _validate_and_plan(root, diff_text, settings)
    if errors:
        raise PatchApplyError(errors)
    planned = _parse(diff_text or "")
    for relative, hunks in planned:
        target = _contained_file(root, relative)
        if target is None:
            raise PatchApplyError([f"path is not inside the isolated snapshot: {relative}"])
        original = target.read_text(encoding="utf-8")
        try:
            updated = _apply_hunks(original, hunks)
        except ValueError as exc:
            raise PatchApplyError([str(exc)]) from exc
        target.write_text(updated, encoding="utf-8")


def _validate_and_plan(root: Path, diff_text: str | None, settings: Settings) -> list[str]:
    if not diff_text or not diff_text.startswith("--- "):
        return ["patch is missing a unified diff"]
    encoded = diff_text.encode("utf-8")
    if len(encoded) > settings.max_patch_bytes:
        return ["patch exceeds configured size limit"]
    if redact_secrets(diff_text) != diff_text:
        return ["patch contains redacted secret material"]
    try:
        planned = _parse(diff_text)
    except ValueError as exc:
        return [str(exc)]
    if not planned:
        return ["patch does not modify a file"]
    if len(planned) > _MAX_FILES:
        return ["patch touches more files than the verification limit"]
    errors: list[str] = []
    for relative, hunks in planned:
        if len(hunks) > _MAX_HUNKS:
            errors.append("patch contains too many hunks")
        if _path_rejected(relative):
            errors.append(f"rejected path: {relative}")
            continue
        target = _contained_file(root, relative)
        if target is None:
            errors.append(f"path is outside the ingested snapshot: {relative}")
    return errors


def _parse(diff_text: str) -> list[tuple[str, list[tuple[int, list[str]]]]]:
    lines = diff_text.splitlines(keepends=True)
    planned: list[tuple[str, list[tuple[int, list[str]]]]] = []
    index = 0
    while index < len(lines):
        if not lines[index].startswith("--- "):
            index += 1
            continue
        if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
            raise ValueError("unified diff is missing a +++ header")
        relative = _relative_path(lines[index + 1][4:])
        index += 2
        hunks: list[tuple[int, list[str]]] = []
        while index < len(lines) and lines[index].startswith("@@"):
            header = _HUNK.match(lines[index].rstrip("\r\n"))
            if header is None:
                raise ValueError("unified diff hunk header is malformed")
            old_start = int(header.group(1))
            index += 1
            body: list[str] = []
            while index < len(lines) and not lines[index].startswith(("@@", "--- ")):
                body.append(lines[index])
                index += 1
            hunks.append((old_start, body))
        if not hunks:
            raise ValueError("unified diff file has no hunks")
        planned.append((relative, hunks))
    return planned


def _apply_hunks(original: str, hunks: list[tuple[int, list[str]]]) -> str:
    lines = original.splitlines(keepends=True)
    offset = 0
    for old_start, body in hunks:
        expected: list[str] = []
        replacement: list[str] = []
        for raw in body:
            if raw.startswith("\\"):
                continue
            if not raw:
                continue
            marker, content = raw[0], raw[1:]
            if marker == " ":
                expected.append(content)
                replacement.append(content)
            elif marker == "-":
                expected.append(content)
            elif marker == "+":
                replacement.append(content)
            else:
                raise ValueError("unified diff contains an unsupported hunk line")
        index = old_start - 1 + offset
        window = lines[index : index + len(expected)]
        if [_normalize(item) for item in window] != [_normalize(item) for item in expected]:
            raise ValueError("patch context does not match the isolated snapshot")
        lines[index : index + len(expected)] = replacement
        offset += len(replacement) - len(expected)
    return "".join(lines)


def _normalize(line: str) -> str:
    return line.rstrip("\r\n")


def _relative_path(header: str) -> str:
    token = header.strip().split("\t", 1)[0].strip()
    if token in {"/dev/null", "dev/null"}:
        raise ValueError("creating or deleting files is not supported")
    if token.startswith(("a/", "b/")):
        token = token[2:]
    return token


def _path_rejected(relative: str) -> bool:
    if not relative or relative.startswith(("/", "\\")):
        return True
    parts = relative.replace("\\", "/").split("/")
    return any(part in {"", ".", ".."} for part in parts)


def _contained_file(root: Path, relative: str) -> Path | None:
    if _path_rejected(relative):
        return None
    base = root.resolve()
    candidate = (base / relative).resolve()
    if not candidate.is_relative_to(base):
        return None
    if candidate.is_symlink() or not candidate.is_file():
        return None
    return candidate
