"""Path containment for ingested workspace snapshots."""

from pathlib import Path


def resolve_source_file(source_root: Path, relative: str) -> Path | None:
    if not relative or relative.startswith(("/", "\\")):
        return None
    parts = relative.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts if part in {".."}):
        return None
    if ".." in parts:
        return None
    root = source_root.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        return None
    if not candidate.is_file() or candidate.is_symlink():
        return None
    return candidate
