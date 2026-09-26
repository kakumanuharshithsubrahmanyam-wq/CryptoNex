"""Source-line language composition from a repository manifest.

Uses the manifest's existing category and detected_language fields. This is
not a second language detector and it is not a security score.
"""

from __future__ import annotations

from app.schemas.project import FileCategory, RepositoryManifest

# Aliases collapse onto the labels already emitted by classify_file.
_CANONICAL = {
    "python": "Python",
    "py": "Python",
    "java": "Java",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "c++": "C++",
    "cpp": "C++",
    "cxx": "C++",
    "cc": "C++",
    "c": "C",
    "rust": "Rust",
    "rs": "Rust",
    "go": "Go",
    "ruby": "Ruby",
    "rb": "Ruby",
    "php": "PHP",
    "c#": "C#",
    "cs": "C#",
    "kotlin": "Kotlin",
    "kt": "Kotlin",
    "swift": "Swift",
    "scala": "Scala",
    "shell": "Shell",
    "sh": "Shell",
}
_GENERATED_PARTS = {"generated", "__pycache__"}


def language_composition(manifest: RepositoryManifest | None) -> dict:
    if manifest is None:
        return {"languages": [], "total_source_files": 0, "total_source_lines": 0}
    chosen: dict[str, tuple[str, int]] = {}
    for record in manifest.files:
        if not _included(record):
            continue
        language = normalize_language(record.detected_language)
        if language is None:
            continue
        path = record.relative_path
        if path in chosen:
            continue
        chosen[path] = (language, record.line_count or 0)

    totals: dict[str, list[int]] = {}
    for language, lines in chosen.values():
        bucket = totals.setdefault(language, [0, 0])
        bucket[0] += 1
        bucket[1] += lines

    ordered = sorted(totals, key=lambda name: (-totals[name][1], name))
    line_counts = [totals[name][1] for name in ordered]
    percentages = _percentages(line_counts)
    languages = [
        {
            "language": name,
            "file_count": totals[name][0],
            "total_lines": totals[name][1],
            "percentage": percentages[index],
        }
        for index, name in enumerate(ordered)
    ]
    return {
        "languages": languages,
        "total_source_files": sum(item["file_count"] for item in languages),
        "total_source_lines": sum(item["total_lines"] for item in languages),
    }


def normalize_language(label: str | None) -> str | None:
    if not label or not label.strip():
        return None
    canonical = _CANONICAL.get(label.strip().lower())
    return canonical


def _included(record) -> bool:
    if record.category != FileCategory.SOURCE:
        return False
    if record.line_count is None:
        return False
    parts = {part.lower() for part in record.relative_path.split("/")}
    if parts & _GENERATED_PARTS:
        return False
    return True


def _percentages(line_counts: list[int]) -> list[float]:
    total = sum(line_counts)
    if total <= 0 or not line_counts:
        return [0.0 for _ in line_counts]
    exact = [count * 1000 / total for count in line_counts]
    floors = [int(value) for value in exact]
    leftover = 1000 - sum(floors)
    order = sorted(
        range(len(line_counts)),
        key=lambda index: (-(exact[index] - floors[index]), -line_counts[index], index),
    )
    for index in order[:leftover]:
        floors[index] += 1
    return [floor / 10 for floor in floors]
