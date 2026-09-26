"""In-memory finding produced by a detector before it is stored."""

from dataclasses import dataclass, field


@dataclass
class RawFinding:
    file_path: str
    line_start: int
    line_end: int
    language: str | None
    algorithm: str | None
    algorithm_family: str | None
    library: str | None
    library_version: str | None
    usage: str
    key_size: int | None
    curve: str | None
    mode: str | None
    evidence: str
    detection_method: str
    confidence: str
    metadata: dict[str, str] = field(default_factory=dict)

    def dedupe_key(self) -> tuple[str, int, str, str, str, str]:
        return (
            self.file_path,
            self.line_start,
            self.algorithm or "",
            self.library or "",
            self.usage,
            self.detection_method,
        )


_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
_USAGE_RANK = {
    "unknown": 0,
    "dependency_only": 0,
    "algorithm_selection": 1,
}


def prefer(current: RawFinding, candidate: RawFinding) -> RawFinding:
    """Keep the more specific finding when two describe the same line and algorithm."""
    current_rank = (
        _CONFIDENCE_RANK.get(current.confidence, 0),
        _USAGE_RANK.get(current.usage, 2),
    )
    candidate_rank = (
        _CONFIDENCE_RANK.get(candidate.confidence, 0),
        _USAGE_RANK.get(candidate.usage, 2),
    )
    if candidate_rank != current_rank:
        return candidate if candidate_rank > current_rank else current
    if candidate.line_end - candidate.line_start < current.line_end - current.line_start:
        return candidate
    return current
