"""go.mod and go.sum."""

import re

from app.core.config import Settings
from app.services.dependencies.parsers.common import line_evidence
from app.services.dependencies.types import DeclaredDependency, Directness, Ecosystem, ManifestParse

_GO = Ecosystem.GO.value
_REQUIRE_LINE = re.compile(r"^\s*require\s+(\S+)\s+(v\S+)(.*)$")
_BLOCK_ENTRY = re.compile(r"^\s*(\S+)\s+(v\S+)(.*)$")
_SUM_LINE = re.compile(r"^\s*(\S+)\s+(v[^\s/]+)(/go\.mod)?\s+h1:")


def parse_go_mod(text: str, file_path: str, settings: Settings) -> ManifestParse:
    lines = text.splitlines()
    result = ManifestParse()
    in_require = False
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if in_require:
            if stripped.startswith(")"):
                in_require = False
                continue
            match = _BLOCK_ENTRY.match(line)
        elif re.match(r"^require\s*\($", stripped):
            in_require = True
            continue
        else:
            match = _REQUIRE_LINE.match(line)
        if not match or match.group(1).startswith("//"):
            continue
        indirect = re.search(r"//\s*indirect\b", match.group(3) or "") is not None
        result.dependencies.append(
            DeclaredDependency(
                name=match.group(1),
                ecosystem=_GO,
                manifest_file=file_path,
                source_line=number,
                raw_declaration=line_evidence(lines, number, settings),
                version=match.group(2),
                direct_or_transitive=(Directness.TRANSITIVE if indirect else Directness.DIRECT).value,
                metadata={"indirect_comment": "true"} if indirect else {},
            )
        )
    return result


def parse_go_sum(text: str, file_path: str, settings: Settings) -> ManifestParse:
    result = ManifestParse()
    seen: set[tuple[str, str]] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        match = _SUM_LINE.match(line)
        if not match:
            continue
        key = (match.group(1), match.group(2))
        if key in seen:
            continue
        seen.add(key)
        result.dependencies.append(
            DeclaredDependency(
                name=match.group(1),
                ecosystem=_GO,
                manifest_file=file_path,
                source_line=number,
                raw_declaration=line_evidence([f"{match.group(1)} {match.group(2)}"], 1, settings),
                version=match.group(2),
            )
        )
    return result
