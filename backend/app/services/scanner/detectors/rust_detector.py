"""Rust cryptographic API detection.

Pipeline: source → comment/doc masking → import/path recognition → API
recognition → algorithm resolver → usage resolver → evidence snippet.

Cargo dependencies are handled by the dependency inventory, not here.
"""

from __future__ import annotations

import re

from app.core.config import Settings
from app.services.scanner.detectors.patterns import each_match
from app.services.scanner.detectors.rust_specs import (
    generic_hash,
    known_crate,
    library_label,
    lookup_identifier,
    method_usage,
    normalize_crate,
    spec_family,
)
from app.services.scanner.evidence import mask_comments, snippet
from app.services.scanner.findings import RawFinding

_CALL = re.compile(
    r"(?P<qual>(?:[A-Za-z_][A-Za-z0-9_]*::)+)?"
    r"(?P<ident>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*::\s*<\s*(?P<generic>[A-Za-z_][A-Za-z0-9_]*)\s*>)?"
    r"\s*::\s*(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_USE_SIMPLE = re.compile(
    r"\buse\s+(?P<path>(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*as\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*))?\s*;"
)
_USE_BRACE = re.compile(
    r"\buse\s+(?P<prefix>(?:[A-Za-z_][A-Za-z0-9_]*::)+)\{(?P<body>[^}]+)\}"
)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def detect_rust(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    masked, spans = mask_comments(source, "rust")
    imports = _import_map(source, masked, spans)
    findings: list[RawFinding] = []
    called: set[str] = set()
    for match, line_start, line_end in each_match(source, "rust", _CALL, masked=masked, spans=spans):
        finding = _call_finding(match, imports, source, file_path, settings, line_start, line_end)
        if finding is None:
            continue
        if finding.algorithm:
            called.add(finding.algorithm)
        findings.append(finding)
    for imported in imports:
        if imported.algorithm in called:
            continue
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                imported.line_start,
                imported.line_end,
                algorithm=imported.algorithm,
                family=spec_family(imported.algorithm),
                library=imported.library,
                usage="unknown",
                method="import_detection",
                confidence="medium",
                resolved=True,
                metadata={"import": imported.path},
            )
        )
    return findings


def _call_finding(
    match: re.Match[str],
    imports: list["_Imported"],
    source: str,
    file_path: str,
    settings: Settings,
    line_start: int,
    line_end: int,
) -> RawFinding | None:
    ident = match.group("ident")
    method = match.group("method")
    generic = match.group("generic")
    qual = match.group("qual") or ""
    crate = _crate_from_path(qual)
    alias = _resolve_alias(ident, imports)
    if alias is not None:
        ident = alias.identifier
        crate = crate or alias.crate
    spec = lookup_identifier(ident, crate)
    if spec is None:
        return None
    if method not in spec.methods:
        return None
    if not spec.distinctive and crate is None:
        return None
    if crate and not known_crate(crate) and not spec.distinctive:
        return None
    usage = method_usage(method, spec.usage)
    metadata: dict[str, str] = {}
    hash_name = spec.hash_name or generic_hash(generic)
    if hash_name:
        metadata["hash"] = hash_name
    library = library_label(spec, crate)
    resolved = bool(crate) or spec.distinctive or _imported_crate(spec, imports)
    return _finding(
        source,
        file_path,
        settings,
        line_start,
        line_end,
        algorithm=spec.algorithm,
        family=spec_family(spec.algorithm),
        library=library,
        usage=usage,
        method="api_detection",
        confidence="high",
        key_size=spec.key_size,
        mode=spec.mode,
        resolved=resolved,
        metadata=metadata,
    )


class _Imported:
    __slots__ = ("local", "identifier", "crate", "path", "library", "algorithm", "line_start", "line_end")

    def __init__(
        self,
        local: str,
        identifier: str,
        crate: str | None,
        path: str,
        library: str,
        algorithm: str,
        line_start: int,
        line_end: int,
    ) -> None:
        self.local = local
        self.identifier = identifier
        self.crate = crate
        self.path = path
        self.library = library
        self.algorithm = algorithm
        self.line_start = line_start
        self.line_end = line_end


def _import_map(source: str, masked: str, spans: list[tuple[int, int]]) -> list[_Imported]:
    imported: list[_Imported] = []
    seen: set[tuple[str, str, int]] = set()
    for match, line_start, line_end in each_match(source, "rust", _USE_SIMPLE, masked=masked, spans=spans):
        path = match.group("path")
        ident = path.rsplit("::", 1)[-1]
        local = match.group("alias") or ident
        crate = _crate_from_path(path if "::" in path else f"{path}::")
        spec = lookup_identifier(ident, crate)
        if spec is None or (not spec.distinctive and crate is None):
            continue
        key = (local, spec.algorithm, line_start)
        if key in seen:
            continue
        seen.add(key)
        imported.append(
            _Imported(local, ident, crate, path, library_label(spec, crate), spec.algorithm, line_start, line_end)
        )
    for match, line_start, line_end in each_match(source, "rust", _USE_BRACE, masked=masked, spans=spans):
        prefix = match.group("prefix")
        crate = _crate_from_path(prefix)
        for item in match.group("body").split(","):
            piece = item.strip()
            if not piece or piece == "self":
                continue
            alias_parts = re.split(r"\s+as\s+", piece)
            ident = alias_parts[0].strip().split("::")[-1]
            local = alias_parts[1].strip() if len(alias_parts) > 1 else ident
            if not _IDENT.fullmatch(ident) or not _IDENT.fullmatch(local):
                continue
            spec = lookup_identifier(ident, crate)
            if spec is None:
                continue
            path = f"{prefix}{ident}"
            key = (local, spec.algorithm, line_start)
            if key in seen:
                continue
            seen.add(key)
            imported.append(
                _Imported(local, ident, crate, path, library_label(spec, crate), spec.algorithm, line_start, line_end)
            )
    return imported


def _crate_from_path(path: str) -> str | None:
    if not path:
        return None
    root = path.strip(":").split("::", 1)[0]
    if not root or root in {"crate", "super", "self"}:
        return None
    return root if known_crate(root) else None


def _resolve_alias(ident: str, imports: list[_Imported]) -> _Imported | None:
    for item in imports:
        if item.local == ident or item.identifier == ident:
            return item
    return None


def _imported_crate(spec, imports: list[_Imported]) -> bool:
    crates = {normalize_crate(item) for item in spec.crates}
    return any(item.crate and normalize_crate(item.crate) in crates for item in imports)


def _finding(
    source: str,
    file_path: str,
    settings: Settings,
    line_start: int,
    line_end: int,
    *,
    algorithm: str | None,
    family: str | None,
    library: str | None,
    usage: str,
    method: str,
    confidence: str,
    key_size: int | None = None,
    mode: str | None = None,
    resolved: bool = True,
    metadata: dict[str, str] | None = None,
) -> RawFinding:
    return RawFinding(
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        language="Rust",
        algorithm=algorithm,
        algorithm_family=family,
        library=library,
        library_version=None,
        usage=usage,
        key_size=key_size,
        curve=None,
        mode=mode,
        evidence=snippet(source, line_start, line_end, settings),
        detection_method=method,
        confidence=confidence,
        metadata=metadata or {},
        library_resolved=resolved,
    )
