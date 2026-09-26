"""Representative javax.crypto and java.security call detection."""

import re

from app.core.config import Settings
from app.services.scanner.detectors.patterns import each_match
from app.services.scanner.evidence import snippet
from app.services.scanner.findings import RawFinding
from app.services.scanner.registry import resolve_transformation

_CALLS = (
    (
        re.compile(r'Cipher\.getInstance\(\s*"([^"]+)"\s*\)'),
        "javax.crypto",
        "algorithm_selection",
    ),
    (
        re.compile(r'KeyPairGenerator\.getInstance\(\s*"([^"]+)"\s*\)'),
        "java.security",
        "key_generation",
    ),
    (
        re.compile(r'Signature\.getInstance\(\s*"([^"]+)"\s*\)'),
        "java.security",
        "algorithm_selection",
    ),
    (
        re.compile(r'Mac\.getInstance\(\s*"([^"]+)"\s*\)'),
        "javax.crypto",
        "mac",
    ),
    (
        re.compile(r'MessageDigest\.getInstance\(\s*"([^"]+)"\s*\)'),
        "java.security",
        "hashing",
    ),
    (
        re.compile(r'KeyAgreement\.getInstance\(\s*"([^"]+)"\s*\)'),
        "javax.crypto",
        "key_agreement",
    ),
)


def detect_java(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for pattern, library, usage in _CALLS:
        for match, line_start, line_end in each_match(source, "c", pattern):
            resolved = resolve_transformation(match.group(1))
            if resolved is None:
                continue
            metadata = {"hash": resolved.hash_name} if resolved.hash_name else {}
            findings.append(
                RawFinding(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    language="Java",
                    algorithm=resolved.name,
                    algorithm_family=resolved.family,
                    library=library,
                    library_version=None,
                    usage=usage,
                    key_size=resolved.key_size,
                    curve=resolved.curve,
                    mode=resolved.mode,
                    evidence=snippet(source, line_start, line_end, settings),
                    detection_method="api_detection",
                    confidence="high",
                    metadata=metadata,
                )
            )
    return findings
