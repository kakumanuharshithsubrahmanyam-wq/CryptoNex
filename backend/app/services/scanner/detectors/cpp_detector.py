"""Representative OpenSSL API detection for C and C++."""

import re

from app.core.config import Settings
from app.services.scanner.detectors.patterns import each_match
from app.services.scanner.evidence import snippet
from app.services.scanner.findings import RawFinding
from app.services.scanner.registry import lookup_curve, resolve_transformation

_EVP_CIPHER = re.compile(
    r"EVP_(Encrypt|Decrypt)Init_ex\s*\([^;]*EVP_aes_(\d+)_(gcm|cbc|ctr)\s*\(",
    re.DOTALL,
)
_EVP_DIGEST = re.compile(r"EVP_DigestInit_ex\s*\([^;]*EVP_(sha256|sha1|sha512|md5)\s*\(", re.DOTALL)
_RSA = re.compile(r"RSA_generate_key_ex\s*\(\s*[^,]+,\s*(\d+)\s*,")
_EC = re.compile(r"EC_KEY_new_by_curve_name\s*\(\s*(NID_[A-Za-z0-9_]+)\s*\)")
_DIGESTS = {
    "sha256": "SHA-256",
    "sha1": "SHA-1",
    "sha512": "SHA-512",
    "md5": "MD5",
}


def detect_cpp(source: str, file_path: str, settings: Settings, language: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for match, line_start, line_end in each_match(source, "c", _EVP_CIPHER):
        operation, bits, mode = match.group(1), match.group(2), match.group(3)
        usage = "encryption" if operation == "Encrypt" else "decryption"
        resolved = resolve_transformation(f"AES-{bits}-{mode}")
        if resolved is None:
            continue
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                "AES",
                "symmetric",
                usage,
                "high",
                key_size=resolved.key_size,
                mode=resolved.mode,
            )
        )
    for match, line_start, line_end in each_match(source, "c", _EVP_DIGEST):
        algorithm = _DIGESTS[match.group(1)]
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                algorithm,
                "hash",
                "hashing",
                "high",
            )
        )
    for match, line_start, line_end in each_match(source, "c", _RSA):
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                "RSA",
                "asymmetric",
                "key_generation",
                "high",
                key_size=int(match.group(1)),
            )
        )
    for match, line_start, line_end in each_match(source, "c", _EC):
        curve = lookup_curve(match.group(1))
        if curve is None:
            continue
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                None,
                None,
                "key_generation",
                "high",
                curve=curve,
            )
        )
    return findings


def _finding(
    source: str,
    file_path: str,
    settings: Settings,
    language: str,
    line_start: int,
    line_end: int,
    algorithm: str | None,
    family: str | None,
    usage: str,
    confidence: str,
    key_size: int | None = None,
    mode: str | None = None,
    curve: str | None = None,
) -> RawFinding:
    return RawFinding(
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        language=language,
        algorithm=algorithm,
        algorithm_family=family,
        library="OpenSSL",
        library_version=None,
        usage=usage,
        key_size=key_size,
        curve=curve,
        mode=mode,
        evidence=snippet(source, line_start, line_end, settings),
        detection_method="api_detection",
        confidence=confidence,
        metadata={},
    )
