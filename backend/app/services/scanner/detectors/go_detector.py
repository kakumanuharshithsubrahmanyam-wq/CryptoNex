"""Go standard-library crypto package and call detection."""

import re

from app.core.config import Settings
from app.services.scanner.detectors.patterns import each_match
from app.services.scanner.evidence import snippet
from app.services.scanner.findings import RawFinding

_IMPORTS = {
    "crypto/rsa": ("RSA", "asymmetric", "crypto/rsa"),
    "crypto/aes": ("AES", "symmetric", "crypto/aes"),
    "crypto/ecdsa": ("ECDSA", "asymmetric", "crypto/ecdsa"),
    "crypto/ed25519": ("Ed25519", "asymmetric", "crypto/ed25519"),
    "crypto/sha256": ("SHA-256", "hash", "crypto/sha256"),
    "crypto/sha1": ("SHA-1", "hash", "crypto/sha1"),
    "crypto/md5": ("MD5", "hash", "crypto/md5"),
    "crypto/hmac": ("HMAC", "mac", "crypto/hmac"),
}
_CALLS = (
    (re.compile(r"\brsa\.GenerateKey\s*\("), "RSA", "asymmetric", "crypto/rsa", "key_generation"),
    (re.compile(r"\baes\.NewCipher\s*\("), "AES", "symmetric", "crypto/aes", "algorithm_selection"),
    (re.compile(r"\becdsa\.GenerateKey\s*\("), "ECDSA", "asymmetric", "crypto/ecdsa", "key_generation"),
    (re.compile(r"\bed25519\.GenerateKey\s*\("), "Ed25519", "asymmetric", "crypto/ed25519", "key_generation"),
    (re.compile(r"\bsha256\.New\s*\("), "SHA-256", "hash", "crypto/sha256", "hashing"),
    (re.compile(r"\bsha1\.New\s*\("), "SHA-1", "hash", "crypto/sha1", "hashing"),
    (re.compile(r"\bmd5\.New\s*\("), "MD5", "hash", "crypto/md5", "hashing"),
    (re.compile(r"\bhmac\.New\s*\("), "HMAC", "mac", "crypto/hmac", "mac"),
    (
        re.compile(r"\bchacha20poly1305\.New\s*\("),
        "ChaCha20-Poly1305",
        "symmetric",
        "golang.org/x/crypto/chacha20poly1305",
        "algorithm_selection",
    ),
)
_IMPORT_DECLARATION = re.compile(r'\bimport\s*(?:\([^)]*\)|(?:[\w.]+\s+)?"[^"\n]*")')
_IMPORT_PATH = re.compile(r'"(crypto/[a-z0-9]+)"')


def detect_go(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    findings: list[RawFinding] = []
    called_algorithms: set[str] = set()
    for pattern, algorithm, family, library, usage in _CALLS:
        for _match, line_start, line_end in each_match(source, "go", pattern):
            called_algorithms.add(algorithm)
            findings.append(
                _finding(
                    source,
                    file_path,
                    settings,
                    line_start,
                    line_end,
                    algorithm,
                    family,
                    library,
                    usage,
                    "high",
                    "api_detection",
                )
            )
    for package, line_start, line_end in _imports(source):
        spec = _IMPORTS.get(package)
        if spec is None or spec[0] in called_algorithms:
            continue
        algorithm, family, library = spec
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                line_start,
                line_end,
                algorithm,
                family,
                library,
                "unknown",
                "medium",
                "import_detection",
            )
        )
    return findings


def _imports(source: str):
    """Yield (package, line_start, line_end) for paths inside import declarations."""
    for match, _line_start, _line_end in each_match(source, "go", _IMPORT_DECLARATION):
        block = match.group(0)
        for path in _IMPORT_PATH.finditer(block):
            offset = match.start() + path.start()
            line = source.count("\n", 0, offset) + 1
            yield path.group(1), line, line


def _finding(
    source: str,
    file_path: str,
    settings: Settings,
    line_start: int,
    line_end: int,
    algorithm: str,
    family: str,
    library: str,
    usage: str,
    confidence: str,
    method: str,
) -> RawFinding:
    return RawFinding(
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        language="Go",
        algorithm=algorithm,
        algorithm_family=family,
        library=library,
        library_version=None,
        usage=usage,
        key_size=None,
        curve=None,
        mode=None,
        evidence=snippet(source, line_start, line_end, settings),
        detection_method=method,
        confidence=confidence,
        metadata={},
    )
