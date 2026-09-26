"""Web Crypto and Node.js crypto call detection."""

import re

from app.core.config import Settings
from app.services.scanner.detectors.patterns import each_match
from app.services.scanner.evidence import mask_comments, snippet
from app.services.scanner.findings import RawFinding
from app.services.scanner.registry import ResolvedAlgorithm, resolve_transformation

_SUBTLE = re.compile(
    r"crypto\.subtle\.(encrypt|decrypt|sign|verify|digest|generateKey|deriveKey|deriveBits)\s*\(",
    re.IGNORECASE,
)
_NAME = re.compile(r"""name\s*:\s*["']([^"']+)["']""")
_STRING_ARG = re.compile(r"""\(\s*["']([^"']+)["']""")
_NODE_CALLS = (
    (re.compile(r"""createCipheriv\(\s*["']([^"']+)["']"""), "encryption"),
    (re.compile(r"""createDecipheriv\(\s*["']([^"']+)["']"""), "decryption"),
    (re.compile(r"""createHash\(\s*["']([^"']+)["']"""), "hashing"),
    (re.compile(r"""createHmac\(\s*["']([^"']+)["']"""), "mac"),
    (re.compile(r"""generateKeyPair(?:Sync)?\(\s*["']([^"']+)["']"""), "key_generation"),
    (re.compile(r"""pbkdf2(?:Sync)?\s*\("""), "key_derivation"),
    (re.compile(r"""scrypt(?:Sync)?\s*\("""), "key_derivation"),
    (re.compile(r"""hkdf(?:Sync)?\s*\("""), "key_derivation"),
)
_SUBTLE_USAGE = {
    "encrypt": "encryption",
    "decrypt": "decryption",
    "sign": "signing",
    "verify": "signature_verification",
    "digest": "hashing",
    "generatekey": "key_generation",
    "derivekey": "key_derivation",
    "derivebits": "key_derivation",
}


def detect_javascript(source: str, file_path: str, settings: Settings, language: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for match, line_start, line_end in each_match(source, "c", _SUBTLE):
        window = _window(source, match.start(), match.end())
        algorithm_token = None
        name_match = _NAME.search(window)
        if name_match:
            algorithm_token = name_match.group(1)
        elif match.group(1).lower() == "digest":
            argument = _STRING_ARG.search(window)
            if argument:
                algorithm_token = argument.group(1)
        resolved = resolve_transformation(algorithm_token) if algorithm_token else None
        if resolved is None:
            continue
        usage = _SUBTLE_USAGE[match.group(1).lower()]
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                resolved,
                "Web Crypto",
                usage,
            )
        )

    node_present = _uses_node_crypto(source)
    if not node_present:
        return findings
    for pattern, usage in _NODE_CALLS:
        for match, line_start, line_end in each_match(source, "c", pattern):
            token = match.group(1) if match.lastindex else None
            if token is None and usage == "key_derivation":
                algorithm = "PBKDF2" if "pbkdf2" in match.group(0).lower() else None
                if "scrypt" in match.group(0).lower():
                    algorithm = "scrypt"
                if "hkdf" in match.group(0).lower():
                    algorithm = "HKDF"
                resolved = resolve_transformation(algorithm) if algorithm else None
            else:
                resolved = resolve_transformation(token) if token else None
            if resolved is None:
                continue
            if usage == "mac" and resolved.family == "hash":
                resolved = ResolvedAlgorithm(
                    name="HMAC",
                    family="mac",
                    hash_name=resolved.name,
                )
            findings.append(
                _finding(
                    source,
                    file_path,
                    settings,
                    language,
                    line_start,
                    line_end,
                    resolved,
                    "node:crypto",
                    usage,
                )
            )
    return findings


def _uses_node_crypto(source: str) -> bool:
    masked, _spans = mask_comments(source, "c")
    return bool(
        re.search(r"""require\(\s*["'](?:node:)?crypto["']\s*\)""", masked)
        or re.search(r"""from\s+["'](?:node:)?crypto["']""", masked)
    )


def _window(source: str, start: int, end: int) -> str:
    return source[start : min(len(source), end + 240)]


def _finding(
    source: str,
    file_path: str,
    settings: Settings,
    language: str,
    line_start: int,
    line_end: int,
    resolved,
    library: str,
    usage: str,
) -> RawFinding:
    metadata = {"hash": resolved.hash_name} if resolved.hash_name else {}
    return RawFinding(
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        language=language,
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
