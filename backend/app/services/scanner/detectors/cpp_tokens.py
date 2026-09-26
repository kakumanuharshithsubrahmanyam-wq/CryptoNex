"""Parse explicit C/C++ factory and constructor algorithm tokens.

Tokens are accepted only when they name a registry algorithm. Curve names
are not turned into algorithms. Nested factory names such as HMAC(SHA-256)
keep the outer primitive as the algorithm.
"""

from __future__ import annotations

import re

from app.services.scanner.registry import lookup_algorithm

_AES_SIZED = re.compile(r"^AES-(\d+)(?:/([A-Za-z0-9]+))?(?:/.*)?$", re.IGNORECASE)
_NESTED = re.compile(r"^([A-Za-z][A-Za-z0-9_+-]*)\((.+)\)$")
_CHACHA = re.compile(r"^ChaCha(?:20)?(?:\((\d+)\))?$", re.IGNORECASE)
_KNOWN_MODES = {"GCM", "CBC", "CTR", "ECB", "CFB", "OFB", "CCM"}


def parse_explicit_token(token: str) -> dict | None:
    cleaned = token.strip()
    if not cleaned:
        return None

    aes = _AES_SIZED.match(cleaned)
    if aes:
        mode = aes.group(2).upper() if aes.group(2) and aes.group(2).upper() in _KNOWN_MODES else None
        return _result("AES", key_size=int(aes.group(1)), mode=mode)

    chacha = _CHACHA.match(cleaned)
    if chacha:
        rounds = chacha.group(1)
        if rounds and rounds != "20":
            return None
        return _result("ChaCha20")

    nested = _NESTED.match(cleaned)
    if nested:
        return _nested(nested.group(1), nested.group(2))

    compact = cleaned.replace("_", "-")
    if compact.lower() in {"chacha20poly1305", "chacha20-poly1305"}:
        return _result("ChaCha20-Poly1305")
    if compact.lower() in {"tripledes", "3des", "des-ede3", "des-ede"}:
        return _result("3DES")

    spec = lookup_algorithm(cleaned)
    if spec is None:
        return None
    return _result(spec.canonical_name)


def _nested(outer: str, inner: str) -> dict | None:
    spec = lookup_algorithm(outer)
    if spec is None:
        if outer.lower() in {"chacha20poly1305", "chacha20-poly1305"}:
            return _result("ChaCha20-Poly1305")
        return None
    parsed = _result(spec.canonical_name)
    inner_name = _inner_algorithm(inner)
    if spec.canonical_name == "HMAC" and inner_name and _is_hash(inner_name):
        parsed["hash"] = inner_name
    if spec.canonical_name in {"HKDF", "PBKDF2"} and inner_name and _is_hash(inner_name):
        parsed["hash"] = inner_name
    if spec.canonical_name == "CMAC" and inner_name:
        parsed["cipher"] = inner_name
    return parsed


def _inner_algorithm(token: str) -> str | None:
    spec = lookup_algorithm(token)
    if spec is not None:
        return spec.canonical_name
    parsed = parse_explicit_token(token)
    return parsed["algorithm"] if parsed else None


def _is_hash(name: str) -> bool:
    spec = lookup_algorithm(name)
    return spec is not None and spec.family == "hash"


def _result(
    algorithm: str,
    *,
    key_size: int | None = None,
    mode: str | None = None,
) -> dict:
    spec = lookup_algorithm(algorithm)
    assert spec is not None
    return {
        "algorithm": spec.canonical_name,
        "family": spec.family,
        "key_size": key_size,
        "mode": mode,
    }
