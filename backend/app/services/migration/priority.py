"""Explainable migration priority. Categories are labels, not a numeric score."""

from __future__ import annotations

from app.services.migration.registry import (
    KEY_ESTABLISHMENT_ALGORITHMS,
    KEY_ESTABLISHMENT_ROLE,
    LEGACY_CIPHER,
    LEGACY_HASH,
    LEGACY_WEAK,
    MODERN_HASH,
    MODERN_SYMMETRIC,
    MULTI_ROLE_ALGORITHMS,
    SIGNATURE_ALGORITHMS,
    SIGNATURE_ROLE,
    advise,
    canonical_algorithm,
    infer_role,
)

PRIORITY_ORDER = ("critical", "high", "medium", "low", "informational")


def prioritize(finding, artifacts: list | None = None) -> tuple[str, list[str]]:
    advice = advise(finding)
    algorithm = canonical_algorithm(getattr(finding, "algorithm", None))
    role = infer_role(finding)
    reasons: list[str] = []
    artifacts = artifacts or []
    key_size = getattr(finding, "key_size", None)
    confidence = getattr(finding, "confidence", None)
    status = getattr(finding, "finding_status", None)
    usage = getattr(finding, "usage", None)
    file_path = getattr(finding, "file_path", None)

    if algorithm in LEGACY_WEAK or algorithm in {"MD5", "DES"}:
        reasons.append("weak/legacy algorithm")
        reasons.append(f"{algorithm} is a broken or legacy primitive")
        return "critical", reasons
    if algorithm == "SHA-1" or algorithm in LEGACY_HASH:
        reasons.append("legacy hash")
        reasons.append(f"{algorithm} is a weak/legacy algorithm")
        return "high", reasons
    if algorithm in LEGACY_CIPHER:
        reasons.append("legacy cipher")
        reasons.append(f"{algorithm} is a weak/legacy algorithm")
        return "high", reasons
    if algorithm == "RSA" and key_size is not None and key_size < 2048:
        reasons.append("classical public-key cryptography")
        reasons.append("explicit weak parameters")
        reasons.append(f"explicit RSA-{key_size} parameter")
        return "critical", reasons

    if advice.category in {"modern_symmetric", "modern_hash", "mac"}:
        if algorithm in MODERN_SYMMETRIC:
            reasons.append("modern symmetric primitive")
        elif algorithm in MODERN_HASH:
            reasons.append("modern hash")
        else:
            reasons.append("modern authentication primitive")
        reasons.append("migration priority differs from public-key cryptography")
        return "informational", reasons

    if advice.category == "key_derivation":
        reasons.append("key-derivation primitive")
        return "low", reasons

    if algorithm in MULTI_ROLE_ALGORITHMS or algorithm in SIGNATURE_ALGORITHMS or algorithm in KEY_ESTABLISHMENT_ALGORITHMS:
        reasons.append("classical public-key cryptography")
        if role == SIGNATURE_ROLE or algorithm in SIGNATURE_ALGORITHMS:
            reasons.append("classical signature")
        if role == KEY_ESTABLISHMENT_ROLE or algorithm in KEY_ESTABLISHMENT_ALGORITHMS:
            reasons.append("used in key establishment" if role == KEY_ESTABLISHMENT_ROLE else "classical key establishment")
        if algorithm == "RSA" and role == SIGNATURE_ROLE:
            reasons.append("classical signature")
        if key_size is not None:
            reasons.append(f"explicit {algorithm}-{key_size} parameter")
        curve = getattr(finding, "curve", None)
        if curve:
            reasons.append(f"explicit curve {curve}")
        if _has_protocol_or_certificate_context(finding, artifacts):
            reasons.append("certificate/protocol usage")
        if usage == "dependency_only" or status == "weak_signal":
            reasons.append("evidence confidence is limited")
            return "medium", _unique(reasons)
        if status == "probable" or confidence == "medium":
            reasons.append("evidence confidence is medium")
            return "high", _unique(reasons)
        if confidence == "low":
            reasons.append("evidence confidence is low")
            return "medium", _unique(reasons)
        return "high", _unique(reasons)

    if usage == "dependency_only":
        reasons.append("dependency presence without a confirmed algorithm")
        return "low", reasons
    if file_path:
        reasons.append("algorithm family is not a defined public-key migration target")
        return "low", reasons
    return "informational", ["insufficient evidence for a higher migration priority"]


def _has_protocol_or_certificate_context(finding, artifacts: list) -> bool:
    path = getattr(finding, "file_path", None)
    algorithm = canonical_algorithm(getattr(finding, "algorithm", None))
    for artifact in artifacts:
        artifact_type = getattr(artifact, "artifact_type", None)
        if artifact_type not in {"certificate", "protocol", "cipher_suite", "ssh_config", "ssh_key"}:
            continue
        same_file = path and getattr(artifact, "file_path", None) == path
        same_algorithm = algorithm and getattr(artifact, "algorithm", None) == algorithm
        if same_file or same_algorithm:
            return True
    return False


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
