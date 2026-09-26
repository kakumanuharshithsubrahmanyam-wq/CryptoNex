"""Strip secrets before any payload is sent to an AI provider."""

from __future__ import annotations

from app.services.scanner.evidence import redact_secrets

_SECRET_KEYS = {
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
    "credential",
    "authorization",
    "openai_api_key",
}
_DROP_ARTIFACT_TYPES = {"private_key"}
_MAX_EVIDENCE = 240


def sanitize_text(value: str | None) -> str:
    return redact_secrets(value or "")


def sanitize_value(value):
    if value is None:
        return None
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(token in lowered for token in _SECRET_KEYS):
                cleaned[key] = "[REDACTED]"
                continue
            cleaned[key] = sanitize_value(item)
        return cleaned
    return value


def finding_brief(finding) -> dict:
    evidence = sanitize_text(getattr(finding, "evidence", None))
    if len(evidence) > _MAX_EVIDENCE:
        evidence = evidence[: _MAX_EVIDENCE - 1] + "…"
    return {
        "id": getattr(finding, "id", None),
        "algorithm": getattr(finding, "algorithm", None),
        "usage": getattr(finding, "usage", None),
        "role": getattr(finding, "cryptographic_role", None),
        "library": getattr(finding, "library", None),
        "file_path": getattr(finding, "file_path", None),
        "line_start": getattr(finding, "line_start", None),
        "key_size": getattr(finding, "key_size", None),
        "curve": getattr(finding, "curve", None),
        "mode": getattr(finding, "mode", None),
        "confidence": getattr(finding, "confidence", None),
        "finding_status": getattr(finding, "finding_status", None),
        "security_concern": getattr(finding, "security_concern", None),
        "quantum_relevance": getattr(finding, "quantum_relevance", None),
        "evidence": evidence,
    }


def dependency_brief(dependency) -> dict:
    return {
        "id": getattr(dependency, "id", None),
        "name": getattr(dependency, "name", None),
        "ecosystem": getattr(dependency, "ecosystem", None),
        "version": getattr(dependency, "version", None),
        "crypto_relevance": getattr(dependency, "crypto_relevance", None),
        "manifest_file": getattr(dependency, "manifest_file", None),
        "library": getattr(dependency, "library", None),
    }


def artifact_brief(artifact) -> dict | None:
    artifact_type = getattr(artifact, "artifact_type", None)
    if artifact_type in _DROP_ARTIFACT_TYPES:
        return {
            "id": getattr(artifact, "id", None),
            "artifact_type": artifact_type,
            "file_path": getattr(artifact, "file_path", None),
            "algorithm": getattr(artifact, "algorithm", None),
            "evidence": "[REDACTED PRIVATE KEY BLOCK]",
        }
    return {
        "id": getattr(artifact, "id", None),
        "artifact_type": artifact_type,
        "file_path": getattr(artifact, "file_path", None),
        "protocol": getattr(artifact, "protocol", None),
        "algorithm": getattr(artifact, "algorithm", None),
        "cipher_suite": getattr(artifact, "cipher_suite", None),
        "subject": getattr(artifact, "subject", None),
        "evidence": sanitize_text(getattr(artifact, "evidence", None))[:_MAX_EVIDENCE],
    }


def contains_secret(text: str) -> bool:
    lowered = text.lower()
    if "-----begin" in lowered and "private key" in lowered:
        return True
    if "sk-" in text and len(text) > 20:
        return True
    return any(token in lowered for token in ("api_key", "password=", "token=", "authorization: bearer"))
