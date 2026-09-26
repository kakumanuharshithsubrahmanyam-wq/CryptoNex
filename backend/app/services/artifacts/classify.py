"""Deterministic repository-context and identity for security artifacts.

Classification uses path and artifact type only. A file is never labeled
production because it is outside a test directory.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.services.artifacts.types import RawArtifact

_TEST_PARTS = {
    "test",
    "tests",
    "testdata",
    "test_data",
    "testing",
    "fixtures",
    "golden",
    "unit_tests",
    "integration_tests",
}
_EXAMPLE_PARTS = {"example", "examples", "sample", "samples", "demo", "demos"}
_GENERATED_PARTS = {"generated", "gen", "corpus", "fuzz", "fuzzing"}
_CONFIG_PARTS = {"config", "configs", "conf"}
_CONFIG_SUFFIXES = {".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".cnf", ".properties", ".env"}
_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".py",
    ".java",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
}
_KIND = {
    "certificate": "certificate_material",
    "private_key": "key_material",
    "public_key": "key_material",
    "ssh_key": "key_material",
    "keystore": "keystore",
    "truststore": "keystore",
    "protocol": "protocol_metadata",
    "ssh_config": "protocol_metadata",
    "cipher_suite": "cipher_suite",
}


def annotate_artifact(artifact: RawArtifact) -> RawArtifact:
    artifact.metadata = {
        **artifact.metadata,
        "repository_context": repository_context(artifact.file_path),
        "artifact_kind": artifact_kind(artifact.artifact_type),
        "content_fingerprint": content_fingerprint(artifact),
    }
    return artifact


def repository_context(file_path: str) -> str:
    parts = {part.lower() for part in Path(file_path).parts}
    name = Path(file_path).name.lower()
    test_path = parts & _TEST_PARTS or name.startswith("test_") or "_test." in name or name.endswith("_test")
    generated_path = bool(parts & _GENERATED_PARTS) or "generated" in name
    if test_path and generated_path:
        return "generated_test_data"
    if generated_path and not test_path:
        return "generated_test_data"
    if test_path:
        return "test_fixture"
    if parts & _EXAMPLE_PARTS:
        return "example"
    suffix = Path(file_path).suffix.lower()
    if parts & _CONFIG_PARTS or suffix in _CONFIG_SUFFIXES:
        return "configuration"
    if suffix in _SOURCE_SUFFIXES:
        return "source"
    return "unknown"


def artifact_kind(artifact_type: str) -> str:
    return _KIND.get(artifact_type, "unknown")


def content_fingerprint(artifact: RawArtifact) -> str:
    if artifact.artifact_type in {"certificate", "private_key", "public_key", "ssh_key"}:
        payload = {
            "artifact_type": artifact.artifact_type,
            "algorithm": artifact.algorithm or "",
            "key_size": artifact.key_size,
            "curve": artifact.curve or "",
            "subject": artifact.subject or "",
            "issuer": artifact.issuer or "",
            "serial_number": artifact.serial_number or "",
            "validity_start": artifact.validity_start or "",
            "validity_end": artifact.validity_end or "",
            "format": artifact.format or "",
            "pem_label": artifact.metadata.get("pem_label", ""),
        }
    else:
        payload = {
            "artifact_type": artifact.artifact_type,
            "file_path": artifact.file_path,
            "protocol": artifact.protocol or "",
            "cipher_suite": artifact.cipher_suite or "",
            "algorithm": artifact.algorithm or "",
            "tls_version": artifact.metadata.get("tls_version", ""),
            "ssh_algorithm": artifact.metadata.get("ssh_algorithm", ""),
            "evidence": " ".join((artifact.evidence or "").split()),
        }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
