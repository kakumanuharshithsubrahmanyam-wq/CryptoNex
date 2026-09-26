"""Persist Phase 5 artifacts."""

import hashlib
import json

from app.models.artifact import SecurityArtifact
from app.services.artifacts.types import RawArtifact


def artifact_row(project_id: int, scan_id: int, artifact: RawArtifact) -> SecurityArtifact:
    payload = {
        "file_path": artifact.file_path,
        "line_start": artifact.line_start,
        "artifact_type": artifact.artifact_type,
        "protocol": artifact.protocol,
        "algorithm": artifact.algorithm,
        "cipher_suite": artifact.cipher_suite,
        "format": artifact.format,
        "serial_number": artifact.serial_number,
        "tls_version": artifact.metadata.get("tls_version"),
        "ssh_algorithm": artifact.metadata.get("ssh_algorithm"),
        "reference": artifact.metadata.get("reference"),
        "observed": artifact.metadata.get("observed"),
    }
    return SecurityArtifact(
        project_id=project_id,
        scan_id=scan_id,
        artifact_type=artifact.artifact_type,
        file_path=artifact.file_path,
        line_start=artifact.line_start,
        line_end=artifact.line_end,
        protocol=artifact.protocol,
        format=artifact.format,
        algorithm=artifact.algorithm,
        key_size=artifact.key_size,
        curve=artifact.curve,
        subject=artifact.subject,
        issuer=artifact.issuer,
        serial_number=artifact.serial_number,
        validity_start=artifact.validity_start,
        validity_end=artifact.validity_end,
        cipher_suite=artifact.cipher_suite,
        evidence=artifact.evidence[:512],
        detection_method=artifact.detection_method,
        confidence=artifact.confidence,
        metadata_json=json.dumps(artifact.metadata, sort_keys=True),
        fingerprint=hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest(),
    )
