"""Choose certificate and protocol detectors for one repository file."""

from pathlib import Path

from app.core.config import Settings
from app.services.artifacts.certificates import (
    detect_certificate_bytes,
    detect_certificate_text,
    is_binary_container_name,
    is_certificate_name,
)
from app.services.artifacts.types import RawArtifact
from app.services.artifacts.protocols import detect_protocols

_CONFIG_STYLE = {
    ".py": "python",
    ".properties": "python",
    ".yml": "python",
    ".yaml": "python",
    ".conf": "python",
    ".cnf": "python",
    ".ini": "python",
    ".env": "python",
    ".cfg": "python",
    ".java": "c",
    ".js": "c",
    ".ts": "c",
    ".go": "c",
    ".c": "c",
    ".cpp": "c",
    ".h": "c",
    ".xml": "c",
}

_SSH_NAMES = {
    "ssh_config",
    "sshd_config",
    "authorized_keys",
    "known_hosts",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
    "id_ecdsa",
    "id_ecdsa.pub",
    "id_dsa",
    "id_dsa.pub",
}


def comment_style(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    return _CONFIG_STYLE.get(suffix, "python")


def detect_text_artifacts(source: str, file_path: str, settings: Settings) -> list[RawArtifact]:
    artifacts = detect_certificate_text(source, file_path, settings)
    artifacts.extend(detect_protocols(source, file_path, settings, comment_style(file_path)))
    return _dedupe(artifacts)


def detect_binary_artifacts(data: bytes, file_path: str, settings: Settings) -> list[RawArtifact]:
    return _dedupe(detect_certificate_bytes(data, file_path, settings))


_PROTOCOL_SUFFIXES = {".xml", ".properties", ".conf", ".cnf", ".pub"}


def is_artifact_filename(file_path: str) -> bool:
    name = Path(file_path).name.lower()
    suffix = Path(file_path).suffix.lower()
    parts = {part.lower() for part in Path(file_path).parts}
    return (
        is_certificate_name(file_path)
        or is_binary_container_name(file_path)
        or name in _SSH_NAMES
        or suffix in _PROTOCOL_SUFFIXES
        or ".ssh" in parts
        or "ssh" in parts
    )


def _dedupe(artifacts: list[RawArtifact]) -> list[RawArtifact]:
    chosen: dict[tuple, RawArtifact] = {}
    for artifact in artifacts:
        key = artifact.dedupe_key()
        if key not in chosen:
            chosen[key] = artifact
    return sorted(chosen.values(), key=lambda item: (item.file_path, item.line_start, item.artifact_type))
