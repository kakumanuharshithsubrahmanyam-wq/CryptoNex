"""In-memory security artifacts produced by Phase 5 detectors."""

from dataclasses import dataclass, field
from enum import Enum


class ArtifactType(str, Enum):
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"
    KEYSTORE = "keystore"
    TRUSTSTORE = "truststore"
    PROTOCOL = "protocol"
    CIPHER_SUITE = "cipher_suite"
    SSH_KEY = "ssh_key"
    SSH_CONFIG = "ssh_config"


class ArtifactFormat(str, Enum):
    PEM = "PEM"
    DER = "DER"
    PKCS12 = "PKCS#12"
    JKS = "JKS"
    JCEKS = "JCEKS"
    OPENSSH = "OPENSSH"
    SSH_PUBLIC = "SSH_PUBLIC"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


@dataclass
class RawArtifact:
    artifact_type: str
    file_path: str
    line_start: int
    line_end: int
    protocol: str | None = None
    format: str | None = None
    algorithm: str | None = None
    key_size: int | None = None
    curve: str | None = None
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    validity_start: str | None = None
    validity_end: str | None = None
    cipher_suite: str | None = None
    evidence: str = ""
    detection_method: str = "pattern_detection"
    confidence: str = "medium"
    metadata: dict[str, str] = field(default_factory=dict)

    def dedupe_key(self) -> tuple:
        return (
            self.file_path,
            self.line_start,
            self.artifact_type,
            self.protocol or "",
            self.algorithm or "",
            self.cipher_suite or "",
            self.format or "",
            self.serial_number or "",
            self.metadata.get("tls_version", ""),
            self.metadata.get("ssh_algorithm", ""),
            self.metadata.get("observed", ""),
            self.metadata.get("reference", ""),
        )
