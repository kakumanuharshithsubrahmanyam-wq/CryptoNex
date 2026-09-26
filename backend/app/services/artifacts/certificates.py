"""Certificate and key artifact detection from file content and names."""

from pathlib import Path

from app.core.config import Settings
from app.services.artifacts.der import (
    decode_pem_blocks,
    parse_certificate,
    parse_pkcs1_ec_key,
    parse_pkcs1_rsa_key,
    parse_pkcs8_key,
)
from app.services.artifacts.types import ArtifactFormat, ArtifactType, RawArtifact
from app.services.scanner.evidence import bounded, redact_secrets

_PEM_CERT_LABELS = {"CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"}
_PEM_PRIVATE = {
    "PRIVATE KEY": parse_pkcs8_key,
    "ENCRYPTED PRIVATE KEY": None,
    "RSA PRIVATE KEY": parse_pkcs1_rsa_key,
    "EC PRIVATE KEY": parse_pkcs1_ec_key,
    "DSA PRIVATE KEY": None,
    "OPENSSH PRIVATE KEY": None,
}
_PEM_PUBLIC = {"PUBLIC KEY", "RSA PUBLIC KEY"}
_PKCS12_EXTENSIONS = {".p12", ".pfx"}
_JKS_EXTENSIONS = {".jks", ".keystore", ".truststore"}
_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".cert", ".der", ".p7b"}
_KEY_EXTENSIONS = {".key"}
JKS_MAGIC = b"\xfe\xed\xfe\xed"
JCEKS_MAGIC = b"\xce\xce\xce\xce"


def detect_certificate_text(source: str, file_path: str, settings: Settings) -> list[RawArtifact]:
    artifacts: list[RawArtifact] = []
    for index, (label, der) in enumerate(decode_pem_blocks(source), start=1):
        line_start, line_end = _block_lines(source, label, index)
        if label in _PEM_CERT_LABELS:
            artifacts.append(_certificate_from_der(der, file_path, line_start, line_end, settings, source, label))
        elif label in _PEM_PRIVATE:
            artifacts.append(_private_key(label, der, file_path, line_start, line_end, settings))
        elif label in _PEM_PUBLIC:
            artifacts.append(
                _artifact(
                    ArtifactType.PUBLIC_KEY.value,
                    file_path,
                    line_start,
                    line_end,
                    ArtifactFormat.PEM.value,
                    "-----BEGIN PUBLIC KEY-----",
                    settings,
                    algorithm=_public_algorithm(der),
                    confidence="high",
                    detection_method="configuration_detection",
                )
            )
    return artifacts


def detect_certificate_bytes(data: bytes, file_path: str, settings: Settings) -> list[RawArtifact]:
    suffix = Path(file_path).suffix.lower()
    name = Path(file_path).name.lower()
    artifacts: list[RawArtifact] = []
    if data.startswith(JKS_MAGIC) or suffix in _JKS_EXTENSIONS:
        role = ArtifactType.TRUSTSTORE.value if "trust" in name else ArtifactType.KEYSTORE.value
        artifacts.append(
            _binary_container(
                role,
                file_path,
                ArtifactFormat.JKS.value if data.startswith(JKS_MAGIC) or suffix == ".jks" else ArtifactFormat.JKS.value,
                settings,
                metadata={"keystore_type": "JKS" if data.startswith(JKS_MAGIC) else "JKS"},
            )
        )
        return artifacts
    if data.startswith(JCEKS_MAGIC):
        artifacts.append(
            _binary_container(ArtifactType.KEYSTORE.value, file_path, ArtifactFormat.JCEKS.value, settings)
        )
        return artifacts
    if suffix in _PKCS12_EXTENSIONS or _looks_like_pkcs12(data, suffix):
        artifacts.append(
            _binary_container(ArtifactType.KEYSTORE.value, file_path, ArtifactFormat.PKCS12.value, settings)
        )
        return artifacts
    if suffix in _CERT_EXTENSIONS | {".der"} and data[:1] == b"\x30":
        parsed = parse_certificate(data)
        if parsed:
            artifacts.append(
                _certificate_from_metadata(
                    parsed,
                    file_path,
                    1,
                    1,
                    settings,
                    "[DER CERTIFICATE]",
                    ArtifactFormat.DER.value,
                )
            )
    return artifacts


def is_binary_container_name(file_path: str) -> bool:
    suffix = Path(file_path).suffix.lower()
    return suffix in _PKCS12_EXTENSIONS | _JKS_EXTENSIONS | {".der"}


def is_certificate_name(file_path: str) -> bool:
    suffix = Path(file_path).suffix.lower()
    name = Path(file_path).name.lower()
    return suffix in _CERT_EXTENSIONS | _KEY_EXTENSIONS | _PKCS12_EXTENSIONS | _JKS_EXTENSIONS or name in {
        "cacert.pem",
        "cert.pem",
        "key.pem",
    }


def _certificate_from_der(
    der: bytes,
    file_path: str,
    line_start: int,
    line_end: int,
    settings: Settings,
    source: str,
    label: str,
) -> RawArtifact:
    parsed = parse_certificate(der) if der else None
    evidence = "-----BEGIN CERTIFICATE-----"
    if parsed and parsed.subject:
        evidence = f"-----BEGIN CERTIFICATE----- subject={parsed.subject}"
    if parsed is None and not der:
        return _artifact(
            ArtifactType.CERTIFICATE.value,
            file_path,
            line_start,
            line_end,
            ArtifactFormat.PEM.value,
            evidence,
            settings,
            confidence="medium",
            detection_method="configuration_detection",
            metadata={"malformed": "true", "pem_label": label},
        )
    if parsed is None:
        return _artifact(
            ArtifactType.CERTIFICATE.value,
            file_path,
            line_start,
            line_end,
            ArtifactFormat.PEM.value,
            evidence,
            settings,
            confidence="medium",
            detection_method="configuration_detection",
            metadata={"malformed": "true"},
        )
    return _certificate_from_metadata(
        parsed, file_path, line_start, line_end, settings, evidence, ArtifactFormat.PEM.value
    )


def _certificate_from_metadata(parsed, file_path, line_start, line_end, settings, evidence, fmt) -> RawArtifact:
    metadata = {}
    if parsed.san:
        metadata["san"] = ",".join(parsed.san)
    if parsed.signature_algorithm:
        metadata["signature_algorithm"] = parsed.signature_algorithm
    if parsed.chain:
        metadata["chain"] = "true"
    return _artifact(
        ArtifactType.CERTIFICATE.value,
        file_path,
        line_start,
        line_end,
        fmt,
        evidence,
        settings,
        algorithm=parsed.public_key_algorithm,
        key_size=parsed.key_size,
        curve=parsed.curve,
        subject=parsed.subject,
        issuer=parsed.issuer,
        serial_number=parsed.serial_number,
        validity_start=parsed.validity_start,
        validity_end=parsed.validity_end,
        confidence="high",
        detection_method="configuration_detection",
        metadata=metadata,
    )


def _private_key(label: str, der: bytes, file_path: str, line_start: int, line_end: int, settings: Settings) -> RawArtifact:
    parser = _PEM_PRIVATE.get(label)
    parsed = parser(der) if parser and der else None
    algorithm = parsed.algorithm if parsed else ("RSA" if label.startswith("RSA") else "EC" if label.startswith("EC") else None)
    if label == "OPENSSH PRIVATE KEY":
        fmt = ArtifactFormat.OPENSSH.value
    else:
        fmt = ArtifactFormat.PEM.value
    return _artifact(
        ArtifactType.PRIVATE_KEY.value,
        file_path,
        line_start,
        line_end,
        fmt,
        "-----BEGIN PRIVATE KEY----- [REDACTED PRIVATE KEY BLOCK]",
        settings,
        algorithm=algorithm,
        key_size=parsed.key_size if parsed else None,
        curve=parsed.curve if parsed else None,
        confidence="high",
        detection_method="configuration_detection",
        metadata={"pem_label": label},
    )


def _public_algorithm(der: bytes) -> str | None:
    parsed = parse_pkcs8_key(der)
    return parsed.algorithm if parsed else None


def _binary_container(
    artifact_type: str,
    file_path: str,
    fmt: str,
    settings: Settings,
    metadata: dict[str, str] | None = None,
) -> RawArtifact:
    return _artifact(
        artifact_type,
        file_path,
        1,
        1,
        fmt,
        f"{Path(file_path).name} [{fmt} container]",
        settings,
        confidence="medium",
        detection_method="configuration_detection",
        metadata=metadata or {},
    )


def _looks_like_pkcs12(data: bytes, suffix: str) -> bool:
    return suffix in _PKCS12_EXTENSIONS and data[:1] == b"\x30"


def _block_lines(source: str, label: str, occurrence: int) -> tuple[int, int]:
    token = f"-----BEGIN {label}-----"
    start = -1
    for _ in range(occurrence):
        start = source.find(token, start + 1)
    if start < 0:
        return 1, 1
    line_start = source.count("\n", 0, start) + 1
    finish = source.find(f"-----END {label}-----", start)
    line_end = source.count("\n", 0, finish) + 1 if finish > 0 else line_start
    return line_start, line_end


def _artifact(
    artifact_type: str,
    file_path: str,
    line_start: int,
    line_end: int,
    fmt: str,
    evidence: str,
    settings: Settings,
    **fields,
) -> RawArtifact:
    detection_method = fields.pop("detection_method", "configuration_detection")
    confidence = fields.pop("confidence", "medium")
    metadata = fields.pop("metadata", {})
    return RawArtifact(
        artifact_type=artifact_type,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        format=fmt,
        evidence=bounded(redact_secrets(evidence), settings),
        detection_method=detection_method,
        confidence=confidence,
        metadata=metadata,
        **fields,
    )
