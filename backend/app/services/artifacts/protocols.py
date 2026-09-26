"""TLS, SSH, and Java keystore configuration detection."""

import re

from app.core.config import Settings
from app.services.artifacts.cipher_suites import parse_cipher_suite
from app.services.artifacts.types import ArtifactFormat, ArtifactType, RawArtifact
from app.services.scanner.detectors.patterns import each_match
from app.services.scanner.evidence import bounded, snippet

_TLS_VERSION = re.compile(
    r"\b(?:TLS\s*v?\s*(1(?:\.[0-3])?)|TLSv1(?:\.(0|1|2|3))?|tls1(?:\.(0|1|2|3))?)\b",
    re.IGNORECASE,
)
_SSL_VERSION = re.compile(r"\bSSLv?(2|3)\b", re.IGNORECASE)
_KEYSTORE = re.compile(
    r"""javax\.net\.ssl\.(keyStore|trustStore)(?:Type)?\s*[=:]\s*["']?([^\s"']+)""",
    re.IGNORECASE,
)
_MTLS = re.compile(
    r"\b(?:needClientAuth|setNeedClientAuth|requestCert|SSLVerifyClient|ssl\.client\.auth|clientAuth|mutual\s+tls|mTLS)\b",
    re.IGNORECASE,
)
_SSH_PUBLIC = re.compile(r"^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+\S+", re.MULTILINE)
_SSH_ALG = re.compile(
    r"\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|diffie-hellman-group14-sha256|diffie-hellman-group-exchange-sha256|curve25519-sha256)\b"
)
_SSH_CONFIG_KEYS = re.compile(
    r"\b(HostKeyAlgorithms|PubkeyAcceptedAlgorithms|KexAlgorithms|Ciphers|MACs|HostKey)\b",
    re.IGNORECASE,
)
_CERT_API = re.compile(
    r"\b(?:ssl\.load_cert_chain|load_cert_chain|set_default_verify_paths|KeyStore\.getInstance|ssl\.wrap_socket|create_default_context)\b"
)

_SSH_ALGORITHM = {
    "ssh-rsa": ("RSA", None, None),
    "ssh-dss": ("DSA", None, None),
    "ssh-ed25519": ("Ed25519", None, None),
    "ecdsa-sha2-nistp256": ("ECDSA", None, "nistp256"),
    "ecdsa-sha2-nistp384": ("ECDSA", None, "nistp384"),
    "ecdsa-sha2-nistp521": ("ECDSA", None, "nistp521"),
    "diffie-hellman-group14-sha256": ("Diffie-Hellman", None, None),
    "diffie-hellman-group-exchange-sha256": ("Diffie-Hellman", None, None),
    "curve25519-sha256": ("X25519", None, None),
}

_TLS_NORMALIZE = {
    "1": "1.0",
    "1.0": "1.0",
    "1.1": "1.1",
    "1.2": "1.2",
    "1.3": "1.3",
    "0": "1.0",
}


def detect_protocols(source: str, file_path: str, settings: Settings, style: str) -> list[RawArtifact]:
    artifacts: list[RawArtifact] = []
    artifacts.extend(_tls_versions(source, file_path, settings, style))
    artifacts.extend(_cipher_suites(source, file_path, settings, style))
    artifacts.extend(_keystore_settings(source, file_path, settings, style))
    artifacts.extend(_mtls(source, file_path, settings, style))
    artifacts.extend(_ssh(source, file_path, settings, style))
    artifacts.extend(_cert_apis(source, file_path, settings, style))
    return artifacts


def _tls_versions(source: str, file_path: str, settings: Settings, style: str) -> list[RawArtifact]:
    artifacts: list[RawArtifact] = []
    seen: set[tuple[int, str]] = set()
    for match, line_start, line_end in each_match(source, style, _TLS_VERSION):
        raw = next((group for group in match.groups() if group), None)
        version = _TLS_NORMALIZE.get(raw or "", raw)
        if version is None:
            continue
        key = (line_start, version)
        if key in seen:
            continue
        seen.add(key)
        artifacts.append(
            _item(
                ArtifactType.PROTOCOL.value,
                file_path,
                line_start,
                line_end,
                settings,
                source,
                protocol="TLS",
                metadata={"tls_version": version},
                confidence="high",
            )
        )
    for match, line_start, line_end in each_match(source, style, _SSL_VERSION):
        artifacts.append(
            _item(
                ArtifactType.PROTOCOL.value,
                file_path,
                line_start,
                line_end,
                settings,
                source,
                protocol="SSL",
                metadata={"ssl_version": match.group(1)},
                confidence="high",
            )
        )
    return artifacts


def _cipher_suites(source: str, file_path: str, settings: Settings, style: str) -> list[RawArtifact]:
    artifacts: list[RawArtifact] = []
    pattern = re.compile(r"\bTLS_[A-Z0-9_]+\b")
    for match, line_start, line_end in each_match(source, style, pattern):
        parts = parse_cipher_suite(match.group(0))
        metadata = {}
        if parts.key_exchange:
            metadata["key_exchange"] = parts.key_exchange
        if parts.authentication:
            metadata["authentication"] = parts.authentication
        if parts.hash_name:
            metadata["hash"] = parts.hash_name
        artifacts.append(
            _item(
                ArtifactType.CIPHER_SUITE.value,
                file_path,
                line_start,
                line_end,
                settings,
                source,
                protocol="TLS",
                algorithm=parts.algorithm,
                key_size=parts.key_size,
                cipher_suite=parts.name,
                metadata=metadata | ({"mode": parts.mode} if parts.mode else {}),
                confidence="high",
            )
        )
    return artifacts


def _keystore_settings(source: str, file_path: str, settings: Settings, style: str) -> list[RawArtifact]:
    artifacts: list[RawArtifact] = []
    for match, line_start, line_end in each_match(source, style, _KEYSTORE):
        field, value = match.group(1), match.group(2)
        lowered = field.lower()
        if lowered.endswith("type"):
            continue
        artifact_type = ArtifactType.TRUSTSTORE.value if "trust" in lowered else ArtifactType.KEYSTORE.value
        keystore_type = _nearby_type(source, match.start())
        metadata = {"reference": value, "role": artifact_type}
        if keystore_type:
            metadata["keystore_type"] = keystore_type
        artifacts.append(
            _item(
                artifact_type,
                file_path,
                line_start,
                line_end,
                settings,
                source,
                format=ArtifactFormat.CONFIGURATION.value,
                metadata=metadata,
                confidence="high",
            )
        )
    return artifacts


def _nearby_type(source: str, offset: int) -> str | None:
    window = source[max(0, offset - 200) : offset + 240]
    match = re.search(r"javax\.net\.ssl\.(?:keyStore|trustStore)Type\s*[=:]\s*([A-Za-z0-9]+)", window)
    return match.group(1) if match else None


def _mtls(source: str, file_path: str, settings: Settings, style: str) -> list[RawArtifact]:
    artifacts: list[RawArtifact] = []
    for match, line_start, line_end in each_match(source, style, _MTLS):
        artifacts.append(
            _item(
                ArtifactType.PROTOCOL.value,
                file_path,
                line_start,
                line_end,
                settings,
                source,
                protocol="TLS",
                metadata={"mtls": "true", "observed": match.group(0)},
                confidence="medium",
            )
        )
    return artifacts


def _ssh(source: str, file_path: str, settings: Settings, style: str) -> list[RawArtifact]:
    artifacts: list[RawArtifact] = []
    for match, line_start, line_end in each_match(source, style, _SSH_PUBLIC):
        token = match.group(1)
        algorithm, _size, curve = _SSH_ALGORITHM.get(token, (None, None, None))
        artifacts.append(
            _item(
                ArtifactType.SSH_KEY.value,
                file_path,
                line_start,
                line_end,
                settings,
                source,
                protocol="SSH",
                format=ArtifactFormat.SSH_PUBLIC.value,
                algorithm=algorithm,
                curve=curve,
                metadata={"ssh_algorithm": token},
                confidence="high",
            )
        )
    name = file_path.rsplit("/", 1)[-1].lower()
    config_file = name in {"ssh_config", "sshd_config", "config"} and (
        "ssh" in file_path.lower() or name.startswith("ssh")
    )
    for match, line_start, line_end in each_match(source, style, _SSH_ALG):
        token = match.group(1)
        if any(
            item.line_start == line_start and item.metadata.get("ssh_algorithm") == token
            for item in artifacts
        ):
            continue
        algorithm, _size, curve = _SSH_ALGORITHM.get(token, (None, None, None))
        kind = ArtifactType.SSH_CONFIG.value if config_file or _SSH_CONFIG_KEYS.search(source) else ArtifactType.SSH_CONFIG.value
        artifacts.append(
            _item(
                kind,
                file_path,
                line_start,
                line_end,
                settings,
                source,
                protocol="SSH",
                format=ArtifactFormat.CONFIGURATION.value,
                algorithm=algorithm,
                curve=curve,
                metadata={"ssh_algorithm": token},
                confidence="high" if config_file else "medium",
            )
        )
    return artifacts


def _cert_apis(source: str, file_path: str, settings: Settings, style: str) -> list[RawArtifact]:
    artifacts: list[RawArtifact] = []
    for match, line_start, line_end in each_match(source, style, _CERT_API):
        artifacts.append(
            _item(
                ArtifactType.CERTIFICATE.value
                if "cert" in match.group(0).lower() or "verify" in match.group(0).lower()
                else ArtifactType.KEYSTORE.value,
                file_path,
                line_start,
                line_end,
                settings,
                source,
                format=ArtifactFormat.CONFIGURATION.value,
                metadata={"api": match.group(0)},
                confidence="medium",
                detection_method="api_detection",
            )
        )
    return artifacts


def _item(
    artifact_type: str,
    file_path: str,
    line_start: int,
    line_end: int,
    settings: Settings,
    source: str,
    *,
    protocol: str | None = None,
    format: str | None = None,
    algorithm: str | None = None,
    key_size: int | None = None,
    curve: str | None = None,
    cipher_suite: str | None = None,
    metadata: dict[str, str] | None = None,
    confidence: str = "medium",
    detection_method: str = "configuration_detection",
) -> RawArtifact:
    return RawArtifact(
        artifact_type=artifact_type,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        protocol=protocol,
        format=format,
        algorithm=algorithm,
        key_size=key_size,
        curve=curve,
        cipher_suite=cipher_suite,
        evidence=snippet(source, line_start, line_end, settings) or bounded(artifact_type, settings),
        detection_method=detection_method,
        confidence=confidence,
        metadata=metadata or {},
    )
