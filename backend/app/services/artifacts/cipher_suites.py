"""Deterministic TLS cipher-suite component extraction."""

from dataclasses import dataclass
import re

_SUITE = re.compile(r"\b(TLS_[A-Z0-9_]+)\b")
_TLS13 = re.compile(r"^TLS_(AES|CHACHA20)_(128|256)_([A-Z0-9]+)_([A-Z0-9]+)$")
_LEGACY = re.compile(
    r"^TLS_(?:(ECDHE|DHE|ECDH|DH|RSA|PSK|ECDHE_PSK|DHE_PSK)_)?"
    r"(?:(RSA|ECDSA|DSS|PSK|ANON)_)?WITH_([A-Z0-9]+)(?:_(\d+))?_([A-Z0-9]+)_([A-Z0-9]+)$"
)

_KEX_MAP = {
    "ECDHE": "ECDH",
    "DHE": "Diffie-Hellman",
    "ECDH": "ECDH",
    "DH": "Diffie-Hellman",
    "RSA": "RSA",
}
_AUTH_MAP = {"RSA": "RSA", "ECDSA": "ECDSA", "DSS": "DSA"}
_HASH_MAP = {
    "SHA": "SHA-1",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "MD5": "MD5",
}


@dataclass(frozen=True)
class CipherSuiteParts:
    name: str
    key_exchange: str | None = None
    authentication: str | None = None
    algorithm: str | None = None
    key_size: int | None = None
    mode: str | None = None
    hash_name: str | None = None


def find_cipher_suites(text: str) -> list[str]:
    return list(dict.fromkeys(_SUITE.findall(text)))


def parse_cipher_suite(name: str) -> CipherSuiteParts:
    tls13 = _TLS13.match(name)
    if tls13:
        cipher, bits, mode, digest = tls13.groups()
        algorithm = "ChaCha20-Poly1305" if cipher == "CHACHA20" else cipher
        return CipherSuiteParts(
            name=name,
            algorithm=algorithm,
            key_size=int(bits),
            mode=mode if cipher != "CHACHA20" else None,
            hash_name=_HASH_MAP.get(digest, digest),
        )
    legacy = _LEGACY.match(name)
    if not legacy:
        return CipherSuiteParts(name=name)
    kex, auth, cipher, bits, mode, digest = legacy.groups()
    if cipher == "CHACHA20":
        algorithm = "ChaCha20-Poly1305"
        mode_name = None
    elif cipher == "3DES":
        algorithm = "3DES"
        mode_name = mode
    else:
        algorithm = cipher
        mode_name = mode
    return CipherSuiteParts(
        name=name,
        key_exchange=_KEX_MAP.get(kex) if kex else None,
        authentication=_AUTH_MAP.get(auth) if auth else (_KEX_MAP.get(kex) if kex == "RSA" else None),
        algorithm=algorithm,
        key_size=int(bits) if bits else None,
        mode=mode_name,
        hash_name=_HASH_MAP.get(digest, digest),
    )
