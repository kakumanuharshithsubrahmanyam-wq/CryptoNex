"""Canonical cryptographic algorithms and dependency package names."""

import re
from dataclasses import dataclass

AlgorithmFamily = str


@dataclass(frozen=True)
class AlgorithmSpec:
    canonical_name: str
    family: AlgorithmFamily
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class ResolvedAlgorithm:
    name: str
    family: AlgorithmFamily
    mode: str | None = None
    key_size: int | None = None
    curve: str | None = None
    hash_name: str | None = None


_SPECS: tuple[AlgorithmSpec, ...] = (
    AlgorithmSpec("RSA", "asymmetric", ("rsa", "rsa-oaep", "rsa-pss", "rsassa-pkcs1-v1_5")),
    AlgorithmSpec("DSA", "asymmetric", ("dsa",)),
    AlgorithmSpec("ECDSA", "asymmetric", ("ecdsa",)),
    AlgorithmSpec("ECDH", "asymmetric", ("ecdh",)),
    AlgorithmSpec("Diffie-Hellman", "asymmetric", ("diffie-hellman", "dh", "diffiehellman")),
    AlgorithmSpec("Ed25519", "asymmetric", ("ed25519",)),
    AlgorithmSpec("Ed448", "asymmetric", ("ed448",)),
    AlgorithmSpec("AES", "symmetric", ("aes",)),
    AlgorithmSpec("DES", "symmetric", ("des",)),
    AlgorithmSpec("3DES", "symmetric", ("3des", "triple des", "tripledes", "des-ede", "des-ede3")),
    AlgorithmSpec("Blowfish", "symmetric", ("blowfish",)),
    AlgorithmSpec("ChaCha20", "symmetric", ("chacha20",)),
    AlgorithmSpec("ChaCha20-Poly1305", "symmetric", ("chacha20-poly1305", "chacha20poly1305")),
    AlgorithmSpec("MD5", "hash", ("md5",)),
    AlgorithmSpec("SHA-1", "hash", ("sha-1", "sha1")),
    AlgorithmSpec("SHA-224", "hash", ("sha-224", "sha224")),
    AlgorithmSpec("SHA-256", "hash", ("sha-256", "sha256")),
    AlgorithmSpec("SHA-384", "hash", ("sha-384", "sha384")),
    AlgorithmSpec("SHA-512", "hash", ("sha-512", "sha512")),
    AlgorithmSpec("SHA-3", "hash", ("sha-3", "sha3", "sha3-224", "sha3-256", "sha3-384", "sha3-512")),
    AlgorithmSpec("BLAKE2", "hash", ("blake2", "blake2b", "blake2s")),
    AlgorithmSpec("BLAKE3", "hash", ("blake3",)),
    AlgorithmSpec("HMAC", "mac", ("hmac",)),
    AlgorithmSpec("CMAC", "mac", ("cmac",)),
    AlgorithmSpec("Poly1305", "mac", ("poly1305",)),
    AlgorithmSpec("PBKDF2", "kdf", ("pbkdf2", "pbkdf2hmac")),
    AlgorithmSpec("scrypt", "kdf", ("scrypt",)),
    AlgorithmSpec("Argon2", "kdf", ("argon2", "argon2id", "argon2i", "argon2d")),
    AlgorithmSpec("HKDF", "kdf", ("hkdf",)),
)

def _normalize(value: str) -> str:
    return "".join(character for character in value.lower() if character not in " _")


_ALIAS_INDEX: dict[str, AlgorithmSpec] = {}
for _spec in _SPECS:
    _ALIAS_INDEX[_normalize(_spec.canonical_name)] = _spec
    for _alias in _spec.aliases:
        _ALIAS_INDEX[_normalize(_alias)] = _spec

_CURVES = {
    _normalize(name): canonical
    for name, canonical in {
        "secp256r1": "secp256r1",
        "prime256v1": "secp256r1",
        "NID_X9_62_prime256v1": "secp256r1",
        "secp384r1": "secp384r1",
        "NID_secp384r1": "secp384r1",
        "secp521r1": "secp521r1",
        "secp256k1": "secp256k1",
        "NID_secp256k1": "secp256k1",
    }.items()
}

_MODES = {"gcm", "cbc", "ctr", "ecb", "cfb", "ofb", "ccm"}
_IGNORE_MODE_TOKENS = {"nopadding", "pkcs5padding", "pkcs7padding", "padding"}

# Package names that indicate a cryptographic dependency. Presence is not usage.
CRYPTO_DEPENDENCIES: dict[str, str] = {
    "cryptography": "cryptography",
    "pycryptodome": "PyCryptodome",
    "pycrypto": "PyCryptodome",
    "bcprov-jdk15on": "Bouncy Castle",
    "bcprov-jdk18on": "Bouncy Castle",
    "bcpkix-jdk18on": "Bouncy Castle",
    "crypto-js": "crypto-js",
    "node-forge": "node-forge",
    "@noble/hashes": "@noble/hashes",
    "@noble/ciphers": "@noble/ciphers",
    "golang.org/x/crypto": "golang.org/x/crypto",
}


def lookup_algorithm(token: str) -> AlgorithmSpec | None:
    return _ALIAS_INDEX.get(_normalize(token))


def lookup_curve(token: str) -> str | None:
    return _CURVES.get(_normalize(token))


def resolve_transformation(token: str) -> ResolvedAlgorithm | None:
    """Parse an explicit algorithm token such as AES/GCM/NoPadding or SHA256withRSA."""
    cleaned = token.strip()
    if not cleaned:
        return None

    lowered = cleaned.lower().replace("_", "-")
    plain_modes = {"aes-gcm": "GCM", "aes-cbc": "CBC", "aes-ctr": "CTR", "aes-ecb": "ECB"}
    if lowered in plain_modes:
        return ResolvedAlgorithm(name="AES", family="symmetric", mode=plain_modes[lowered])
    aes_sized = _AES_SIZED.match(lowered)
    if aes_sized:
        spec = lookup_algorithm("AES")
        assert spec is not None
        return ResolvedAlgorithm(
            name=spec.canonical_name,
            family=spec.family,
            mode=aes_sized.group(2).upper(),
            key_size=int(aes_sized.group(1)),
        )

    if "with" in lowered and "/" not in lowered:
        left, right = lowered.split("with", 1)
        hash_spec = lookup_algorithm(left)
        algorithm_spec = lookup_algorithm(right)
        if hash_spec and algorithm_spec and hash_spec.family == "hash":
            return ResolvedAlgorithm(
                name=algorithm_spec.canonical_name,
                family=algorithm_spec.family,
                hash_name=hash_spec.canonical_name,
            )

    if lowered.startswith("hmac"):
        digest = lowered[4:].lstrip("-")
        hash_spec = lookup_algorithm(digest) if digest else None
        spec = lookup_algorithm("HMAC")
        assert spec is not None
        return ResolvedAlgorithm(
            name=spec.canonical_name,
            family=spec.family,
            hash_name=hash_spec.canonical_name if hash_spec else None,
        )

    if "/" in cleaned:
        parts = [part for part in cleaned.split("/") if part]
        spec = lookup_algorithm(parts[0]) if parts else None
        if spec is None:
            return None
        mode = None
        for part in parts[1:]:
            if part.lower() in _MODES:
                mode = part.upper()
            elif _normalize(part) not in _IGNORE_MODE_TOKENS and lookup_algorithm(part) is None:
                continue
        return ResolvedAlgorithm(name=spec.canonical_name, family=spec.family, mode=mode)

    spec = lookup_algorithm(cleaned)
    if spec is None:
        curve = lookup_curve(cleaned)
        if curve:
            return ResolvedAlgorithm(name="ECDSA", family="asymmetric", curve=curve)
        return None
    return ResolvedAlgorithm(name=spec.canonical_name, family=spec.family)


_AES_SIZED = re.compile(r"^aes-(\d+)-(gcm|cbc|ctr|ecb|cfb|ofb)$")
