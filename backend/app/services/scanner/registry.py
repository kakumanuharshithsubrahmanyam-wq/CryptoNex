"""Canonical cryptographic algorithms.

Each spec also carries the deterministic context used by the evidence and
context classifier: which parameters describe an instance of the algorithm,
its cryptographic concern category, and its post-quantum migration family.
These are classifications of the primitive, not verdicts about an application.
"""

import re
from dataclasses import dataclass

AlgorithmFamily = str


@dataclass(frozen=True)
class AlgorithmSpec:
    canonical_name: str
    family: AlgorithmFamily
    aliases: tuple[str, ...]
    # Parameters that describe an instance. An empty tuple means the primitive
    # has no tunable parameters that the scanner needs to extract.
    parameters: tuple[str, ...] = ()
    security_concern: str = "unknown"
    quantum_relevance: str = "unknown"


@dataclass(frozen=True)
class ResolvedAlgorithm:
    name: str
    family: AlgorithmFamily
    mode: str | None = None
    key_size: int | None = None
    curve: str | None = None
    hash_name: str | None = None


def _asym(name: str, aliases: tuple[str, ...], parameters: tuple[str, ...], concern: str, quantum: str) -> AlgorithmSpec:
    return AlgorithmSpec(name, "asymmetric", aliases, parameters, concern, quantum)


def _sym(name: str, aliases: tuple[str, ...], parameters: tuple[str, ...], concern: str) -> AlgorithmSpec:
    return AlgorithmSpec(name, "symmetric", aliases, parameters, concern, "symmetric")


def _hash(name: str, aliases: tuple[str, ...], concern: str = "modern_hash") -> AlgorithmSpec:
    return AlgorithmSpec(name, "hash", aliases, (), concern, "hash")


def _mac(name: str, aliases: tuple[str, ...], parameters: tuple[str, ...]) -> AlgorithmSpec:
    return AlgorithmSpec(name, "mac", aliases, parameters, "mac", "mac")


def _kdf(name: str, aliases: tuple[str, ...], parameters: tuple[str, ...]) -> AlgorithmSpec:
    return AlgorithmSpec(name, "kdf", aliases, parameters, "key_derivation", "key_derivation")


_SPECS: tuple[AlgorithmSpec, ...] = (
    _asym(
        "RSA",
        ("rsa", "rsa-oaep", "rsa-pss", "rsassa-pkcs1-v1_5"),
        ("key_size",),
        "classical_public_key",
        "classical_public_key",
    ),
    _asym("DSA", ("dsa",), ("key_size",), "classical_signature", "classical_signature"),
    _asym("ECDSA", ("ecdsa",), ("curve",), "classical_signature", "classical_signature"),
    _asym("ECDH", ("ecdh",), ("curve",), "classical_key_exchange", "classical_key_establishment"),
    _asym(
        "Diffie-Hellman",
        ("diffie-hellman", "dh", "diffiehellman"),
        ("key_size",),
        "classical_key_exchange",
        "classical_key_establishment",
    ),
    _asym("Ed25519", ("ed25519",), (), "classical_signature", "classical_signature"),
    _asym("Ed448", ("ed448",), (), "classical_signature", "classical_signature"),
    _asym("X25519", ("x25519", "curve25519"), (), "classical_key_exchange", "classical_key_establishment"),
    _asym("ML-KEM", ("ml-kem", "mlkem", "kyber"), (), "post_quantum", "post_quantum"),
    _asym("ML-DSA", ("ml-dsa", "mldsa", "dilithium"), (), "post_quantum", "post_quantum"),
    _asym("SLH-DSA", ("slh-dsa", "slhdsa", "sphincs", "sphincsplus"), (), "post_quantum", "post_quantum"),
    _asym("X-Wing", ("x-wing", "xwing"), (), "hybrid", "hybrid"),
    AlgorithmSpec("HPKE", "protocol", ("hpke",), (), "hybrid", "hybrid"),
    _sym("AES", ("aes",), ("key_size", "mode"), "symmetric_cryptography"),
    _sym("DES", ("des",), ("mode",), "legacy_cipher"),
    _sym("3DES", ("3des", "triple des", "tripledes", "des-ede", "des-ede3"), ("key_size", "mode"), "legacy_cipher"),
    _sym("Blowfish", ("blowfish",), ("key_size", "mode"), "legacy_cipher"),
    _sym("ChaCha20", ("chacha20",), (), "symmetric_cryptography"),
    _sym("ChaCha20-Poly1305", ("chacha20-poly1305", "chacha20poly1305"), (), "symmetric_cryptography"),
    _sym("XChaCha20-Poly1305", ("xchacha20-poly1305", "xchacha20poly1305"), (), "symmetric_cryptography"),
    _hash("MD5", ("md5",), "legacy_hash"),
    _hash("SHA-1", ("sha-1", "sha1"), "legacy_hash"),
    _hash("SHA-224", ("sha-224", "sha224")),
    _hash("SHA-256", ("sha-256", "sha256")),
    _hash("SHA-384", ("sha-384", "sha384")),
    _hash("SHA-512", ("sha-512", "sha512")),
    _hash("SHA-3", ("sha-3", "sha3", "sha3-224", "sha3-256", "sha3-384", "sha3-512")),
    _hash("BLAKE2", ("blake2", "blake2b", "blake2s")),
    _hash("BLAKE3", ("blake3",)),
    _mac("HMAC", ("hmac",), ("hash",)),
    _mac("CMAC", ("cmac",), ("cipher",)),
    _mac("Poly1305", ("poly1305",), ()),
    _kdf("PBKDF2", ("pbkdf2", "pbkdf2hmac"), ("hash", "iterations")),
    _kdf("scrypt", ("scrypt",), ("cost",)),
    _kdf("Argon2", ("argon2", "argon2id", "argon2i", "argon2d"), ("cost",)),
    _kdf("HKDF", ("hkdf",), ("hash",)),
)

# Key derivation functions designed to stretch low-entropy passwords.
PASSWORD_BASED_KDFS = frozenset({"PBKDF2", "scrypt", "Argon2"})


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
