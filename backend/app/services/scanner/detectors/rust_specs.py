"""Registry of recognizable Rust cryptographic APIs.

Identifiers are matched only when they appear as typed API usage
(`Type::method(`) or as imported crate paths. A Cargo dependency name is
not an algorithm finding.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.scanner.registry import lookup_algorithm


@dataclass(frozen=True)
class RustApiSpec:
    identifiers: tuple[str, ...]
    algorithm: str
    usage: str
    crates: tuple[str, ...]
    methods: tuple[str, ...]
    distinctive: bool = True
    key_size: int | None = None
    hash_name: str | None = None
    mode: str | None = None


_COMMON_CTOR = ("new", "new_from_slice", "try_new", "from_slice")
_HASH_METHODS = ("digest", "new", "finalize", "finalize_reset", "update")
_MAC_METHODS = ("new", "new_from_slice", "update", "finalize", "finalize_fixed")
_KDF_METHODS = ("new", "derive", "extract", "expand", "hash_password", "hash_password_simple", "hash_password_into")
_AEAD_METHODS = ("new", "new_from_slice", "encrypt", "decrypt", "encrypt_in_place", "decrypt_in_place")
_SIGN_METHODS = ("sign", "verify", "generate", "from_bytes", "from_slice", "new")
_KEX_METHODS = ("diffie_hellman", "generate", "encapsulate", "decapsulate", "new", "from")
_HPKE_METHODS = ("setup_sender", "setup_receiver", "seal", "open", "new")

RUST_APIS: tuple[RustApiSpec, ...] = (
    RustApiSpec(("Sha224",), "SHA-224", "hashing", ("sha2",), _HASH_METHODS),
    RustApiSpec(("Sha256",), "SHA-256", "hashing", ("sha2",), _HASH_METHODS),
    RustApiSpec(("Sha384",), "SHA-384", "hashing", ("sha2",), _HASH_METHODS),
    RustApiSpec(("Sha512",), "SHA-512", "hashing", ("sha2",), _HASH_METHODS),
    RustApiSpec(("Sha1",), "SHA-1", "hashing", ("sha1",), _HASH_METHODS),
    RustApiSpec(("Md5",), "MD5", "hashing", ("md5", "md_5"), _HASH_METHODS),
    RustApiSpec(("Sha3_224", "Sha3_256", "Sha3_384", "Sha3_512", "Keccak256"), "SHA-3", "hashing", ("sha3",), _HASH_METHODS),
    RustApiSpec(("Blake2b", "Blake2s", "Blake2b512", "Blake2s256", "Blake2bMac"), "BLAKE2", "hashing", ("blake2",), _HASH_METHODS),
    RustApiSpec(("Hasher",), "BLAKE3", "hashing", ("blake3",), ("new", "finalize", "update", "hash", "derive_key"), distinctive=False),
    RustApiSpec(("Blake3",), "BLAKE3", "hashing", ("blake3",), ("hash", "derive_key", "new")),
    RustApiSpec(("HmacSha256",), "HMAC", "mac", ("hmac",), _MAC_METHODS, hash_name="SHA-256"),
    RustApiSpec(("HmacSha384",), "HMAC", "mac", ("hmac",), _MAC_METHODS, hash_name="SHA-384"),
    RustApiSpec(("HmacSha512",), "HMAC", "mac", ("hmac",), _MAC_METHODS, hash_name="SHA-512"),
    RustApiSpec(("Hmac",), "HMAC", "mac", ("hmac",), _MAC_METHODS),
    RustApiSpec(("HkdfSha256", "HkdfSha384", "HkdfSha512"), "HKDF", "key_derivation", ("hkdf",), _KDF_METHODS),
    RustApiSpec(("Hkdf",), "HKDF", "key_derivation", ("hkdf",), _KDF_METHODS),
    RustApiSpec(("Pbkdf2", "Pbkdf2Sha256", "pbkdf2_hmac"), "PBKDF2", "key_derivation", ("pbkdf2",), _KDF_METHODS),
    RustApiSpec(("Argon2", "Argon2id", "Argon2i", "Argon2d"), "Argon2", "key_derivation", ("argon2",), _KDF_METHODS),
    RustApiSpec(("Scrypt",), "scrypt", "key_derivation", ("scrypt",), _KDF_METHODS),
    RustApiSpec(("Aes128",), "AES", "algorithm_selection", ("aes",), _COMMON_CTOR, key_size=128),
    RustApiSpec(("Aes192",), "AES", "algorithm_selection", ("aes",), _COMMON_CTOR, key_size=192),
    RustApiSpec(("Aes256",), "AES", "algorithm_selection", ("aes",), _COMMON_CTOR, key_size=256),
    RustApiSpec(("AesGcm",), "AES", "encryption", ("aes_gcm", "aes-gcm"), _AEAD_METHODS, mode="GCM"),
    RustApiSpec(("Aes128Gcm",), "AES", "encryption", ("aes_gcm", "aes-gcm"), _AEAD_METHODS, key_size=128, mode="GCM"),
    RustApiSpec(("Aes256Gcm",), "AES", "encryption", ("aes_gcm", "aes-gcm"), _AEAD_METHODS, key_size=256, mode="GCM"),
    RustApiSpec(("Aes128GcmSiv", "Aes256GcmSiv"), "AES", "encryption", ("aes_gcm_siv", "aes-gcm-siv"), _AEAD_METHODS, mode="GCM"),
    RustApiSpec(("ChaCha20",), "ChaCha20", "algorithm_selection", ("chacha20",), _COMMON_CTOR + ("apply_keystream",)),
    RustApiSpec(("ChaCha20Poly1305",), "ChaCha20-Poly1305", "encryption", ("chacha20poly1305",), _AEAD_METHODS),
    RustApiSpec(("XChaCha20Poly1305",), "XChaCha20-Poly1305", "encryption", ("chacha20poly1305",), _AEAD_METHODS),
    RustApiSpec(("Ed25519",), "Ed25519", "unknown", ("ed25519_dalek", "ed25519-dalek", "ed25519"), _SIGN_METHODS),
    RustApiSpec(
        ("SigningKey", "VerifyingKey"),
        "Ed25519",
        "unknown",
        ("ed25519_dalek", "ed25519-dalek"),
        _SIGN_METHODS,
        distinctive=False,
    ),
    RustApiSpec(("Ecdsa", "ECDSA"), "ECDSA", "unknown", ("ecdsa", "p256", "k256"), _SIGN_METHODS),
    RustApiSpec(
        ("SigningKey", "VerifyingKey"),
        "ECDSA",
        "unknown",
        ("p256", "k256", "ecdsa"),
        _SIGN_METHODS,
        distinctive=False,
    ),
    RustApiSpec(("Rsa", "RsaPrivateKey", "RsaPublicKey"), "RSA", "unknown", ("rsa",), _SIGN_METHODS + ("encrypt", "decrypt")),
    RustApiSpec(("X25519",), "X25519", "key_agreement", ("x25519_dalek", "x25519-dalek", "x25519"), _KEX_METHODS),
    RustApiSpec(
        ("StaticSecret", "EphemeralSecret"),
        "X25519",
        "key_agreement",
        ("x25519_dalek", "x25519-dalek"),
        _KEX_METHODS,
        distinctive=False,
    ),
    RustApiSpec(
        ("MlKem", "MlKem512", "MlKem768", "MlKem1024", "Kyber", "Kyber512", "Kyber768", "Kyber1024"),
        "ML-KEM",
        "key_agreement",
        ("ml_kem", "ml-kem", "kyber"),
        _KEX_METHODS,
    ),
    RustApiSpec(("XWing", "XWingKem"), "X-Wing", "key_agreement", ("x_wing", "x-wing", "xwing"), _KEX_METHODS),
    RustApiSpec(("Hpke", "HPKE"), "HPKE", "encryption", ("hpke",), _HPKE_METHODS),
)

_METHOD_USAGE = {
    "digest": "hashing",
    "hash": "hashing",
    "finalize": "hashing",
    "hash_password": "key_derivation",
    "hash_password_simple": "key_derivation",
    "hash_password_into": "key_derivation",
    "derive": "key_derivation",
    "derive_key": "key_derivation",
    "extract": "key_derivation",
    "expand": "key_derivation",
    "encrypt": "encryption",
    "decrypt": "decryption",
    "encrypt_in_place": "encryption",
    "decrypt_in_place": "decryption",
    "apply_keystream": "encryption",
    "sign": "signing",
    "verify": "signature_verification",
    "diffie_hellman": "key_agreement",
    "encapsulate": "key_agreement",
    "decapsulate": "key_agreement",
    "setup_sender": "encryption",
    "setup_receiver": "decryption",
    "seal": "encryption",
    "open": "decryption",
    "generate": "key_generation",
}

_GENERIC_HASH = {
    "Sha224": "SHA-224",
    "Sha256": "SHA-256",
    "Sha384": "SHA-384",
    "Sha512": "SHA-512",
    "Sha1": "SHA-1",
    "Md5": "MD5",
    "Sha3_256": "SHA-3",
    "Sha3_384": "SHA-3",
    "Sha3_512": "SHA-3",
    "Blake2b": "BLAKE2",
    "Blake2s": "BLAKE2",
    "Blake3": "BLAKE3",
}


def normalize_crate(name: str) -> str:
    return name.replace("-", "_").lower()


def spec_family(algorithm: str) -> str | None:
    spec = lookup_algorithm(algorithm)
    return spec.family if spec else None


def method_usage(method: str, default: str) -> str:
    return _METHOD_USAGE.get(method, default)


def generic_hash(name: str | None) -> str | None:
    if not name:
        return None
    return _GENERIC_HASH.get(name)


def lookup_identifier(identifier: str, crate: str | None) -> RustApiSpec | None:
    """Resolve an identifier, preferring a crate-qualified match."""
    crate_key = normalize_crate(crate) if crate else None
    fallback = None
    for spec in RUST_APIS:
        if identifier not in spec.identifiers:
            continue
        crates = {normalize_crate(item) for item in spec.crates}
        if crate_key and crate_key in crates:
            return spec
        if spec.distinctive and fallback is None:
            fallback = spec
    if crate_key:
        return None
    return fallback


def known_crate(name: str) -> bool:
    crate_key = normalize_crate(name)
    return any(crate_key == normalize_crate(item) for spec in RUST_APIS for item in spec.crates)


def library_label(spec: RustApiSpec, crate: str | None) -> str:
    if crate:
        return crate.replace("_", "-")
    return spec.crates[0].replace("_", "-")
