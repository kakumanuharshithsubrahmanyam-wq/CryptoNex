"""Known cryptography packages per ecosystem.

Classification comes only from this table. A package is never treated as
cryptographic because its name contains words such as "crypto" or "secure".
Runtime and standard-library crypto APIs (Node's crypto module, Go's crypto/*,
Python's hashlib, the JDK providers, OpenSSL) are platform APIs, not packages.
"""

from dataclasses import dataclass

from app.services.dependencies.types import CryptoRelevance, Ecosystem, normalize_name


@dataclass(frozen=True)
class CryptoPackage:
    ecosystem: str
    name: str
    library: str
    relevance: str = CryptoRelevance.CRYPTOGRAPHIC_LIBRARY.value
    # Library labels used by source detectors that this package supplies.
    source_libraries: tuple[str, ...] = ()
    # Match every package whose normalized name starts with `name`.
    prefix: bool = False


_LIB = CryptoRelevance.CRYPTOGRAPHIC_LIBRARY.value
_RELATED = CryptoRelevance.CRYPTO_RELATED.value
_UNKNOWN = CryptoRelevance.UNKNOWN.value
_PY = Ecosystem.PYTHON.value
_JAVA = Ecosystem.JAVA.value
_JS = Ecosystem.JAVASCRIPT.value
_GO = Ecosystem.GO.value
_RUST = Ecosystem.RUST.value

_PACKAGES: tuple[CryptoPackage, ...] = (
    CryptoPackage(_PY, "cryptography", "cryptography", source_libraries=("cryptography",)),
    CryptoPackage(_PY, "pycryptodome", "PyCryptodome", source_libraries=("PyCryptodome",)),
    CryptoPackage(_PY, "pycryptodomex", "PyCryptodome", source_libraries=("PyCryptodome",)),
    # PyCrypto installs the same Crypto namespace that source detection labels PyCryptodome.
    CryptoPackage(_PY, "pycrypto", "PyCrypto", source_libraries=("PyCryptodome",)),
    CryptoPackage(_PY, "pyopenssl", "pyOpenSSL"),
    CryptoPackage(_PY, "pynacl", "PyNaCl"),
    CryptoPackage(_PY, "bcrypt", "bcrypt"),
    CryptoPackage(_PY, "argon2-cffi", "argon2-cffi"),
    CryptoPackage(_PY, "ecdsa", "python-ecdsa"),
    CryptoPackage(_PY, "rsa", "python-rsa"),
    CryptoPackage(_PY, "passlib", "passlib", _RELATED),
    CryptoPackage(_PY, "pyjwt", "PyJWT", _RELATED),
    CryptoPackage(_PY, "python-jose", "python-jose", _RELATED),
    CryptoPackage(_PY, "paramiko", "paramiko", _RELATED),
    CryptoPackage(_JAVA, "org.bouncycastle:", "Bouncy Castle", prefix=True),
    CryptoPackage(_JAVA, "com.google.crypto.tink:", "Tink", prefix=True),
    CryptoPackage(_JAVA, "io.jsonwebtoken:", "JJWT", _RELATED, prefix=True),
    CryptoPackage(_JAVA, "com.nimbusds:nimbus-jose-jwt", "Nimbus JOSE+JWT", _RELATED),
    CryptoPackage(_JS, "crypto-js", "crypto-js"),
    CryptoPackage(_JS, "node-forge", "node-forge"),
    CryptoPackage(_JS, "@noble/hashes", "@noble/hashes"),
    CryptoPackage(_JS, "@noble/ciphers", "@noble/ciphers"),
    CryptoPackage(_JS, "@noble/curves", "@noble/curves"),
    CryptoPackage(_JS, "tweetnacl", "tweetnacl"),
    CryptoPackage(_JS, "libsodium-wrappers", "libsodium-wrappers"),
    CryptoPackage(_JS, "jsrsasign", "jsrsasign"),
    CryptoPackage(_JS, "elliptic", "elliptic"),
    CryptoPackage(_JS, "bcrypt", "bcrypt"),
    CryptoPackage(_JS, "bcryptjs", "bcryptjs"),
    CryptoPackage(_JS, "argon2", "argon2"),
    CryptoPackage(_JS, "jsonwebtoken", "jsonwebtoken", _RELATED),
    CryptoPackage(_JS, "jose", "jose", _RELATED),
    # The npm "crypto" package is a deprecated placeholder, not Node's built-in module.
    CryptoPackage(_JS, "crypto", "crypto (npm placeholder)", _UNKNOWN),
    CryptoPackage(
        _GO,
        "golang.org/x/crypto",
        "golang.org/x/crypto",
        source_libraries=("golang.org/x/crypto",),
    ),
    CryptoPackage(_GO, "github.com/cloudflare/circl", "CIRCL"),
    CryptoPackage(_GO, "filippo.io/edwards25519", "edwards25519"),
    CryptoPackage(_GO, "github.com/golang-jwt/jwt", "golang-jwt", _RELATED, prefix=True),
    CryptoPackage(_RUST, "ring", "ring"),
    CryptoPackage(_RUST, "openssl", "rust-openssl"),
    CryptoPackage(_RUST, "rustls", "rustls", _RELATED),
    CryptoPackage(_RUST, "aes", "RustCrypto aes"),
    CryptoPackage(_RUST, "aes-gcm", "RustCrypto aes-gcm"),
    CryptoPackage(_RUST, "chacha20poly1305", "RustCrypto chacha20poly1305"),
    CryptoPackage(_RUST, "sha2", "RustCrypto sha2"),
    CryptoPackage(_RUST, "sha1", "RustCrypto sha1"),
    CryptoPackage(_RUST, "md-5", "RustCrypto md-5"),
    CryptoPackage(_RUST, "hmac", "RustCrypto hmac"),
    CryptoPackage(_RUST, "pbkdf2", "RustCrypto pbkdf2"),
    CryptoPackage(_RUST, "hkdf", "RustCrypto hkdf"),
    CryptoPackage(_RUST, "argon2", "RustCrypto argon2"),
    CryptoPackage(_RUST, "rsa", "RustCrypto rsa"),
    CryptoPackage(_RUST, "p256", "RustCrypto p256"),
    CryptoPackage(_RUST, "k256", "RustCrypto k256"),
    CryptoPackage(_RUST, "ed25519-dalek", "ed25519-dalek"),
    CryptoPackage(_RUST, "x25519-dalek", "x25519-dalek"),
    CryptoPackage(_RUST, "blake2", "RustCrypto blake2"),
    CryptoPackage(_RUST, "blake3", "blake3"),
)

_EXACT: dict[tuple[str, str], CryptoPackage] = {
    (package.ecosystem, normalize_name(package.ecosystem, package.name)): package
    for package in _PACKAGES
    if not package.prefix
}
_PREFIXES: tuple[CryptoPackage, ...] = tuple(package for package in _PACKAGES if package.prefix)

LANGUAGE_ECOSYSTEMS: dict[str, str] = {
    "Python": _PY,
    "Java": _JAVA,
    "JavaScript": _JS,
    "TypeScript": _JS,
    "Go": _GO,
}


def lookup_package(ecosystem: str, name: str) -> CryptoPackage | None:
    normalized = normalize_name(ecosystem, name)
    package = _EXACT.get((ecosystem, normalized))
    if package is not None:
        return package
    for candidate in _PREFIXES:
        if candidate.ecosystem == ecosystem and normalized.startswith(candidate.name):
            return candidate
    return None


def supplies_library(package: CryptoPackage, source_library: str) -> bool:
    return any(
        source_library == label or source_library.startswith(f"{label}/")
        for label in package.source_libraries
    )
