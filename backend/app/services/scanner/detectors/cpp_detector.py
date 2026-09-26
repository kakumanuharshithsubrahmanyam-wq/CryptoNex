"""C and C++ cryptographic API detection.

Matches recognizable OpenSSL and Botan APIs, types, and includes. Algorithm
names in comments, documentation, capability macros, or header names alone
are not treated as confirmed usage.
"""

from __future__ import annotations

import re

from app.core.config import Settings
from app.services.scanner.detectors.cpp_tokens import parse_explicit_token
from app.services.scanner.detectors.patterns import each_match
from app.services.scanner.evidence import mask_comments, snippet
from app.services.scanner.findings import RawFinding
from app.services.scanner.registry import lookup_algorithm, lookup_curve

_INCLUDE = re.compile(
    r"""^\s*#\s*include\s*[<"](?P<header>(?P<library>botan|openssl)/[^">]+)[>"]""",
    re.IGNORECASE | re.MULTILINE,
)
_ENCRYPT = re.compile(
    r"EVP_EncryptInit_ex\s*\((?P<args>[^;]{0,200}?EVP_(?P<cipher>chacha20_poly1305|chacha20|des_ede3|des_ede|aes|bf)(?:_(?P<size>\d+))?(?:_(?P<mode>gcm|cbc|ctr|ecb|cfb|ofb))?\s*\(\s*\))",
    re.IGNORECASE,
)
_DECRYPT = re.compile(
    r"EVP_DecryptInit_ex\s*\((?P<args>[^;]{0,200}?EVP_(?P<cipher>chacha20_poly1305|chacha20|des_ede3|des_ede|aes|bf)(?:_(?P<size>\d+))?(?:_(?P<mode>gcm|cbc|ctr|ecb|cfb|ofb))?\s*\(\s*\))",
    re.IGNORECASE,
)
_DIGEST = re.compile(
    r"EVP_DigestInit_ex\s*\((?P<args>[^;]{0,200}?EVP_(?P<hash>sha3_512|sha3_384|sha3_256|sha3_224|sha512|sha384|sha256|sha224|sha1|md5|blake2b512|blake2s256)\s*\(\s*\))",
    re.IGNORECASE,
)
_RSA_KEYGEN = re.compile(r"RSA_generate_key_ex\s*\((?P<args>[^;]{0,160}?)\)", re.IGNORECASE)
_RSA_SIGN = re.compile(r"\bRSA_sign\s*\(", re.IGNORECASE)
_RSA_VERIFY = re.compile(r"\bRSA_verify\s*\(", re.IGNORECASE)
_RSA_ENCRYPT = re.compile(r"\bRSA_public_encrypt\s*\(", re.IGNORECASE)
_RSA_DECRYPT = re.compile(r"\bRSA_private_decrypt\s*\(", re.IGNORECASE)
_ECDSA_SIGN = re.compile(r"\bECDSA_(?:do_)?sign\s*\(", re.IGNORECASE)
_ECDSA_VERIFY = re.compile(r"\bECDSA_(?:do_)?verify\s*\(", re.IGNORECASE)
_ECDH = re.compile(r"\bECDH_compute_key\s*\(", re.IGNORECASE)
_DH = re.compile(r"\bDH_compute_key\s*\(", re.IGNORECASE)
_HMAC = re.compile(r"\bHMAC_Init(?:_ex)?\s*\(", re.IGNORECASE)
_CMAC = re.compile(r"\bCMAC_Init\s*\(", re.IGNORECASE)
_PBKDF2 = re.compile(r"\bPKCS5_PBKDF2_HMAC(?:_SHA1)?\s*\(", re.IGNORECASE)
_SCRYPT = re.compile(r"\bEVP_PBE_scrypt\s*\(", re.IGNORECASE)
_HKDF = re.compile(r"\bEVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_HKDF", re.IGNORECASE)
_ED25519 = re.compile(r"\bEVP_PKEY_(?:CTX_new_id|new_raw_private_key|new_raw_public_key)\s*\(\s*EVP_PKEY_ED25519", re.IGNORECASE)
_ED448 = re.compile(r"\bEVP_PKEY_(?:CTX_new_id|new_raw_private_key|new_raw_public_key)\s*\(\s*EVP_PKEY_ED448", re.IGNORECASE)
_X25519 = re.compile(r"\bEVP_PKEY_(?:CTX_new_id|new_raw_private_key|new_raw_public_key)\s*\(\s*EVP_PKEY_X25519", re.IGNORECASE)
_MLKEM = re.compile(r"\bEVP_PKEY_(?:CTX_new_id|new_raw_private_key|new_raw_public_key)\s*\(\s*EVP_PKEY_(?:ML_KEM(?:_\d+)?|KYBER)", re.IGNORECASE)
_EC = re.compile(r"EC_KEY_new_by_curve_name\s*\(\s*(?P<curve>NID_[A-Za-z0-9_]+)\s*\)")
_FACTORY = re.compile(
    r"\b(?:Botan::)?(?P<factory>HashFunction|BlockCipher|StreamCipher|AEAD_Mode|Cipher_Mode|"
    r"MessageAuthenticationCode|KDF|PBKDF|PasswordHashFamily|PasswordHash)\s*::\s*"
    r"create(?:_or_throw)?\s*\(\s*\"(?P<token>[^\"]+)\"",
)
_EC_GROUP = re.compile(r"\b(?:Botan::)?EC_Group::from_name\s*\(\s*\"(?P<curve>[^\"]+)\"")
_RSA_BITS = re.compile(r"\b(?:Botan::)?RSA_PrivateKey\b[^;\n]{0,80}?,\s*(?P<bits>\d{3,5})\b")
_WITH_HASH = re.compile(r"with_hash\s*\(\s*\"(?P<hash>[^\"]+)\"")
_TLS_VERSION = re.compile(r"\b(?:Botan::)?TLS::Protocol_Version::(?P<version>TLS_V1[2-3]|TLS_V1_[2-3]|TLS_V12|TLS_V13)\b")

_HASHES = {
    "sha3_512": "SHA-3",
    "sha3_384": "SHA-3",
    "sha3_256": "SHA-3",
    "sha3_224": "SHA-3",
    "sha512": "SHA-512",
    "sha384": "SHA-384",
    "sha256": "SHA-256",
    "sha224": "SHA-224",
    "sha1": "SHA-1",
    "md5": "MD5",
    "blake2b512": "BLAKE2",
    "blake2s256": "BLAKE2",
}
_OPENSSL_CIPHERS = {
    "aes": ("AES", "symmetric"),
    "des_ede3": ("3DES", "symmetric"),
    "des_ede": ("3DES", "symmetric"),
    "bf": ("Blowfish", "symmetric"),
    "chacha20_poly1305": ("ChaCha20-Poly1305", "symmetric"),
    "chacha20": ("ChaCha20", "symmetric"),
}

# Distinctive Botan types. Bare names such as HMAC are omitted to avoid
# colliding with application identifiers and CLI command classes.
_BOTAN_TYPES: tuple[tuple[str, str, str | None], ...] = (
    ("RSA_PrivateKey", "RSA", None),
    ("RSA_PublicKey", "RSA", None),
    ("ECDSA_PrivateKey", "ECDSA", None),
    ("ECDSA_PublicKey", "ECDSA", None),
    ("ECDH_PrivateKey", "ECDH", "key_agreement"),
    ("ECDH_PublicKey", "ECDH", "key_agreement"),
    ("DH_PrivateKey", "Diffie-Hellman", "key_agreement"),
    ("DH_PublicKey", "Diffie-Hellman", "key_agreement"),
    ("Ed25519_PrivateKey", "Ed25519", None),
    ("Ed25519_PublicKey", "Ed25519", None),
    ("Ed448_PrivateKey", "Ed448", None),
    ("Ed448_PublicKey", "Ed448", None),
    ("AES_128", "AES", None),
    ("AES_192", "AES", None),
    ("AES_256", "AES", None),
    ("TripleDES", "3DES", None),
    ("SHA_1", "SHA-1", "hashing"),
    ("SHA_224", "SHA-224", "hashing"),
    ("SHA_256", "SHA-256", "hashing"),
    ("SHA_384", "SHA-384", "hashing"),
    ("SHA_512", "SHA-512", "hashing"),
    ("SHA_3_224", "SHA-3", "hashing"),
    ("SHA_3_256", "SHA-3", "hashing"),
    ("SHA_3_384", "SHA-3", "hashing"),
    ("SHA_3_512", "SHA-3", "hashing"),
    ("BLAKE2b", "BLAKE2", "hashing"),
    ("BLAKE2s", "BLAKE2", "hashing"),
    ("BLAKE3", "BLAKE3", "hashing"),
    ("PKCS5_PBKDF2", "PBKDF2", "key_derivation"),
    ("Scrypt_Family", "scrypt", "key_derivation"),
    ("Argon2_Family", "Argon2", "key_derivation"),
    ("X25519_PrivateKey", "X25519", "key_agreement"),
    ("X25519_PublicKey", "X25519", "key_agreement"),
    ("ML_KEM_PrivateKey", "ML-KEM", None),
    ("ML_KEM_PublicKey", "ML-KEM", None),
    ("ML_DSA_PrivateKey", "ML-DSA", None),
    ("ML_DSA_PublicKey", "ML-DSA", None),
    ("SLH_DSA_PrivateKey", "SLH-DSA", None),
    ("SLH_DSA_PublicKey", "SLH-DSA", None),
)
_BOTAN_QUALIFIED = (
    (re.compile(r"\bBotan::HMAC\b"), "HMAC", "mac"),
    (re.compile(r"\bBotan::CMAC\b"), "CMAC", "mac"),
    (re.compile(r"\bBotan::Poly1305\b"), "Poly1305", "mac"),
    (re.compile(r"\bBotan::MD5\b"), "MD5", "hashing"),
    (re.compile(r"\bBotan::DES\b"), "DES", None),
    (re.compile(r"\bBotan::Blowfish\b"), "Blowfish", None),
    (re.compile(r"\bBotan::ChaCha\b"), "ChaCha20", None),
    (re.compile(r"\bBotan::ChaCha20_Poly1305\b"), "ChaCha20-Poly1305", None),
    (re.compile(r"\bBotan::HKDF\b"), "HKDF", "key_derivation"),
    (re.compile(r"\bBotan::Scrypt\b"), "scrypt", "key_derivation"),
    (re.compile(r"\bBotan::Argon2\b"), "Argon2", "key_derivation"),
    (re.compile(r"\bBotan::SHA_3\b"), "SHA-3", "hashing"),
    (re.compile(r"\bBotan::SHA_1\b"), "SHA-1", "hashing"),
    (re.compile(r"\bBotan::X25519\b"), "X25519", "key_agreement"),
    (re.compile(r"\bBotan::ML_KEM\b"), "ML-KEM", None),
    (re.compile(r"\bBotan::ML_DSA\b"), "ML-DSA", None),
    (re.compile(r"\bBotan::SLH_DSA\b"), "SLH-DSA", None),
)
_BOTAN_CLASS_DEFS = (
    (re.compile(r"\bclass\s+HMAC\s+final\s*:\s*public\s+MessageAuthenticationCode\b"), "HMAC", "mac"),
    (re.compile(r"\bclass\s+CMAC\s+final\s*:\s*public\s+MessageAuthenticationCode\b"), "CMAC", "mac"),
    (re.compile(r"\bclass\s+Poly1305\s+final\s*:\s*public\s+MessageAuthenticationCode\b"), "Poly1305", "mac"),
    (re.compile(r"\bclass\s+MD5\s+final\s*:\s*public\s+HashFunction\b"), "MD5", "hashing"),
    (re.compile(r"\bclass\s+DES\s+final\s*:"), "DES", None),
    (re.compile(r"\bclass\s+Blowfish\s+final\s*:"), "Blowfish", None),
    (re.compile(r"\bclass\s+ChaCha\s+final\s*:\s*public\s+StreamCipher\b"), "ChaCha20", None),
    (re.compile(r"\bclass\s+HKDF\s+final\s*:\s*public\s+KDF\b"), "HKDF", "key_derivation"),
    (re.compile(r"\bclass\s+Scrypt\s+final\s*:\s*public\s+PasswordHash\b"), "scrypt", "key_derivation"),
    (re.compile(r"\bclass\s+Argon2\s+final\s*:\s*public\s+PasswordHash\b"), "Argon2", "key_derivation"),
    (re.compile(r"\bclass\s+SHA_3\s*:\s*public\s+HashFunction\b"), "SHA-3", "hashing"),
)
_PK_OPS = (
    (re.compile(r"\b(?:Botan::)?PK_Signer\b"), "signing"),
    (re.compile(r"\b(?:Botan::)?PK_Verifier\b"), "signature_verification"),
    (re.compile(r"\b(?:Botan::)?PK_Encryptor(?:_EME)?\b"), "encryption"),
    (re.compile(r"\b(?:Botan::)?PK_Decryptor(?:_EME)?\b"), "decryption"),
    (re.compile(r"\b(?:Botan::)?PK_Key_Agreement\b"), "key_agreement"),
)
_TLS_TYPES = re.compile(r"\b(?:Botan::)?TLS::(?:Client|Server|Callbacks|Policy|Protocol_Version)\b")
_X509_TYPES = re.compile(r"\b(?:Botan::)?X509_(?:Certificate|CA|CRL)\b")
_KEYGEN_HINT = re.compile(r"\b(?:rng|RNG|AutoSeeded_RNG)\b")
_TYPE_PATTERNS = tuple(
    (re.compile(rf"\b(?:Botan::)?{re.escape(name)}\b"), algorithm, usage) for name, algorithm, usage in _BOTAN_TYPES
)
_FACTORY_USAGE = {
    "HashFunction": "hashing",
    "MessageAuthenticationCode": "mac",
    "KDF": "key_derivation",
    "PBKDF": "key_derivation",
    "PasswordHashFamily": "key_derivation",
    "PasswordHash": "key_derivation",
}


def detect_cpp(source: str, file_path: str, settings: Settings, language: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    masked, spans = mask_comments(source, "c")
    libraries = _include_libraries(source, masked, spans)
    findings.extend(_include_findings(source, file_path, settings, language, libraries))
    findings.extend(_openssl_findings(source, file_path, settings, language, masked, spans))
    findings.extend(_botan_findings(source, file_path, settings, language, libraries, masked, spans))
    return findings


def _search(source: str, pattern: re.Pattern, masked: str, spans: list[tuple[int, int]]):
    return each_match(source, "c", pattern, masked=masked, spans=spans)


def _include_libraries(
    source: str, masked: str, spans: list[tuple[int, int]]
) -> dict[str, tuple[int, int, str]]:
    found: dict[str, tuple[int, int, str]] = {}
    for match, line_start, line_end in _search(source, _INCLUDE, masked, spans):
        library = "Botan" if match.group("library").lower() == "botan" else "OpenSSL"
        if library not in found:
            found[library] = (line_start, line_end, match.group("header"))
    return found


def _include_findings(
    source: str,
    file_path: str,
    settings: Settings,
    language: str,
    libraries: dict[str, tuple[int, int, str]],
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for library, (line_start, line_end, header) in libraries.items():
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                library=library,
                usage="unknown",
                method="import_detection",
                confidence="medium",
                metadata={"header": header},
            )
        )
    return findings


def _openssl_findings(
    source: str,
    file_path: str,
    settings: Settings,
    language: str,
    masked: str,
    spans: list[tuple[int, int]],
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for match, line_start, line_end in _search(source, _ENCRYPT, masked, spans):
        findings.append(_openssl_cipher(source, file_path, settings, language, match, line_start, line_end, "encryption"))
    for match, line_start, line_end in _search(source, _DECRYPT, masked, spans):
        findings.append(_openssl_cipher(source, file_path, settings, language, match, line_start, line_end, "decryption"))
    for match, line_start, line_end in _search(source, _DIGEST, masked, spans):
        algorithm = _HASHES[match.group("hash").lower()]
        spec = lookup_algorithm(algorithm)
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                algorithm=algorithm,
                family=spec.family if spec else "hash",
                library="OpenSSL",
                usage="hashing",
            )
        )
    for match, line_start, line_end in _search(source, _RSA_KEYGEN, masked, spans):
        key_size = _literal_int(match.group("args"))
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                algorithm="RSA",
                family="asymmetric",
                library="OpenSSL",
                usage="key_generation",
                key_size=key_size,
            )
        )
    simple = (
        (_RSA_SIGN, "RSA", "asymmetric", "signing"),
        (_RSA_VERIFY, "RSA", "asymmetric", "signature_verification"),
        (_RSA_ENCRYPT, "RSA", "asymmetric", "encryption"),
        (_RSA_DECRYPT, "RSA", "asymmetric", "decryption"),
        (_ECDSA_SIGN, "ECDSA", "asymmetric", "signing"),
        (_ECDSA_VERIFY, "ECDSA", "asymmetric", "signature_verification"),
        (_ECDH, "ECDH", "asymmetric", "key_agreement"),
        (_DH, "Diffie-Hellman", "asymmetric", "key_agreement"),
        (_HMAC, "HMAC", "mac", "mac"),
        (_CMAC, "CMAC", "mac", "mac"),
        (_PBKDF2, "PBKDF2", "kdf", "key_derivation"),
        (_SCRYPT, "scrypt", "kdf", "key_derivation"),
        (_HKDF, "HKDF", "kdf", "key_derivation"),
        (_ED25519, "Ed25519", "asymmetric", "unknown"),
        (_ED448, "Ed448", "asymmetric", "unknown"),
        (_X25519, "X25519", "asymmetric", "key_agreement"),
        (_MLKEM, "ML-KEM", "asymmetric", "key_agreement"),
    )
    for pattern, algorithm, family, usage in simple:
        for _match, line_start, line_end in _search(source, pattern, masked, spans):
            findings.append(
                _finding(
                    source,
                    file_path,
                    settings,
                    language,
                    line_start,
                    line_end,
                    algorithm=algorithm,
                    family=family,
                    library="OpenSSL",
                    usage=usage,
                )
            )
    for match, line_start, line_end in _search(source, _EC, masked, spans):
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                library="OpenSSL",
                usage="unknown",
                curve=lookup_curve(match.group("curve")),
            )
        )
    return findings


def _openssl_cipher(
    source: str,
    file_path: str,
    settings: Settings,
    language: str,
    match: re.Match[str],
    line_start: int,
    line_end: int,
    usage: str,
) -> RawFinding:
    cipher = match.group("cipher").lower()
    algorithm, family = _OPENSSL_CIPHERS[cipher]
    size = match.group("size")
    mode = match.group("mode")
    return _finding(
        source,
        file_path,
        settings,
        language,
        line_start,
        line_end,
        algorithm=algorithm,
        family=family,
        library="OpenSSL",
        usage=usage,
        key_size=int(size) if size else None,
        mode=mode.upper() if mode else None,
    )


def _botan_findings(
    source: str,
    file_path: str,
    settings: Settings,
    language: str,
    libraries: dict[str, tuple[int, int, str]],
    masked: str,
    spans: list[tuple[int, int]],
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    resolved = "Botan" in libraries or "Botan::" in source
    for match, line_start, line_end in _search(source, _FACTORY, masked, spans):
        parsed = parse_explicit_token(match.group("token"))
        if parsed is None:
            continue
        usage = _FACTORY_USAGE.get(match.group("factory"), "algorithm_selection")
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                algorithm=parsed["algorithm"],
                family=parsed["family"],
                library="Botan",
                usage=usage,
                key_size=parsed.get("key_size"),
                mode=parsed.get("mode"),
                resolved=resolved,
                metadata={key: parsed[key] for key in ("hash", "cipher") if parsed.get(key)},
            )
        )
    for pattern, algorithm, usage in _TYPE_PATTERNS:
        spec = lookup_algorithm(algorithm)
        for match, line_start, line_end in _search(source, pattern, masked, spans):
            line = _line_text(source, line_start)
            actual_usage = usage or _type_usage(algorithm, line)
            key_size = None
            if algorithm == "RSA":
                bits = _RSA_BITS.search(line)
                if bits:
                    key_size = int(bits.group("bits"))
                    actual_usage = "key_generation"
            elif algorithm == "AES" and match.group(0).endswith(("128", "192", "256")):
                key_size = int(match.group(0)[-3:])
            findings.append(
                _finding(
                    source,
                    file_path,
                    settings,
                    language,
                    line_start,
                    line_end,
                    algorithm=algorithm,
                    family=spec.family if spec else None,
                    library="Botan",
                    usage=actual_usage,
                    key_size=key_size,
                    resolved=resolved or match.group(0).startswith("Botan::"),
                )
            )
    for pattern, algorithm, usage in _BOTAN_QUALIFIED + _BOTAN_CLASS_DEFS:
        spec = lookup_algorithm(algorithm)
        for _match, line_start, line_end in _search(source, pattern, masked, spans):
            findings.append(
                _finding(
                    source,
                    file_path,
                    settings,
                    language,
                    line_start,
                    line_end,
                    algorithm=algorithm,
                    family=spec.family if spec else None,
                    library="Botan",
                    usage=usage or "unknown",
                    resolved=True,
                )
            )
    for pattern, usage in _PK_OPS:
        for match, line_start, line_end in _search(source, pattern, masked, spans):
            line = _line_text(source, line_start)
            hash_name = None
            hashed = _WITH_HASH.search(line)
            if hashed:
                spec = lookup_algorithm(hashed.group("hash"))
                hash_name = spec.canonical_name if spec and spec.family == "hash" else None
            findings.append(
                _finding(
                    source,
                    file_path,
                    settings,
                    language,
                    line_start,
                    line_end,
                    library="Botan",
                    usage=usage,
                    resolved=resolved or match.group(0).startswith("Botan::"),
                    metadata={"hash": hash_name} if hash_name else None,
                )
            )
    for match, line_start, line_end in _search(source, _EC_GROUP, masked, spans):
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                library="Botan",
                usage="unknown",
                curve=lookup_curve(match.group("curve")),
                resolved=resolved,
            )
        )
    for match, line_start, line_end in _search(source, _TLS_TYPES, masked, spans):
        metadata = {}
        version = _TLS_VERSION.search(_line_text(source, line_start))
        if version:
            metadata["tls_version"] = _tls_version(version.group("version"))
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                library="Botan",
                usage="unknown",
                resolved=resolved or match.group(0).startswith("Botan::"),
                metadata=metadata or {"api": "tls"},
            )
        )
    for match, line_start, line_end in _search(source, _X509_TYPES, masked, spans):
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                library="Botan",
                usage="unknown",
                resolved=resolved or match.group(0).startswith("Botan::"),
                metadata={"api": "x509"},
            )
        )
    for match, line_start, line_end in _search(source, _TLS_VERSION, masked, spans):
        if any(item.line_start == line_start and item.metadata.get("tls_version") for item in findings):
            continue
        findings.append(
            _finding(
                source,
                file_path,
                settings,
                language,
                line_start,
                line_end,
                library="Botan",
                usage="unknown",
                resolved=resolved,
                metadata={"tls_version": _tls_version(match.group("version"))},
            )
        )
    return findings


def _type_usage(algorithm: str, line: str) -> str:
    spec = lookup_algorithm(algorithm)
    if spec and spec.family == "hash":
        return "hashing"
    if spec and spec.family == "kdf":
        return "key_derivation"
    if spec and spec.family == "mac":
        return "mac"
    if algorithm in {"ECDH", "Diffie-Hellman"}:
        return "key_agreement"
    if spec and spec.family == "asymmetric" and _KEYGEN_HINT.search(line) and "PrivateKey" in line:
        return "key_generation"
    return "unknown"


def _tls_version(token: str) -> str:
    if token.endswith("13") or token.endswith("1_3"):
        return "1.3"
    return "1.2"


def _line_text(source: str, line_start: int) -> str:
    lines = source.splitlines()
    if 1 <= line_start <= len(lines):
        return lines[line_start - 1]
    return ""


def _literal_int(text: str) -> int | None:
    match = re.search(r"\b(\d{3,5})\b", text)
    return int(match.group(1)) if match else None


def _finding(
    source: str,
    file_path: str,
    settings: Settings,
    language: str,
    line_start: int,
    line_end: int,
    *,
    algorithm: str | None = None,
    family: str | None = None,
    library: str | None,
    usage: str,
    method: str = "api_detection",
    confidence: str = "high",
    key_size: int | None = None,
    curve: str | None = None,
    mode: str | None = None,
    metadata: dict[str, str] | None = None,
    resolved: bool = True,
) -> RawFinding:
    if algorithm and family is None:
        spec = lookup_algorithm(algorithm)
        family = spec.family if spec else None
    return RawFinding(
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        language=language,
        algorithm=algorithm,
        algorithm_family=family,
        library=library,
        library_version=None,
        usage=usage,
        key_size=key_size,
        curve=curve,
        mode=mode,
        evidence=snippet(source, line_start, line_end, settings),
        detection_method=method,
        confidence=confidence,
        metadata=metadata or {},
        library_resolved=resolved,
    )
