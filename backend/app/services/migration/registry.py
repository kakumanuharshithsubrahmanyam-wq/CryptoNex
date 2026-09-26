"""Centralized role-based migration registry.

Migration logic lives here. Services look up candidates; they do not hardcode
RSA→ML-KEM style replacements. Mapping depends on cryptographic role.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.pqc.registry import PQC_ALGORITHMS, pqc_as_dict
from app.services.scanner.registry import lookup_algorithm

SIGNATURE_ROLE = "digital_signature"
KEY_ESTABLISHMENT_ROLE = "key_establishment"
UNKNOWN_ROLE = "unknown"

SIGNATURE_ALGORITHMS = frozenset({"DSA", "ECDSA", "Ed25519", "Ed448"})
KEY_ESTABLISHMENT_ALGORITHMS = frozenset({"ECDH", "Diffie-Hellman", "X25519"})
MULTI_ROLE_ALGORITHMS = frozenset({"RSA"})
LEGACY_WEAK = frozenset({"MD5", "DES", "RC4"})
LEGACY_HASH = frozenset({"MD5", "SHA-1"})
LEGACY_CIPHER = frozenset({"DES", "3DES", "Blowfish"})
MODERN_SYMMETRIC = frozenset({"AES", "ChaCha20", "ChaCha20-Poly1305", "XChaCha20-Poly1305"})
MODERN_HASH = frozenset({"SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-3", "BLAKE2", "BLAKE3"})
MAC_ALGORITHMS = frozenset({"HMAC", "CMAC", "Poly1305"})
KDF_ALGORITHMS = frozenset({"PBKDF2", "scrypt", "Argon2", "HKDF"})
DEPLOYED_PQC = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA"})
HYBRID_ALGORITHMS = frozenset({"X-Wing", "HPKE"})
MANUAL_PUBLIC_KEY = SIGNATURE_ALGORITHMS | KEY_ESTABLISHMENT_ALGORITHMS | MULTI_ROLE_ALGORITHMS

CLASSICAL_COUNTERPARTS: dict[str, tuple[str, ...]] = {
    "MD5": ("SHA-256", "SHA-384", "SHA-512", "SHA-3", "BLAKE2", "BLAKE3"),
    "SHA-1": ("SHA-256", "SHA-384", "SHA-512", "SHA-3", "BLAKE2", "BLAKE3"),
    "DES": ("AES", "ChaCha20-Poly1305"),
    "3DES": ("AES", "ChaCha20-Poly1305"),
    "Blowfish": ("AES", "ChaCha20-Poly1305"),
    "RC4": ("AES", "ChaCha20-Poly1305"),
}
DEFAULT_CLASSICAL_REPLACEMENT = {
    "MD5": "SHA-256",
    "SHA-1": "SHA-256",
}

_USAGE_TO_ROLE = {
    "signing": SIGNATURE_ROLE,
    "signature_verification": SIGNATURE_ROLE,
    "key_agreement": KEY_ESTABLISHMENT_ROLE,
    "encryption": "confidentiality",
    "decryption": "confidentiality",
    "hashing": "integrity",
    "mac": "authentication",
    "key_derivation": "password_protection",
    "key_generation": UNKNOWN_ROLE,
    "algorithm_selection": UNKNOWN_ROLE,
    "dependency_only": UNKNOWN_ROLE,
}

_SIGNATURE_CANDIDATES = ("ML-DSA", "SLH-DSA")
_KEM_CANDIDATES = ("ML-KEM",)


@dataclass(frozen=True)
class ReplacementCandidate:
    algorithm: str
    role: str
    family: str
    purpose: str
    hybrid_suitable: bool
    notes: str


@dataclass(frozen=True)
class MigrationAdvice:
    algorithm: str
    role: str
    category: str
    replaceable: bool
    candidates: tuple[ReplacementCandidate, ...]
    explanation: str
    warnings: tuple[str, ...]


def canonical_algorithm(name: str | None) -> str | None:
    if not name:
        return None
    spec = lookup_algorithm(name)
    if spec is not None:
        return spec.canonical_name
    stripped = name.strip()
    return stripped or None


def infer_role(finding) -> str:
    """Resolve a cryptographic role from stored context, then usage, then algorithm."""
    stored = getattr(finding, "cryptographic_role", None)
    if stored and stored != UNKNOWN_ROLE:
        return stored
    usage = getattr(finding, "usage", None) or ""
    usage_role = _USAGE_TO_ROLE.get(usage)
    algorithm = canonical_algorithm(getattr(finding, "algorithm", None))
    if usage_role == "confidentiality" and algorithm in MULTI_ROLE_ALGORITHMS:
        return KEY_ESTABLISHMENT_ROLE
    if usage_role and usage_role != UNKNOWN_ROLE:
        return usage_role
    concern = getattr(finding, "security_concern", None)
    if concern == "classical_signature":
        return SIGNATURE_ROLE
    if concern in {"classical_key_exchange"}:
        return KEY_ESTABLISHMENT_ROLE
    quantum = getattr(finding, "quantum_relevance", None)
    if quantum == "classical_signature":
        return SIGNATURE_ROLE
    if quantum == "classical_key_establishment":
        return KEY_ESTABLISHMENT_ROLE
    if algorithm in SIGNATURE_ALGORITHMS:
        return SIGNATURE_ROLE
    if algorithm in KEY_ESTABLISHMENT_ALGORITHMS:
        return KEY_ESTABLISHMENT_ROLE
    return UNKNOWN_ROLE


def _candidate(name: str) -> ReplacementCandidate:
    spec = PQC_ALGORITHMS[name]
    return ReplacementCandidate(
        algorithm=spec.name,
        role=spec.role,
        family=spec.family,
        purpose=spec.purpose,
        hybrid_suitable=spec.hybrid_suitable,
        notes=spec.notes,
    )


def _candidates(names: tuple[str, ...]) -> tuple[ReplacementCandidate, ...]:
    return tuple(_candidate(name) for name in names)


def advise(finding) -> MigrationAdvice:
    """Return role-based replacement advice. Never maps an algorithm blindly."""
    algorithm = canonical_algorithm(getattr(finding, "algorithm", None))
    role = infer_role(finding)
    if algorithm is None:
        return MigrationAdvice(
            algorithm="unknown",
            role=role,
            category="unknown",
            replaceable=False,
            candidates=(),
            explanation="No algorithm was identified on this finding.",
            warnings=("Replacement candidates cannot be selected without an identified algorithm.",),
        )
    if algorithm in DEPLOYED_PQC:
        return MigrationAdvice(
            algorithm=algorithm,
            role=role,
            category="post_quantum",
            replaceable=False,
            candidates=(),
            explanation=(
                f"{algorithm} is already a registered post-quantum primitive. "
                "CryptoNex does not recommend replacing it with another PQC algorithm by default."
            ),
            warnings=("Presence of a PQC primitive is not a claim that the repository is quantum-safe.",),
        )
    if algorithm in HYBRID_ALGORITHMS:
        return MigrationAdvice(
            algorithm=algorithm,
            role=role,
            category="hybrid",
            replaceable=False,
            candidates=(),
            explanation=f"{algorithm} is a hybrid construction. It is not a one-line replacement target.",
            warnings=("Hybrid constructions require protocol-level review, not a local identifier swap.",),
        )
    if algorithm in MODERN_SYMMETRIC:
        return MigrationAdvice(
            algorithm=algorithm,
            role=role if role != UNKNOWN_ROLE else "confidentiality",
            category="modern_symmetric",
            replaceable=False,
            candidates=(),
            explanation=(
                f"{algorithm} is a modern symmetric primitive. Migration priority differs "
                "from public-key cryptography. CryptoNex does not recommend replacing it "
                "solely because it is not a post-quantum public-key algorithm."
            ),
            warnings=(
                f"{algorithm} is not labeled quantum-vulnerable in the same way as RSA or ECDSA.",
                "Do not replace modern symmetric primitives with ML-KEM, ML-DSA, or SLH-DSA by default.",
            ),
        )
    if algorithm in MODERN_HASH:
        return MigrationAdvice(
            algorithm=algorithm,
            role=role if role != UNKNOWN_ROLE else "integrity",
            category="modern_hash",
            replaceable=False,
            candidates=(),
            explanation=(
                f"{algorithm} is a modern hash function. Migration priority differs from "
                "public-key cryptography. It is not a PQC replacement target."
            ),
            warnings=(
                f"{algorithm} is not labeled quantum-vulnerable in the same way as RSA or ECDSA.",
            ),
        )
    if algorithm in MAC_ALGORITHMS:
        return MigrationAdvice(
            algorithm=algorithm,
            role=role if role != UNKNOWN_ROLE else "authentication",
            category="mac",
            replaceable=False,
            candidates=(),
            explanation=f"{algorithm} is a message-authentication primitive, not a public-key migration target.",
            warnings=("Do not replace MAC primitives with PQC signature or KEM algorithms by default.",),
        )
    if algorithm in KDF_ALGORITHMS:
        return MigrationAdvice(
            algorithm=algorithm,
            role=role if role != UNKNOWN_ROLE else "password_protection",
            category="key_derivation",
            replaceable=False,
            candidates=(),
            explanation=f"{algorithm} is a key-derivation function. PQC public-key candidates do not replace it.",
            warnings=(),
        )
    if algorithm in LEGACY_HASH or algorithm in LEGACY_CIPHER or algorithm in LEGACY_WEAK:
        return MigrationAdvice(
            algorithm=algorithm,
            role=role,
            category="legacy",
            replaceable=False,
            candidates=(),
            explanation=(
                f"{algorithm} is a weak or legacy primitive. Replace it with a modern "
                "classical counterpart first; it is not mapped to a PQC public-key candidate."
            ),
            warnings=(f"{algorithm} should be retired independently of post-quantum public-key migration.",),
        )
    if algorithm in SIGNATURE_ALGORITHMS:
        return MigrationAdvice(
            algorithm=algorithm,
            role=SIGNATURE_ROLE,
            category="classical_signature",
            replaceable=True,
            candidates=_candidates(_SIGNATURE_CANDIDATES),
            explanation=(
                f"{algorithm} is used for digital signatures. Candidate replacements are "
                "ML-DSA and optionally SLH-DSA. ML-KEM is not a signature replacement."
            ),
            warnings=("This is a planning recommendation. CryptoNex has not migrated any source.",),
        )
    if algorithm in KEY_ESTABLISHMENT_ALGORITHMS:
        return MigrationAdvice(
            algorithm=algorithm,
            role=KEY_ESTABLISHMENT_ROLE,
            category="classical_key_establishment",
            replaceable=True,
            candidates=_candidates(_KEM_CANDIDATES),
            explanation=(
                f"{algorithm} is used for key establishment. The planning candidate is ML-KEM. "
                "ML-DSA is not a key-establishment replacement."
            ),
            warnings=("This is a planning recommendation. CryptoNex has not migrated any source.",),
        )
    if algorithm in MULTI_ROLE_ALGORITHMS:
        if role == SIGNATURE_ROLE:
            return MigrationAdvice(
                algorithm=algorithm,
                role=role,
                category="classical_public_key",
                replaceable=True,
                candidates=_candidates(_SIGNATURE_CANDIDATES),
                explanation=(
                    "RSA is used for signatures. Candidate replacements are ML-DSA and SLH-DSA. "
                    "RSA signature usage does not map to ML-KEM."
                ),
                warnings=("This is a planning recommendation. CryptoNex has not migrated any source.",),
            )
        if role == KEY_ESTABLISHMENT_ROLE:
            return MigrationAdvice(
                algorithm=algorithm,
                role=role,
                category="classical_public_key",
                replaceable=True,
                candidates=_candidates(_KEM_CANDIDATES),
                explanation=(
                    "RSA is used for key establishment or encryption-related public-key operations. "
                    "The planning candidate is ML-KEM."
                ),
                warnings=("This is a planning recommendation. CryptoNex has not migrated any source.",),
            )
        return MigrationAdvice(
            algorithm=algorithm,
            role=UNKNOWN_ROLE,
            category="classical_public_key",
            replaceable=True,
            candidates=_candidates(_SIGNATURE_CANDIDATES + _KEM_CANDIDATES),
            explanation=(
                "RSA can serve signatures or key establishment. The cryptographic role is unknown, "
                "so both ML-DSA/SLH-DSA and ML-KEM remain candidates."
            ),
            warnings=(
                "Role is unknown. Do not select a single replacement without confirming the use case.",
                "This is a planning recommendation. CryptoNex has not migrated any source.",
            ),
        )
    spec = lookup_algorithm(algorithm)
    if spec and spec.family == "asymmetric":
        return MigrationAdvice(
            algorithm=algorithm,
            role=role,
            category="classical_public_key",
            replaceable=True,
            candidates=_candidates(_SIGNATURE_CANDIDATES + _KEM_CANDIDATES) if role == UNKNOWN_ROLE else (),
            explanation=f"{algorithm} is a classical public-key primitive. Role-specific candidates are limited.",
            warnings=("Role or algorithm coverage is incomplete.",),
        )
    return MigrationAdvice(
        algorithm=algorithm,
        role=role,
        category="unknown",
        replaceable=False,
        candidates=(),
        explanation=f"No migration mapping is defined for {algorithm}.",
        warnings=("Unknown algorithm family. Replacement is unknown.",),
    )


def candidate_dicts(advice: MigrationAdvice) -> list[dict]:
    payload = []
    for item in advice.candidates:
        spec = PQC_ALGORITHMS.get(item.algorithm)
        body = {
            "algorithm": item.algorithm,
            "role": item.role,
            "family": item.family,
            "purpose": item.purpose,
            "hybrid_suitable": item.hybrid_suitable,
            "notes": item.notes,
        }
        if spec is not None:
            body.update({key: value for key, value in pqc_as_dict(spec).items() if key not in body})
        payload.append(body)
    return payload


def registered_replacement_names(advice: MigrationAdvice) -> set[str]:
    names = {item.algorithm for item in advice.candidates}
    names.update(CLASSICAL_COUNTERPARTS.get(advice.algorithm, ()))
    return names


def is_registered_replacement(advice: MigrationAdvice, replacement: str | None) -> bool:
    canonical = canonical_algorithm(replacement)
    if canonical is None:
        return False
    return canonical in registered_replacement_names(advice)


def default_replacement(advice: MigrationAdvice) -> str | None:
    if advice.algorithm in DEFAULT_CLASSICAL_REPLACEMENT:
        return DEFAULT_CLASSICAL_REPLACEMENT[advice.algorithm]
    if len(advice.candidates) == 1:
        return advice.candidates[0].algorithm
    return None


def current_parameters(finding) -> dict:
    parameters = {}
    for field in ("key_size", "curve", "mode"):
        value = getattr(finding, field, None)
        if value is not None:
            parameters[field] = value
    return parameters
