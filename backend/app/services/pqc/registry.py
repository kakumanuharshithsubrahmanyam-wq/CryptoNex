"""Central PQC candidate metadata.

This is a planning catalog. CryptoNex does not implement ML-KEM, ML-DSA, or
SLH-DSA and does not assert that using a listed candidate makes a system
quantum-safe.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PqcAlgorithm:
    name: str
    family: str
    purpose: str
    role: str
    migration_target: str
    hybrid_suitable: bool
    notes: str


PQC_ALGORITHMS: dict[str, PqcAlgorithm] = {
    "ML-KEM": PqcAlgorithm(
        name="ML-KEM",
        family="module-lattice key encapsulation",
        purpose="key_encapsulation",
        role="key_establishment",
        migration_target="classical key establishment and encryption-related public-key use",
        hybrid_suitable=True,
        notes=(
            "NIST FIPS 203 family. Planning candidate for key establishment. "
            "CryptoNex records metadata only and does not implement ML-KEM."
        ),
    ),
    "ML-DSA": PqcAlgorithm(
        name="ML-DSA",
        family="module-lattice digital signature",
        purpose="digital_signature",
        role="digital_signature",
        migration_target="classical digital signatures",
        hybrid_suitable=True,
        notes=(
            "NIST FIPS 204 family. Planning candidate for signature use cases. "
            "CryptoNex records metadata only and does not implement ML-DSA."
        ),
    ),
    "SLH-DSA": PqcAlgorithm(
        name="SLH-DSA",
        family="stateless hash-based digital signature",
        purpose="digital_signature",
        role="digital_signature",
        migration_target="classical digital signatures",
        hybrid_suitable=True,
        notes=(
            "NIST FIPS 205 family. Optional signature alternative to ML-DSA. "
            "CryptoNex records metadata only and does not implement SLH-DSA."
        ),
    ),
}


def get_pqc(name: str) -> PqcAlgorithm | None:
    return PQC_ALGORITHMS.get((name or "").strip())


def list_pqc() -> list[PqcAlgorithm]:
    return [PQC_ALGORITHMS[name] for name in sorted(PQC_ALGORITHMS)]


def pqc_as_dict(algorithm: PqcAlgorithm) -> dict:
    return {
        "algorithm": algorithm.name,
        "family": algorithm.family,
        "purpose": algorithm.purpose,
        "role": algorithm.role,
        "migration_target": algorithm.migration_target,
        "hybrid_suitable": algorithm.hybrid_suitable,
        "notes": algorithm.notes,
    }
