"""Phase 10 PQC registry, hybrid planning, what-if simulation, and agility."""

from app.core.exceptions import AppError
from app.services.migration.registry import advise
from app.services.pqc.agility import analyze_agility
from app.services.pqc.registry import get_pqc, list_pqc
from app.services.pqc.simulator import estimate_complexity, hybrid_plan, what_if
from tests.intelligence_helpers import finding, rsa_graph, snapshot
import pytest


def test_pqc_registry_contains_required_algorithms() -> None:
    names = {item.name for item in list_pqc()}
    assert names == {"ML-DSA", "ML-KEM", "SLH-DSA"}
    kem = get_pqc("ML-KEM")
    assert kem is not None
    assert kem.role == "key_establishment"
    assert kem.hybrid_suitable is True
    assert "does not implement" in kem.notes


def test_role_based_pqc_mapping_via_what_if() -> None:
    cases = [
        (finding(cryptographic_role="digital_signature", usage="signing"), "ML-DSA", "digital_signature"),
        (finding(cryptographic_role="key_establishment", usage="key_agreement"), "ML-KEM", "key_establishment"),
        (finding(algorithm="ECDSA", cryptographic_role="digital_signature", usage="signing", key_size=None), "ML-DSA", "digital_signature"),
        (finding(algorithm="ECDH", cryptographic_role="key_establishment", usage="key_agreement", key_size=None), "ML-KEM", "key_establishment"),
    ]
    for row, replacement, role in cases:
        context = snapshot([row], graph=rsa_graph())
        result = what_if(context, row.id, replacement, "pqc")
        assert result["proposed_replacement"] == replacement
        assert result["source_migrated"] is False
        assert result["current_algorithm"]
        if role == "key_establishment":
            assert result["proposed_replacement"] == "ML-KEM"


def test_hybrid_simulation() -> None:
    row = finding(algorithm="ECDH", cryptographic_role="key_establishment", usage="key_agreement", key_size=None)
    result = hybrid_plan(snapshot([row], graph=rsa_graph()), row, "ML-KEM")
    assert result["hybrid_option"]["classical"] == "ECDH"
    assert result["hybrid_option"]["pqc"] == "ML-KEM"
    assert result["hybrid_option"]["path"] == ["classical", "hybrid", "pqc"]
    assert result["hybrid_option"]["mode"] == "hybrid"
    assert any("does not claim production" in item.lower() for item in result["interoperability_considerations"])


def test_what_if_simulator_and_complexity() -> None:
    row = finding(cryptographic_role="key_establishment", usage="key_agreement")
    context = snapshot([row], graph=rsa_graph())
    result = what_if(context, 1, "ML-KEM", "hybrid")
    assert result["migration_mode"] == "hybrid"
    assert result["estimated_migration_complexity"] in {"low", "medium", "high", "unknown"}
    assert "src/auth.py" in result["affected_files"]
    assert "cryptography" in result["affected_dependencies"]
    assert "TLS" in result["affected_protocols"]
    assert "server.crt" in result["affected_certificates"]
    assert result["related_findings"]
    assert result["source_migrated"] is False
    assert what_if(context, 1, "ML-KEM", "hybrid") == result


def test_what_if_unknown_role_complexity() -> None:
    row = finding(cryptographic_role="unknown", usage="key_generation")
    result = what_if(snapshot([row]), 1, "ML-KEM", "pqc")
    assert result["estimated_migration_complexity"] == "unknown"


def test_what_if_rejects_invalid_mode() -> None:
    with pytest.raises(AppError) as exc:
        what_if(snapshot([finding()]), 1, "ML-KEM", "teleport")
    assert exc.value.code == "INVALID_WHAT_IF"


def test_aes_what_if_warns_against_blind_replacement() -> None:
    row = finding(algorithm="AES", usage="encryption", key_size=256, security_concern="symmetric_cryptography")
    result = what_if(snapshot([row]), 1, "ML-KEM", "pqc")
    assert any("Do not blindly replace" in warning for warning in result["warnings"])
    assert estimate_complexity(advise(row), {"affected_files": [], "affected_protocols": [], "affected_certificates": [], "related_findings": []}, "pqc") == "low"


def test_crypto_agility_classification() -> None:
    scattered = [
        finding(id=index, file_path=f"src/mod{index}.py", algorithm="RSA", usage="signing", cryptographic_role="digital_signature")
        for index in range(1, 6)
    ]
    low = analyze_agility(snapshot(scattered))
    assert low["classification"] == "low_agility"
    assert "multiple direct crypto API calls" in low["evidence"]

    concentrated = [
        finding(id=1, file_path="config/crypto.yml", usage="algorithm_selection", evidence_type="confirmed_configuration"),
        finding(id=2, file_path="src/crypto.py", usage="signing", cryptographic_role="digital_signature"),
    ]
    high = analyze_agility(snapshot(concentrated))
    assert high["classification"] in {"high_agility", "moderate_agility"}

    empty = analyze_agility(snapshot([]))
    assert empty["classification"] == "unknown"
    assert analyze_agility(snapshot(scattered)) == low
