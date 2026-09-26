"""Phase 8 migration registry, priority, plans, and blast radius."""

from app.services.migration.blast_radius import blast_radius
from app.services.migration.planner import plan_finding
from app.services.migration.priority import prioritize
from app.services.migration.registry import advise, infer_role
from tests.intelligence_helpers import finding, rsa_graph, snapshot


def _names(advice) -> list[str]:
    return [item.algorithm for item in advice.candidates]


def test_rsa_signature_maps_to_ml_dsa_not_ml_kem() -> None:
    advice = advise(finding(cryptographic_role="digital_signature", usage="signing"))
    assert advice.role == "digital_signature"
    assert _names(advice) == ["ML-DSA", "SLH-DSA"]
    assert "ML-KEM" not in _names(advice)


def test_rsa_key_establishment_maps_to_ml_kem() -> None:
    advice = advise(finding(cryptographic_role="key_establishment", usage="key_agreement"))
    assert advice.role == "key_establishment"
    assert _names(advice) == ["ML-KEM"]
    assert "ML-DSA" not in _names(advice)


def test_rsa_encryption_usage_is_key_establishment() -> None:
    advice = advise(finding(cryptographic_role="unknown", usage="encryption"))
    assert infer_role(finding(cryptographic_role="unknown", usage="encryption")) == "key_establishment"
    assert _names(advice) == ["ML-KEM"]


def test_ecdsa_ed25519_and_dsa_map_to_signatures() -> None:
    for algorithm, concern in (
        ("ECDSA", "classical_signature"),
        ("Ed25519", "classical_signature"),
        ("DSA", "classical_signature"),
    ):
        advice = advise(finding(algorithm=algorithm, cryptographic_role="unknown", usage="key_generation", security_concern=concern))
        assert advice.role == "digital_signature"
        assert _names(advice) == ["ML-DSA", "SLH-DSA"]


def test_x25519_maps_to_ml_kem() -> None:
    advice = advise(
        finding(
            algorithm="X25519",
            cryptographic_role="unknown",
            usage="key_agreement",
            security_concern="classical_key_exchange",
            key_size=None,
        )
    )
    assert advice.role == "key_establishment"
    assert _names(advice) == ["ML-KEM"]


def test_ecdh_and_dh_map_to_ml_kem() -> None:
    for algorithm in ("ECDH", "Diffie-Hellman"):
        advice = advise(
            finding(
                algorithm=algorithm,
                cryptographic_role="unknown",
                usage="key_agreement",
                security_concern="classical_key_exchange",
                key_size=None,
            )
        )
        assert advice.role == "key_establishment"
        assert _names(advice) == ["ML-KEM"]


def test_aes_is_not_treated_as_quantum_vulnerable_public_key() -> None:
    advice = advise(finding(algorithm="AES", usage="encryption", key_size=256, security_concern="symmetric_cryptography"))
    priority, reasons = prioritize(finding(algorithm="AES", usage="encryption", key_size=256, security_concern="symmetric_cryptography"))
    assert advice.candidates == ()
    assert advice.category == "modern_symmetric"
    assert priority == "informational"
    assert any("modern symmetric" in reason for reason in reasons)
    assert all("quantum-vulnerable" not in reason for reason in reasons)
    assert any("not labeled quantum-vulnerable" in warning for warning in advice.warnings)


def test_sha256_is_modern_hash() -> None:
    row = finding(algorithm="SHA-256", usage="hashing", key_size=None, security_concern="modern_hash", cryptographic_role="integrity")
    advice = advise(row)
    priority, reasons = prioritize(row)
    assert advice.candidates == ()
    assert advice.category == "modern_hash"
    assert priority == "informational"
    assert any("modern hash" in reason for reason in reasons)


def test_unknown_rsa_role_returns_multiple_candidates() -> None:
    advice = advise(finding(cryptographic_role="unknown", usage="key_generation"))
    assert advice.role == "unknown"
    assert _names(advice) == ["ML-DSA", "SLH-DSA", "ML-KEM"]
    assert any("Role is unknown" in warning for warning in advice.warnings)


def test_priority_reasoning_for_rsa_2048() -> None:
    priority, reasons = prioritize(finding())
    assert priority == "high"
    assert "classical public-key cryptography" in reasons
    assert "explicit RSA-2048 parameter" in reasons


def test_weak_rsa_is_critical() -> None:
    priority, reasons = prioritize(finding(key_size=1024))
    assert priority == "critical"
    assert "explicit weak parameters" in reasons


def test_md5_is_critical() -> None:
    priority, reasons = prioritize(finding(algorithm="MD5", usage="hashing", key_size=None, security_concern="legacy_hash"))
    assert priority == "critical"
    assert any("legacy" in reason for reason in reasons)


def test_migration_plan_is_deterministic_and_does_not_claim_migration() -> None:
    row = finding(cryptographic_role="key_establishment", usage="key_agreement")
    context = snapshot([row], graph=rsa_graph())
    first = plan_finding(context, row)
    second = plan_finding(context, row)
    assert first == second
    assert first["finding_id"] == 1
    assert first["current_algorithm"] == "RSA"
    assert first["current_usage"] == "key_agreement"
    assert first["current_library"] == "cryptography"
    assert first["current_parameters"] == {"key_size": 2048}
    assert first["candidate_replacements"][0]["algorithm"] == "ML-KEM"
    assert first["migration_occurred"] is False
    assert "identify key establishment API" in first["migration_steps"]
    assert "evaluate hybrid classical/PQC mode" in first["migration_steps"]


def test_blast_radius_traverses_graph() -> None:
    radius = blast_radius(rsa_graph(), 1, finding())
    assert {item["label"] for item in radius["affected_files"]} == {"src/auth.py"}
    assert {item["label"] for item in radius["affected_dependencies"]} == {"cryptography"}
    assert {item["label"] for item in radius["affected_algorithms"]} == {"RSA"}
    assert {item["label"] for item in radius["affected_protocols"]} == {"TLS"}
    assert {item["label"] for item in radius["affected_certificates"]} == {"server.crt"}
    assert any(item["finding_id"] == 2 for item in radius["related_findings"])
    assert radius["graph_paths"]
    assert "Finding 1 may affect" in radius["impact_summary"]
    assert blast_radius(rsa_graph(), 1, finding()) == radius


def test_empty_graph_blast_radius() -> None:
    radius = blast_radius({"nodes": [], "edges": []}, 1, finding())
    assert radius["affected_files"][0]["label"] == "src/auth.py"
    assert radius["affected_algorithms"][0]["label"] == "RSA"
    assert radius["related_findings"] == []
    assert radius["graph_paths"] == []
    assert "No graph relationships" in radius["impact_summary"] or radius["affected_files"]
