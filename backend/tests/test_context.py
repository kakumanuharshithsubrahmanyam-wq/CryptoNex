"""Deterministic evidence, confidence, and cryptographic context."""

from dataclasses import fields
from pathlib import Path

import pytest

from app.core.config import Settings
from app.schemas.scan import FindingResponse
from app.services.context.classifier import FindingContext, classify
from app.services.ingestion.manifest import build_manifest
from app.services.scanner.engine import scan_manifest
from app.services.scanner.evidence import redact_secrets
from app.services.scanner.findings import RawFinding

RSA_SOURCE = """
from cryptography.hazmat.primitives.asymmetric import rsa

rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
"""


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


def _scan(tmp_path: Path, files: dict[str, str]):
    root = tmp_path / "source"
    for relative, content in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    settings = _settings(tmp_path)
    return scan_manifest(root, build_manifest(root, settings), settings)


def _classified(tmp_path: Path, files: dict[str, str]) -> list[tuple[RawFinding, FindingContext]]:
    return [(finding, classify(finding)) for finding in _scan(tmp_path, files).findings]


def _pick(pairs, **expected) -> tuple[RawFinding, FindingContext]:
    for finding, context in pairs:
        if all(getattr(finding, key) == value for key, value in expected.items()):
            return finding, context
    raise AssertionError([(item.algorithm, item.library, item.usage, item.file_path) for item, _ in pairs])


def _raw(**overrides) -> RawFinding:
    values = {
        "file_path": "src/app.py",
        "line_start": 1,
        "line_end": 1,
        "language": "Python",
        "algorithm": None,
        "algorithm_family": None,
        "library": None,
        "library_version": None,
        "usage": "unknown",
        "key_size": None,
        "curve": None,
        "mode": None,
        "evidence": "x",
        "detection_method": "api_detection",
        "confidence": "high",
    }
    values.update(overrides)
    return RawFinding(**values)


def test_high_confidence_api_finding_is_confirmed_with_reasons(tmp_path: Path) -> None:
    finding, context = _pick(_classified(tmp_path, {"src/auth.py": RSA_SOURCE}), algorithm="RSA")
    assert context.evidence_type.value == "confirmed_api_usage"
    assert context.confidence.value == "high"
    assert context.finding_status.value == "confirmed"
    assert [reason.value for reason in context.confidence_reasons] == [
        "recognized_crypto_api_call",
        "recognized_crypto_library",
        "algorithm_identified_from_api",
        "explicit_key_size_detected",
    ]
    assert context.parameter_completeness.value == "complete"
    assert context.security_concern.value == "classical_public_key"
    assert context.quantum_relevance.value == "classical_public_key"
    assert context.cryptographic_role.value == "unknown"
    assert finding.usage == "key_generation"


def test_unresolved_python_library_is_medium_and_probable(tmp_path: Path) -> None:
    source = "exchange = ec.ECDH()\n"
    finding, context = _pick(_classified(tmp_path, {"app.py": source}), algorithm="ECDH")
    assert finding.library == "cryptography"
    assert finding.library_resolved is False
    assert context.confidence.value == "medium"
    assert context.finding_status.value == "probable"
    assert "library_not_confirmed_by_import" in [reason.value for reason in context.confidence_reasons]


def test_go_import_without_call_is_confirmed_import(tmp_path: Path) -> None:
    source = 'package main\nimport "crypto/sha256"\nfunc main() {}\n'
    _finding, context = _pick(_classified(tmp_path, {"main.go": source}), algorithm="SHA-256")
    assert context.evidence_type.value == "confirmed_import"
    assert context.confidence.value == "medium"
    assert context.finding_status.value == "probable"
    assert [reason.value for reason in context.confidence_reasons] == [
        "recognized_crypto_import",
        "algorithm_identified_from_import",
        "no_api_call_observed",
    ]
    assert context.cryptographic_role.value == "unknown"


def test_go_block_import_is_skipped_when_called(tmp_path: Path) -> None:
    source = (
        'package main\nimport (\n\t"crypto/md5"\n\t"crypto/rsa"\n)\n'
        "func main() { rsa.GenerateKey(nil, 2048) }\n"
    )
    pairs = _classified(tmp_path, {"main.go": source})
    _md5, md5_context = _pick(pairs, algorithm="MD5")
    assert md5_context.evidence_type.value == "confirmed_import"
    assert _md5.line_start == 3
    rsa = [finding for finding, _context in pairs if finding.algorithm == "RSA"]
    assert [finding.detection_method for finding in rsa] == ["api_detection"]


def test_dependency_only_finding_is_low_weak_signal(tmp_path: Path) -> None:
    finding, context = _pick(
        _classified(tmp_path, {"requirements.txt": "cryptography==42.0.5\n"}),
        usage="dependency_only",
    )
    assert finding.algorithm is None
    assert context.evidence_type.value == "dependency_presence"
    assert context.confidence.value == "low"
    assert context.finding_status.value == "weak_signal"
    assert [reason.value for reason in context.confidence_reasons] == [
        "crypto_dependency_declared",
        "no_confirmed_source_api_usage",
    ]
    assert context.cryptographic_role.value == "unknown"
    assert context.security_concern.value == "unknown"
    assert context.quantum_relevance.value == "unknown"
    assert context.parameter_completeness.value == "unknown"


def test_weak_textual_signal_is_never_confirmed() -> None:
    context = classify(_raw(algorithm="AES", detection_method="pattern_detection", usage="encryption"))
    assert context.evidence_type.value == "weak_textual_reference"
    assert context.confidence.value == "low"
    assert context.finding_status.value == "weak_signal"
    assert context.cryptographic_role.value == "unknown"


def test_unknown_detection_method_maps_to_unknown_evidence() -> None:
    context = classify(_raw(detection_method="something_new"))
    assert context.evidence_type.value == "unknown"
    assert context.confidence.value == "low"
    assert context.finding_status.value == "weak_signal"


USAGE_SOURCES = {
    "web/crypto.js": """
const key = null;
crypto.subtle.encrypt({ name: "AES-GCM" }, key, data);
crypto.subtle.decrypt({ name: "AES-GCM" }, key, data);
crypto.subtle.sign({ name: "ECDSA" }, key, data);
crypto.subtle.verify({ name: "ECDSA" }, key, sig, data);
crypto.subtle.digest("SHA-256", data);
""",
    "py/kdf.py": """
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
hmac.HMAC(b"k", hashes.SHA256())
PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"s", iterations=1)
HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
ec.ECDH()
""",
}


@pytest.mark.parametrize(
    ("expected", "role"),
    [
        ({"algorithm": "AES", "usage": "encryption"}, "confidentiality"),
        ({"algorithm": "AES", "usage": "decryption"}, "confidentiality"),
        ({"algorithm": "ECDSA", "usage": "signing"}, "digital_signature"),
        ({"algorithm": "ECDSA", "usage": "signature_verification"}, "digital_signature"),
        ({"algorithm": "SHA-256", "library": "Web Crypto"}, "integrity"),
        ({"algorithm": "HMAC", "usage": "mac"}, "authentication"),
        ({"algorithm": "PBKDF2", "usage": "key_derivation"}, "password_protection"),
        ({"algorithm": "HKDF", "usage": "key_derivation"}, "unknown"),
        ({"algorithm": "ECDH", "usage": "key_agreement"}, "key_establishment"),
    ],
)
def test_usage_and_cryptographic_role(tmp_path: Path, expected: dict, role: str) -> None:
    _finding, context = _pick(_classified(tmp_path, USAGE_SOURCES), **expected)
    assert context.cryptographic_role.value == role


def test_cipher_transformation_stays_algorithm_selection(tmp_path: Path) -> None:
    source = 'class A { void f() { Cipher.getInstance("AES/GCM/NoPadding"); } }\n'
    finding, context = _pick(_classified(tmp_path, {"A.java": source}), algorithm="AES")
    assert finding.usage == "algorithm_selection"
    assert finding.mode == "GCM"
    assert finding.key_size is None
    assert context.cryptographic_role.value == "unknown"
    assert context.parameter_completeness.value == "partial"
    assert context.confidence.value == "high"
    assert "explicit_mode_detected" in [reason.value for reason in context.confidence_reasons]
    assert context.security_concern.value == "symmetric_cryptography"
    assert context.quantum_relevance.value == "symmetric"


def test_signature_transformation_records_hash_without_signing(tmp_path: Path) -> None:
    source = 'class A { void f() { Signature.getInstance("SHA256withRSA"); } }\n'
    finding, context = _pick(_classified(tmp_path, {"A.java": source}), algorithm="RSA")
    assert finding.usage == "algorithm_selection"
    assert finding.metadata == {"hash": "SHA-256"}
    assert context.cryptographic_role.value == "unknown"
    assert context.parameter_completeness.value == "unknown"
    assert "explicit_hash_detected" in [reason.value for reason in context.confidence_reasons]


def test_ec_curve_only_detection_keeps_algorithm_unknown(tmp_path: Path) -> None:
    source = "void f() { EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); }\n"
    finding, context = _pick(_classified(tmp_path, {"ec.c": source}), library="OpenSSL")
    assert finding.algorithm is None
    assert finding.curve == "secp256r1"
    assert context.confidence.value == "medium"
    assert context.finding_status.value == "probable"
    assert "curve_identified_algorithm_unknown" in [reason.value for reason in context.confidence_reasons]
    assert context.parameter_completeness.value == "partial"
    assert context.cryptographic_role.value == "unknown"
    assert context.security_concern.value == "classical_public_key"
    assert context.quantum_relevance.value == "classical_public_key"


@pytest.mark.parametrize(
    ("finding", "completeness"),
    [
        (_raw(algorithm="RSA", key_size=2048), "complete"),
        (_raw(algorithm="RSA"), "unknown"),
        (_raw(algorithm="AES", mode="GCM"), "partial"),
        (_raw(algorithm="AES", mode="GCM", key_size=256), "complete"),
        (_raw(algorithm="ECDSA", curve="secp256r1"), "complete"),
        (_raw(algorithm="SHA-256"), "complete"),
        (_raw(algorithm="HMAC"), "unknown"),
        (_raw(algorithm="HMAC", metadata={"hash": "SHA-256"}), "complete"),
        (_raw(algorithm="PBKDF2", metadata={"hash": "SHA-256"}), "partial"),
        (_raw(algorithm=None), "unknown"),
    ],
)
def test_parameter_completeness(finding: RawFinding, completeness: str) -> None:
    assert classify(finding).parameter_completeness.value == completeness


def test_unknown_parameters_stay_null(tmp_path: Path) -> None:
    source = 'class A { void f() { KeyPairGenerator.getInstance("RSA"); } }\n'
    finding, context = _pick(_classified(tmp_path, {"A.java": source}), algorithm="RSA")
    assert finding.key_size is None
    assert context.parameter_completeness.value == "unknown"
    assert "explicit_key_size_detected" not in [reason.value for reason in context.confidence_reasons]


@pytest.mark.parametrize(
    ("algorithm", "concern", "relevance"),
    [
        ("MD5", "legacy_hash", "hash"),
        ("SHA-1", "legacy_hash", "hash"),
        ("DES", "legacy_cipher", "symmetric"),
        ("3DES", "legacy_cipher", "symmetric"),
        ("RSA", "classical_public_key", "classical_public_key"),
        ("DSA", "classical_signature", "classical_signature"),
        ("ECDSA", "classical_signature", "classical_signature"),
        ("Ed25519", "classical_signature", "classical_signature"),
        ("ECDH", "classical_key_exchange", "classical_key_establishment"),
        ("Diffie-Hellman", "classical_key_exchange", "classical_key_establishment"),
        ("AES", "symmetric_cryptography", "symmetric"),
        ("ChaCha20", "symmetric_cryptography", "symmetric"),
        ("SHA-256", "modern_hash", "hash"),
        ("PBKDF2", "key_derivation", "key_derivation"),
        ("HMAC", "mac", "mac"),
    ],
)
def test_security_concern_and_quantum_relevance(algorithm: str, concern: str, relevance: str) -> None:
    context = classify(_raw(algorithm=algorithm))
    assert context.security_concern.value == concern
    assert context.quantum_relevance.value == relevance


def test_no_quantum_verdict_fields_exist() -> None:
    names = {field.name for field in fields(FindingContext)} | set(FindingResponse.model_fields)
    assert not {name for name in names if "quantum_safe" in name or "quantum_vulnerable" in name}
    assert not {name for name in names if "risk" in name or "score" in name}


def test_comments_and_documentation_produce_no_context(tmp_path: Path) -> None:
    pairs = _classified(
        tmp_path,
        {
            "src/notes.py": "# rsa.generate_private_key(key_size=2048)\nrsa_label = 'RSA'\n",
            "src/notes.js": "// crypto.subtle.encrypt({ name: 'AES-GCM' }, k, d)\n",
            "README.md": "We used AES and RSA.\n",
            "docs/design.md": "Cipher.getInstance(\"AES/GCM/NoPadding\")\n",
        },
    )
    assert pairs == []


def test_dependency_only_findings_remain_distinct_from_usage(tmp_path: Path) -> None:
    pairs = _classified(tmp_path, {"requirements.txt": "cryptography==42.0.5\n", "src/auth.py": RSA_SOURCE})
    dependency, dependency_context = _pick(pairs, usage="dependency_only")
    usage, usage_context = _pick(pairs, algorithm="RSA")
    assert dependency.algorithm is None
    assert dependency_context.evidence_type.value == "dependency_presence"
    assert usage_context.evidence_type.value == "confirmed_api_usage"
    assert dependency.file_path == "requirements.txt"
    assert usage.file_path == "src/auth.py"


def test_repeated_classification_is_identical(tmp_path: Path) -> None:
    files = {"src/auth.py": RSA_SOURCE, "web/crypto.js": USAGE_SOURCES["web/crypto.js"], "requirements.txt": "cryptography>=42\n"}
    first = [(finding.file_path, finding.line_start, classify(finding)) for finding in _scan(tmp_path / "a", files).findings]
    second = [(finding.file_path, finding.line_start, classify(finding)) for finding in _scan(tmp_path / "b", files).findings]
    assert first == second
    assert first


def test_secrets_are_redacted_from_evidence(tmp_path: Path) -> None:
    source = 'import hashlib\nkey = hashlib.pbkdf2_hmac("sha256", password="hunter2", salt=b"s", iterations=1)\n'
    finding, _context = _pick(_classified(tmp_path, {"app.py": source}), algorithm="PBKDF2")
    assert "hunter2" not in finding.evidence
    assert '[REDACTED]' in finding.evidence


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----", "MIIBOgIBAAJBAK"),
        ('API_KEY = "abcd1234secret"', "abcd1234secret"),
        ('"clientSecret": "s3cr3t-value"', "s3cr3t-value"),
        ("pkg @ git+https://alice:tok3n@github.com/org/pkg.git", "tok3n"),
        ("token AKIAABCDEFGHIJKLMNOP here", "AKIAABCDEFGHIJKLMNOP"),
    ],
)
def test_redaction_patterns(text: str, secret: str) -> None:
    assert secret not in redact_secrets(text)


def test_redaction_keeps_crypto_parameters() -> None:
    text = "rsa.generate_private_key(public_exponent=65537, key_size=2048)"
    assert redact_secrets(text) == text
