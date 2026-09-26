"""Phase 11 policy engine, drift comparison, and reports."""

from types import SimpleNamespace

import pytest

from app.core.exceptions import AppError
from app.services.drift.compare import compare_snapshots
from app.services.policy.defaults import DEFAULT_POLICY_YAML
from app.services.policy.engine import evaluate_findings
from app.services.policy.parser import parse_policy
from app.services.reports.builder import render_markdown
from tests.intelligence_helpers import finding, snapshot


def _eval(*rows, yaml: str | None = None) -> dict:
    rules = parse_policy(yaml or DEFAULT_POLICY_YAML)
    return evaluate_findings(list(rows), rules, scan_id=1, source="test")


def test_md5_and_des_fail() -> None:
    md5 = _eval(finding(algorithm="MD5", usage="hashing", key_size=None, security_concern="legacy_hash"))
    des = _eval(finding(algorithm="DES", usage="encryption", key_size=None, security_concern="legacy_cipher"))
    assert md5["status"] == "fail"
    assert des["status"] == "fail"
    assert md5["ci_exit_code"] == 1
    assert any(item["rule"] == "reject_md5" for item in md5["violations"])
    assert any(item["rule"] == "reject_des" for item in des["violations"])


def test_weak_rsa_fails_and_rsa_2048_warns() -> None:
    weak = _eval(finding(key_size=1024))
    warn = _eval(finding())
    assert weak["status"] == "fail"
    assert any(item["rule"] == "reject_small_rsa" for item in weak["violations"])
    assert warn["status"] == "warn"
    assert any(item["rule"] == "warn_rsa" for item in warn["violations"])
    assert all(item["rule"] != "reject_small_rsa" for item in warn["violations"])


def test_sha1_warns_and_aes256_passes() -> None:
    sha1 = _eval(finding(algorithm="SHA-1", usage="hashing", key_size=None, security_concern="legacy_hash"))
    aes = _eval(finding(algorithm="AES", usage="encryption", key_size=256, security_concern="symmetric_cryptography"))
    assert sha1["status"] == "warn"
    assert any(item["rule"] == "warn_sha1" for item in sha1["violations"])
    assert aes["status"] == "pass"
    assert aes["violations"] == []
    assert aes["ci_exit_code"] == 0


def test_policy_parsing_and_malformed_policy() -> None:
    rules = parse_policy(DEFAULT_POLICY_YAML)
    assert {rule.rule for rule in rules} >= {"reject_md5", "reject_des", "reject_small_rsa", "warn_rsa", "allow_aes"}
    with pytest.raises(AppError) as empty:
        parse_policy("")
    assert empty.value.code == "POLICY_INVALID"
    with pytest.raises(AppError) as tags:
        parse_policy("policies:\n  - rule: !!python/object/apply:os.system ['id']\n    action: fail\n")
    assert tags.value.code == "POLICY_INVALID"
    with pytest.raises(AppError):
        parse_policy("not a mapping")


def test_custom_policy_overrides_defaults() -> None:
    yaml = """
policies:
  - rule: allow_rsa
    algorithm: RSA
    action: allow
"""
    result = _eval(finding(), yaml=yaml)
    assert result["status"] == "pass"


def test_drift_added_removed_changed_and_deterministic() -> None:
    before = snapshot(
        [
            finding(id=1, algorithm="RSA", key_size=2048),
            finding(id=2, algorithm="MD5", usage="hashing", key_size=None, file_path="src/hash.py"),
        ],
        dependencies=[SimpleNamespace(id=1, name="cryptography", ecosystem="pypi", version="42.0.5", version_constraint=None, direct_or_transitive="direct")],
        artifacts=[
            SimpleNamespace(artifact_type="certificate", file_path="certs/old.crt", algorithm="RSA", key_size=2048, subject="old", serial_number="1", metadata_json="{}", protocol=None, cipher_suite=None),
            SimpleNamespace(artifact_type="protocol", file_path="nginx.conf", protocol="TLS", metadata_json='{"tls_version":"1.2"}', cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", algorithm=None, key_size=None, subject=None, serial_number=None),
        ],
    )
    after = snapshot(
        [
            finding(id=3, algorithm="RSA", key_size=4096),
            finding(id=4, algorithm="AES", usage="encryption", key_size=256, file_path="src/aes.py", security_concern="symmetric_cryptography"),
        ],
        dependencies=[SimpleNamespace(id=2, name="pycryptodome", ecosystem="pypi", version="3.20.0", version_constraint=None, direct_or_transitive="direct")],
        artifacts=[
            SimpleNamespace(artifact_type="certificate", file_path="certs/new.crt", algorithm="RSA", key_size=4096, subject="new", serial_number="2", metadata_json="{}", protocol=None, cipher_suite=None),
            SimpleNamespace(artifact_type="protocol", file_path="nginx.conf", protocol="TLS", metadata_json='{"tls_version":"1.3"}', cipher_suite="TLS_AES_128_GCM_SHA256", algorithm=None, key_size=None, subject=None, serial_number=None),
        ],
    )
    after.project = SimpleNamespace(id=1)
    after.scan = SimpleNamespace(id=2)
    before.scan = SimpleNamespace(id=1)
    first = compare_snapshots(before, after)
    second = compare_snapshots(before, after)
    assert first == second
    assert "AES" in first["added"]["algorithms"]
    assert "MD5" in first["removed"]["algorithms"]
    assert first["changed"]["key_sizes"]
    assert any(item["algorithm"] == "RSA" for item in first["changed"]["key_sizes"])
    assert "pycryptodome|pypi|3.20.0||direct" in first["added"]["dependencies"]
    assert "cryptography|pypi|42.0.5||direct" in first["removed"]["dependencies"]
    assert any("new.crt" in item for item in first["added"]["certificates"])
    assert any("old.crt" in item for item in first["removed"]["certificates"])
    assert "Comparison uses stable identities" in first["notes"][0]


def test_report_markdown_does_not_invent_findings() -> None:
    document = {
        "scan_id": 1,
        "executive_summary": "Scan 1 recorded 1 cryptographic finding(s).",
        "finding_counts": {"total": 1},
        "dependency_counts": {"total": 1},
        "certificate_counts": 0,
        "policy_status": {"status": "warn"},
        "migration_priorities": {"high": 1, "informational": 0},
        "top_migration_actions": [{"finding_id": 1, "action": "Plan a key_establishment migration of RSA toward ML-KEM"}],
        "limitations": ["This report is assembled from stored static-analysis records only."],
    }
    markdown = render_markdown(document)
    assert "Scan 1 recorded 1 cryptographic finding(s)." in markdown
    assert "Finding 1:" in markdown
    assert "quantum-safe" not in markdown
