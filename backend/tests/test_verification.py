"""Isolated fix, rescan, and verification. The ingested snapshot is never modified."""

import difflib
import hashlib
from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.exceptions import AppError
from app.main import create_app
from app.models.patch import MigrationPatchProposal
from app.models.scan import CryptoFinding, Scan

HASH_SOURCE = "import hashlib\n\ndef digest(data):\n    return hashlib.md5(data)\n"
REPO = {
    "src/hash.py": HASH_SOURCE,
    "src/auth.py": (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "\n"
        "rsa.generate_private_key(\n"
        "    public_exponent=65537,\n"
        "    key_size=2048,\n"
        ")\n"
    ),
    "requirements.txt": "cryptography==42.0.5\n",
}


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


@contextmanager
def _client(tmp_path: Path, monkeypatch):
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        for relative, content in REPO.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    with TestClient(create_app(_settings(tmp_path))) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        assert client.post(f"/api/v1/projects/{project_id}/ingest").status_code == 200
        scanned = client.post(f"/api/v1/projects/{project_id}/scan")
        assert scanned.status_code == 200
        yield client, scanned.json()["scan_id"]


def _finding_id(client: TestClient, scan_id: int, **expected) -> int:
    items = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
    for item in items:
        if all(item.get(field) == value for field, value in expected.items()):
            return item["id"]
    raise AssertionError([(item["algorithm"], item["usage"], item["file_path"]) for item in items])


def _patch(client: TestClient, scan_id: int, finding_id: int) -> dict:
    created = client.post(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch", json={"mode": "minimal"})
    assert created.status_code == 200
    return created.json()


def _diff(before: str, after: str, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def _store_diff(client: TestClient, patch_id: int, diff: str) -> None:
    session = client.app.state.session_factory()
    row = session.get(MigrationPatchProposal, patch_id)
    row.unified_diff = diff
    row.changed_files_json = '["src/hash.py"]'
    session.commit()
    session.close()


def _source_hash(tmp_path: Path) -> str:
    digest = hashlib.sha256()
    root = tmp_path / "workspaces" / "projects" / "1" / "source"
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _original_findings(client: TestClient, scan_id: int) -> list[tuple]:
    session = client.app.state.session_factory()
    rows = session.query(CryptoFinding).filter_by(scan_id=scan_id).order_by(CryptoFinding.id).all()
    payload = [(row.id, row.fingerprint, row.algorithm, row.evidence, row.usage) for row in rows]
    session.close()
    return payload


def _verify(client: TestClient, scan_id: int, finding_id: int, patch_id: int) -> dict:
    response = client.post(
        f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch/verify",
        json={"patch_id": patch_id},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_verified_md5_fix_rescan_and_original_unchanged(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        before_hash = _source_hash(tmp_path)
        before_rows = _original_findings(client, scan_id)
        finding_id = _finding_id(client, scan_id, algorithm="MD5", usage="hashing")
        missing = client.get(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch/verify")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "VERIFICATION_NOT_FOUND"
        proposal = _patch(client, scan_id, finding_id)
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "verified"
        assert body["target_status"] == "resolved"
        assert body["original_finding_present"] is False
        assert body["replacement_finding_present"] is True
        assert body["replacement_algorithm"] == "SHA-256"
        assert body["original_scan_id"] == scan_id
        assert body["verification_scan_id"] != scan_id
        assert body["regressions"] == []
        assert body["policy_before"]["change"] == "decreased"
        assert body["cbom_after"]["change"] == "expected"
        assert _source_hash(tmp_path) == before_hash
        assert "hashlib.md5" in (tmp_path / "workspaces").joinpath("projects/1/source/src/hash.py").read_text()
        assert _original_findings(client, scan_id) == before_rows
        session = client.app.state.session_factory()
        original = session.get(Scan, scan_id)
        verification = session.get(Scan, body["verification_scan_id"])
        assert original.kind == "inventory"
        assert original.status == "completed"
        assert verification.kind == "verification"
        assert verification.status == "completed"
        session.close()


def test_repeated_verification_is_deterministic(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        first = _verify(client, scan_id, finding_id, proposal["id"])
        second = _verify(client, scan_id, finding_id, proposal["id"])
        latest = client.get(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch/verify").json()
        assert latest["id"] == second["id"]
        assert first["id"] != second["id"]
        for field in ("status", "target_status", "regressions", "new_findings", "removed_findings", "policy_before", "cbom_after"):
            assert first[field] == second[field]


def test_no_change_and_still_present(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        updated = HASH_SOURCE.replace("def digest(data):", "def digest(payload):")
        _store_diff(client, proposal["id"], _diff(HASH_SOURCE, updated, "src/hash.py"))
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "no_change"
        assert body["target_status"] == "still_present"
        assert body["original_finding_present"] is True
        assert body["replacement_finding_present"] is False


def test_partial_resolution(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        updated = HASH_SOURCE.replace("hashlib.md5", "hashlib.sha1")
        _store_diff(client, proposal["id"], _diff(HASH_SOURCE, updated, "src/hash.py"))
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "partially_verified"
        assert body["target_status"] == "partially_resolved"
        assert body["replacement_finding_present"] is False
        assert body["original_finding_present"] is False


def test_manual_review_when_both_algorithms_remain(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        updated = HASH_SOURCE + "\ndef extra(data):\n    return hashlib.sha256(data)\n"
        _store_diff(client, proposal["id"], _diff(HASH_SOURCE, updated, "src/hash.py"))
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "manual_review_required"
        assert body["target_status"] == "still_present"
        assert body["original_finding_present"] is True
        assert body["replacement_finding_present"] is True


def test_regression_new_crypto_policy_and_cbom(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        updated = (
            "import hashlib\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "\n"
            "def digest(data):\n"
            "    return hashlib.sha256(data)\n"
            "\n"
            "rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        )
        _store_diff(client, proposal["id"], _diff(HASH_SOURCE, updated, "src/hash.py"))
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "regression_detected"
        assert body["target_status"] == "resolved"
        kinds = {item["type"] for item in body["regressions"]}
        assert "new_crypto_finding" in kinds or "new_legacy_crypto" in kinds
        assert "unexpected_cbom_change" in kinds
        assert "new_policy_violation" in kinds
        assert body["policy_after"]["change"] == "increased" or any(
            item["type"] == "new_policy_violation" for item in body["regressions"]
        )


def test_new_policy_violation_from_extra_legacy_hash(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        updated = (
            HASH_SOURCE
            + "\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n"
            + "rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        )
        _store_diff(client, proposal["id"], _diff(HASH_SOURCE, updated, "src/hash.py"))
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "regression_detected"
        assert body["policy_after"]["change"] == "increased"
        assert any(item["type"] == "new_policy_violation" for item in body["regressions"])
        assert any(item["type"] == "new_crypto_finding" for item in body["regressions"])


def test_unexpected_dependency_change(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        requirements = "cryptography==42.0.5\npycrypto==2.6.1\n"
        hash_updated = HASH_SOURCE.replace("hashlib.md5", "hashlib.sha256")
        diff = _diff(HASH_SOURCE, hash_updated, "src/hash.py") + _diff(
            "cryptography==42.0.5\n", requirements, "requirements.txt"
        )
        _store_diff(client, proposal["id"], diff)
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "regression_detected"
        assert any(item["type"] == "unexpected_dependency_change" for item in body["regressions"])


def test_unexpected_certificate_change(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        updated = HASH_SOURCE + "\n# -----BEGIN CERTIFICATE-----\nTWF0dGVy\n-----END CERTIFICATE-----\n"
        _store_diff(client, proposal["id"], _diff(HASH_SOURCE, updated, "src/hash.py"))
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "regression_detected"
        assert any(item["type"] == "unexpected_certificate_or_protocol_change" for item in body["regressions"])


def test_patch_application_failures(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        before_hash = _source_hash(tmp_path)
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        cases = {
            "mismatch": "--- a/src/hash.py\n+++ b/src/hash.py\n@@ -1,2 +1,2 @@\n-not the file\n+other\n",
            "invalid": "this is not a diff\n",
            "traversal": "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-root\n+root2\n",
            "absolute": "--- a/src/hash.py\n+++ /tmp/hash.py\n@@ -1 +1 @@\n-x\n+y\n",
            "outside": "--- a/missing.py\n+++ b/missing.py\n@@ -1 +1 @@\n-x\n+y\n",
        }
        for diff in cases.values():
            _store_diff(client, proposal["id"], diff)
            body = _verify(client, scan_id, finding_id, proposal["id"])
            assert body["status"] == "patch_failed"
            assert body["verification_scan_id"] is None
            assert body["validation_messages"]
        assert _source_hash(tmp_path) == before_hash


def test_rescan_failure(tmp_path: Path, monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise AppError("SCAN_FAILED", "The cryptographic scan failed.", status_code=500)

    monkeypatch.setattr("app.services.verification.service.scan_isolated_tree", boom)
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        before_hash = _source_hash(tmp_path)
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["status"] == "rescan_failed"
        assert body["verification_scan_id"] is None
        assert _source_hash(tmp_path) == before_hash


def test_invalid_status_and_wrong_ids(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        md5_id = _finding_id(client, scan_id, algorithm="MD5")
        rsa_id = _finding_id(client, scan_id, algorithm="RSA")
        md5_patch = _patch(client, scan_id, md5_id)
        rsa_patch = _patch(client, scan_id, rsa_id)
        invalid = client.post(
            f"/api/v1/scans/{scan_id}/migrations/{rsa_id}/patch/verify",
            json={"patch_id": rsa_patch["id"]},
        )
        assert invalid.status_code == 400
        assert invalid.json()["error"]["code"] == "INVALID_PATCH_STATUS"
        wrong_finding = client.post(
            f"/api/v1/scans/{scan_id}/migrations/{rsa_id}/patch/verify",
            json={"patch_id": md5_patch["id"]},
        )
        assert wrong_finding.status_code == 404
        missing_scan = client.post(
            f"/api/v1/scans/999/migrations/{md5_id}/patch/verify",
            json={"patch_id": md5_patch["id"]},
        )
        assert missing_scan.status_code == 404


def test_unknown_when_scanner_loses_the_call(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        proposal = _patch(client, scan_id, finding_id)
        updated = "import hashlib\n\ndef digest(data):\n    return data\n"
        _store_diff(client, proposal["id"], _diff(HASH_SOURCE, updated, "src/hash.py"))
        body = _verify(client, scan_id, finding_id, proposal["id"])
        assert body["target_status"] == "unknown"
        assert body["status"] == "verification_failed"
