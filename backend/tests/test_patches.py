"""Deterministic migration patch proposals. Generating a patch does not apply it."""

from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.exceptions import AppError
from app.main import create_app
from app.services.patches.generator import generate_proposal
from app.services.patches.types import STATUS_GENERATED, STATUS_MANUAL, STATUS_UNSUPPORTED, STATUS_VALIDATION_FAILED
from tests.intelligence_helpers import finding, rsa_graph, snapshot

HASH_REPO = {
    "src/hash.py": "import hashlib\n\ndef digest(data):\n    return hashlib.md5(data)\n",
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


def _settings(tmp_path: Path, **overrides) -> Settings:
    values = dict(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )
    values.update(overrides)
    return Settings(**values)


@contextmanager
def _client(tmp_path: Path, monkeypatch, files: dict[str, str], **settings_overrides):
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        for relative, content in files.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    with TestClient(create_app(_settings(tmp_path, **settings_overrides))) as client:
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
    raise AssertionError((expected, [(item["algorithm"], item["usage"], item["file_path"]) for item in items]))


def test_generated_hash_patch_and_get_round_trip(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch, HASH_REPO) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5", usage="hashing")
        missing = client.get(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "PATCH_NOT_FOUND"
        created = client.post(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch", json={"mode": "minimal"})
        assert created.status_code == 200
        body = created.json()
        assert body["patch_status"] == STATUS_GENERATED
        assert body["source_migrated"] is False
        assert body["current_algorithm"] == "MD5"
        assert body["proposed_replacement"] == "SHA-256"
        assert body["unified_diff"].startswith("--- a/src/hash.py")
        assert "-    return hashlib.md5(data)" in body["unified_diff"]
        assert "+    return hashlib.sha256(data)" in body["unified_diff"]
        assert body["patch_status"] != "applied"
        fetched = client.get(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch")
        assert fetched.status_code == 200
        assert fetched.json()["id"] == body["id"]
        assert fetched.json()["unified_diff"] == body["unified_diff"]
        source = next((tmp_path / "workspaces").rglob("hash.py"))
        assert "hashlib.md5" in source.read_text(encoding="utf-8")


def test_rsa_requires_manual_migration(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch, HASH_REPO) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="RSA")
        body = client.post(
            f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch",
            json={"replacement": "ML-DSA", "mode": "migration"},
        ).json()
        assert body["patch_status"] == STATUS_MANUAL
        assert body["unified_diff"] is None
        assert body["source_migrated"] is False
        assert "redesign" in body["rationale"].lower() or "one-line" in body["rationale"]
        assert body["suggested_migration_strategy"]


def test_invalid_replacement_and_mode(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch, HASH_REPO) as (client, scan_id):
        md5_id = _finding_id(client, scan_id, algorithm="MD5")
        rsa_id = _finding_id(client, scan_id, algorithm="RSA")
        invalid = client.post(
            f"/api/v1/scans/{scan_id}/migrations/{md5_id}/patch",
            json={"replacement": "ML-KEM"},
        )
        assert invalid.status_code == 400
        assert invalid.json()["error"]["code"] == "INVALID_REPLACEMENT"
        role = client.post(
            f"/api/v1/scans/{scan_id}/migrations/{rsa_id}/patch",
            json={"replacement": "SHA-256"},
        )
        assert role.status_code == 400
        mode = client.post(
            f"/api/v1/scans/{scan_id}/migrations/{md5_id}/patch",
            json={"mode": "teleport"},
        )
        assert mode.status_code == 400
        assert mode.json()["error"]["code"] == "INVALID_PATCH_MODE"


def test_dependency_only_is_unsupported(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch, HASH_REPO) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, usage="dependency_only")
        body = client.post(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch").json()
        assert body["patch_status"] == STATUS_UNSUPPORTED
        assert body["unified_diff"] is None


def test_wrong_scan_or_finding(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch, HASH_REPO) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        missing_scan = client.post(f"/api/v1/scans/999/migrations/{finding_id}/patch")
        assert missing_scan.status_code == 404
        missing_finding = client.post(f"/api/v1/scans/{scan_id}/migrations/999/patch")
        assert missing_finding.status_code == 404
        assert missing_finding.json()["error"]["code"] == "FINDING_NOT_FOUND"


def test_source_mismatch_and_missing_source(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch, HASH_REPO) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        source = next((tmp_path / "workspaces").rglob("hash.py"))
        source.write_text("import hashlib\n\ndef digest(data):\n    return data\n", encoding="utf-8")
        mismatch = client.post(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch").json()
        assert mismatch["patch_status"] == STATUS_VALIDATION_FAILED
        source.unlink()
        missing = client.post(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch").json()
        assert missing["patch_status"] == STATUS_VALIDATION_FAILED


def test_secret_redaction_blocks_generated_diff(tmp_path: Path, monkeypatch) -> None:
    files = {
        **HASH_REPO,
        "src/hash.py": (
            "import hashlib\n"
            "API_KEY = 'sk-abcdefghijklmnopqrstuvwxyz1234567890'\n"
            "def digest(data):\n"
            "    return hashlib.md5(data)\n"
        ),
    }
    with _client(tmp_path, monkeypatch, files) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        body = client.post(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch").json()
        assert body["patch_status"] == STATUS_VALIDATION_FAILED
        assert body["unified_diff"] is None
        assert any("secret" in item for item in body["validation_errors"])


def test_oversized_patch(tmp_path: Path, monkeypatch) -> None:
    with _client(tmp_path, monkeypatch, HASH_REPO, max_patch_bytes=40) as (client, scan_id):
        finding_id = _finding_id(client, scan_id, algorithm="MD5")
        body = client.post(f"/api/v1/scans/{scan_id}/migrations/{finding_id}/patch").json()
        assert body["patch_status"] == STATUS_VALIDATION_FAILED
        assert any("size" in item for item in body["validation_errors"])


def test_path_traversal_unit(tmp_path: Path) -> None:
    workspace = tmp_path / "workspaces" / "projects" / "1"
    (workspace / "source" / "src").mkdir(parents=True)
    (workspace / "source" / "src" / "hash.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    row = finding(
        algorithm="MD5",
        usage="hashing",
        language="Python",
        file_path="../secret.py",
        line_start=2,
        line_end=2,
        detection_method="ast_detection",
        cryptographic_role="integrity",
        security_concern="legacy_hash",
    )
    context = snapshot([row], graph=rsa_graph())
    context.project.workspace_path = str(workspace)
    proposal = generate_proposal(context, row, _settings(tmp_path))
    assert proposal.patch_status == STATUS_VALIDATION_FAILED
    assert any("path" in item or "traversal" in item for item in proposal.validation_errors)


def test_unsupported_modern_hash_unit(tmp_path: Path) -> None:
    row = finding(
        algorithm="SHA-256",
        usage="hashing",
        language="Python",
        cryptographic_role="integrity",
        security_concern="modern_hash",
        file_path="src/hash.py",
        line_start=1,
        line_end=1,
    )
    proposal = generate_proposal(snapshot([row]), row, _settings(tmp_path))
    assert proposal.patch_status == STATUS_UNSUPPORTED
    assert proposal.source_migrated is False


def test_wrong_migration_role_unit() -> None:
    row = finding(
        algorithm="ECDSA",
        usage="signing",
        cryptographic_role="digital_signature",
        security_concern="classical_signature",
        key_size=None,
    )
    with pytest.raises(AppError) as exc:
        generate_proposal(snapshot([row]), row, Settings(environment="test"), replacement="ML-KEM")
    assert exc.value.code == "INVALID_REPLACEMENT"
