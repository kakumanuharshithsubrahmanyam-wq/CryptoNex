"""CryptoNex CBOM generation and inventory."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from tests.test_artifacts import RSA_CERT, TLS_CONFIG

RSA_SOURCE = """
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


def _client(tmp_path: Path, monkeypatch, files: dict[str, str]) -> tuple[TestClient, int]:
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        for relative, content in files.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    application = create_app(_settings(tmp_path))
    client = TestClient(application)
    client.__enter__()
    created = client.post(
        "/api/v1/projects",
        json={"name": "Demo", "repository_url": "https://github.com/octocat/Hello-World"},
    )
    project_id = created.json()["id"]
    assert client.post(f"/api/v1/projects/{project_id}/ingest").status_code == 200
    return client, project_id


def _scan(client: TestClient, project_id: int) -> int:
    scanned = client.post(f"/api/v1/projects/{project_id}/scan")
    assert scanned.status_code == 200
    return scanned.json()["scan_id"]


def test_cbom_combined_scan_and_determinism(tmp_path: Path, monkeypatch) -> None:
    files = {
        "src/auth.py": RSA_SOURCE,
        "requirements.txt": "cryptography==42.0.5\n",
        "certs/server.crt": RSA_CERT,
        "nginx.conf": TLS_CONFIG,
    }
    client, project_id = _client(tmp_path, monkeypatch, files)
    try:
        first = _scan(client, project_id)
        second = _scan(client, project_id)
        cbom = client.get(f"/api/v1/scans/{first}/cbom").json()
        again = client.get(f"/api/v1/scans/{first}/cbom").json()
        assert cbom == again
        assert cbom["schema_version"] == "1.0"
        assert cbom["schema_name"] == "cryptonex-cbom"
        types = {item["component_type"] for item in cbom["components"]}
        assert {"algorithm", "crypto_usage", "library", "dependency", "certificate", "protocol", "cipher_suite"} <= types
        assert cbom["summary"]["algorithms"] >= 1
        assert cbom["summary"]["dependencies"] >= 1
        assert cbom["summary"]["certificates"] >= 1
        assert cbom["summary"]["protocols"] >= 1
        assert any(item["type"] == "uses" for item in cbom["relationships"])
        assert any(item["type"] == "declared_by" for item in cbom["relationships"])
        assert any(item["type"] == "located_in" for item in cbom["relationships"])
        exported = client.get(f"/api/v1/scans/{first}/cbom/export")
        assert exported.status_code == 200
        assert "cryptonex-cbom" in exported.headers["content-disposition"]
        assert exported.json()["scan_id"] == first
        other = client.get(f"/api/v1/scans/{second}/cbom").json()
        left = {key: value for key, value in cbom.items() if key != "generated_at"}
        right = {key: value for key, value in other.items() if key != "generated_at"}
        assert left["summary"] == right["summary"]
        assert {item["component_type"] for item in left["components"]} == {
            item["component_type"] for item in right["components"]
        }
        inventory = client.get(f"/api/v1/scans/{first}/inventory").json()
        assert inventory["algorithms"]["RSA"] >= 1
        assert "cryptography" in inventory["libraries"]
        assert inventory["certificates"] >= 1
        assert "TLS 1.2" in inventory["protocols"] or "TLS 1.3" in inventory["protocols"]
        assert "TLS_AES_128_GCM_SHA256" in inventory["cipher_suites"]
        assert "src/auth.py" in inventory["source_locations"]
        assert "MIIEvQ" not in exported.text
    finally:
        client.__exit__(None, None, None)


def test_cbom_empty_repository(tmp_path: Path, monkeypatch) -> None:
    client, project_id = _client(tmp_path, monkeypatch, {"README.md": "nothing\n"})
    try:
        scan_id = _scan(client, project_id)
        cbom = client.get(f"/api/v1/scans/{scan_id}/cbom").json()
        assert cbom["summary"]["crypto_usages"] == 0
        assert cbom["summary"]["certificates"] == 0
    finally:
        client.__exit__(None, None, None)


def test_cbom_dependency_only(tmp_path: Path, monkeypatch) -> None:
    client, project_id = _client(tmp_path, monkeypatch, {"requirements.txt": "cryptography==42.0.5\n"})
    try:
        scan_id = _scan(client, project_id)
        cbom = client.get(f"/api/v1/scans/{scan_id}/cbom").json()
        assert cbom["summary"]["dependencies"] >= 1
        assert cbom["summary"]["certificates"] == 0
        usage = next(item for item in cbom["components"] if item["component_type"] == "crypto_usage")
        assert usage.get("algorithm") is None
    finally:
        client.__exit__(None, None, None)


def test_cbom_unknown_scan(client: TestClient) -> None:
    response = client.get("/api/v1/scans/999/cbom")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"
