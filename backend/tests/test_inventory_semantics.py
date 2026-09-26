"""Inventory lists finding algorithms; graph keeps artifact algorithm evidence."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from tests.test_artifacts import EC_CERT, RSA_CERT
from tests.test_cbom import RSA_SOURCE


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


def test_inventory_excludes_artifact_only_algorithms(tmp_path: Path, monkeypatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        files = {
            "src/auth.py": RSA_SOURCE,
            "certs/ec.crt": EC_CERT,
            "certs/rsa.crt": RSA_CERT,
        }
        for relative, content in files.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    application = create_app(_settings(tmp_path))
    with TestClient(application) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        assert client.post(f"/api/v1/projects/{project_id}/ingest").status_code == 200
        scan_id = client.post(f"/api/v1/projects/{project_id}/scan").json()["scan_id"]
        inventory = client.get(f"/api/v1/scans/{scan_id}/inventory").json()
        assert inventory["algorithms"] == {"RSA": 1}
        assert "EC" not in inventory["algorithms"]
        graph = client.get(f"/api/v1/scans/{scan_id}/graph").json()
        algorithms = {node["label"]: node["metadata"] for node in graph["nodes"] if node["type"] == "algorithm"}
        assert algorithms["RSA"]["confirmed_usage"] == "true"
        assert "crypto_finding" in algorithms["RSA"]["evidence_origins"]
        assert "certificate" in algorithms["RSA"]["evidence_origins"]
        assert algorithms["EC"]["confirmed_usage"] == "false"
        assert algorithms["EC"]["evidence_origins"] == "certificate"
        cbom = client.get(f"/api/v1/scans/{scan_id}/cbom").json()
        rsa = next(item for item in cbom["components"] if item["component_type"] == "algorithm" and item["name"] == "RSA")
        assert rsa["confirmed_usage"] == "true"
        ec = next(item for item in cbom["components"] if item["component_type"] == "algorithm" and item["name"] == "EC")
        assert ec["confirmed_usage"] == "false"
