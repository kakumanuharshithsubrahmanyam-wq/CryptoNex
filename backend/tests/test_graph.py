"""Cryptographic knowledge graph."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from tests.test_artifacts import RSA_CERT, TLS_CONFIG
from tests.test_cbom import RSA_SOURCE


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


def test_graph_nodes_edges_filters_and_secrets(tmp_path: Path, monkeypatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        files = {
            "src/auth.py": RSA_SOURCE,
            "requirements.txt": "cryptography==42.0.5\n",
            "certs/server.crt": RSA_CERT,
            "nginx.conf": TLS_CONFIG,
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
        first = client.post(f"/api/v1/projects/{project_id}/scan").json()["scan_id"]
        second = client.post(f"/api/v1/projects/{project_id}/scan").json()["scan_id"]
        graph = client.get(f"/api/v1/scans/{first}/graph").json()
        types = {node["type"] for node in graph["nodes"]}
        assert {
            "project",
            "scan",
            "crypto_finding",
            "algorithm",
            "crypto_library",
            "dependency",
            "file",
            "certificate",
            "protocol",
            "cipher_suite",
            "component",
        } <= types
        edges = {(edge["source"].split(":")[0], edge["type"], edge["target"].split(":")[0]) for edge in graph["edges"]}
        assert ("finding", "USES_ALGORITHM", "algorithm") in edges
        assert ("finding", "USES_LIBRARY", "library") in edges
        assert ("finding", "LOCATED_IN", "file") in edges
        assert ("library", "PROVIDED_BY", "dependency") in edges
        assert ("certificate", "USES_ALGORITHM", "algorithm") in edges
        assert ("protocol", "USES_CIPHER_SUITE", "cipher_suite") in edges
        ids = [node["id"] for node in graph["nodes"]]
        edge_keys = [(edge["source"], edge["target"], edge["type"]) for edge in graph["edges"]]
        assert len(ids) == len(set(ids))
        assert len(edge_keys) == len(set(edge_keys))
        filtered = client.get(f"/api/v1/scans/{first}/graph", params={"algorithm": "RSA"}).json()
        assert any(node["label"] == "RSA" for node in filtered["nodes"])
        assert all(
            node["type"] in {"algorithm", "crypto_finding", "certificate", "key", "component", "file", "scan", "project", "crypto_library"}
            or "RSA" in node["label"]
            or node["metadata"].get("algorithm") == "RSA"
            or node["id"].startswith("component:")
            or node["type"] in {"file", "scan", "project", "crypto_library", "dependency"}
            for node in filtered["nodes"]
        )
        repeat = client.get(f"/api/v1/scans/{first}/graph").json()
        assert graph == repeat
        other = client.get(f"/api/v1/scans/{second}/graph").json()
        assert graph["summary"]["node_types"] == other["summary"]["node_types"]
        assert "MIIEvQ" not in client.get(f"/api/v1/scans/{first}/graph").text
        missing = client.get("/api/v1/scans/999/graph")
        assert missing.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_empty_graph_has_project_and_scan(tmp_path: Path, monkeypatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        Path(args[-1]).mkdir(parents=True)
        (Path(args[-1]) / "README.md").write_text("docs\n", encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    application = create_app(_settings(tmp_path))
    with TestClient(application) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Empty", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        assert client.post(f"/api/v1/projects/{project_id}/ingest").status_code == 200
        scan_id = client.post(f"/api/v1/projects/{project_id}/scan").json()["scan_id"]
        graph = client.get(f"/api/v1/scans/{scan_id}/graph").json()
        types = {node["type"] for node in graph["nodes"]}
        assert {"project", "scan"} <= types
        assert any(edge["type"] == "HAS_SCAN" for edge in graph["edges"])
