"""Scan retrieval API, persistence of context and dependencies, and schema upgrades."""

import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.core.config import Settings
from app.core.database import create_db_engine, init_db
from app.main import create_app

REPOSITORY = {
    "requirements.txt": "cryptography==42.0.5\nrequests>=2.31\n",
    "src/auth.py": (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "\n"
        "rsa.generate_private_key(\n"
        "    public_exponent=65537,\n"
        "    key_size=2048,\n"
        ")\n"
    ),
    "web/package.json": '{"dependencies": {"express": "4.19.2"}}\n',
    "README.md": "We used AES and RSA.\n",
}
_VOLATILE = {"id", "scan_id", "created_at", "dependency_id", "dependencies"}


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        for relative, content in REPOSITORY.items():
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
        yield client, project_id


def _forbid_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args, **_kwargs):
        raise AssertionError("scanner attempted to start a process")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr("os.system", refuse)


def test_scan_persists_context_and_dependency_links(api, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, project_id = api
    _forbid_processes(monkeypatch)
    scanned = client.post(f"/api/v1/projects/{project_id}/scan")
    assert scanned.status_code == 200
    body = scanned.json()
    summary = body["summary"]
    assert set(body) == {"scan_id", "project_id", "status", "summary"}
    assert summary["findings"] == 2
    assert summary["algorithms"] == {"RSA": 1}
    assert (summary["high_confidence"], summary["low_confidence"]) == (1, 1)
    assert (summary["confirmed_findings"], summary["probable_findings"], summary["weak_signal_findings"]) == (1, 0, 1)
    assert (summary["dependencies"], summary["crypto_dependencies"], summary["malformed_manifests"]) == (3, 1, 0)

    scan_id = body["scan_id"]
    detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail["status"] == "completed"
    assert detail["summary"] == summary

    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    assert findings["total"] == 2
    items = {item["usage"]: item for item in findings["items"]}
    rsa = items["key_generation"]
    assert rsa["algorithm"] == "RSA"
    assert rsa["library"] == "cryptography"
    assert rsa["library_version"] == "42.0.5"
    assert rsa["key_size"] == 2048
    assert rsa["file_path"] == "src/auth.py"
    assert (rsa["line_start"], rsa["line_end"]) == (3, 6)
    assert rsa["evidence_type"] == "confirmed_api_usage"
    assert rsa["detection_method"] == "ast_detection"
    assert rsa["confidence"] == "high"
    assert rsa["confidence_reasons"] == [
        "recognized_crypto_api_call",
        "recognized_crypto_library",
        "algorithm_identified_from_api",
        "explicit_key_size_detected",
    ]
    assert rsa["finding_status"] == "confirmed"
    assert rsa["cryptographic_role"] == "unknown"
    assert rsa["parameter_completeness"] == "complete"
    assert rsa["security_concern"] == "classical_public_key"
    assert rsa["quantum_relevance"] == "classical_public_key"
    assert [(link["name"], link["ecosystem"], link["manifest_file"], link["version"], link["relationship_type"]) for link in rsa["dependencies"]] == [
        ("cryptography", "python", "requirements.txt", "42.0.5", "finding_uses_dependency")
    ]

    dependency_only = items["dependency_only"]
    assert dependency_only["algorithm"] is None
    assert dependency_only["evidence_type"] == "dependency_presence"
    assert dependency_only["finding_status"] == "weak_signal"
    assert dependency_only["dependencies"][0]["relationship_type"] == "dependency_only"

    dependencies = client.get(f"/api/v1/scans/{scan_id}/dependencies").json()
    assert dependencies["total"] == 3
    by_name = {item["name"]: item for item in dependencies["items"]}
    cryptography = by_name["cryptography"]
    assert cryptography["evidence"] == {
        "manifest_file": "requirements.txt",
        "source_line": 1,
        "raw_declaration": "cryptography==42.0.5",
    }
    assert cryptography["crypto_relevance"] == "cryptographic_library"
    assert sorted(cryptography["finding_ids"]) == sorted([rsa["id"], dependency_only["id"]])
    assert by_name["requests"]["version_constraint"] == ">=2.31"
    assert by_name["requests"]["version"] is None
    assert by_name["express"]["crypto_relevance"] == "non_crypto"
    assert by_name["express"]["finding_ids"] == []

    for response in (scanned, client.get(f"/api/v1/scans/{scan_id}/findings"), client.get(f"/api/v1/scans/{scan_id}/dependencies")):
        assert str(tmp_path) not in response.text
        assert "Traceback" not in response.text


def test_repeated_scans_produce_identical_results(api) -> None:
    client, project_id = api
    first = client.post(f"/api/v1/projects/{project_id}/scan").json()
    second = client.post(f"/api/v1/projects/{project_id}/scan").json()
    assert first["summary"] == second["summary"]

    def stable(scan_id: int, resource: str) -> list[dict]:
        items = client.get(f"/api/v1/scans/{scan_id}/{resource}").json()["items"]
        return [
            {key: value for key, value in item.items() if key not in _VOLATILE | {"finding_ids", "required_by_dependency_ids"}}
            for item in items
        ]

    assert stable(first["scan_id"], "findings") == stable(second["scan_id"], "findings")
    assert stable(first["scan_id"], "dependencies") == stable(second["scan_id"], "dependencies")


def test_findings_pagination(api) -> None:
    client, project_id = api
    scan_id = client.post(f"/api/v1/projects/{project_id}/scan").json()["scan_id"]
    page = client.get(f"/api/v1/scans/{scan_id}/findings", params={"limit": 1, "offset": 1}).json()
    assert (page["total"], page["limit"], page["offset"], len(page["items"])) == (2, 1, 1, 1)


@pytest.mark.parametrize("path", ["/api/v1/scans/999", "/api/v1/scans/999/findings", "/api/v1/scans/999/dependencies"])
def test_unknown_scan_uses_error_envelope(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 404
    assert response.json() == {"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found.", "details": {}}}


def test_invalid_pagination_uses_error_envelope(client: TestClient) -> None:
    response = client.get("/api/v1/scans/1/findings", params={"limit": 0})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_new_tables_exist_without_later_phase_tables(client: TestClient) -> None:
    tables = set(inspect(client.app.state.engine).get_table_names())
    assert {"projects", "scans", "crypto_findings", "dependencies", "dependency_relationships"} <= tables
    forbidden = {"certificates", "protocols", "cbom", "migration_plans", "risk_scores", "knowledge_graph"}
    assert not tables & forbidden


def test_existing_findings_table_gains_context_columns(tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE crypto_findings (id INTEGER PRIMARY KEY, usage VARCHAR(32) NOT NULL)"))
        connection.execute(text("INSERT INTO crypto_findings (id, usage) VALUES (1, 'hashing')"))
    init_db(engine)
    columns = {column["name"] for column in inspect(engine).get_columns("crypto_findings")}
    assert {
        "evidence_type",
        "confidence_reasons_json",
        "finding_status",
        "cryptographic_role",
        "parameter_completeness",
        "security_concern",
        "quantum_relevance",
    } <= columns
    with engine.connect() as connection:
        assert connection.execute(text("SELECT finding_status FROM crypto_findings")).scalar() is None
    engine.dispose()
