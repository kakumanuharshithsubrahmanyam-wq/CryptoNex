"""HTTP wiring for migration, AI, PQC, policy, drift, and reports."""

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
        openai_api_key="",
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


def test_migration_blast_ai_pqc_policy_report_and_drift(tmp_path: Path, monkeypatch) -> None:
    files = {
        "src/auth.py": RSA_SOURCE,
        "requirements.txt": "cryptography==42.0.5\n",
        "certs/server.crt": RSA_CERT,
        "nginx.conf": TLS_CONFIG,
    }
    client, project_id = _client(tmp_path, monkeypatch, files)
    try:
        first = client.post(f"/api/v1/projects/{project_id}/scan").json()["scan_id"]
        findings = client.get(f"/api/v1/scans/{first}/findings").json()["items"]
        rsa = next(item for item in findings if item["algorithm"] == "RSA")

        migrations = client.get(f"/api/v1/scans/{first}/migrations")
        assert migrations.status_code == 200
        assert migrations.json()["summary"]["high"] >= 1
        plan = client.get(f"/api/v1/scans/{first}/migrations/{rsa['id']}")
        assert plan.status_code == 200
        body = plan.json()
        assert body["migration_occurred"] is False
        assert body["current_algorithm"] == "RSA"
        assert body["priority_reasons"]
        custom = client.post(
            f"/api/v1/scans/{first}/migration-plan",
            json={"finding_id": rsa["id"], "replacement": "ML-KEM"},
        )
        assert custom.status_code == 200

        radius = client.get(f"/api/v1/scans/{first}/blast-radius/{rsa['id']}")
        assert radius.status_code == 200
        assert radius.json()["affected_files"]
        assert any(item["label"] == "cryptography" for item in radius.json()["affected_dependencies"])
        assert radius.json()["affected_certificates"]

        architect = client.post(f"/api/v1/scans/{first}/ai/architect", json={})
        assert architect.status_code == 200
        assert architect.json()["source"] == "deterministic_fallback"
        assert "sk-" not in architect.json()["answer"]
        asked = client.post(f"/api/v1/scans/{first}/ask", json={"question": "What are the highest-priority migration concerns?"})
        assert asked.status_code == 200
        assert asked.json()["supporting_findings"]
        root = client.post(f"/api/v1/scans/{first}/ai/root-cause", json={"finding_id": rsa["id"]})
        assert root.status_code == 200
        assert root.json()["items"][0]["finding_id"] == rsa["id"]

        pqc = client.get(f"/api/v1/scans/{first}/pqc")
        assert {item["algorithm"] for item in pqc.json()["algorithms"]} == {"ML-DSA", "ML-KEM", "SLH-DSA"}
        what_if = client.post(
            f"/api/v1/scans/{first}/what-if",
            json={"finding_id": rsa["id"], "replacement": "ML-KEM", "mode": "hybrid"},
        )
        assert what_if.status_code == 200
        assert what_if.json()["source_migrated"] is False
        assert what_if.json()["hybrid_option"]["pqc"] == "ML-KEM"
        agility = client.get(f"/api/v1/scans/{first}/agility")
        assert agility.json()["classification"] in {"high_agility", "moderate_agility", "low_agility", "unknown"}

        policy = client.post(f"/api/v1/scans/{first}/policy/check", json={})
        assert policy.status_code == 200
        assert policy.json()["status"] in {"pass", "warn", "fail"}
        project_policy = client.post(f"/api/v1/projects/{project_id}/policy/check", json={})
        assert project_policy.status_code == 200

        report = client.get(f"/api/v1/scans/{first}/report")
        assert report.status_code == 200
        assert report.json()["finding_counts"]["total"] >= 1
        assert "does not invent findings" in report.json()["executive_summary"]
        markdown = client.get(f"/api/v1/scans/{first}/report/export", params={"format": "markdown"})
        assert markdown.status_code == 200
        assert markdown.headers["content-type"].startswith("text/markdown")

        auth = tmp_path / "workspaces" / "projects" / str(project_id) / "source" / "src" / "auth.py"
        auth.write_text(auth.read_text(encoding="utf-8") + "\nimport hashlib\nhashlib.md5(b'data')\n", encoding="utf-8")
        second = client.post(f"/api/v1/projects/{project_id}/scan").json()["scan_id"]
        drift = client.get(f"/api/v1/projects/{project_id}/drift")
        assert drift.status_code == 200
        assert drift.json()["from_scan_id"] == first
        assert drift.json()["to_scan_id"] == second
        assert "MD5" in drift.json()["added"]["algorithms"]

        missing = client.get(f"/api/v1/scans/{first}/migrations/999999")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "FINDING_NOT_FOUND"
    finally:
        client.__exit__(None, None, None)


def test_workspace_policy_file_and_secret_redaction(tmp_path: Path, monkeypatch) -> None:
    files = {
        "src/auth.py": 'password="super-secret-value"\n' + RSA_SOURCE,
        "cryptonex-policy.yml": "policies:\n  - rule: allow_all_rsa\n    algorithm: RSA\n    action: allow\n",
    }
    client, project_id = _client(tmp_path, monkeypatch, files)
    try:
        scan_id = client.post(f"/api/v1/projects/{project_id}/scan").json()["scan_id"]
        policy = client.post(f"/api/v1/scans/{scan_id}/policy/check", json={})
        assert policy.json()["policy_source"].startswith("workspace:")
        assert policy.json()["status"] == "pass"
        asked = client.post(f"/api/v1/scans/{scan_id}/ask", json={"question": "Summarize the cryptographic posture of this repository."})
        dumped = str(asked.json())
        assert "super-secret-value" not in dumped
        assert asked.json()["source"] == "deterministic_fallback"
    finally:
        client.__exit__(None, None, None)
