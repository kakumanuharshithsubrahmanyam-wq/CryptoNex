"""Repository manifest generation."""

import hashlib
from pathlib import Path

from app.core.config import Settings
from app.services.ingestion.manifest import build_manifest


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
    )


def test_manifest_is_deterministic_and_classified(tmp_path: Path) -> None:
    root = tmp_path / "source"
    (root / "src").mkdir(parents=True)
    (root / ".git").mkdir()
    source = b"print('hi')\n"
    (root / "src" / "app.py").write_bytes(source)
    (root / "README.md").write_text("# Notes\n", encoding="utf-8")
    (root / "package.json").write_text("{}\n", encoding="utf-8")
    (root / "config.yaml").write_text("name: demo\n", encoding="utf-8")
    (root / "cert.pem").write_text("-----BEGIN-----\n", encoding="utf-8")
    (root / "logo.png").write_bytes(b"\x89PNG\x00\x00")
    (root / ".git" / "config").write_text("secret\n", encoding="utf-8")

    first = build_manifest(root, _settings(tmp_path))
    second = build_manifest(root, _settings(tmp_path))
    assert first.model_dump() == second.model_dump()

    paths = [record.relative_path for record in first.files]
    assert paths == sorted(paths)
    assert ".git/config" not in paths
    assert all(not path.startswith("/") and ".." not in path.split("/") for path in paths)

    by_path = {record.relative_path: record for record in first.files}
    python_file = by_path["src/app.py"]
    assert python_file.filename == "app.py"
    assert python_file.extension == ".py"
    assert python_file.detected_language == "Python"
    assert python_file.category == "source"
    assert python_file.file_size == len(source)
    assert python_file.line_count == 1
    assert python_file.sha256 == hashlib.sha256(source).hexdigest()
    assert by_path["README.md"].category == "documentation"
    assert by_path["package.json"].category == "dependency"
    assert by_path["config.yaml"].category == "configuration"
    assert by_path["cert.pem"].category == "certificate"
    assert by_path["logo.png"].category == "binary"
    assert by_path["logo.png"].line_count is None
    assert first.file_count == 6
    assert first.total_size == sum(record.file_size for record in first.files)
    assert first.languages == {"Python": 1}
