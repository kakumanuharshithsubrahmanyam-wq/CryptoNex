"""Deterministic source-line language composition."""

from pathlib import Path

from app.core.config import Settings
from app.schemas.project import FileCategory, ManifestFileRecord, RepositoryManifest
from app.services.ingestion.manifest import build_manifest
from app.services.reports.builder import render_markdown
from app.services.scanner.languages import language_composition, normalize_language


def _record(path: str, language: str | None, lines: int | None, category: FileCategory = FileCategory.SOURCE) -> ManifestFileRecord:
    return ManifestFileRecord(
        relative_path=path,
        filename=Path(path).name,
        extension=Path(path).suffix.lower(),
        detected_language=language,
        file_size=lines or 0,
        line_count=lines,
        sha256="a" * 64,
        category=category,
    )


def _manifest(records: list[ManifestFileRecord]) -> RepositoryManifest:
    return RepositoryManifest(file_count=len(records), total_size=0, languages={}, files=records)


def test_single_language_repository() -> None:
    result = language_composition(_manifest([_record("src/a.py", "Python", 4), _record("src/b.py", "Python", 6)]))
    assert result["total_source_files"] == 2
    assert result["total_source_lines"] == 10
    assert result["languages"] == [{"language": "Python", "file_count": 2, "total_lines": 10, "percentage": 100.0}]


def test_multi_language_percentages_and_rounding() -> None:
    result = language_composition(
        _manifest(
            [
                _record("a.cpp", "C++", 2),
                _record("b.c", "C", 1),
                _record("c.py", "Python", 1),
            ]
        )
    )
    assert [item["language"] for item in result["languages"]] == ["C++", "C", "Python"]
    assert [item["percentage"] for item in result["languages"]] == [50.0, 25.0, 25.0]
    thirds = language_composition(
        _manifest(
            [
                _record("a.c", "C", 1),
                _record("b.cpp", "C++", 1),
                _record("c.py", "Python", 1),
            ]
        )
    )
    percentages = [item["percentage"] for item in thirds["languages"]]
    assert percentages == [33.4, 33.3, 33.3]
    assert round(sum(percentages), 1) == 100.0


def test_mixed_source_is_separated_from_documentation_and_locks() -> None:
    result = language_composition(
        _manifest(
            [
                _record("src/main.cpp", "C++", 8),
                _record("README.md", None, 20, FileCategory.DOCUMENTATION),
                _record("package-lock.json", None, 100, FileCategory.DEPENDENCY),
                _record("Cargo.lock", None, 40, FileCategory.DEPENDENCY),
                _record("config/app.yaml", None, 5, FileCategory.CONFIGURATION),
            ]
        )
    )
    assert result["languages"] == [{"language": "C++", "file_count": 1, "total_lines": 8, "percentage": 100.0}]
    assert result["total_source_files"] == 1
    assert result["total_source_lines"] == 8


def test_generated_binary_and_certificate_files_are_excluded() -> None:
    result = language_composition(
        _manifest(
            [
                _record("src/lib.rs", "Rust", 3),
                _record("generated/out.rs", "Rust", 100),
                _record("src/__pycache__/mod.py", "Python", 50),
                _record("logo.png", None, None, FileCategory.BINARY),
                _record("cert.pem", None, 12, FileCategory.CERTIFICATE),
            ]
        )
    )
    assert result["languages"] == [{"language": "Rust", "file_count": 1, "total_lines": 3, "percentage": 100.0}]


def test_language_labels_are_normalized() -> None:
    assert normalize_language("javascript") == "JavaScript"
    assert normalize_language("ts") == "TypeScript"
    assert normalize_language("cpp") == "C++"
    assert normalize_language("cxx") == "C++"
    assert normalize_language("cc") == "C++"
    assert normalize_language("c") == "C"
    assert normalize_language("rs") == "Rust"
    assert normalize_language("py") == "Python"
    assert normalize_language("Java") == "Java"
    assert normalize_language("go") == "Go"
    result = language_composition(
        _manifest(
            [
                _record("web/app.js", "js", 2),
                _record("web/app.ts", "typescript", 2),
                _record("native/a.cc", "cpp", 2),
            ]
        )
    )
    assert [item["language"] for item in result["languages"]] == ["C++", "JavaScript", "TypeScript"]


def test_zero_line_files_do_not_divide_by_zero() -> None:
    result = language_composition(_manifest([_record("src/empty.py", "Python", 0), _record("src/also.py", "py", 0)]))
    assert result["total_source_files"] == 2
    assert result["total_source_lines"] == 0
    assert result["languages"][0]["percentage"] == 0.0
    mixed = language_composition(_manifest([_record("src/empty.py", "Python", 0), _record("src/lib.go", "Go", 4)]))
    assert mixed["total_source_lines"] == 4
    assert mixed["languages"][0] == {"language": "Go", "file_count": 1, "total_lines": 4, "percentage": 100.0}
    assert mixed["languages"][1]["language"] == "Python"
    assert mixed["languages"][1]["total_lines"] == 0
    assert mixed["languages"][1]["percentage"] == 0.0


def test_unknown_language_is_omitted() -> None:
    result = language_composition(
        _manifest(
            [
                _record("src/app.py", "Python", 5),
                _record("notes.xyz", None, 9, FileCategory.UNKNOWN),
                _record("src/mystery.txt", "not-a-language", 7, FileCategory.SOURCE),
            ]
        )
    )
    assert result["languages"] == [{"language": "Python", "file_count": 1, "total_lines": 5, "percentage": 100.0}]
    assert normalize_language("not-a-language") is None
    assert normalize_language(None) is None


def test_duplicate_paths_are_counted_once() -> None:
    result = language_composition(
        _manifest(
            [
                _record("src/app.py", "Python", 4),
                _record("src/app.py", "Python", 100),
            ]
        )
    )
    assert result == {
        "languages": [{"language": "Python", "file_count": 1, "total_lines": 4, "percentage": 100.0}],
        "total_source_files": 1,
        "total_source_lines": 4,
    }


def test_manifest_detector_names_feed_composition(tmp_path: Path) -> None:
    root = tmp_path / "source"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("print(1)\nprint(2)\n", encoding="utf-8")
    (root / "src" / "b.cpp").write_text("int main(){return 0;}\n", encoding="utf-8")
    (root / "src" / "c.js").write_text("console.log(1)\n", encoding="utf-8")
    (root / "src" / "d.rs").write_text("fn main() {}\n", encoding="utf-8")
    (root / "README.md").write_text("# docs\n", encoding="utf-8")
    (root / "logo.png").write_bytes(b"\x89PNG\x00")
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
    )
    composition = language_composition(build_manifest(root, settings))
    assert {item["language"] for item in composition["languages"]} == {"Python", "C++", "JavaScript", "Rust"}
    assert composition["total_source_files"] == 4
    assert round(sum(item["percentage"] for item in composition["languages"]), 1) == 100.0
    again = language_composition(build_manifest(root, settings))
    assert composition == again


def test_report_lists_repository_languages_without_a_score() -> None:
    document = {
        "scan_id": 1,
        "executive_summary": "Scan 1 recorded 1 cryptographic finding(s).",
        "finding_counts": {"total": 1},
        "dependency_counts": {"total": 1},
        "certificate_counts": 0,
        "policy_status": {"status": "warn"},
        "migration_priorities": {"high": 1},
        "top_migration_actions": [],
        "limitations": ["This report is assembled from stored static-analysis records only."],
        "language_composition": {
            "languages": [
                {"language": "C++", "file_count": 2, "total_lines": 8, "percentage": 80.0},
                {"language": "Python", "file_count": 1, "total_lines": 2, "percentage": 20.0},
            ],
            "total_source_files": 3,
            "total_source_lines": 10,
        },
    }
    markdown = render_markdown(document)
    assert "## Repository Languages" in markdown
    assert "C++" in markdown
    assert "80.0%" in markdown
    assert "Python" in markdown
    assert "20.0%" in markdown
    assert "not a security score" in markdown
    assert "quantum-safe" not in markdown
