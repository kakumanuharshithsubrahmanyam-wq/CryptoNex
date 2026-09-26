"""ZIP extraction security limits."""

import io
import stat
import zipfile
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.exceptions import AppError
from app.services.ingestion.zip import extract_zip, save_zip_upload


class _Upload:
    def __init__(self, payload: bytes) -> None:
        self.file = io.BytesIO(payload)


def _settings(tmp_path: Path, **overrides: int) -> Settings:
    values = {
        "database_url": f"sqlite:///{tmp_path / 'test.db'}",
        "environment": "test",
        "log_level": "WARNING",
        "workspace_root": str(tmp_path / "workspaces"),
        "max_file_count": 10,
        "max_file_size_mb": 5,
        "max_zip_size_mb": 5,
        "max_zip_extracted_size_mb": 5,
    }
    values.update(overrides)
    return Settings(**values)


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def test_valid_zip_extracts_inside_workspace(tmp_path: Path) -> None:
    destination = tmp_path / "source"
    extract_zip(
        _write(tmp_path, _zip_bytes({"src/app.py": b"print(1)\n"})),
        destination,
        _settings(tmp_path),
    )
    assert (destination / "src" / "app.py").read_bytes() == b"print(1)\n"


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    with pytest.raises(AppError) as captured:
        extract_zip(
            _write(tmp_path, _zip_bytes({"../outside.txt": b"nope"})),
            tmp_path / "source",
            _settings(tmp_path),
        )
    assert captured.value.code == "ZIP_PATH_TRAVERSAL"
    assert not outside.exists()


def test_absolute_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(AppError) as captured:
        extract_zip(
            _write(tmp_path, _zip_bytes({"/tmp/cryptonex-absolute.txt": b"nope"})),
            tmp_path / "source",
            _settings(tmp_path),
        )
    assert captured.value.code == "ZIP_PATH_TRAVERSAL"
    assert not Path("/tmp/cryptonex-absolute.txt").exists()


def test_symlink_entry_is_rejected(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, b"/tmp/cryptonex-link")
    with pytest.raises(AppError) as captured:
        extract_zip(_write(tmp_path, buffer.getvalue()), tmp_path / "source", _settings(tmp_path))
    assert captured.value.code == "INVALID_ZIP"


def test_too_many_files_are_rejected(tmp_path: Path) -> None:
    entries = {f"file{index}.txt": b"x" for index in range(3)}
    with pytest.raises(AppError) as captured:
        extract_zip(
            _write(tmp_path, _zip_bytes(entries)),
            tmp_path / "source",
            _settings(tmp_path, max_file_count=2),
        )
    assert captured.value.code == "TOO_MANY_FILES"


def test_excessive_extracted_size_is_rejected(tmp_path: Path) -> None:
    payload = b"a" * (2 * 1024 * 1024)
    with pytest.raises(AppError) as captured:
        extract_zip(
            _write(tmp_path, _zip_bytes({"big.bin": payload})),
            tmp_path / "source",
            _settings(tmp_path, max_zip_extracted_size_mb=1, max_file_size_mb=5),
        )
    assert captured.value.code == "ZIP_TOO_LARGE"


def test_invalid_zip_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    archive.write_bytes(b"PK\x03\x04this is not a zip")
    with pytest.raises(AppError) as captured:
        extract_zip(archive, tmp_path / "source", _settings(tmp_path))
    assert captured.value.code == "INVALID_ZIP"


def test_upload_rejects_non_zip(tmp_path: Path) -> None:
    destination = tmp_path / "archive.zip"
    with pytest.raises(AppError) as captured:
        save_zip_upload(_Upload(b"hello"), destination, _settings(tmp_path))
    assert captured.value.code == "INVALID_ZIP"
    assert not destination.exists()


def test_upload_rejects_archive_over_limit(tmp_path: Path) -> None:
    destination = tmp_path / "archive.zip"
    payload = b"PK\x03\x04" + (b"a" * (1024 * 1024))
    with pytest.raises(AppError) as captured:
        save_zip_upload(_Upload(payload), destination, _settings(tmp_path, max_zip_size_mb=1))
    assert captured.value.code == "ZIP_TOO_LARGE"
    assert not destination.exists()


def _write(tmp_path: Path, payload: bytes) -> Path:
    archive = tmp_path / "input.zip"
    archive.write_bytes(payload)
    return archive
