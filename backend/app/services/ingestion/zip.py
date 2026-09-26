"""Extract a ZIP archive into a controlled workspace.

Archive entry names are untrusted. Extraction writes only regular files whose
normalized relative path stays inside the destination directory.
"""

import stat
import zipfile
from pathlib import Path

from app.core.config import Settings
from app.core.exceptions import AppError
from app.services.ingestion.limits import megabytes_to_bytes

_CHUNK_SIZE = 64 * 1024
_ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def save_zip_upload(upload, destination: Path, settings: Settings) -> None:
    """Read an uploaded file with a hard size cap and store it as archive.zip."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    limit = megabytes_to_bytes(settings.max_zip_size_mb)
    written = 0
    header = b""
    try:
        with destination.open("wb") as handle:
            while True:
                chunk = upload.file.read(_CHUNK_SIZE)
                if not chunk:
                    break
                if len(header) < 4:
                    header += chunk[: 4 - len(header)]
                written += len(chunk)
                if written > limit:
                    raise AppError(
                        "ZIP_TOO_LARGE",
                        "The ZIP archive exceeds the configured size limit.",
                        status_code=413,
                        details={"limit_mb": settings.max_zip_size_mb},
                    )
                handle.write(chunk)
    except AppError:
        destination.unlink(missing_ok=True)
        raise
    if written == 0 or not header.startswith(_ZIP_PREFIXES):
        destination.unlink(missing_ok=True)
        raise AppError("INVALID_ZIP", "The uploaded file is not a ZIP archive.", status_code=400)


def extract_zip(archive: Path, destination: Path, settings: Settings) -> None:
    """Extract archive into destination, enforcing path and size limits."""
    destination.mkdir(parents=True, exist_ok=True)
    max_files = settings.max_file_count
    max_file_bytes = megabytes_to_bytes(settings.max_file_size_mb)
    max_extracted = megabytes_to_bytes(settings.max_zip_extracted_size_mb)
    extracted_bytes = 0
    file_count = 0

    try:
        zip_file = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise AppError("INVALID_ZIP", "The ZIP archive could not be read.", status_code=400) from exc

    with zip_file:
        for info in zip_file.infolist():
            if info.flag_bits & 0x1:
                raise AppError("INVALID_ZIP", "Encrypted ZIP archives are not supported.", status_code=400)
            relative = _safe_member_path(info.filename)
            if relative is None:
                continue
            if _is_symlink(info):
                raise AppError(
                    "INVALID_ZIP",
                    "ZIP archives must not contain symbolic links.",
                    status_code=400,
                )
            target = destination.joinpath(*relative.parts)
            if not _is_inside(destination, target):
                raise AppError(
                    "ZIP_PATH_TRAVERSAL",
                    "The ZIP archive contains an unsafe path.",
                    status_code=400,
                )
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            file_count += 1
            if file_count > max_files:
                raise AppError(
                    "TOO_MANY_FILES",
                    "The archive contains too many files.",
                    status_code=413,
                    details={"limit": max_files},
                )
            if info.file_size > max_file_bytes:
                raise AppError(
                    "FILE_TOO_LARGE",
                    "The archive contains a file that exceeds the size limit.",
                    status_code=413,
                    details={"limit_mb": settings.max_file_size_mb},
                )
            if info.file_size > max_extracted - extracted_bytes:
                raise AppError(
                    "ZIP_TOO_LARGE",
                    "Extracting the archive would exceed the size limit.",
                    status_code=413,
                    details={"limit_mb": settings.max_zip_extracted_size_mb},
                )

            target.parent.mkdir(parents=True, exist_ok=True)
            written = _extract_member(zip_file, info, target, max_file_bytes)
            extracted_bytes += written
            if extracted_bytes > max_extracted:
                raise AppError(
                    "ZIP_TOO_LARGE",
                    "Extracting the archive would exceed the size limit.",
                    status_code=413,
                    details={"limit_mb": settings.max_zip_extracted_size_mb},
                )


def _extract_member(zip_file: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path, max_file_bytes: int) -> int:
    written = 0
    with zip_file.open(info, "r") as source, target.open("wb") as handle:
        while True:
            chunk = source.read(_CHUNK_SIZE)
            if not chunk:
                break
            written += len(chunk)
            if written > max_file_bytes:
                raise AppError(
                    "FILE_TOO_LARGE",
                    "The archive contains a file that exceeds the size limit.",
                    status_code=413,
                )
            handle.write(chunk)
    return written


def _safe_member_path(name: str) -> Path | None:
    if not name or "\x00" in name:
        raise AppError("ZIP_PATH_TRAVERSAL", "The ZIP archive contains an unsafe path.", status_code=400)
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise AppError("ZIP_PATH_TRAVERSAL", "The ZIP archive contains an absolute path.", status_code=400)
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if not parts:
        return None
    if any(part == ".." or part.startswith("/") or len(part) > 255 for part in parts):
        raise AppError("ZIP_PATH_TRAVERSAL", "The ZIP archive contains an unsafe path.", status_code=400)
    return Path(*parts)


def _is_inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)
