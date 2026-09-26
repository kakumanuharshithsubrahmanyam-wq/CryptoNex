"""Run a deterministic scan for an ingested project and store findings."""

import hashlib
import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AppError
from app.models.project import Project, ProjectStatus
from app.models.scan import CryptoFinding, Scan, ScanStatus
from app.schemas.project import RepositoryManifest
from app.schemas.scan import ScanResponse, ScanSummary
from app.services.ingestion.workspace import source_directory
from app.services.scanner.engine import scan_manifest
from app.services.scanner.findings import RawFinding

logger = logging.getLogger(__name__)


def scan_project(session: Session, project: Project, settings: Settings) -> ScanResponse:
    if project.status != ProjectStatus.READY.value or not project.manifest_json or not project.workspace_path:
        raise AppError(
            "PROJECT_NOT_INGESTED",
            "The project must be ingested before it can be scanned.",
            status_code=409,
        )
    try:
        manifest = RepositoryManifest.model_validate_json(project.manifest_json)
    except ValueError as exc:
        raise AppError("SCAN_FAILED", "The repository manifest could not be read.", status_code=500) from exc

    workspace = Path(project.workspace_path)
    source_root = source_directory(workspace)
    if not _workspace_is_contained(settings, workspace) or not source_root.is_dir():
        raise AppError("SCAN_FAILED", "The ingested repository is not available.", status_code=500)

    scan = Scan(project_id=project.id, status=ScanStatus.RUNNING.value)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    try:
        if manifest.file_count > settings.max_file_count:
            raise AppError(
                "RESOURCE_LIMIT_EXCEEDED",
                "The repository has more files than the scanner is allowed to read.",
                status_code=413,
                details={"limit": settings.max_file_count},
            )
        result = scan_manifest(source_root, manifest, settings)
        for finding in result.findings:
            session.add(_row(project.id, scan.id, finding))
        summary = _summary(result.files_scanned, result.skip_reasons, result.findings)
        scan.status = ScanStatus.COMPLETED.value
        scan.summary_json = summary.model_dump_json()
        session.commit()
        logger.info("Scan completed project_id=%s scan_id=%s", project.id, scan.id)
        return ScanResponse(
            scan_id=scan.id,
            project_id=project.id,
            status=ScanStatus.COMPLETED,
            summary=summary,
        )
    except AppError as exc:
        _fail(session, scan.id)
        raise exc
    except Exception as exc:
        _fail(session, scan.id)
        logger.error("Scan failed project_id=%s error_type=%s", project.id, type(exc).__name__)
        raise AppError("SCAN_FAILED", "The cryptographic scan failed.", status_code=500) from exc


def _workspace_is_contained(settings: Settings, workspace: Path) -> bool:
    root = Path(settings.workspace_root).expanduser().resolve()
    try:
        resolved = workspace.resolve()
    except OSError:
        return False
    return resolved.is_relative_to(root)


def _row(project_id: int, scan_id: int, finding: RawFinding) -> CryptoFinding:
    payload = {
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "algorithm": finding.algorithm,
        "library": finding.library,
        "usage": finding.usage,
        "detection_method": finding.detection_method,
    }
    fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return CryptoFinding(
        project_id=project_id,
        scan_id=scan_id,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        language=finding.language,
        algorithm=finding.algorithm,
        algorithm_family=finding.algorithm_family,
        library=finding.library,
        library_version=finding.library_version,
        usage=finding.usage,
        key_size=finding.key_size,
        curve=finding.curve,
        mode=finding.mode,
        evidence=finding.evidence[:512],
        detection_method=finding.detection_method,
        confidence=finding.confidence,
        metadata_json=json.dumps(finding.metadata, sort_keys=True),
        fingerprint=fingerprint,
    )


def _summary(files_scanned: int, skip_reasons: dict[str, int], findings: list[RawFinding]) -> ScanSummary:
    algorithms: dict[str, int] = {}
    for finding in findings:
        if finding.usage == "dependency_only" or not finding.algorithm:
            continue
        algorithms[finding.algorithm] = algorithms.get(finding.algorithm, 0) + 1
    ordered = {name: algorithms[name] for name in sorted(algorithms)}
    return ScanSummary(
        files_scanned=files_scanned,
        files_skipped=sum(skip_reasons.values()),
        skip_reasons=dict(sorted(skip_reasons.items())),
        findings=len(findings),
        high_confidence=sum(1 for finding in findings if finding.confidence == "high"),
        medium_confidence=sum(1 for finding in findings if finding.confidence == "medium"),
        low_confidence=sum(1 for finding in findings if finding.confidence == "low"),
        algorithms=ordered,
    )


def _fail(session: Session, scan_id: int) -> None:
    session.rollback()
    scan = session.get(Scan, scan_id)
    if scan is not None:
        scan.status = ScanStatus.FAILED.value
        session.commit()
