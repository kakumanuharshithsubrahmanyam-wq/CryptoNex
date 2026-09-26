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
from app.services.artifacts.persistence import artifact_row
from app.services.cbom.builder import attach_cbom_children, build_cbom_document, persist_cbom
from app.services.context.classifier import FindingContext, classify
from app.services.context.taxonomy import FindingStatus
from app.services.dependencies.linking import apply_declared_versions, link_all
from app.services.dependencies.persistence import dependency_row, relationship_rows
from app.services.dependencies.types import CryptoRelevance
from app.services.ingestion.workspace import source_directory
from app.services.scanner.engine import ScanRun, scan_manifest
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
        contexts = [classify(finding) for finding in result.findings]
        for finding, context in zip(result.findings, contexts):
            finding.confidence = context.confidence.value
        links = link_all(result.findings, result.dependencies)
        apply_declared_versions(result.findings, result.dependencies, links)

        dependency_rows = [dependency_row(project.id, scan.id, item) for item in result.dependencies]
        finding_rows = [
            _row(project.id, scan.id, finding, context)
            for finding, context in zip(result.findings, contexts)
        ]
        artifact_rows = [artifact_row(project.id, scan.id, item) for item in result.artifacts]
        session.add_all(dependency_rows)
        session.add_all(finding_rows)
        session.add_all(artifact_rows)
        session.flush()
        relationship_models = relationship_rows(
            scan.id,
            links,
            [row.id for row in finding_rows],
            [row.id for row in dependency_rows],
        )
        session.add_all(relationship_models)
        session.flush()
        document = build_cbom_document(scan, finding_rows, dependency_rows, artifact_rows, relationship_models)
        cbom, cbom_components, cbom_relationships = persist_cbom(scan, document)
        session.add(cbom)
        session.flush()
        attach_cbom_children(cbom, cbom_components, cbom_relationships)
        session.add_all(cbom_components)
        session.add_all(cbom_relationships)
        summary = _summary(result, contexts)
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
        session.rollback()
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


def _row(project_id: int, scan_id: int, finding: RawFinding, context: FindingContext) -> CryptoFinding:
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
        evidence_type=context.evidence_type.value,
        confidence_reasons_json=json.dumps([reason.value for reason in context.confidence_reasons]),
        finding_status=context.finding_status.value,
        cryptographic_role=context.cryptographic_role.value,
        parameter_completeness=context.parameter_completeness.value,
        security_concern=context.security_concern.value,
        quantum_relevance=context.quantum_relevance.value,
    )


def _summary(result: ScanRun, contexts: list[FindingContext]) -> ScanSummary:
    findings = result.findings
    algorithms: dict[str, int] = {}
    for finding in findings:
        if finding.usage == "dependency_only" or not finding.algorithm:
            continue
        algorithms[finding.algorithm] = algorithms.get(finding.algorithm, 0) + 1
    ordered = {name: algorithms[name] for name in sorted(algorithms)}
    statuses = [context.finding_status for context in contexts]
    return ScanSummary(
        files_scanned=result.files_scanned,
        files_skipped=sum(result.skip_reasons.values()),
        skip_reasons=dict(sorted(result.skip_reasons.items())),
        findings=len(findings),
        high_confidence=sum(1 for finding in findings if finding.confidence == "high"),
        medium_confidence=sum(1 for finding in findings if finding.confidence == "medium"),
        low_confidence=sum(1 for finding in findings if finding.confidence == "low"),
        algorithms=ordered,
        confirmed_findings=statuses.count(FindingStatus.CONFIRMED),
        probable_findings=statuses.count(FindingStatus.PROBABLE),
        weak_signal_findings=statuses.count(FindingStatus.WEAK_SIGNAL),
        dependencies=len(result.dependencies),
        crypto_dependencies=sum(
            1
            for dependency in result.dependencies
            if dependency.crypto_relevance == CryptoRelevance.CRYPTOGRAPHIC_LIBRARY.value
        ),
        malformed_manifests=result.malformed_manifests,
        artifacts=len(result.artifacts),
        certificates=sum(1 for item in result.artifacts if item.artifact_type == "certificate"),
        protocols=sum(1 for item in result.artifacts if item.artifact_type in {"protocol", "ssh_config"}),
    )


def _fail(session: Session, scan_id: int) -> None:
    session.rollback()
    scan = session.get(Scan, scan_id)
    if scan is not None:
        scan.status = ScanStatus.FAILED.value
        session.commit()
