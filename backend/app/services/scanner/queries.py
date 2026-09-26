"""Read stored scans and findings."""

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models.dependency import Dependency, DependencyRelationship
from app.models.scan import CryptoFinding, Scan, ScanStatus
from app.schemas.scan import (
    FindingDependencyLink,
    FindingListResponse,
    FindingResponse,
    ScanDetailResponse,
    ScanSummary,
)


def get_scan(session: Session, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise AppError("SCAN_NOT_FOUND", "Scan not found.", status_code=404)
    return scan


def scan_detail(scan: Scan) -> ScanDetailResponse:
    summary = ScanSummary.model_validate_json(scan.summary_json) if scan.summary_json else None
    return ScanDetailResponse(
        scan_id=scan.id,
        project_id=scan.project_id,
        status=ScanStatus(scan.status),
        created_at=scan.created_at,
        summary=summary,
    )


def list_findings(session: Session, scan: Scan, limit: int, offset: int) -> FindingListResponse:
    total = session.scalar(select(func.count()).select_from(CryptoFinding).where(CryptoFinding.scan_id == scan.id))
    rows = session.scalars(
        select(CryptoFinding)
        .where(CryptoFinding.scan_id == scan.id)
        .order_by(CryptoFinding.file_path, CryptoFinding.line_start, CryptoFinding.id)
        .limit(limit)
        .offset(offset)
    ).all()
    links = _dependency_links(session, [row.id for row in rows])
    return FindingListResponse(
        scan_id=scan.id,
        total=total or 0,
        limit=limit,
        offset=offset,
        items=[_finding_response(row, links.get(row.id, [])) for row in rows],
    )


def _dependency_links(session: Session, finding_ids: list[int]) -> dict[int, list[FindingDependencyLink]]:
    if not finding_ids:
        return {}
    pairs = session.execute(
        select(DependencyRelationship, Dependency)
        .join(Dependency, Dependency.id == DependencyRelationship.dependency_id)
        .where(DependencyRelationship.finding_id.in_(finding_ids))
        .order_by(DependencyRelationship.finding_id, Dependency.manifest_file, Dependency.source_line)
    ).all()
    grouped: dict[int, list[FindingDependencyLink]] = {}
    for relationship, dependency in pairs:
        grouped.setdefault(relationship.finding_id, []).append(
            FindingDependencyLink(
                dependency_id=dependency.id,
                relationship_type=relationship.relationship_type,
                name=dependency.name,
                ecosystem=dependency.ecosystem,
                version=dependency.version,
                version_constraint=dependency.version_constraint,
                manifest_file=dependency.manifest_file,
                source_line=dependency.source_line,
            )
        )
    return grouped


def _finding_response(row: CryptoFinding, links: list[FindingDependencyLink]) -> FindingResponse:
    return FindingResponse(
        id=row.id,
        project_id=row.project_id,
        scan_id=row.scan_id,
        file_path=row.file_path,
        line_start=row.line_start,
        line_end=row.line_end,
        language=row.language,
        algorithm=row.algorithm,
        algorithm_family=row.algorithm_family,
        library=row.library,
        library_version=row.library_version,
        usage=row.usage,
        key_size=row.key_size,
        curve=row.curve,
        mode=row.mode,
        evidence=row.evidence,
        detection_method=row.detection_method,
        confidence=row.confidence,
        metadata=_json_dict(row.metadata_json),
        evidence_type=row.evidence_type,
        confidence_reasons=_json_list(row.confidence_reasons_json),
        finding_status=row.finding_status,
        cryptographic_role=row.cryptographic_role,
        parameter_completeness=row.parameter_completeness,
        security_concern=row.security_concern,
        quantum_relevance=row.quantum_relevance,
        dependencies=links,
        created_at=row.created_at,
    )


def _json_dict(value: str | None) -> dict[str, str]:
    try:
        loaded = json.loads(value or "{}")
    except ValueError:
        return {}
    return {str(key): str(item) for key, item in loaded.items()} if isinstance(loaded, dict) else {}


def _json_list(value: str | None) -> list[str]:
    try:
        loaded = json.loads(value or "[]")
    except ValueError:
        return []
    return [str(item) for item in loaded] if isinstance(loaded, list) else []
