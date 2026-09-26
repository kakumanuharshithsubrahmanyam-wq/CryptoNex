"""Read the stored dependency inventory for a scan."""

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.dependency import Dependency, DependencyRelationship
from app.models.scan import Scan
from app.schemas.dependency import DependencyEvidence, DependencyListResponse, DependencyResponse
from app.services.dependencies.types import RelationshipType


def list_dependencies(session: Session, scan: Scan, limit: int, offset: int) -> DependencyListResponse:
    total = session.scalar(select(func.count()).select_from(Dependency).where(Dependency.scan_id == scan.id))
    rows = session.scalars(
        select(Dependency)
        .where(Dependency.scan_id == scan.id)
        .order_by(Dependency.manifest_file, Dependency.source_line, Dependency.id)
        .limit(limit)
        .offset(offset)
    ).all()
    finding_ids, parent_ids = _relationships(session, [row.id for row in rows])
    return DependencyListResponse(
        scan_id=scan.id,
        total=total or 0,
        limit=limit,
        offset=offset,
        items=[
            DependencyResponse(
                id=row.id,
                project_id=row.project_id,
                scan_id=row.scan_id,
                name=row.name,
                ecosystem=row.ecosystem,
                version=row.version,
                version_constraint=row.version_constraint,
                dependency_type=row.dependency_type,
                direct_or_transitive=row.direct_or_transitive,
                crypto_relevance=row.crypto_relevance,
                library=row.library,
                manifest_file=row.manifest_file,
                source_line=row.source_line,
                evidence=DependencyEvidence(
                    manifest_file=row.manifest_file,
                    source_line=row.source_line,
                    raw_declaration=row.evidence,
                ),
                metadata=_json_dict(row.metadata_json),
                finding_ids=finding_ids.get(row.id, []),
                required_by_dependency_ids=parent_ids.get(row.id, []),
                created_at=row.created_at,
            )
            for row in rows
        ],
    )


def _relationships(
    session: Session, dependency_ids: list[int]
) -> tuple[dict[int, list[int]], dict[int, list[int]]]:
    findings: dict[int, list[int]] = {}
    parents: dict[int, list[int]] = {}
    if not dependency_ids:
        return findings, parents
    rows = session.scalars(
        select(DependencyRelationship)
        .where(DependencyRelationship.dependency_id.in_(dependency_ids))
        .order_by(DependencyRelationship.id)
    ).all()
    for row in rows:
        if row.relationship_type == RelationshipType.TRANSITIVE_DEPENDENCY.value and row.source_dependency_id:
            parents.setdefault(row.dependency_id, []).append(row.source_dependency_id)
        elif row.finding_id is not None:
            findings.setdefault(row.dependency_id, []).append(row.finding_id)
    return (
        {key: sorted(set(value)) for key, value in findings.items()},
        {key: sorted(set(value)) for key, value in parents.items()},
    )


def _json_dict(value: str | None) -> dict[str, str]:
    try:
        loaded = json.loads(value or "{}")
    except ValueError:
        return {}
    return {str(key): str(item) for key, item in loaded.items()} if isinstance(loaded, dict) else {}
