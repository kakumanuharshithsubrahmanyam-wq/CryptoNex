"""Read stored security artifacts."""

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.artifact import SecurityArtifact
from app.models.scan import Scan
from app.schemas.artifact import ArtifactListResponse, ArtifactResponse


def list_artifacts(session: Session, scan: Scan, limit: int, offset: int) -> ArtifactListResponse:
    total = session.scalar(select(func.count()).select_from(SecurityArtifact).where(SecurityArtifact.scan_id == scan.id))
    rows = session.scalars(
        select(SecurityArtifact)
        .where(SecurityArtifact.scan_id == scan.id)
        .order_by(SecurityArtifact.file_path, SecurityArtifact.line_start, SecurityArtifact.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return ArtifactListResponse(
        scan_id=scan.id,
        total=total or 0,
        limit=limit,
        offset=offset,
        items=[_item(row) for row in rows],
    )


def _item(row: SecurityArtifact) -> ArtifactResponse:
    return ArtifactResponse(
        id=row.id,
        project_id=row.project_id,
        scan_id=row.scan_id,
        artifact_type=row.artifact_type,
        file_path=row.file_path,
        line_start=row.line_start,
        line_end=row.line_end,
        protocol=row.protocol,
        format=row.format,
        algorithm=row.algorithm,
        key_size=row.key_size,
        curve=row.curve,
        subject=row.subject,
        issuer=row.issuer,
        serial_number=row.serial_number,
        validity_start=row.validity_start,
        validity_end=row.validity_end,
        cipher_suite=row.cipher_suite,
        evidence=row.evidence,
        detection_method=row.detection_method,
        confidence=row.confidence,
        metadata=_json_dict(row.metadata_json),
        created_at=row.created_at,
    )


def _json_dict(value: str | None) -> dict[str, str]:
    try:
        loaded = json.loads(value or "{}")
    except ValueError:
        return {}
    return {str(key): str(item) for key, item in loaded.items()} if isinstance(loaded, dict) else {}
