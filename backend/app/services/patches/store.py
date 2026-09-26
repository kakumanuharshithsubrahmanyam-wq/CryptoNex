"""Persist the latest patch proposal per scan finding."""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models.patch import MigrationPatchProposal
from app.services.patches.types import PatchProposal


def save_proposal(session: Session, proposal: PatchProposal) -> PatchProposal:
    payload = json.dumps(
        {
            "affected_protocols": proposal.affected_protocols,
            "affected_certificates": proposal.affected_certificates,
            "reason": proposal.reason,
            "suggested_migration_strategy": proposal.suggested_migration_strategy,
            "validation_errors": proposal.validation_errors,
        }
    )
    row = session.scalar(
        select(MigrationPatchProposal).where(
            MigrationPatchProposal.scan_id == proposal.scan_id,
            MigrationPatchProposal.finding_id == proposal.finding_id,
        )
    )
    if row is None:
        row = MigrationPatchProposal(scan_id=proposal.scan_id, finding_id=proposal.finding_id)
        session.add(row)
    row.source_file = proposal.source_file
    row.migration_id = proposal.migration_id
    row.current_algorithm = proposal.current_algorithm
    row.proposed_replacement = proposal.proposed_replacement
    row.migration_mode = proposal.migration_mode
    row.patch_status = proposal.patch_status
    row.confidence = proposal.confidence
    row.rationale = proposal.rationale
    row.affected_files_json = json.dumps(proposal.affected_files)
    row.affected_dependencies_json = json.dumps(proposal.affected_dependencies)
    row.warnings_json = json.dumps(proposal.warnings)
    row.validation_checklist_json = json.dumps(proposal.validation_checklist)
    row.unified_diff = proposal.unified_diff
    row.changed_files_json = json.dumps(proposal.changed_files)
    row.payload_json = payload
    row.source_migrated = False
    row.generated_at = proposal.generated_at
    session.commit()
    session.refresh(row)
    return row_to_proposal(row)


def latest_proposal(session: Session, scan_id: int, finding_id: int) -> PatchProposal:
    row = session.scalar(
        select(MigrationPatchProposal).where(
            MigrationPatchProposal.scan_id == scan_id,
            MigrationPatchProposal.finding_id == finding_id,
        )
    )
    if row is None:
        raise AppError("PATCH_NOT_FOUND", "No patch proposal has been generated for this finding.", status_code=404)
    return row_to_proposal(row)


def row_to_proposal(row: MigrationPatchProposal) -> PatchProposal:
    extra = json.loads(row.payload_json or "{}")
    proposal = PatchProposal(
        id=row.id,
        scan_id=row.scan_id,
        finding_id=row.finding_id,
        source_file=row.source_file,
        migration_id=row.migration_id,
        current_algorithm=row.current_algorithm,
        proposed_replacement=row.proposed_replacement,
        migration_mode=row.migration_mode,
        patch_status=row.patch_status,
        confidence=row.confidence,
        rationale=row.rationale,
        affected_files=json.loads(row.affected_files_json or "[]"),
        affected_dependencies=json.loads(row.affected_dependencies_json or "[]"),
        affected_protocols=extra.get("affected_protocols") or [],
        affected_certificates=extra.get("affected_certificates") or [],
        warnings=json.loads(row.warnings_json or "[]"),
        validation_checklist=json.loads(row.validation_checklist_json or "[]"),
        unified_diff=row.unified_diff,
        changed_files=json.loads(row.changed_files_json or "[]"),
        generated_at=row.generated_at,
        source_migrated=False,
        reason=extra.get("reason"),
        suggested_migration_strategy=extra.get("suggested_migration_strategy") or [],
        validation_errors=extra.get("validation_errors") or [],
    )
    return proposal
