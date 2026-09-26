"""Apply a stored patch in isolation, rescan, and compare.

The ingested repository snapshot and the original scan are never modified.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import AppError
from app.models.scan import CryptoFinding, Scan
from app.models.verification import MigrationVerification
from app.services.ingestion.workspace import source_directory
from app.services.intelligence.snapshot import load_snapshot
from app.services.patches.store import proposal_row
from app.services.patches.types import STATUS_GENERATED
from app.services.policy.engine import resolve_policy_text
from app.services.policy.parser import parse_policy
from app.services.scanner.service import scan_isolated_tree
from app.services.verification.compare import compare_verification
from app.services.verification.diff_apply import PatchApplyError, apply_unified_diff

_WARNINGS = (
    "Verification applied the stored proposal only inside an isolated snapshot.",
    "The original repository and original scan were not modified.",
    "A verified result is scanner evidence about this snapshot, not a quantum-safety claim.",
    "No commit, push, or pull request was created.",
)


def verify_finding_patch(session: Session, scan: Scan, finding_id: int, patch_id: int, settings: Settings) -> dict:
    snapshot = load_snapshot(session, scan)
    finding = snapshot.finding(finding_id)
    proposal = proposal_row(session, scan.id, finding_id, patch_id)
    if proposal.patch_status != STATUS_GENERATED:
        raise AppError(
            "INVALID_PATCH_STATUS",
            "Only a generated patch proposal can be verified.",
            status_code=400,
            details={"patch_status": proposal.patch_status},
        )
    source_root = _original_source(snapshot.project, settings)
    before_tree = _tree_fingerprint(source_root)
    before_findings = _finding_fingerprint(session, scan.id)
    isolated = _isolated_root(settings, snapshot.project.id)
    verification_scan_id = None
    try:
        try:
            _copy_snapshot(source_root, isolated, settings)
            apply_unified_diff(isolated, proposal.unified_diff, settings)
        except PatchApplyError as exc:
            stored = _persist(
                session,
                snapshot,
                finding,
                proposal,
                status="patch_failed",
                target_status="unknown",
                verification_scan_id=None,
                comparison=None,
                messages=exc.messages,
            )
            _assert_original_unchanged(source_root, before_tree, session, scan.id, before_findings)
            return stored
        try:
            verification_scan = scan_isolated_tree(session, snapshot.project, isolated, settings)
            verification_scan_id = verification_scan.id
        except AppError as exc:
            stored = _persist(
                session,
                snapshot,
                finding,
                proposal,
                status="rescan_failed",
                target_status="unknown",
                verification_scan_id=None,
                comparison=None,
                messages=[exc.message],
            )
            _assert_original_unchanged(source_root, before_tree, session, scan.id, before_findings)
            return stored
        after = load_snapshot(session, verification_scan)
        policy_text, _source = resolve_policy_text(snapshot.project, None)
        compared = compare_verification(
            snapshot,
            after,
            target=finding,
            replacement=proposal.proposed_replacement,
            source_file=proposal.source_file or finding.file_path,
            rules=parse_policy(policy_text),
        )
        stored = _persist(
            session,
            snapshot,
            finding,
            proposal,
            status=compared["status"],
            target_status=compared["target_status"],
            verification_scan_id=verification_scan_id,
            comparison=compared,
            messages=[],
        )
    finally:
        shutil.rmtree(isolated.parent, ignore_errors=True)
    _assert_original_unchanged(source_root, before_tree, session, scan.id, before_findings)
    return stored


def latest_verification(session: Session, scan: Scan, finding_id: int) -> dict:
    snapshot = load_snapshot(session, scan)
    snapshot.finding(finding_id)
    row = session.scalar(
        select(MigrationVerification)
        .where(
            MigrationVerification.original_scan_id == scan.id,
            MigrationVerification.finding_id == finding_id,
        )
        .order_by(MigrationVerification.id.desc())
    )
    if row is None:
        raise AppError("VERIFICATION_NOT_FOUND", "No verification result exists for this finding.", status_code=404)
    return _as_dict(row)


def _persist(
    session: Session,
    snapshot,
    finding,
    proposal,
    *,
    status: str,
    target_status: str,
    verification_scan_id: int | None,
    comparison: dict | None,
    messages: list[str],
) -> dict:
    comparison = comparison or {}
    detail = {
        "new_findings": comparison.get("new_findings") or [],
        "removed_findings": comparison.get("removed_findings") or [],
        "changed_findings": comparison.get("changed_findings") or [],
        "regressions": comparison.get("regressions") or [],
        "policy_before": comparison.get("policy_before") or {},
        "policy_after": comparison.get("policy_after") or {},
        "cbom_before": comparison.get("cbom_before") or {},
        "cbom_after": comparison.get("cbom_after") or {},
        "affected_files": [proposal.source_file] if proposal.source_file else [],
        "validation_messages": messages,
        "warnings": list(_WARNINGS),
    }
    row = MigrationVerification(
        project_id=snapshot.project.id,
        original_scan_id=snapshot.scan.id,
        verification_scan_id=verification_scan_id,
        finding_id=finding.id,
        patch_id=proposal.id,
        status=status,
        target_status=target_status,
        original_algorithm=proposal.current_algorithm or finding.algorithm,
        replacement_algorithm=proposal.proposed_replacement,
        original_finding_present=bool(comparison.get("original_finding_present")),
        replacement_finding_present=bool(comparison.get("replacement_finding_present")),
        detail_json=json.dumps(detail, sort_keys=True),
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return _as_dict(row)


def _as_dict(row: MigrationVerification) -> dict:
    detail = json.loads(row.detail_json or "{}")
    created = row.created_at
    stamp = created.isoformat().replace("+00:00", "Z")
    return {
        "id": row.id,
        "project_id": row.project_id,
        "original_scan_id": row.original_scan_id,
        "verification_scan_id": row.verification_scan_id,
        "finding_id": row.finding_id,
        "patch_id": row.patch_id,
        "status": row.status,
        "target_status": row.target_status,
        "original_algorithm": row.original_algorithm,
        "replacement_algorithm": row.replacement_algorithm,
        "original_finding_present": row.original_finding_present,
        "replacement_finding_present": row.replacement_finding_present,
        "new_findings": detail.get("new_findings") or [],
        "removed_findings": detail.get("removed_findings") or [],
        "changed_findings": detail.get("changed_findings") or [],
        "regressions": detail.get("regressions") or [],
        "policy_before": detail.get("policy_before") or {},
        "policy_after": detail.get("policy_after") or {},
        "cbom_before": detail.get("cbom_before") or {},
        "cbom_after": detail.get("cbom_after") or {},
        "affected_files": detail.get("affected_files") or [],
        "validation_messages": detail.get("validation_messages") or [],
        "warnings": detail.get("warnings") or [],
        "created_at": stamp,
    }


def _original_source(project, settings: Settings) -> Path:
    if not project.workspace_path:
        raise AppError("SCAN_FAILED", "The ingested repository is not available.", status_code=500)
    root = source_directory(Path(project.workspace_path))
    workspace_root = Path(settings.workspace_root).expanduser().resolve()
    resolved = root.resolve()
    if not resolved.is_dir() or not resolved.is_relative_to(workspace_root):
        raise AppError("SCAN_FAILED", "The ingested repository is not available.", status_code=500)
    return resolved


def _isolated_root(settings: Settings, project_id: int) -> Path:
    workspace_root = Path(settings.workspace_root).expanduser().resolve()
    destination = workspace_root / "verifications" / str(project_id) / uuid.uuid4().hex / "source"
    resolved = destination.resolve()
    if not resolved.is_relative_to(workspace_root):
        raise AppError("SCAN_FAILED", "The verification workspace could not be created.", status_code=500)
    destination.mkdir(parents=True, exist_ok=False)
    return destination


def _copy_snapshot(source: Path, dest: Path, settings: Settings) -> None:
    count = 0
    base = source.resolve()
    target_root = dest.resolve()
    for path in sorted(base.rglob("*")):
        if path.is_symlink():
            continue
        relative = path.relative_to(base)
        if ".." in relative.parts:
            raise PatchApplyError(["path traversal while copying the snapshot"])
        target = (target_root / relative).resolve()
        if not target.is_relative_to(target_root):
            raise PatchApplyError(["copy escaped the isolated workspace"])
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not path.is_file():
            continue
        count += 1
        if count > settings.max_file_count:
            raise PatchApplyError(["isolated snapshot exceeds the file-count limit"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def _tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    base = root.resolve()
    for path in sorted(base.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        digest.update(str(path.relative_to(base)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _finding_fingerprint(session: Session, scan_id: int) -> tuple:
    rows = session.scalars(select(CryptoFinding).where(CryptoFinding.scan_id == scan_id).order_by(CryptoFinding.id))
    return tuple((row.id, row.fingerprint, row.algorithm, row.evidence, row.usage) for row in rows)


def _assert_original_unchanged(source_root: Path, before_tree: str, session: Session, scan_id: int, before_findings: tuple) -> None:
    if _tree_fingerprint(source_root) != before_tree:
        raise AppError("VERIFICATION_UNSAFE", "The original repository snapshot changed during verification.", status_code=500)
    if _finding_fingerprint(session, scan_id) != before_findings:
        raise AppError("VERIFICATION_UNSAFE", "The original scan changed during verification.", status_code=500)
