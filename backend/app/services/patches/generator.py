"""Deterministic migration patch generation from an ingested snapshot.

This module produces a reviewable proposal. It does not apply patches, run
repository code, install packages, or contact the scanned repository.
"""

from __future__ import annotations

import difflib
from pathlib import Path

from app.core.config import Settings
from app.core.exceptions import AppError
from app.services.ingestion.workspace import source_directory
from app.services.intelligence.snapshot import ScanSnapshot
from app.services.migration.blast_radius import blast_radius
from app.services.migration.planner import plan_finding
from app.services.migration.registry import (
    CLASSICAL_COUNTERPARTS,
    LEGACY_CIPHER,
    LEGACY_HASH,
    MANUAL_PUBLIC_KEY,
    advise,
    canonical_algorithm,
    default_replacement,
    is_registered_replacement,
)
from app.services.patches.paths import resolve_source_file
from app.services.patches.rewrites import apply_rewrite, replace_span, span_text
from app.services.patches.types import (
    ALLOWED_MODES,
    STATUS_GENERATED,
    STATUS_MANUAL,
    STATUS_UNSUPPORTED,
    STATUS_VALIDATION_FAILED,
    PatchProposal,
)
from app.services.patches.validate import validate_generated
from app.services.scanner.evidence import redact_secrets

_CHECKLIST = (
    "Review the unified diff against the ingested snapshot before any apply step.",
    "Generating a patch does not migrate source and does not mark the finding resolved.",
    "Re-scan after an approved apply; do not treat this proposal as verification.",
    "Static analysis cannot claim that a repository is quantum-safe.",
)
_MANUAL_STRATEGY = (
    "Introduce a cryptographic abstraction rather than a one-line identifier swap.",
    "Plan hybrid operation if peers still require the classical primitive.",
    "Update certificates, protocol configuration, and tests after the API redesign.",
    "Validate interoperability and performance before removing the classical path.",
)


def generate_proposal(
    snapshot: ScanSnapshot,
    finding,
    settings: Settings,
    replacement: str | None = None,
    mode: str = "minimal",
) -> PatchProposal:
    if mode not in ALLOWED_MODES:
        raise AppError("INVALID_PATCH_MODE", "mode must be minimal or migration.", status_code=400)
    advice = advise(finding)
    requested = canonical_algorithm(replacement) if replacement else default_replacement(advice)
    if replacement:
        if not is_registered_replacement(advice, replacement):
            raise AppError(
                "INVALID_REPLACEMENT",
                "Replacement is not registered for this finding.",
                status_code=400,
                details={"replacement": replacement, "algorithm": advice.algorithm, "role": advice.role},
            )
        requested = canonical_algorithm(replacement)
    plan = plan_finding(snapshot, finding)
    radius = blast_radius(snapshot.graph, finding.id, finding)
    base = _base_proposal(snapshot, finding, mode, advice.algorithm, requested, plan, radius)

    if getattr(finding, "usage", None) == "dependency_only" or getattr(finding, "detection_method", None) == "dependency_detection":
        return _finish(
            base,
            STATUS_UNSUPPORTED,
            "low",
            "Dependency presence is not a source transformation. CryptoNex will not invent a package version.",
            migration_id=f"unsupported:dependency:{advice.algorithm}",
        )
    if not getattr(finding, "file_path", None):
        return _finish(base, STATUS_UNSUPPORTED, "low", "Finding has no source file.", migration_id="unsupported:missing-file")
    if advice.algorithm in MANUAL_PUBLIC_KEY:
        return _manual_public_key(base, advice.algorithm, requested, plan)
    if advice.algorithm in LEGACY_CIPHER:
        return _finish(
            base,
            STATUS_MANUAL,
            "medium",
            f"{advice.algorithm} cipher replacement is not a deterministic one-line rewrite.",
            migration_id=f"manual:{advice.algorithm}:{requested or 'unspecified'}",
            strategy=list(_MANUAL_STRATEGY),
        )
    if advice.category in {"modern_symmetric", "modern_hash", "mac", "key_derivation", "post_quantum", "hybrid"}:
        return _finish(
            base,
            STATUS_UNSUPPORTED,
            "low",
            f"{advice.algorithm} is not a deterministic automatic-replacement target.",
            migration_id=f"unsupported:{advice.algorithm}",
        )
    if advice.algorithm in LEGACY_HASH and requested in CLASSICAL_COUNTERPARTS.get(advice.algorithm, ()):
        return _legacy_hash_patch(snapshot, finding, settings, base, advice.algorithm, requested)
    return _finish(
        base,
        STATUS_UNSUPPORTED,
        "low",
        f"No deterministic patch transformation is registered for {advice.algorithm}.",
        migration_id=f"unsupported:{advice.algorithm}",
    )


def _legacy_hash_patch(
    snapshot: ScanSnapshot,
    finding,
    settings: Settings,
    base: PatchProposal,
    algorithm: str,
    replacement: str,
) -> PatchProposal:
    source_root = _source_root(snapshot)
    if source_root is None:
        return _validation_failed(base, algorithm, replacement, ["ingested source snapshot is unavailable"])
    relative = finding.file_path
    target = resolve_source_file(source_root, relative)
    if target is None:
        reason = (
            "path traversal is not allowed"
            if ".." in relative.replace("\\", "/").split("/") or relative.startswith(("/", "\\"))
            else "target file is missing from the ingested snapshot"
        )
        return _validation_failed(base, algorithm, replacement, [reason])
    original = target.read_text(encoding="utf-8")
    try:
        observed = span_text(original, finding.line_start, finding.line_end)
    except ValueError:
        return _validation_failed(base, algorithm, replacement, ["original source context is outside the stored file"])
    rewritten = apply_rewrite(getattr(finding, "language", None), algorithm, replacement, observed)
    if rewritten is None:
        return _validation_failed(
            base,
            algorithm,
            replacement,
            ["original source context does not match a registered rewrite"],
        )
    updated = replace_span(original, finding.line_start, finding.line_end, rewritten)
    diff = _unified_diff(relative, original, updated)
    proposal = _finish(
        base,
        STATUS_GENERATED,
        "high",
        f"Replace recognized {algorithm} API usage with {replacement} at the stored source location.",
        migration_id=f"rewrite:{algorithm}:{replacement}",
        replacement=replacement,
        diff=diff,
        changed=[relative],
    )
    if proposal.patch_status != STATUS_GENERATED:
        return proposal
    errors = validate_generated(
        proposal,
        source_root=source_root,
        original=original,
        updated=updated,
        finding=finding,
        advice=advise(finding),
        settings=settings,
    )
    if errors:
        return _validation_failed(base, algorithm, replacement, errors)
    return proposal


def _manual_public_key(base: PatchProposal, algorithm: str, replacement: str | None, plan: dict) -> PatchProposal:
    target = replacement or "role-appropriate PQC candidate"
    return _finish(
        base,
        STATUS_MANUAL,
        "medium",
        (
            f"{algorithm} → {target} requires API and protocol redesign. "
            "CryptoNex will not fabricate a one-line replacement."
        ),
        migration_id=f"manual:{algorithm}:{replacement or 'unspecified'}",
        replacement=replacement,
        strategy=list(plan.get("migration_steps") or _MANUAL_STRATEGY),
    )


def _base_proposal(snapshot, finding, mode, algorithm, replacement, plan, radius) -> PatchProposal:
    return PatchProposal(
        scan_id=snapshot.scan.id,
        finding_id=finding.id,
        source_file=getattr(finding, "file_path", "") or "",
        migration_id="pending",
        current_algorithm=algorithm if algorithm != "unknown" else getattr(finding, "algorithm", None),
        proposed_replacement=replacement,
        migration_mode=mode,
        patch_status=STATUS_UNSUPPORTED,
        confidence="low",
        rationale="",
        affected_files=[item["label"] for item in radius.get("affected_files", [])] or plan.get("affected_files") or [],
        affected_dependencies=[item["label"] for item in radius.get("affected_dependencies", [])]
        or plan.get("affected_dependencies")
        or [],
        affected_protocols=[item["label"] for item in radius.get("affected_protocols", [])]
        or plan.get("affected_protocols")
        or [],
        affected_certificates=[item["label"] for item in radius.get("affected_certificates", [])]
        or plan.get("affected_certificates")
        or [],
        warnings=list(plan.get("warnings") or [])
        + [
            "This is a patch proposal. CryptoNex has not modified the source repository.",
            "Review imports and call-site types; the rewrite only replaces the recognized span.",
        ],
        validation_checklist=list(_CHECKLIST),
        source_migrated=False,
    )


def _finish(
    base: PatchProposal,
    status: str,
    confidence: str,
    rationale: str,
    *,
    migration_id: str,
    replacement: str | None = None,
    diff: str | None = None,
    changed: list[str] | None = None,
    strategy: list[str] | None = None,
    errors: list[str] | None = None,
) -> PatchProposal:
    base.patch_status = status
    base.confidence = confidence
    base.rationale = rationale
    base.reason = rationale
    base.migration_id = migration_id
    if replacement is not None:
        base.proposed_replacement = replacement
    base.unified_diff = redact_secrets(diff) if diff else None
    if diff and base.unified_diff != diff:
        base.patch_status = STATUS_VALIDATION_FAILED
        base.confidence = "low"
        base.validation_errors = ["generated content contains redacted secrets"]
        base.unified_diff = None
        base.changed_files = []
        return base
    base.changed_files = list(changed or [])
    base.suggested_migration_strategy = list(strategy or [])
    base.validation_errors = list(errors or [])
    base.source_migrated = False
    return base


def _validation_failed(base: PatchProposal, algorithm: str, replacement: str | None, errors: list[str]) -> PatchProposal:
    return _finish(
        base,
        STATUS_VALIDATION_FAILED,
        "low",
        "Patch validation failed. The proposal was not marked generated.",
        migration_id=f"validation-failed:{algorithm}:{replacement or 'unspecified'}",
        replacement=replacement,
        errors=errors,
    )


def _source_root(snapshot: ScanSnapshot) -> Path | None:
    workspace = getattr(snapshot.project, "workspace_path", None)
    if not workspace:
        return None
    root = source_directory(Path(workspace))
    if not root.is_dir():
        return None
    return root


def _unified_diff(path: str, original: str, updated: str) -> str:
    old = original.splitlines(keepends=True)
    new = updated.splitlines(keepends=True)
    return "".join(difflib.unified_diff(old, new, fromfile=f"a/{path}", tofile=f"b/{path}"))
