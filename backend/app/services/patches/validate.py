"""Deterministic validation of a generated patch proposal."""

from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from app.services.migration.registry import is_registered_replacement
from app.services.patches.paths import resolve_source_file
from app.services.patches.rewrites import replace_span, span_text
from app.services.patches.types import STATUS_GENERATED, PatchProposal
from app.services.scanner.evidence import REDACTED, redact_secrets


def validate_generated(
    proposal: PatchProposal,
    *,
    source_root: Path,
    original: str,
    updated: str,
    finding,
    advice,
    settings: Settings,
) -> list[str]:
    errors: list[str] = []
    if proposal.patch_status != STATUS_GENERATED:
        errors.append("generated validation ran on a non-generated proposal")
    if proposal.source_migrated:
        errors.append("source_migrated must remain false")
    target = resolve_source_file(source_root, proposal.source_file)
    if target is None:
        errors.append("target file is missing or escapes the ingested snapshot")
        return errors
    stored = target.read_text(encoding="utf-8")
    if stored != original:
        errors.append("stored snapshot changed while the proposal was generated")
    try:
        observed = span_text(original, finding.line_start, finding.line_end)
    except ValueError:
        errors.append("original source context is outside the stored file")
        observed = ""
    if not observed.strip():
        errors.append("original source context does not match the stored finding")
    try:
        conceptual = replace_span(original, finding.line_start, finding.line_end, span_text(updated, finding.line_start, finding.line_end))
    except ValueError:
        errors.append("replacement span cannot be applied to the stored snapshot")
        conceptual = None
    if conceptual is not None and conceptual != updated:
        errors.append("diff does not apply conceptually to the stored source snapshot")
    if proposal.unified_diff is None or not proposal.unified_diff.startswith("--- a/"):
        errors.append("unified diff is missing or not in unified format")
    if proposal.unified_diff and len(proposal.unified_diff.encode("utf-8")) > settings.max_patch_bytes:
        errors.append("patch exceeds configured size limit")
    if proposal.changed_files != [proposal.source_file]:
        errors.append("patch modifies an unrelated file")
    redacted = redact_secrets(proposal.unified_diff or "")
    if redacted != (proposal.unified_diff or "") or REDACTED in redacted or "REDACTED PRIVATE KEY" in redacted:
        errors.append("generated content contains redacted secrets")
    if not is_registered_replacement(advice, proposal.proposed_replacement):
        errors.append("replacement is not registered for this finding")
    if not _role_compatible(finding, advice, proposal.proposed_replacement):
        errors.append("replacement is not compatible with the finding role")
    return errors


def _role_compatible(finding, advice, replacement: str | None) -> bool:
    if replacement is None:
        return False
    if advice.algorithm in {"MD5", "SHA-1"} and replacement in {
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA-3",
        "BLAKE2",
        "BLAKE3",
    }:
        return True
    names = {item.algorithm for item in advice.candidates}
    if replacement not in names:
        return False
    role = advice.role
    if replacement == "ML-KEM" and role == "digital_signature":
        return False
    if replacement in {"ML-DSA", "SLH-DSA"} and role == "key_establishment":
        return False
    return True
