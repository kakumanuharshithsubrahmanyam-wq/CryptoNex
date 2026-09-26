"""Structured migration patch proposal. A proposal is never an applied fix."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

STATUS_GENERATED = "generated"
STATUS_MANUAL = "manual_migration_required"
STATUS_UNSUPPORTED = "unsupported"
STATUS_VALIDATION_FAILED = "validation_failed"
ALLOWED_STATUSES = frozenset(
    {STATUS_GENERATED, STATUS_MANUAL, STATUS_UNSUPPORTED, STATUS_VALIDATION_FAILED}
)
ALLOWED_MODES = frozenset({"minimal", "migration"})


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PatchProposal:
    scan_id: int
    finding_id: int
    source_file: str
    migration_id: str
    current_algorithm: str | None
    proposed_replacement: str | None
    migration_mode: str
    patch_status: str
    confidence: str
    rationale: str
    affected_files: list[str] = field(default_factory=list)
    affected_dependencies: list[str] = field(default_factory=list)
    affected_protocols: list[str] = field(default_factory=list)
    affected_certificates: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    validation_checklist: list[str] = field(default_factory=list)
    unified_diff: str | None = None
    changed_files: list[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=utcnow)
    source_migrated: bool = False
    reason: str | None = None
    suggested_migration_strategy: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)
    id: int | None = None

    def as_dict(self) -> dict:
        generated = self.generated_at
        if generated.tzinfo is None:
            generated = generated.replace(tzinfo=timezone.utc)
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "finding_id": self.finding_id,
            "source_file": self.source_file,
            "migration_id": self.migration_id,
            "current_algorithm": self.current_algorithm,
            "proposed_replacement": self.proposed_replacement,
            "migration_mode": self.migration_mode,
            "patch_status": self.patch_status,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "affected_files": list(self.affected_files),
            "affected_dependencies": list(self.affected_dependencies),
            "affected_protocols": list(self.affected_protocols),
            "affected_certificates": list(self.affected_certificates),
            "warnings": list(self.warnings),
            "validation_checklist": list(self.validation_checklist),
            "unified_diff": self.unified_diff,
            "changed_files": list(self.changed_files),
            "generated_at": generated.isoformat().replace("+00:00", "Z"),
            "source_migrated": False,
            "reason": self.reason or self.rationale,
            "suggested_migration_strategy": list(self.suggested_migration_strategy),
            "validation_errors": list(self.validation_errors),
        }
