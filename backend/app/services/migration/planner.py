"""Build a per-finding migration plan from stored records. No source is changed."""

from __future__ import annotations

from app.services.migration.blast_radius import blast_radius
from app.services.migration.priority import prioritize
from app.services.migration.registry import (
    KEY_ESTABLISHMENT_ROLE,
    SIGNATURE_ROLE,
    UNKNOWN_ROLE,
    advise,
    candidate_dicts,
    current_parameters,
    infer_role,
)
from app.services.pqc.registry import get_pqc

_SIGNATURE_STEPS = (
    "identify signature and verification APIs",
    "introduce a compatible cryptographic abstraction",
    "evaluate hybrid classical/PQC signatures if interoperability is required",
    "update signing configuration and key material handling",
    "update certificates if applicable",
    "test interoperability of sign and verify paths",
    "validate performance",
    "remove the legacy dependency only after validation",
)
_KEX_STEPS = (
    "identify key establishment API",
    "introduce compatible abstraction",
    "evaluate hybrid classical/PQC mode",
    "update key exchange configuration",
    "update certificates/protocol configuration if applicable",
    "test interoperability",
    "validate performance",
    "remove legacy dependency only after validation",
)
_SYMMETRIC_STEPS = (
    "confirm current parameters meet modern guidance",
    "do not replace the primitive solely because it is not a post-quantum public-key algorithm",
    "review key size and mode when they are present",
    "retain the primitive unless a separate weakness is observed",
)
_LEGACY_STEPS = (
    "identify every call site of the legacy primitive",
    "replace it with a modern classical counterpart first",
    "re-scan after the classical replacement before considering PQC public-key work",
)
_UNKNOWN_STEPS = (
    "confirm the cryptographic role from additional evidence",
    "do not select a single PQC candidate until the role is known",
    "re-evaluate candidates after the role is identified",
)
_VALIDATION_STEPS = (
    "compare observed findings against this plan; the plan does not modify source",
    "test interoperability with current peers before removing classical primitives",
    "validate performance and failure handling",
    "confirm certificates and protocol configuration after any planned change",
)


def plan_finding(snapshot, finding, selected_replacement: str | None = None) -> dict:
    advice = advise(finding)
    priority, reasons = prioritize(finding, snapshot.artifacts)
    radius = blast_radius(snapshot.graph, finding.id, finding)
    parameters = current_parameters(finding)
    unknowns = _unknowns(finding, advice, radius)
    warnings = list(advice.warnings)
    candidates = candidate_dicts(advice)
    if selected_replacement:
        candidates, extra_warnings = _select_candidate(advice, selected_replacement)
        warnings.extend(extra_warnings)
    return {
        "finding_id": finding.id,
        "current_algorithm": advice.algorithm if advice.algorithm != "unknown" else getattr(finding, "algorithm", None),
        "current_usage": getattr(finding, "usage", None),
        "current_library": getattr(finding, "library", None),
        "current_parameters": parameters,
        "current_role": infer_role(finding),
        "migration_priority": priority,
        "priority_reasons": reasons,
        "candidate_replacements": candidates,
        "affected_files": [item["label"] for item in radius["affected_files"]],
        "affected_dependencies": [item["label"] for item in radius["affected_dependencies"]],
        "affected_protocols": [item["label"] for item in radius["affected_protocols"]],
        "affected_certificates": [item["label"] for item in radius["affected_certificates"]],
        "migration_steps": list(_steps(advice)),
        "validation_steps": list(_VALIDATION_STEPS),
        "unknowns": unknowns,
        "warnings": warnings,
        "migration_occurred": False,
    }


def list_plans(snapshot) -> dict:
    items = [plan_finding(snapshot, finding) for finding in snapshot.findings]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for item in items:
        counts[item["migration_priority"]] = counts.get(item["migration_priority"], 0) + 1
    return {
        "scan_id": snapshot.scan.id,
        "project_id": snapshot.project.id,
        "items": items,
        "summary": counts,
    }


def _steps(advice) -> tuple[str, ...]:
    if advice.category in {"modern_symmetric", "modern_hash", "mac", "key_derivation"}:
        return _SYMMETRIC_STEPS
    if advice.category == "legacy":
        return _LEGACY_STEPS
    if advice.role == SIGNATURE_ROLE:
        return _SIGNATURE_STEPS
    if advice.role == KEY_ESTABLISHMENT_ROLE:
        return _KEX_STEPS
    if advice.role == UNKNOWN_ROLE and advice.replaceable:
        return _UNKNOWN_STEPS + _KEX_STEPS[:1] + _SIGNATURE_STEPS[:1]
    return _UNKNOWN_STEPS


def _unknowns(finding, advice, radius: dict) -> list[str]:
    unknowns: list[str] = []
    if not getattr(finding, "algorithm", None):
        unknowns.append("algorithm is unknown")
    if infer_role(finding) == UNKNOWN_ROLE:
        unknowns.append("cryptographic role is unknown")
    if getattr(finding, "parameter_completeness", None) in {None, "unknown", "partial"}:
        if not current_parameters(finding):
            unknowns.append("algorithm parameters are unknown")
    if not radius["affected_dependencies"]:
        unknowns.append("no linked dependency was observed")
    if not radius["affected_protocols"]:
        unknowns.append("protocol impact is unknown from stored artifacts")
    if not radius["affected_certificates"]:
        unknowns.append("certificate impact is unknown from stored artifacts")
    if advice.category in {"modern_symmetric", "modern_hash"}:
        unknowns.append("symmetric/hash migration need cannot be inferred from public-key PQC mapping")
    return unknowns


def _select_candidate(advice, replacement: str) -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    spec = get_pqc(replacement)
    names = {item.algorithm for item in advice.candidates}
    if spec is None:
        warnings.append(f"{replacement} is not in the CryptoNex PQC registry.")
        return candidate_dicts(advice), warnings
    if replacement not in names:
        warnings.append(
            f"{replacement} is not a role-appropriate candidate for {advice.algorithm} used as {advice.role}."
        )
    selected = [item for item in candidate_dicts(advice) if item["algorithm"] == replacement]
    if not selected:
        selected = [
            {
                "algorithm": spec.name,
                "role": spec.role,
                "family": spec.family,
                "purpose": spec.purpose,
                "hybrid_suitable": spec.hybrid_suitable,
                "notes": spec.notes,
                "selected": True,
            }
        ]
    else:
        selected[0]["selected"] = True
    return selected, warnings
