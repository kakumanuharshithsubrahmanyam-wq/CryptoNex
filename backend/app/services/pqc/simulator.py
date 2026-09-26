"""Hybrid and what-if migration simulation. Planning only; source is not changed."""

from __future__ import annotations

from app.core.exceptions import AppError
from app.services.migration.blast_radius import blast_radius
from app.services.migration.planner import plan_finding
from app.services.migration.registry import advise, infer_role
from app.services.pqc.registry import get_pqc, pqc_as_dict

VALID_MODES = frozenset({"classical", "hybrid", "pqc"})


def hybrid_plan(snapshot, finding, replacement: str | None = None) -> dict:
    advice = advise(finding)
    chosen = replacement or _default_replacement(advice)
    spec = get_pqc(chosen) if chosen else None
    radius = blast_radius(snapshot.graph, finding.id, finding)
    option = None
    if spec is not None and spec.hybrid_suitable and advice.replaceable:
        option = {
            "mode": "hybrid",
            "classical": advice.algorithm,
            "pqc": spec.name,
            "description": f"{advice.algorithm} + {spec.name} hybrid {spec.role}",
            "path": ["classical", "hybrid", "pqc"],
        }
    return {
        "finding_id": finding.id,
        "current_primitive": advice.algorithm,
        "current_role": infer_role(finding),
        "pqc_candidate": pqc_as_dict(spec) if spec else None,
        "hybrid_option": option,
        "affected_components": {
            "files": [item["label"] for item in radius["affected_files"]],
            "dependencies": [item["label"] for item in radius["affected_dependencies"]],
            "protocols": [item["label"] for item in radius["affected_protocols"]],
            "certificates": [item["label"] for item in radius["affected_certificates"]],
        },
        "migration_considerations": _considerations(advice, "hybrid", spec),
        "interoperability_considerations": [
            "Peers must accept both the classical and PQC components during a hybrid period.",
            "CryptoNex does not claim production cryptographic interoperability.",
        ],
        "unknowns": [
            "Runtime negotiation behavior is not observed from a static repository scan.",
            "Library support for hybrid modes is not verified.",
        ],
        "warnings": [
            "This is an architecture plan. No source was migrated.",
            "Do not treat the hybrid option as a deployed configuration.",
        ],
    }


def what_if(snapshot, finding_id: int, replacement: str, mode: str) -> dict:
    if mode not in VALID_MODES:
        raise AppError("INVALID_WHAT_IF", "mode must be classical, hybrid, or pqc.", status_code=400)
    finding = snapshot.finding(finding_id)
    advice = advise(finding)
    spec = get_pqc(replacement)
    plan = plan_finding(snapshot, finding, selected_replacement=replacement)
    radius = blast_radius(snapshot.graph, finding.id, finding)
    warnings = list(plan["warnings"])
    if spec is None:
        warnings.append(f"{replacement} is not a registered PQC planning candidate.")
    elif spec.role != advice.role and advice.role != "unknown" and advice.replaceable:
        warnings.append(
            f"{replacement} is intended for {spec.role}; this finding is classified as {advice.role}."
        )
    if advice.category in {"modern_symmetric", "modern_hash", "mac"}:
        warnings.append("Do not blindly replace modern symmetric or hash primitives with PQC algorithms.")
    if mode == "hybrid" and spec is not None and not spec.hybrid_suitable:
        warnings.append(f"{replacement} is not marked hybrid-suitable in the PQC registry.")
    warnings.append("CryptoNex has not migrated source code.")
    return {
        "scan_id": snapshot.scan.id,
        "finding_id": finding.id,
        "current_algorithm": plan["current_algorithm"],
        "proposed_replacement": replacement,
        "migration_mode": mode,
        "affected_files": plan["affected_files"],
        "affected_dependencies": plan["affected_dependencies"],
        "affected_protocols": plan["affected_protocols"],
        "affected_certificates": plan["affected_certificates"],
        "related_findings": radius["related_findings"],
        "estimated_migration_complexity": estimate_complexity(advice, radius, mode),
        "compatibility_considerations": _considerations(advice, mode, spec),
        "validation_checklist": plan["validation_steps"],
        "hybrid_option": hybrid_plan(snapshot, finding, replacement)["hybrid_option"] if mode == "hybrid" else None,
        "warnings": warnings,
        "source_migrated": False,
    }


def estimate_complexity(advice, radius: dict, mode: str) -> str:
    if advice.category in {"modern_symmetric", "modern_hash", "mac"}:
        return "low"
    if advice.role == "unknown" or advice.algorithm == "unknown":
        return "unknown"
    files = len(radius.get("affected_files") or [])
    protocols = len(radius.get("affected_protocols") or [])
    certificates = len(radius.get("affected_certificates") or [])
    related = len(radius.get("related_findings") or [])
    if protocols or certificates or files >= 4 or related >= 3 or mode == "hybrid":
        return "high"
    if files >= 2 or related or mode == "pqc":
        return "medium"
    return "medium"


def _default_replacement(advice) -> str | None:
    if advice.candidates:
        return advice.candidates[0].algorithm
    return None


def _considerations(advice, mode: str, spec) -> list[str]:
    considerations = [
        f"Current primitive: {advice.algorithm} in role {advice.role}.",
        f"Requested mode follows the conceptual path classical → hybrid → PQC; this request uses {mode}.",
    ]
    if spec is not None:
        considerations.append(f"{spec.name} is a planning candidate for {spec.role}.")
    considerations.append("Interoperability with unmodified peers is unknown.")
    considerations.append("Performance and packet-size impact are not measured by CryptoNex.")
    return considerations
