"""Repository Q&A over relevant stored findings, not the full repository."""

from __future__ import annotations

import re

from app.core.config import Settings
from app.services.ai.architect import architect_answer
from app.services.ai.prompts import build_context_pack
from app.services.ai.provider import AIProvider
from app.services.ai.root_cause import explain_root_causes
from app.services.migration.planner import list_plans
from app.services.migration.registry import canonical_algorithm

_TOPIC_TERMS = {
    "rsa",
    "ecdsa",
    "ecdh",
    "ed25519",
    "dsa",
    "aes",
    "sha",
    "md5",
    "tls",
    "ssh",
    "certificate",
    "protocol",
    "cipher",
    "depend",
    "migrat",
    "hybrid",
    "pqc",
    "priority",
    "posture",
    "agility",
    "blast",
    "root",
    "quantum",
}


def ask(
    snapshot,
    settings: Settings,
    question: str,
    provider: AIProvider | None = None,
) -> dict:
    cleaned = question.strip()
    relevant_ids = _relevant_finding_ids(snapshot, cleaned)
    if not relevant_ids and not _looks_supported(cleaned):
        return {
            "scan_id": snapshot.scan.id,
            "question": cleaned,
            "answer": "The supplied CryptoNex scan data does not contain enough evidence to answer this question.",
            "source": "deterministic_fallback",
            "provider_available": bool((settings.openai_api_key or "").strip()),
            "supporting_findings": [],
            "supporting_files": [],
            "supporting_dependencies": [],
            "caveats": ["The question did not match stored findings, dependencies, or supported analysis topics."],
        }
    result = architect_answer(snapshot, settings, cleaned, provider=provider)
    if relevant_ids:
        context = build_context_pack(snapshot, cleaned, finding_ids=relevant_ids)
        result["grounded_context"] = context
        result["supporting_findings"] = relevant_ids
        selected = [row for row in snapshot.findings if row.id in set(relevant_ids)]
        result["supporting_files"] = sorted({row.file_path for row in selected if row.file_path})
        names = {canonical_algorithm(row.algorithm) for row in selected if row.algorithm}
        result["supporting_dependencies"] = sorted(
            {
                row.name
                for row in snapshot.dependencies
                if row.name.lower() in cleaned.lower()
                or (row.library and any(name and name.lower() in (row.library or "").lower() for name in names))
                or row.crypto_relevance in {"cryptographic_library", "crypto_related"}
            }
        )
        if result["source"] == "deterministic_fallback":
            result["answer"] = _fallback_answer(snapshot, cleaned, selected)
    return result


def _relevant_finding_ids(snapshot, question: str) -> list[int]:
    tokens = set(re.findall(r"[a-z0-9+.-]+", question.lower()))
    selected: list[int] = []
    for finding in snapshot.findings:
        haystack = " ".join(
            str(value)
            for value in (
                finding.algorithm,
                finding.usage,
                finding.library,
                finding.file_path,
                finding.cryptographic_role,
                finding.security_concern,
            )
            if value
        ).lower()
        if any(token in haystack for token in tokens if len(token) >= 3):
            selected.append(finding.id)
    if selected:
        return selected
    if any(term in question.lower() for term in ("posture", "priority", "migrat", "first", "summar")):
        plans = list_plans(snapshot)
        ordered = sorted(
            plans["items"],
            key=lambda item: ("critical", "high", "medium", "low", "informational").index(item["migration_priority"]),
        )
        return [item["finding_id"] for item in ordered[:8]]
    return []


def _looks_supported(question: str) -> bool:
    lowered = question.lower()
    return any(term in lowered for term in _TOPIC_TERMS)


def _fallback_answer(snapshot, question: str, findings: list) -> str:
    if "root" in question.lower():
        causes = explain_root_causes(snapshot)
        relevant = [item for item in causes if item["finding_id"] in {row.id for row in findings}]
        if not relevant:
            return "Root cause cannot be determined from static repository evidence."
        return " ".join(f"Finding {item['finding_id']}: {item['root_cause']}" for item in relevant)
    algorithms = sorted({row.algorithm for row in findings if row.algorithm})
    files = sorted({row.file_path for row in findings if row.file_path})
    deps = sorted({row.name for row in snapshot.dependencies})
    parts = [
        f"Stored evidence mentions {', '.join(algorithms) or 'no named algorithm'} in {', '.join(files) or 'no file'}.",
        f"Declared dependencies include {', '.join(deps) or 'none'}.",
    ]
    if "hybrid" in question.lower():
        parts.append("A hybrid path is classical plus a role-appropriate PQC candidate, then PQC-only after validation. This is a plan, not a completed migration.")
    return " ".join(parts)
