"""AI Crypto Architect over grounded scan data, with a deterministic fallback."""

from __future__ import annotations

from app.core.config import Settings
from app.services.ai.prompts import build_context_pack, build_grounded_messages
from app.services.ai.provider import AIProvider, provider_from_settings
from app.services.ai.root_cause import explain_root_causes
from app.services.migration.planner import list_plans


def architect_answer(
    snapshot,
    settings: Settings,
    question: str | None = None,
    provider: AIProvider | None = None,
) -> dict:
    asked = (question or "Summarize the cryptographic posture of this repository.").strip()
    context = build_context_pack(snapshot, asked)
    messages = build_grounded_messages(context, asked)
    client = provider or provider_from_settings(settings)
    source = "deterministic_fallback"
    answer = _fallback_architect(snapshot, asked)
    if client.available:
        try:
            answer = client.complete(messages)
            source = "ai"
        except RuntimeError:
            source = "deterministic_fallback"
    return {
        "scan_id": snapshot.scan.id,
        "question": asked,
        "answer": answer,
        "source": source,
        "provider_available": client.available,
        "supporting_findings": [row.id for row in snapshot.findings],
        "supporting_files": sorted({row.file_path for row in snapshot.findings if row.file_path}),
        "supporting_dependencies": sorted({row.name for row in snapshot.dependencies}),
        "caveats": [
            "The deterministic CryptoNex engine remains the source of truth.",
            "The answer must not be treated as proof that a system is quantum-safe.",
            "No migration has occurred unless a stored record says so.",
        ],
        "grounded_context": context,
    }


def _fallback_architect(snapshot, question: str) -> str:
    plans = list_plans(snapshot)
    causes = explain_root_causes(snapshot)
    high = [item for item in plans["items"] if item["migration_priority"] in {"critical", "high"}]
    algorithms = sorted({item["current_algorithm"] for item in plans["items"] if item["current_algorithm"]})
    lines = [
        "Deterministic CryptoNex summary (AI provider unavailable or failed).",
        f"Observed algorithms: {', '.join(algorithms) if algorithms else 'none'}.",
        (
            "Highest-priority migration concerns: "
            + (
                ", ".join(
                    f"finding {item['finding_id']} ({item['current_algorithm']} / {item['current_role']} / {item['migration_priority']})"
                    for item in high
                )
                or "none at critical or high priority"
            )
            + "."
        ),
        f"Dependencies observed: {', '.join(sorted({row.name for row in snapshot.dependencies}) or ['none'])}.",
        f"Certificates observed: {sum(1 for row in snapshot.artifacts if row.artifact_type == 'certificate')}.",
        f"Question received: {question}",
    ]
    determined = [item for item in causes if item["determined"]]
    if determined:
        lines.append(
            "Root-cause hypotheses with supporting evidence: "
            + "; ".join(f"finding {item['finding_id']}: {item['root_cause']}" for item in determined)
            + "."
        )
    lines.append("Facts above come only from stored findings, dependencies, and artifacts. Recommendations are planning guidance, not completed migrations.")
    return " ".join(lines)
