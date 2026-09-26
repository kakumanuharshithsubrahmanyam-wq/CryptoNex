"""Grounded prompt construction from stored CryptoNex records."""

from __future__ import annotations

import json

from app.services.ai.provider import SYSTEM_INSTRUCTION
from app.services.ai.sanitize import artifact_brief, dependency_brief, finding_brief, sanitize_value
from app.services.migration.planner import list_plans
from app.services.pqc.agility import analyze_agility


def build_context_pack(snapshot, question: str | None = None, finding_ids: list[int] | None = None) -> dict:
    selected = snapshot.findings
    if finding_ids:
        allowed = set(finding_ids)
        selected = [row for row in snapshot.findings if row.id in allowed]
    plans = list_plans(snapshot)
    relevant_plans = [
        {
            "finding_id": item["finding_id"],
            "current_algorithm": item["current_algorithm"],
            "current_role": item["current_role"],
            "migration_priority": item["migration_priority"],
            "priority_reasons": item["priority_reasons"],
            "candidate_replacements": [entry["algorithm"] for entry in item["candidate_replacements"]],
            "unknowns": item["unknowns"],
        }
        for item in plans["items"]
        if not finding_ids or item["finding_id"] in set(finding_ids)
    ]
    artifacts = [brief for brief in (artifact_brief(item) for item in snapshot.artifacts) if brief is not None]
    pack = {
        "scan_id": snapshot.scan.id,
        "project_id": snapshot.project.id,
        "question": question,
        "findings": [finding_brief(row) for row in selected],
        "dependencies": [dependency_brief(row) for row in snapshot.dependencies],
        "artifacts": artifacts,
        "migration_summary": plans["summary"],
        "migration_plans": relevant_plans,
        "graph_summary": snapshot.graph.get("summary", {}),
        "crypto_agility": analyze_agility(snapshot)["classification"],
    }
    return sanitize_value(pack)


def build_grounded_messages(context: dict, question: str) -> list[dict]:
    user = (
        "Answer the question using only the CryptoNex JSON that follows. "
        "Cite finding ids, files, and dependencies that support the answer. "
        "If the JSON does not contain the fact, say it is unknown.\n\n"
        f"Question: {question}\n\n"
        f"CryptoNex scan data:\n{json.dumps(context, indent=2, sort_keys=True)}"
    )
    return [
        {"role": "system", "content": SYSTEM_INSTRUCTION},
        {"role": "user", "content": user},
    ]
