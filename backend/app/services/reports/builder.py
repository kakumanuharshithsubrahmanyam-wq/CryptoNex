"""Deterministic security report over stored findings, CBOM, policy, and plans."""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.schemas.scan import LanguageComposition, ScanSummary
from app.services.cbom.queries import get_cbom, inventory
from app.services.intelligence.snapshot import load_snapshot
from app.services.migration.planner import list_plans
from app.services.policy.engine import evaluate_scan
from app.services.pqc.agility import analyze_agility

_LIMITATIONS = (
    "This report is assembled from stored static-analysis records only.",
    "CryptoNex does not claim the application is quantum-safe or quantum-vulnerable as a whole.",
    "Migration plans are recommendations. No source was migrated.",
    "AI interpretations, if present, are not the source of truth.",
    "Runtime behavior, deployed certificates, and peer interoperability are unknown.",
)


def build_report(session: Session, scan: Scan) -> dict:
    snapshot = load_snapshot(session, scan)
    plans = list_plans(snapshot)
    policy = evaluate_scan(session, scan)
    inventory_doc = inventory(session, scan)
    cbom_doc = get_cbom(session, scan)
    agility = analyze_agility(snapshot)
    high = [item for item in plans["items"] if item["migration_priority"] in {"critical", "high"}]
    top_actions = []
    for item in high[:8]:
        candidate = item["candidate_replacements"][0]["algorithm"] if item["candidate_replacements"] else None
        top_actions.append(
            {
                "finding_id": item["finding_id"],
                "algorithm": item["current_algorithm"],
                "priority": item["migration_priority"],
                "action": (
                    f"Plan a {item['current_role']} migration of {item['current_algorithm']}"
                    + (f" toward {candidate}" if candidate else "")
                ),
            }
        )
    certificates = sum(1 for row in snapshot.artifacts if row.artifact_type == "certificate")
    protocol_counts = {}
    for row in snapshot.artifacts:
        if row.artifact_type in {"protocol", "ssh_config"} and row.protocol:
            protocol_counts[row.protocol] = protocol_counts.get(row.protocol, 0) + 1
    blast = {
        "findings": len(snapshot.findings),
        "files": len({row.file_path for row in snapshot.findings}),
        "dependencies": len(snapshot.dependencies),
        "certificates": certificates,
        "protocols": sum(protocol_counts.values()),
    }
    executive = _executive_summary(snapshot, plans, policy, certificates)
    return {
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "executive_summary": executive,
        "finding_counts": {
            "total": len(snapshot.findings),
            "by_priority": plans["summary"],
            "by_algorithm": inventory_doc.algorithms,
        },
        "dependency_counts": {
            "total": len(snapshot.dependencies),
            "crypto_related": sum(
                1
                for row in snapshot.dependencies
                if row.crypto_relevance in {"cryptographic_library", "crypto_related"}
            ),
        },
        "certificate_counts": certificates,
        "protocol_counts": {name: protocol_counts[name] for name in sorted(protocol_counts)},
        "migration_priorities": plans["summary"],
        "blast_radius_summary": blast,
        "policy_status": {
            "status": policy["status"],
            "warnings": policy["summary"]["warnings"],
            "failures": policy["summary"]["failures"],
            "ci_exit_code": policy["ci_exit_code"],
        },
        "cbom_summary": cbom_doc.summary if hasattr(cbom_doc, "summary") else {},
        "crypto_agility": agility["classification"],
        "language_composition": _language_composition(scan),
        "top_migration_actions": top_actions,
        "limitations": list(_LIMITATIONS),
    }


def export_report(session: Session, scan: Scan, fmt: str) -> tuple[bytes, str, str]:
    document = build_report(session, scan)
    if fmt == "markdown":
        return render_markdown(document).encode("utf-8"), "text/markdown", f"cryptonex-report-{scan.id}.md"
    payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
    return payload, "application/json", f"cryptonex-report-{scan.id}.json"


def render_markdown(document: dict) -> str:
    lines = [
        f"# CryptoNex security report (scan {document['scan_id']})",
        "",
        document["executive_summary"],
        "",
        "## Counts",
        f"- Findings: {document['finding_counts']['total']}",
        f"- Dependencies: {document['dependency_counts']['total']}",
        f"- Certificates: {document['certificate_counts']}",
        f"- Policy status: {document['policy_status']['status']}",
        "",
        "## Repository Languages",
    ]
    composition = document.get("language_composition") or {}
    shares = composition.get("languages") or []
    if not shares:
        lines.append("- No recognized source files.")
    else:
        lines.append(
            f"- Source files: {composition.get('total_source_files', 0)}; "
            f"source lines: {composition.get('total_source_lines', 0)}"
        )
        for item in shares:
            lines.append(
                f"- {item['language']:<12} {item['percentage']:.1f}%  "
                f"({item['file_count']} files, {item['total_lines']} lines)"
            )
        lines.append("- Language share is repository composition, not a security score.")
    lines.extend(["", "## Migration priorities"])
    for name, count in document["migration_priorities"].items():
        lines.append(f"- {name}: {count}")
    lines.extend(["", "## Top migration actions"])
    if not document["top_migration_actions"]:
        lines.append("- None at critical or high priority.")
    for item in document["top_migration_actions"]:
        lines.append(f"- Finding {item['finding_id']}: {item['action']}")
    lines.extend(["", "## Limitations"])
    for item in document["limitations"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def _language_composition(scan: Scan) -> dict:
    if not scan.summary_json:
        return LanguageComposition().model_dump()
    summary = ScanSummary.model_validate_json(scan.summary_json)
    return summary.language_composition.model_dump()


def _executive_summary(snapshot, plans, policy, certificates: int) -> str:
    high = plans["summary"].get("critical", 0) + plans["summary"].get("high", 0)
    return (
        f"Scan {snapshot.scan.id} recorded {len(snapshot.findings)} cryptographic finding(s), "
        f"{len(snapshot.dependencies)} dependency(ies), and {certificates} certificate(s). "
        f"{high} finding(s) are critical or high migration priority. "
        f"Policy status is {policy['status']}. "
        "This summary is derived from stored records and does not invent findings."
    )
