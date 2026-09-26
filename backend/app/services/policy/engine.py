"""Evaluate stored findings against a parsed policy. No repository code is executed."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models.project import Project
from app.models.scan import Scan
from app.services.intelligence.snapshot import load_snapshot
from app.services.migration.registry import canonical_algorithm
from app.services.policy.defaults import DEFAULT_POLICY_YAML
from app.services.policy.parser import PolicyRule, parse_policy

_POLICY_FILENAMES = ("cryptonex-policy.yml", "cryptonex-policy.yaml", ".cryptonex-policy.yml")


def evaluate_scan(session: Session, scan: Scan, policy_yaml: str | None = None) -> dict:
    snapshot = load_snapshot(session, scan)
    document, source = resolve_policy_text(snapshot.project, policy_yaml)
    rules = parse_policy(document)
    return evaluate_findings(snapshot.findings, rules, scan.id, source)


def evaluate_project(session: Session, project: Project, policy_yaml: str | None = None) -> dict:
    from sqlalchemy import select

    from app.models.scan import ScanStatus

    scan = session.scalar(
        select(Scan)
        .where(
            Scan.project_id == project.id,
            Scan.status == ScanStatus.COMPLETED.value,
            Scan.kind == "inventory",
        )
        .order_by(Scan.id.desc())
    )
    if scan is None:
        raise AppError("SCAN_NOT_FOUND", "No completed scan is available for this project.", status_code=404)
    return evaluate_scan(session, scan, policy_yaml)


def resolve_policy_text(project: Project, policy_yaml: str | None) -> tuple[str, str]:
    if policy_yaml and policy_yaml.strip():
        return policy_yaml, "request"
    workspace = project.workspace_path
    if workspace:
        root = Path(workspace)
        search = (root, root / "source")
        for directory in search:
            for name in _POLICY_FILENAMES:
                path = directory / name
                if path.is_file():
                    try:
                        return path.read_text(encoding="utf-8"), f"workspace:{name}"
                    except OSError as exc:
                        raise AppError("POLICY_INVALID", "Policy file could not be read.", status_code=400) from exc
    return DEFAULT_POLICY_YAML, "builtin"


def evaluate_findings(findings: list, rules: list[PolicyRule], scan_id: int, source: str) -> dict:
    violations: list[dict] = []
    for finding in findings:
        for rule in rules:
            if rule.action == "allow":
                continue
            if _matches(finding, rule):
                violations.append(
                    {
                        "finding_id": getattr(finding, "id", None),
                        "rule": rule.rule,
                        "action": rule.action,
                        "reason": _reason(finding, rule),
                        "file": getattr(finding, "file_path", None),
                        "line": getattr(finding, "line_start", None),
                        "algorithm": getattr(finding, "algorithm", None),
                    }
                )
    failures = [item for item in violations if item["action"] == "fail"]
    warnings = [item for item in violations if item["action"] == "warn"]
    if failures:
        status = "fail"
    elif warnings:
        status = "warn"
    else:
        status = "pass"
    return {
        "scan_id": scan_id,
        "status": status,
        "ci_exit_code": 1 if status == "fail" else 0,
        "policy_source": source,
        "violations": violations,
        "summary": {
            "passed": status == "pass",
            "warnings": len(warnings),
            "failures": len(failures),
        },
    }


def _matches(finding, rule: PolicyRule) -> bool:
    algorithm = canonical_algorithm(getattr(finding, "algorithm", None))
    if rule.algorithm:
        expected, required_size = _rule_algorithm(rule.algorithm)
        if algorithm != expected:
            return False
        if required_size is not None and getattr(finding, "key_size", None) not in {None, required_size}:
            return False
    if rule.security_concern and getattr(finding, "security_concern", None) != rule.security_concern:
        return False
    if rule.usage and getattr(finding, "usage", None) != rule.usage:
        return False
    key_size = getattr(finding, "key_size", None)
    if rule.max_key_size is not None:
        if key_size is None or key_size >= rule.max_key_size:
            return False
    if rule.min_key_size is not None:
        if key_size is None or key_size >= rule.min_key_size:
            return False
    return True


def _reason(finding, rule: PolicyRule) -> str:
    algorithm = getattr(finding, "algorithm", None) or "unknown algorithm"
    if rule.max_key_size is not None:
        return f"{algorithm} key size {getattr(finding, 'key_size', None)} is below {rule.max_key_size} ({rule.rule})"
    if rule.security_concern:
        return f"{algorithm} matches {rule.security_concern} ({rule.rule})"
    return f"{algorithm} matched {rule.rule} with action {rule.action}"


def _rule_algorithm(token: str) -> tuple[str, int | None]:
    import re

    match = re.fullmatch(r"(AES|RSA)-(\d{3,4})", token.strip(), flags=re.IGNORECASE)
    if match:
        return match.group(1).upper(), int(match.group(2))
    return (canonical_algorithm(token) or token.strip()), None
