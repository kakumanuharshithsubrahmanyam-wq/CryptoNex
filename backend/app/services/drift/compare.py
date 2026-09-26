"""Deterministic drift detection between two stored scans."""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.intelligence.snapshot import ScanSnapshot, load_snapshot
from app.services.policy.defaults import DEFAULT_POLICY_YAML
from app.services.policy.engine import evaluate_findings
from app.services.policy.parser import parse_policy


def project_drift(session: Session, project: Project, from_scan_id: int | None, to_scan_id: int | None) -> dict:
    left, right = _resolve_scans(session, project, from_scan_id, to_scan_id)
    if left is None:
        right_snapshot = load_snapshot(session, right)
        return {
            "project_id": project.id,
            "from_scan_id": None,
            "to_scan_id": right.id,
            "added": _empty_bucket(),
            "removed": _empty_bucket(),
            "changed": {"key_sizes": [], "protocols": [], "cipher_suites": [], "findings": []},
            "unchanged": _counts(_inventory(right_snapshot)),
            "notes": ["Fewer than two completed scans are available for comparison."],
        }
    return compare_snapshots(load_snapshot(session, left), load_snapshot(session, right))


def compare_snapshots(before: ScanSnapshot, after: ScanSnapshot) -> dict:
    left = _inventory(before)
    right = _inventory(after)
    added = {key: _present_only(right[key], left[key]) for key in left}
    removed = {key: _present_only(left[key], right[key]) for key in left}
    changed = {
        "key_sizes": _changed_key_sizes(before, after),
        "protocols": _changed_by_key(left["protocols"], right["protocols"], "identity"),
        "cipher_suites": [],
        "findings": _changed_findings(before, after),
    }
    unchanged = {
        key: len(set(left[key]) & set(right[key])) if key != "key_sizes" else len(_shared_algorithms(before, after))
        for key in left
    }
    return {
        "project_id": after.project.id,
        "from_scan_id": before.scan.id,
        "to_scan_id": after.scan.id,
        "added": {key: sorted(added[key]) for key in sorted(added)},
        "removed": {key: sorted(removed[key]) for key in sorted(removed)},
        "changed": changed,
        "unchanged": unchanged,
        "notes": ["Comparison uses stable identities, not timestamps."],
    }


def _resolve_scans(
    session: Session, project: Project, from_scan_id: int | None, to_scan_id: int | None
) -> tuple[Scan | None, Scan]:
    completed = list(
        session.scalars(
            select(Scan)
            .where(Scan.project_id == project.id, Scan.status == ScanStatus.COMPLETED.value)
            .order_by(Scan.id)
        )
    )
    if not completed:
        raise AppError("SCAN_NOT_FOUND", "No completed scan is available for this project.", status_code=404)
    if from_scan_id is None and to_scan_id is None:
        if len(completed) == 1:
            return None, completed[0]
        return completed[-2], completed[-1]
    by_id = {scan.id: scan for scan in completed}
    right = by_id.get(to_scan_id) if to_scan_id is not None else completed[-1]
    left = by_id.get(from_scan_id) if from_scan_id is not None else (completed[-2] if len(completed) > 1 else None)
    if right is None:
        raise AppError("SCAN_NOT_FOUND", "Scan not found.", status_code=404)
    if from_scan_id is not None and left is None:
        raise AppError("SCAN_NOT_FOUND", "Scan not found.", status_code=404)
    return left, right


def _inventory(snapshot: ScanSnapshot) -> dict[str, list[str]]:
    algorithms = sorted(
        {
            row.algorithm
            for row in snapshot.findings
            if row.algorithm and row.usage != "dependency_only"
        }
    )
    dependencies = sorted({_dependency_identity(row) for row in snapshot.dependencies})
    certificates = sorted(
        {_certificate_identity(row) for row in snapshot.artifacts if row.artifact_type == "certificate"}
    )
    protocols = sorted(
        {_protocol_identity(row) for row in snapshot.artifacts if row.artifact_type in {"protocol", "ssh_config"}}
    )
    suites = sorted({row.cipher_suite for row in snapshot.artifacts if row.cipher_suite})
    violations = sorted({item["rule"] + "|" + (item["reason"] or "") for item in _policy_violations(snapshot)})
    key_sizes = sorted(
        {
            f"{row.algorithm}:{row.key_size}"
            for row in snapshot.findings
            if row.algorithm and row.key_size is not None
        }
    )
    return {
        "algorithms": algorithms,
        "dependencies": dependencies,
        "certificates": certificates,
        "protocols": protocols,
        "cipher_suites": suites,
        "policy_violations": violations,
        "key_sizes": key_sizes,
    }


def _policy_violations(snapshot: ScanSnapshot) -> list[dict]:
    return evaluate_findings(snapshot.findings, parse_policy(DEFAULT_POLICY_YAML), snapshot.scan.id, "builtin")["violations"]


def _finding_identity(finding) -> str:
    return "|".join(
        [
            finding.file_path or "",
            str(finding.line_start or ""),
            finding.algorithm or "",
            finding.usage or "",
            finding.library or "",
            str(finding.key_size or ""),
            finding.curve or "",
            finding.mode or "",
        ]
    )


def _stable_finding_key(finding) -> str:
    return "|".join(
        [
            finding.file_path or "",
            finding.algorithm or "",
            finding.usage or "",
            finding.library or "",
        ]
    )


def _dependency_identity(dependency) -> str:
    return "|".join(
        [
            dependency.name,
            dependency.ecosystem,
            dependency.version or "",
            dependency.version_constraint or "",
            dependency.direct_or_transitive,
        ]
    )


def _certificate_identity(artifact) -> str:
    return "|".join(
        [
            artifact.file_path or "",
            artifact.algorithm or "",
            str(artifact.key_size or ""),
            artifact.subject or "",
            artifact.serial_number or "",
        ]
    )


def _protocol_identity(artifact) -> str:
    meta = {}
    try:
        loaded = json.loads(artifact.metadata_json or "{}")
        if isinstance(loaded, dict):
            meta = loaded
    except ValueError:
        meta = {}
    return "|".join(
        [
            artifact.protocol or "",
            str(meta.get("tls_version") or ""),
            artifact.file_path or "",
            artifact.cipher_suite or "",
        ]
    )


def _present_only(right: list[str], left: list[str]) -> list[str]:
    return [item for item in right if item not in set(left)]


def _changed_key_sizes(before: ScanSnapshot, after: ScanSnapshot) -> list[dict]:
    previous = _algorithm_key_sizes(before)
    current = _algorithm_key_sizes(after)
    changed = []
    for algorithm in sorted(set(previous) & set(current)):
        if previous[algorithm] != current[algorithm]:
            changed.append({"algorithm": algorithm, "from": sorted(previous[algorithm]), "to": sorted(current[algorithm])})
    return changed


def _algorithm_key_sizes(snapshot: ScanSnapshot) -> dict[str, set[int]]:
    sizes: dict[str, set[int]] = {}
    for row in snapshot.findings:
        if row.algorithm and row.key_size is not None:
            sizes.setdefault(row.algorithm, set()).add(row.key_size)
    return sizes


def _changed_findings(before: ScanSnapshot, after: ScanSnapshot) -> list[dict]:
    previous = {_stable_finding_key(row): row for row in before.findings}
    current = {_stable_finding_key(row): row for row in after.findings}
    changed = []
    for key in sorted(set(previous) & set(current)):
        left = previous[key]
        right = current[key]
        if (left.key_size, left.curve, left.mode, left.library) != (right.key_size, right.curve, right.mode, right.library):
            changed.append(
                {
                    "identity": key,
                    "from": {"key_size": left.key_size, "curve": left.curve, "mode": left.mode},
                    "to": {"key_size": right.key_size, "curve": right.curve, "mode": right.mode},
                }
            )
    return changed


def _changed_by_key(left: list[str], right: list[str], _field: str) -> list[str]:
    return []


def _shared_algorithms(before: ScanSnapshot, after: ScanSnapshot) -> set[str]:
    return {row.algorithm for row in before.findings if row.algorithm} & {
        row.algorithm for row in after.findings if row.algorithm
    }


def _empty_bucket() -> dict:
    return {
        "algorithms": [],
        "dependencies": [],
        "certificates": [],
        "protocols": [],
        "cipher_suites": [],
        "policy_violations": [],
        "key_sizes": [],
    }


def _counts(inventory: dict[str, list[str]]) -> dict[str, int]:
    return {key: len(value) for key, value in inventory.items()}
