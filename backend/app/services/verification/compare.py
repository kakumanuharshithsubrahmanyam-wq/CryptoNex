"""Deterministic before/after comparison for an isolated verification scan."""

from __future__ import annotations

import json

from app.services.migration.registry import LEGACY_CIPHER, LEGACY_HASH, canonical_algorithm
from app.services.policy.engine import evaluate_findings
from app.services.policy.parser import parse_policy

_LEGACY = LEGACY_HASH | LEGACY_CIPHER


def compare_verification(
    before,
    after,
    *,
    target,
    replacement: str | None,
    source_file: str,
    rules,
) -> dict:
    before_findings = list(before.findings)
    after_findings = list(after.findings)
    before_keys = {_finding_key(item): item for item in before_findings}
    after_keys = {_finding_key(item): item for item in after_findings}
    original_present = _matches_target(after_findings, target)
    replacement_name = canonical_algorithm(replacement)
    replacement_present = _replacement_present(after_findings, source_file, replacement_name)
    role_match = _same_role_replacement(after_findings, source_file, target, replacement_name)

    new_items = [_brief(after_keys[key]) for key in sorted(set(after_keys) - set(before_keys))]
    removed_items = [_brief(before_keys[key]) for key in sorted(set(before_keys) - set(after_keys))]
    changed_items = _changed(before_keys, after_keys)

    allowed_new = _allowed_new_findings(new_items, source_file, replacement_name, original_present)
    regressions: list[dict] = []
    for item in new_items:
        if item.get("usage") == "dependency_only":
            continue
        identity = _finding_key_parts(item.get("file"), item.get("algorithm"), item.get("usage"), item.get("library"))
        if identity in allowed_new:
            continue
        algorithm = item.get("algorithm")
        kind = "new_legacy_crypto" if algorithm in _LEGACY else "new_crypto_finding"
        regressions.append({**item, "type": kind})
    for item in removed_items:
        if _is_target_brief(item, target):
            continue
        regressions.append({**item, "type": "unrelated_finding_removed"})

    policy_before = _policy(before_findings, rules, before.scan.id)
    policy_after = _policy(after_findings, rules, after.scan.id)
    policy_change = _count_change(
        policy_before["summary"]["failures"],
        policy_after["summary"]["failures"],
    )
    before_failures = {_violation_key(item) for item in policy_before["violations"] if item["action"] == "fail"}
    after_failures = {_violation_key(item) for item in policy_after["violations"] if item["action"] == "fail"}
    for key in sorted(after_failures - before_failures):
        rule, file_path, algorithm = key.split("|", 2)
        if algorithm == (target.algorithm or "") and file_path == (target.file_path or ""):
            continue
        regressions.append(
            {
                "type": "new_policy_violation",
                "file": file_path,
                "algorithm": algorithm or None,
                "evidence": rule,
            }
        )

    dependency_change = _set_change(_dependency_ids(before), _dependency_ids(after))
    if dependency_change["added"] or dependency_change["removed"]:
        regressions.append(
            {
                "type": "unexpected_dependency_change",
                "file": source_file,
                "algorithm": None,
                "evidence": json.dumps(dependency_change, sort_keys=True),
            }
        )
    artifact_change = _set_change(_artifact_ids(before), _artifact_ids(after))
    if artifact_change["added"] or artifact_change["removed"]:
        regressions.append(
            {
                "type": "unexpected_certificate_or_protocol_change",
                "file": source_file,
                "algorithm": None,
                "evidence": json.dumps(artifact_change, sort_keys=True),
            }
        )

    cbom_before = _cbom_view(before)
    cbom_after = _cbom_view(after)
    cbom_change = _cbom_change(cbom_before, cbom_after, target, replacement_name, source_file, original_present)
    if cbom_change == "unexpected":
        regressions.append(
            {
                "type": "unexpected_cbom_change",
                "file": source_file,
                "algorithm": replacement_name,
                "evidence": "CBOM algorithms, usages, libraries, or dependencies changed beyond the patched finding.",
            }
        )

    target_status = _target_status(original_present, replacement_present, role_match, after_findings)
    status = _status(
        target_status,
        regressions,
        before_keys,
        after_keys,
        original_present,
        original_present and replacement_present,
    )
    return {
        "status": status,
        "target_status": target_status,
        "original_finding_present": original_present,
        "replacement_finding_present": replacement_present,
        "new_findings": new_items,
        "removed_findings": removed_items,
        "changed_findings": changed_items,
        "regressions": regressions,
        "policy_before": {**policy_before, "change": policy_change},
        "policy_after": {**policy_after, "change": policy_change},
        "cbom_before": cbom_before,
        "cbom_after": {**cbom_after, "change": cbom_change},
    }


def _target_status(original_present: bool, replacement_present: bool, role_match: bool, after_findings: list) -> str:
    if after_findings is None:
        return "unknown"
    if original_present and replacement_present:
        return "still_present"
    if original_present:
        return "still_present"
    if replacement_present:
        return "resolved"
    if role_match:
        return "partially_resolved"
    return "unknown"


def _status(
    target_status: str,
    regressions: list,
    before_keys: dict,
    after_keys: dict,
    original_present: bool,
    both_present: bool,
) -> str:
    if regressions:
        return "regression_detected"
    if target_status == "resolved":
        return "verified"
    if target_status == "partially_resolved":
        return "partially_verified"
    if target_status == "unknown":
        return "verification_failed"
    if both_present:
        return "manual_review_required"
    if original_present and before_keys.keys() == after_keys.keys():
        return "no_change"
    if original_present:
        return "verification_failed"
    return "verification_failed"


def _allowed_new_findings(new_items: list[dict], source_file: str, replacement: str | None, original_present: bool) -> set[tuple]:
    source_new = [
        item for item in new_items if item.get("file") == source_file and item.get("usage") != "dependency_only"
    ]
    allowed: set[tuple] = set()
    if original_present:
        for item in source_new:
            if replacement and item.get("algorithm") == replacement:
                allowed.add(_finding_key_parts(item.get("file"), item.get("algorithm"), item.get("usage"), item.get("library")))
        return allowed
    if len(source_new) == 1:
        item = source_new[0]
        allowed.add(_finding_key_parts(item.get("file"), item.get("algorithm"), item.get("usage"), item.get("library")))
        return allowed
    for item in source_new:
        if replacement and item.get("algorithm") == replacement:
            allowed.add(_finding_key_parts(item.get("file"), item.get("algorithm"), item.get("usage"), item.get("library")))
    return allowed


def _matches_target(findings: list, target) -> bool:
    for item in findings:
        if (
            item.file_path == target.file_path
            and (item.algorithm or None) == (target.algorithm or None)
            and item.usage == target.usage
            and (item.library or None) == (target.library or None)
        ):
            return True
    return False


def _replacement_present(findings: list, source_file: str, replacement: str | None) -> bool:
    if not replacement:
        return False
    return any(
        item.file_path == source_file and item.algorithm == replacement and item.usage != "dependency_only"
        for item in findings
    )


def _same_role_replacement(findings: list, source_file: str, target, replacement: str | None) -> bool:
    role = getattr(target, "cryptographic_role", None)
    for item in findings:
        if item.file_path != source_file or not item.algorithm or item.algorithm == target.algorithm:
            continue
        if replacement and item.algorithm == replacement:
            continue
        if role and getattr(item, "cryptographic_role", None) == role:
            return True
    return False


def _finding_key(item) -> tuple:
    return _finding_key_parts(item.file_path, item.algorithm, item.usage, item.library)


def _finding_key_parts(file_path, algorithm, usage, library) -> tuple:
    return (file_path or "", algorithm or "", usage or "", library or "")


def _brief(item) -> dict:
    return {
        "file": item.file_path,
        "algorithm": item.algorithm,
        "usage": item.usage,
        "library": item.library,
        "confidence": item.confidence,
        "evidence": item.evidence,
    }


def _is_target_brief(item: dict, target) -> bool:
    return (
        item.get("file") == target.file_path
        and item.get("algorithm") == target.algorithm
        and item.get("usage") == target.usage
        and item.get("library") == target.library
    )


def _changed(before_keys: dict, after_keys: dict) -> list[dict]:
    changed = []
    for key in sorted(set(before_keys) & set(after_keys)):
        left = before_keys[key]
        right = after_keys[key]
        if (left.confidence, left.line_start, left.evidence) != (right.confidence, right.line_start, right.evidence):
            changed.append(
                {
                    "file": right.file_path,
                    "algorithm": right.algorithm,
                    "usage": right.usage,
                    "before_confidence": left.confidence,
                    "after_confidence": right.confidence,
                    "evidence": right.evidence,
                }
            )
    return changed


def _policy(findings: list, rules, scan_id: int) -> dict:
    parsed = rules if not isinstance(rules, str) else parse_policy(rules)
    result = evaluate_findings(findings, parsed, scan_id, "verification")
    return {
        "status": result["status"],
        "summary": result["summary"],
        "violations": result["violations"],
    }


def _violation_key(item: dict) -> str:
    return "|".join([item.get("rule") or "", item.get("file") or "", item.get("algorithm") or ""])


def _count_change(before: int, after: int) -> str:
    if after < before:
        return "decreased"
    if after > before:
        return "increased"
    return "unchanged"


def _dependency_ids(snapshot) -> set[str]:
    return {
        "|".join([row.name or "", row.version or "", row.manifest_file or "", row.version_constraint or ""])
        for row in snapshot.dependencies
    }


def _artifact_ids(snapshot) -> set[str]:
    values = set()
    for row in snapshot.artifacts:
        if row.artifact_type not in {"certificate", "protocol", "ssh_config", "cipher_suite"}:
            continue
        values.add("|".join([row.artifact_type, row.file_path or "", row.algorithm or "", row.protocol or "", row.cipher_suite or ""]))
    return values


def _set_change(before: set[str], after: set[str]) -> dict:
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def _cbom_view(snapshot) -> dict:
    algorithms = sorted({row.algorithm for row in snapshot.findings if row.algorithm and row.usage != "dependency_only"})
    usages = sorted(
        "|".join([row.file_path or "", row.algorithm or "", row.usage or "", row.library or ""])
        for row in snapshot.findings
        if row.usage != "dependency_only"
    )
    dependencies = sorted({row.name for row in snapshot.dependencies})
    libraries = sorted({row.library for row in snapshot.findings if row.library})
    components = getattr(snapshot, "components", []) or []
    component_algorithms = sorted({row.name for row in components if row.component_type == "algorithm"})
    if component_algorithms:
        algorithms = component_algorithms
    return {
        "algorithms": algorithms,
        "usages": usages,
        "dependencies": dependencies,
        "libraries": libraries,
    }


def _cbom_change(before: dict, after: dict, target, replacement: str | None, source_file: str, original_present: bool) -> str:
    if before == after:
        return "unchanged"
    expected_usages = set(before["usages"])
    target_usage = "|".join([source_file, target.algorithm or "", target.usage or "", target.library or ""])
    new_on_file = [
        usage
        for usage in after["usages"]
        if usage.split("|", 1)[0] == source_file and usage not in before["usages"]
    ]
    if replacement:
        for usage in new_on_file:
            algorithm = usage.split("|")[1] if "|" in usage else ""
            if algorithm == replacement:
                expected_usages.add(usage)
    if not original_present:
        expected_usages.discard(target_usage)
        if len(new_on_file) == 1:
            expected_usages.add(new_on_file[0])
    usage_ok = set(after["usages"]) == expected_usages
    expected_libraries = {item.split("|")[3] for item in expected_usages if len(item.split("|")) > 3 and item.split("|")[3]}
    expected_libraries |= set(before["libraries"]) - {
        item.split("|")[3] for item in before["usages"] if len(item.split("|")) > 3 and item.split("|")[3]
    }
    libraries_ok = set(after["libraries"]) == expected_libraries
    usage_algorithms = {item.split("|")[1] for item in before["usages"] if "|" in item and item.split("|")[1]}
    expected_usage_algorithms = {item.split("|")[1] for item in expected_usages if "|" in item and item.split("|")[1]}
    expected_algorithms = (set(before["algorithms"]) - usage_algorithms) | expected_usage_algorithms
    algorithms_ok = set(after["algorithms"]) == expected_algorithms
    dependencies_ok = before["dependencies"] == after["dependencies"]
    if usage_ok and algorithms_ok and dependencies_ok and libraries_ok:
        return "expected"
    return "unexpected"
