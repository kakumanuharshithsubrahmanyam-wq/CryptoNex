"""Deterministic root-cause hypotheses from stored evidence, then optional AI explanation."""

from __future__ import annotations

from app.services.migration.registry import KEY_ESTABLISHMENT_ROLE, SIGNATURE_ROLE, infer_role


UNDETERMINED = "Root cause cannot be determined from static repository evidence."


def deterministic_root_cause(snapshot, finding) -> dict:
    role = infer_role(finding)
    usage = getattr(finding, "usage", None)
    evidence_type = getattr(finding, "evidence_type", None)
    algorithm = getattr(finding, "algorithm", None)
    hypotheses: list[str] = []
    evidence: list[str] = []

    related_artifacts = [
        artifact
        for artifact in snapshot.artifacts
        if getattr(artifact, "file_path", None) == finding.file_path
        or (algorithm and getattr(artifact, "algorithm", None) == algorithm)
    ]
    certs = [item for item in related_artifacts if item.artifact_type == "certificate"]
    protocols = [item for item in related_artifacts if item.artifact_type in {"protocol", "cipher_suite", "ssh_config"}]

    if evidence_type == "confirmed_configuration" or usage == "algorithm_selection":
        hypotheses.append("explicit configuration")
        evidence.append("The finding is an explicit configuration or algorithm-selection site.")
    if role == SIGNATURE_ROLE or usage in {"signing", "signature_verification"}:
        hypotheses.append("legacy authentication architecture")
        evidence.append("Stored usage or role indicates digital signatures.")
    if role == KEY_ESTABLISHMENT_ROLE or usage == "key_agreement":
        hypotheses.append("legacy key exchange")
        evidence.append("Stored usage or role indicates key establishment.")
    if certs:
        hypotheses.append("certificate dependency")
        evidence.append("A certificate artifact shares this file or algorithm.")
    if protocols:
        hypotheses.append("protocol or cipher-suite configuration")
        evidence.append("A protocol or cipher-suite artifact is associated with this finding.")
    if usage == "dependency_only":
        hypotheses = []
        evidence = ["Only a dependency declaration was observed; that is not a confirmed architectural root cause."]

    determined = bool(hypotheses) and usage != "dependency_only"
    return {
        "finding_id": finding.id,
        "algorithm": algorithm,
        "role": role,
        "root_cause": hypotheses[0] if determined else UNDETERMINED,
        "possible_causes": hypotheses if determined else [],
        "evidence": evidence if determined else [UNDETERMINED],
        "determined": determined,
    }


def explain_root_causes(snapshot, finding_id: int | None = None) -> list[dict]:
    findings = snapshot.findings if finding_id is None else [snapshot.finding(finding_id)]
    return [deterministic_root_cause(snapshot, finding) for finding in findings]
