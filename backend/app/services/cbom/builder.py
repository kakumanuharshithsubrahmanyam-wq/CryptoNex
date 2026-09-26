"""Build a deterministic CryptoNex CBOM from persisted scan records."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from app.models.artifact import SecurityArtifact
from app.models.cbom import Cbom, CbomComponent, CbomRelationship
from app.models.dependency import Dependency, DependencyRelationship
from app.models.scan import CryptoFinding, Scan
from app.services.dependencies.types import RelationshipType

SCHEMA_VERSION = "1.0"


def build_cbom_document(
    scan: Scan,
    findings: list[CryptoFinding],
    dependencies: list[Dependency],
    artifacts: list[SecurityArtifact],
    links: list[DependencyRelationship],
    generated_at: datetime | None = None,
) -> dict:
    components: dict[str, dict] = {}
    relationships: list[dict] = []

    def add(component: dict) -> None:
        components[component["key"]] = component

    add(_component(f"scan:{scan.id}", "scan", f"scan-{scan.id}", {"project_id": scan.project_id, "scan_id": scan.id}))

    algorithm_origins: dict[str, set[str]] = {}
    for finding in findings:
        if finding.algorithm:
            algorithm_origins.setdefault(finding.algorithm, set()).add("crypto_finding")
    for artifact in artifacts:
        if artifact.algorithm:
            algorithm_origins.setdefault(artifact.algorithm, set()).add(_artifact_origin(artifact.artifact_type))

    for finding in findings:
        add(_file_component(finding.file_path))
        usage_key = f"crypto_usage:{finding.id}"
        add(
            _component(
                usage_key,
                "crypto_usage",
                finding.algorithm or finding.library or "unknown",
                {
                    "finding_id": finding.id,
                    "algorithm": finding.algorithm,
                    "library": finding.library,
                    "usage": finding.usage,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "line_end": finding.line_end,
                    "key_size": finding.key_size,
                    "curve": finding.curve,
                    "mode": finding.mode,
                    "confidence": finding.confidence,
                    "evidence": finding.evidence,
                },
            )
        )
        relationships.append(_rel(usage_key, f"file:{finding.file_path}", "located_in"))
        if finding.algorithm:
            alg_key = f"algorithm:{finding.algorithm}"
            add(_algorithm_component(finding.algorithm, finding.algorithm_family, algorithm_origins.get(finding.algorithm)))
            relationships.append(_rel(usage_key, alg_key, "uses"))
        if finding.library:
            lib_key = f"library:{finding.library}"
            add(_component(lib_key, "library", finding.library, {"version": finding.library_version}))
            relationships.append(_rel(usage_key, lib_key, "uses"))

    for dependency in dependencies:
        add(_file_component(dependency.manifest_file))
        dep_key = f"dependency:{dependency.id}"
        add(
            _component(
                dep_key,
                "dependency",
                dependency.name,
                {
                    "dependency_id": dependency.id,
                    "version": dependency.version,
                    "version_constraint": dependency.version_constraint,
                    "ecosystem": dependency.ecosystem,
                    "manifest_file": dependency.manifest_file,
                    "source_line": dependency.source_line,
                    "crypto_relevance": dependency.crypto_relevance,
                    "evidence": dependency.evidence,
                },
            )
        )
        relationships.append(_rel(dep_key, f"file:{dependency.manifest_file}", "located_in"))
        if dependency.library:
            lib_key = f"library:{dependency.library}"
            add(_component(lib_key, "library", dependency.library, {"ecosystem": dependency.ecosystem}))
            relationships.append(_rel(lib_key, dep_key, "declared_by"))

    for artifact in artifacts:
        add(_file_component(artifact.file_path))
        kind, key = _artifact_component(artifact)
        add(kind)
        relationships.append(_rel(key, f"file:{artifact.file_path}", "located_in"))
        if artifact.algorithm:
            alg_key = f"algorithm:{artifact.algorithm}"
            add(_algorithm_component(artifact.algorithm, None, algorithm_origins.get(artifact.algorithm)))
            relationships.append(_rel(key, alg_key, "uses"))
        if artifact.cipher_suite:
            suite_key = f"cipher_suite:{artifact.cipher_suite}"
            if artifact.artifact_type == "protocol":
                relationships.append(_rel(key, suite_key, "uses"))

    for link in links:
        if link.relationship_type == RelationshipType.FINDING_USES_DEPENDENCY.value and link.finding_id:
            relationships.append(_rel(f"crypto_usage:{link.finding_id}", f"dependency:{link.dependency_id}", "uses"))
            finding = next((item for item in findings if item.id == link.finding_id), None)
            if finding and finding.library:
                relationships.append(
                    _rel(f"library:{finding.library}", f"dependency:{link.dependency_id}", "declared_by")
                )
        if link.relationship_type == RelationshipType.TRANSITIVE_DEPENDENCY.value and link.source_dependency_id:
            relationships.append(
                _rel(f"dependency:{link.source_dependency_id}", f"dependency:{link.dependency_id}", "depends_on")
            )

    _link_protocols_to_suites(artifacts, relationships)

    ordered = [components[key] for key in sorted(components)]
    ordered_rels = _unique_relationships(relationships)
    summary = {
        "algorithms": sum(1 for item in ordered if item["component_type"] == "algorithm"),
        "crypto_usages": sum(1 for item in ordered if item["component_type"] == "crypto_usage"),
        "libraries": sum(1 for item in ordered if item["component_type"] == "library"),
        "dependencies": sum(1 for item in ordered if item["component_type"] == "dependency"),
        "certificates": sum(1 for item in ordered if item["component_type"] == "certificate"),
        "keys": sum(1 for item in ordered if item["component_type"] == "key"),
        "protocols": sum(1 for item in ordered if item["component_type"] == "protocol"),
        "cipher_suites": sum(1 for item in ordered if item["component_type"] == "cipher_suite"),
    }
    timestamp = generated_at or datetime.now(timezone.utc)
    return {
        "schema_version": SCHEMA_VERSION,
        "schema_name": "cryptonex-cbom",
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "generated_at": timestamp.isoformat(),
        "summary": summary,
        "components": ordered,
        "relationships": ordered_rels,
    }


def persist_cbom(scan: Scan, document: dict) -> tuple[Cbom, list[CbomComponent], list[CbomRelationship]]:
    row = Cbom(
        project_id=scan.project_id,
        scan_id=scan.id,
        schema_version=document["schema_version"],
        payload_json=json.dumps(document, sort_keys=True, separators=(",", ":")),
        metadata_json=json.dumps({"schema_name": "cryptonex-cbom"}, sort_keys=True),
    )
    components = [
        CbomComponent(
            component_key=item["key"],
            component_type=item["component_type"],
            name=item["name"],
            payload_json=json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
        for item in document["components"]
    ]
    relationships = [
        CbomRelationship(
            relationship_type=item["type"],
            source_key=item["source"],
            target_key=item["target"],
        )
        for item in document["relationships"]
    ]
    return row, components, relationships


def attach_cbom_children(
    cbom: Cbom, components: list[CbomComponent], relationships: list[CbomRelationship]
) -> None:
    for component in components:
        component.cbom_id = cbom.id
    for relationship in relationships:
        relationship.cbom_id = cbom.id


def _component(key: str, component_type: str, name: str, fields: dict) -> dict:
    payload = {"key": key, "component_type": component_type, "name": name}
    payload.update({field: value for field, value in fields.items() if value is not None})
    return payload


def _algorithm_component(name: str, family: str | None, origins: set[str] | None = None) -> dict:
    origin_list = ",".join(sorted(origins or ()))
    return _component(
        f"algorithm:{name}",
        "algorithm",
        name,
        {
            "algorithm": name,
            "algorithm_family": family,
            "evidence_origins": origin_list or None,
            "confirmed_usage": "true" if origins and "crypto_finding" in origins else "false",
        },
    )


def _artifact_origin(artifact_type: str) -> str:
    if artifact_type == "certificate":
        return "certificate"
    if artifact_type in {"private_key", "public_key", "ssh_key"}:
        return "key"
    if artifact_type == "cipher_suite":
        return "cipher_suite"
    if artifact_type in {"protocol", "ssh_config"}:
        return "protocol"
    return "artifact"


def _file_component(path: str) -> dict:
    return _component(f"file:{path}", "file", path, {"file_path": path})


def _artifact_component(artifact: SecurityArtifact) -> tuple[dict, str]:
    if artifact.artifact_type == "certificate":
        key = f"certificate:{artifact.id}"
        return (
            _component(
                key,
                "certificate",
                artifact.subject or artifact.file_path,
                {
                    "artifact_id": artifact.id,
                    "algorithm": artifact.algorithm,
                    "key_size": artifact.key_size,
                    "curve": artifact.curve,
                    "subject": artifact.subject,
                    "issuer": artifact.issuer,
                    "file_path": artifact.file_path,
                    "line_start": artifact.line_start,
                    "evidence": artifact.evidence,
                    "confidence": artifact.confidence,
                },
            ),
            key,
        )
    if artifact.artifact_type in {"private_key", "public_key", "ssh_key"}:
        key = f"key:{artifact.id}"
        return (
            _component(
                key,
                "key",
                artifact.algorithm or artifact.artifact_type,
                {
                    "artifact_id": artifact.id,
                    "artifact_type": artifact.artifact_type,
                    "algorithm": artifact.algorithm,
                    "key_size": artifact.key_size,
                    "curve": artifact.curve,
                    "file_path": artifact.file_path,
                    "evidence": artifact.evidence,
                },
            ),
            key,
        )
    if artifact.artifact_type == "cipher_suite" and artifact.cipher_suite:
        key = f"cipher_suite:{artifact.cipher_suite}"
        return (
            _component(
                key,
                "cipher_suite",
                artifact.cipher_suite,
                {
                    "algorithm": artifact.algorithm,
                    "key_size": artifact.key_size,
                    "protocol": artifact.protocol,
                    "file_path": artifact.file_path,
                },
            ),
            key,
        )
    if artifact.artifact_type in {"protocol", "ssh_config"}:
        version = json.loads(artifact.metadata_json).get("tls_version") if artifact.metadata_json else None
        label = f"{artifact.protocol or 'protocol'} {version}".strip() if version else (artifact.protocol or artifact.artifact_type)
        key = f"protocol:{artifact.id}"
        return (
            _component(
                key,
                "protocol",
                label,
                {
                    "artifact_id": artifact.id,
                    "protocol": artifact.protocol,
                    "tls_version": version,
                    "file_path": artifact.file_path,
                    "evidence": artifact.evidence,
                },
            ),
            key,
        )
    key = f"component:{artifact.id}"
    return (
        _component(
            key,
            artifact.artifact_type,
            artifact.artifact_type,
            {"artifact_id": artifact.id, "file_path": artifact.file_path, "evidence": artifact.evidence},
        ),
        key,
    )


def _link_protocols_to_suites(artifacts: list[SecurityArtifact], relationships: list[dict]) -> None:
    suites_by_file: dict[str, list[SecurityArtifact]] = {}
    for artifact in artifacts:
        if artifact.artifact_type == "cipher_suite" and artifact.cipher_suite:
            suites_by_file.setdefault(artifact.file_path, []).append(artifact)
    for artifact in artifacts:
        if artifact.artifact_type != "protocol" or artifact.protocol != "TLS":
            continue
        for suite in suites_by_file.get(artifact.file_path, []):
            relationships.append(_rel(f"protocol:{artifact.id}", f"cipher_suite:{suite.cipher_suite}", "uses"))


def _rel(source: str, target: str, relationship_type: str) -> dict:
    return {"source": source, "target": target, "type": relationship_type}


def _unique_relationships(items: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    ordered: list[dict] = []
    for item in sorted(items, key=lambda value: (value["type"], value["source"], value["target"])):
        key = (item["source"], item["target"], item["type"])
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    return ordered
