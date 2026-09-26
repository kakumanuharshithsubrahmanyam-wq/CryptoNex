"""Construct a traversal-ready graph from findings, dependencies, artifacts, and CBOM."""

from __future__ import annotations

import json

from app.models.artifact import SecurityArtifact
from app.models.cbom import Cbom, CbomComponent, CbomRelationship
from app.models.dependency import Dependency, DependencyRelationship
from app.models.project import Project
from app.models.scan import CryptoFinding, Scan
from app.services.dependencies.types import RelationshipType


def build_graph(
    project: Project,
    scan: Scan,
    findings: list[CryptoFinding],
    dependencies: list[Dependency],
    artifacts: list[SecurityArtifact],
    links: list[DependencyRelationship],
    cbom: Cbom | None,
    components: list[CbomComponent],
    cbom_relationships: list[CbomRelationship],
) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(node_id: str, node_type: str, label: str, metadata: dict | None = None) -> None:
        nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "metadata": {key: value for key, value in (metadata or {}).items() if value is not None},
        }

    def edge(source: str, target: str, edge_type: str) -> None:
        edges.append({"source": source, "target": target, "type": edge_type})

    project_id = f"project:{project.id}"
    scan_id = f"scan:{scan.id}"
    node(project_id, "project", project.name, {"project_id": project.id})
    node(scan_id, "scan", f"scan-{scan.id}", {"scan_id": scan.id, "status": scan.status})
    edge(project_id, scan_id, "HAS_SCAN")

    for finding in findings:
        finding_id = f"finding:{finding.id}"
        file_id = f"file:{finding.file_path}"
        node(
            finding_id,
            "crypto_finding",
            finding.algorithm or finding.usage,
            {
                "algorithm": finding.algorithm,
                "usage": finding.usage,
                "library": finding.library,
                "file_path": finding.file_path,
                "confidence": finding.confidence,
            },
        )
        node(file_id, "file", finding.file_path, {"file_path": finding.file_path})
        edge(scan_id, finding_id, "CONTAINS_FINDING")
        edge(finding_id, file_id, "LOCATED_IN")
        if finding.algorithm:
            algorithm_id = f"algorithm:{finding.algorithm}"
            node(algorithm_id, "algorithm", finding.algorithm, {"family": finding.algorithm_family})
            edge(finding_id, algorithm_id, "USES_ALGORITHM")
        if finding.library:
            library_id = f"library:{finding.library}"
            node(library_id, "crypto_library", finding.library, {"version": finding.library_version})
            edge(finding_id, library_id, "USES_LIBRARY")

    for dependency in dependencies:
        dep_id = f"dependency:{dependency.id}"
        file_id = f"file:{dependency.manifest_file}"
        node(
            dep_id,
            "dependency",
            dependency.name,
            {
                "ecosystem": dependency.ecosystem,
                "version": dependency.version,
                "manifest_file": dependency.manifest_file,
            },
        )
        node(file_id, "file", dependency.manifest_file, {"file_path": dependency.manifest_file})
        edge(dep_id, file_id, "DECLARED_IN")
        if dependency.library:
            library_id = f"library:{dependency.library}"
            node(library_id, "crypto_library", dependency.library, {"ecosystem": dependency.ecosystem})
            edge(library_id, dep_id, "PROVIDED_BY")

    for link in links:
        if link.relationship_type == RelationshipType.FINDING_USES_DEPENDENCY.value and link.finding_id:
            edge(f"finding:{link.finding_id}", f"dependency:{link.dependency_id}", "USES_DEPENDENCY")

    for artifact in artifacts:
        file_id = f"file:{artifact.file_path}"
        node(file_id, "file", artifact.file_path, {"file_path": artifact.file_path})
        if artifact.artifact_type == "certificate":
            artifact_id = f"certificate:{artifact.id}"
            node(artifact_id, "certificate", artifact.subject or artifact.file_path, {"algorithm": artifact.algorithm})
            edge(scan_id, artifact_id, "CONTAINS_FINDING")
            edge(artifact_id, file_id, "LOCATED_IN")
            if artifact.algorithm:
                algorithm_id = f"algorithm:{artifact.algorithm}"
                node(algorithm_id, "algorithm", artifact.algorithm)
                edge(artifact_id, algorithm_id, "USES_ALGORITHM")
        elif artifact.artifact_type in {"private_key", "public_key", "ssh_key"}:
            artifact_id = f"key:{artifact.id}"
            node(artifact_id, "key", artifact.algorithm or artifact.artifact_type, {"artifact_type": artifact.artifact_type})
            edge(artifact_id, file_id, "LOCATED_IN")
            if artifact.algorithm:
                algorithm_id = f"algorithm:{artifact.algorithm}"
                node(algorithm_id, "algorithm", artifact.algorithm)
                edge(artifact_id, algorithm_id, "USES_ALGORITHM")
        elif artifact.artifact_type == "cipher_suite" and artifact.cipher_suite:
            suite_id = f"cipher_suite:{artifact.cipher_suite}"
            node(suite_id, "cipher_suite", artifact.cipher_suite, {"algorithm": artifact.algorithm})
            edge(suite_id, file_id, "LOCATED_IN")
            if artifact.algorithm:
                algorithm_id = f"algorithm:{artifact.algorithm}"
                node(algorithm_id, "algorithm", artifact.algorithm)
                edge(suite_id, algorithm_id, "USES_ALGORITHM")
        elif artifact.artifact_type in {"protocol", "ssh_config"}:
            artifact_id = f"protocol:{artifact.id}"
            meta = _json(artifact.metadata_json)
            label = artifact.protocol or artifact.artifact_type
            if meta.get("tls_version"):
                label = f"{artifact.protocol} {meta['tls_version']}"
            node(artifact_id, "protocol", label, {"protocol": artifact.protocol, **meta})
            edge(artifact_id, file_id, "LOCATED_IN")
            if artifact.algorithm:
                algorithm_id = f"algorithm:{artifact.algorithm}"
                node(algorithm_id, "algorithm", artifact.algorithm)
                edge(artifact_id, algorithm_id, "USES_ALGORITHM")

    for artifact in artifacts:
        if artifact.artifact_type != "protocol" or artifact.protocol != "TLS":
            continue
        for suite in artifacts:
            if suite.artifact_type == "cipher_suite" and suite.cipher_suite and suite.file_path == artifact.file_path:
                edge(f"protocol:{artifact.id}", f"cipher_suite:{suite.cipher_suite}", "USES_CIPHER_SUITE")

    for component in components:
        node(
            f"component:{component.component_key}",
            "component",
            component.name,
            {"component_type": component.component_type, "key": component.component_key},
        )
    for relationship in cbom_relationships:
        source = f"component:{relationship.source_key}"
        target = f"component:{relationship.target_key}"
        if source in nodes and target in nodes:
            edge(source, target, relationship.relationship_type.upper())

    unique_edges = _unique_edges(edges)
    return {
        "scan_id": scan.id,
        "project_id": project.id,
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": unique_edges,
        "summary": {
            "nodes": len(nodes),
            "edges": len(unique_edges),
            "node_types": _counts(nodes.values(), "type"),
        },
    }


def filter_graph(graph: dict, node_type: str | None, algorithm: str | None, file_path: str | None, dependency: str | None) -> dict:
    if not any([node_type, algorithm, file_path, dependency]):
        return graph
    selected = set()
    for node in graph["nodes"]:
        if node_type and node["type"] != node_type:
            continue
        if algorithm and not (
            node["id"] == f"algorithm:{algorithm}"
            or node["metadata"].get("algorithm") == algorithm
            or node["label"] == algorithm
        ):
            continue
        if file_path and not (
            node["id"] == f"file:{file_path}" or node["metadata"].get("file_path") == file_path
        ):
            continue
        if dependency and (node["type"] != "dependency" or node["label"] != dependency):
            continue
        selected.add(node["id"])
    neighbors = set(selected)
    for edge in graph["edges"]:
        if edge["source"] in selected or edge["target"] in selected:
            neighbors.add(edge["source"])
            neighbors.add(edge["target"])
    nodes = [node for node in graph["nodes"] if node["id"] in neighbors]
    edges = [edge for edge in graph["edges"] if edge["source"] in neighbors and edge["target"] in neighbors]
    return {
        "scan_id": graph["scan_id"],
        "project_id": graph["project_id"],
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "node_types": _counts(nodes, "type"),
        },
    }


def _json(value: str | None) -> dict:
    try:
        loaded = json.loads(value or "{}")
    except ValueError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _unique_edges(edges: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    ordered: list[dict] = []
    for edge in sorted(edges, key=lambda item: (item["type"], item["source"], item["target"])):
        key = (edge["source"], edge["target"], edge["type"])
        if key in seen:
            continue
        seen.add(key)
        ordered.append(edge)
    return ordered


def _counts(items, field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item[field]
        counts[value] = counts.get(value, 0) + 1
    return {key: counts[key] for key in sorted(counts)}
