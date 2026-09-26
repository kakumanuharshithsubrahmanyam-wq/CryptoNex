"""Deterministic blast-radius traversal over the stored knowledge graph."""

from __future__ import annotations

from collections import defaultdict, deque

_AFFECTED_TYPES = {
    "file": "affected_files",
    "dependency": "affected_dependencies",
    "algorithm": "affected_algorithms",
    "protocol": "affected_protocols",
    "certificate": "affected_certificates",
    "cipher_suite": "affected_cipher_suites",
    "key": "affected_keys",
    "crypto_library": "affected_libraries",
}

_TRAVERSAL_SKIP = {"project", "scan", "component"}


def blast_radius(graph: dict, finding_id: int, finding=None) -> dict:
    """Traverse finding → algorithm → file → dependency → related crypto → protocol/cert."""
    nodes = {node["id"]: node for node in graph.get("nodes", [])}
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in graph.get("edges", []):
        adjacency[edge["source"]].append((edge["target"], edge["type"]))
        adjacency[edge["target"]].append((edge["source"], edge["type"]))

    origin = f"finding:{finding_id}"
    collected = {
        "affected_files": [],
        "affected_dependencies": [],
        "affected_algorithms": [],
        "affected_protocols": [],
        "affected_certificates": [],
        "affected_cipher_suites": [],
        "affected_keys": [],
        "affected_libraries": [],
        "related_findings": [],
        "graph_paths": [],
    }

    if origin not in nodes:
        _seed_from_finding(collected, finding)
        collected["impact_summary"] = _summary(finding_id, collected, empty_graph=True)
        return collected

    parents: dict[str, tuple[str, str] | None] = {origin: None}
    queue = deque([origin])
    visited = {origin}
    while queue:
        current = queue.popleft()
        for neighbor, edge_type in sorted(adjacency[current], key=lambda item: (item[0], item[1])):
            if neighbor in visited:
                continue
            neighbor_node = nodes.get(neighbor)
            if neighbor_node is None:
                continue
            if neighbor_node["type"] in _TRAVERSAL_SKIP:
                continue
            visited.add(neighbor)
            parents[neighbor] = (current, edge_type)
            queue.append(neighbor)

    for node_id in sorted(visited):
        node = nodes[node_id]
        node_type = node["type"]
        if node_id == origin:
            continue
        if node_type == "crypto_finding":
            related_id = _numeric_suffix(node_id)
            if related_id is not None and related_id != finding_id:
                collected["related_findings"].append(
                    {
                        "finding_id": related_id,
                        "algorithm": node.get("metadata", {}).get("algorithm"),
                        "file_path": node.get("metadata", {}).get("file_path"),
                        "usage": node.get("metadata", {}).get("usage"),
                    }
                )
            continue
        bucket = _AFFECTED_TYPES.get(node_type)
        if bucket:
            collected[bucket].append(_node_ref(node))

    for bucket in collected:
        if bucket in {"graph_paths", "impact_summary"}:
            continue
        collected[bucket] = _dedupe(collected[bucket])

    targets = [node_id for node_id in sorted(visited) if node_id != origin and nodes[node_id]["type"] not in _TRAVERSAL_SKIP]
    collected["graph_paths"] = [_path(origin, target, parents) for target in targets if target in parents]
    _seed_from_finding(collected, finding)
    collected["impact_summary"] = _summary(finding_id, collected, empty_graph=len(visited) <= 1)
    return collected


def _seed_from_finding(collected: dict, finding) -> None:
    if finding is None:
        return
    path = getattr(finding, "file_path", None)
    algorithm = getattr(finding, "algorithm", None)
    library = getattr(finding, "library", None)
    if path:
        collected["affected_files"] = _dedupe(
            collected["affected_files"] + [{"id": f"file:{path}", "label": path, "type": "file"}]
        )
    if algorithm:
        collected["affected_algorithms"] = _dedupe(
            collected["affected_algorithms"] + [{"id": f"algorithm:{algorithm}", "label": algorithm, "type": "algorithm"}]
        )
    if library:
        collected["affected_libraries"] = _dedupe(
            collected["affected_libraries"] + [{"id": f"library:{library}", "label": library, "type": "crypto_library"}]
        )


def _node_ref(node: dict) -> dict:
    return {"id": node["id"], "label": node["label"], "type": node["type"]}


def _path(origin: str, target: str, parents: dict[str, tuple[str, str] | None]) -> dict:
    nodes = [target]
    edges: list[str] = []
    current = target
    while parents.get(current):
        previous, edge_type = parents[current]
        edges.append(edge_type)
        nodes.append(previous)
        current = previous
        if current == origin:
            break
    nodes.reverse()
    edges.reverse()
    return {"from": origin, "to": target, "nodes": nodes, "edges": edges}


def _summary(finding_id: int, collected: dict, empty_graph: bool) -> str:
    if empty_graph and not collected["affected_files"] and not collected["affected_algorithms"]:
        return f"No graph relationships are available for finding {finding_id}."
    parts = [
        f"{len(collected['affected_files'])} file(s)",
        f"{len(collected['affected_dependencies'])} dependency(ies)",
        f"{len(collected['affected_algorithms'])} algorithm(s)",
        f"{len(collected['affected_protocols'])} protocol(s)",
        f"{len(collected['affected_certificates'])} certificate(s)",
        f"{len(collected['related_findings'])} related finding(s)",
    ]
    return f"Finding {finding_id} may affect " + ", ".join(parts) + "."


def _numeric_suffix(node_id: str) -> int | None:
    if ":" not in node_id:
        return None
    suffix = node_id.split(":", 1)[1]
    return int(suffix) if suffix.isdigit() else None


def _dedupe(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    ordered: list[dict] = []
    for item in sorted(items, key=lambda value: (value.get("id", ""), value.get("label", ""))):
        key = item.get("id") or item.get("label") or repr(item)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    return ordered
