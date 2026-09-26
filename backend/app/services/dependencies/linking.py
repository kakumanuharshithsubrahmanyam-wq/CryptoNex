"""Deterministic links between findings and dependency records.

A source finding links to a dependency only when the registry says that package
supplies the library the detector identified, the ecosystems match, and the
manifest's directory contains the source file. Nothing is matched by
similarity.
"""

from dataclasses import dataclass

from app.services.dependencies.registry import LANGUAGE_ECOSYSTEMS, lookup_package, supplies_library
from app.services.dependencies.types import DeclaredDependency, RelationshipType, normalize_name
from app.services.scanner.findings import RawFinding


@dataclass(frozen=True)
class Link:
    relationship_type: str
    dependency_index: int
    finding_index: int | None = None
    source_dependency_index: int | None = None


def link_all(findings: list[RawFinding], dependencies: list[DeclaredDependency]) -> list[Link]:
    links: set[Link] = set()
    links.update(_dependency_only_links(findings, dependencies))
    links.update(_usage_links(findings, dependencies))
    links.update(_transitive_links(dependencies))
    return sorted(
        links,
        key=lambda link: (
            link.relationship_type,
            link.dependency_index,
            -1 if link.finding_index is None else link.finding_index,
            -1 if link.source_dependency_index is None else link.source_dependency_index,
        ),
    )


def apply_declared_versions(
    findings: list[RawFinding], dependencies: list[DeclaredDependency], links: list[Link]
) -> None:
    """Set library_version on a source finding when its linked declarations agree on one exact version."""
    versions: dict[int, set[str]] = {}
    for link in links:
        if link.relationship_type != RelationshipType.FINDING_USES_DEPENDENCY.value or link.finding_index is None:
            continue
        version = dependencies[link.dependency_index].version
        bucket = versions.setdefault(link.finding_index, set())
        if version:
            bucket.add(version)
    for index, found in versions.items():
        finding = findings[index]
        if finding.library_version is None and len(found) == 1:
            finding.library_version = next(iter(found))


def _dependency_only_links(findings: list[RawFinding], dependencies: list[DeclaredDependency]) -> list[Link]:
    by_location = {
        (dependency.manifest_file, dependency.source_line, dependency.library): index
        for index, dependency in enumerate(dependencies)
    }
    links: list[Link] = []
    for index, finding in enumerate(findings):
        if finding.usage != "dependency_only":
            continue
        target = by_location.get((finding.file_path, finding.line_start, finding.library))
        if target is not None:
            links.append(Link(RelationshipType.DEPENDENCY_ONLY.value, target, finding_index=index))
    return links


def _usage_links(findings: list[RawFinding], dependencies: list[DeclaredDependency]) -> list[Link]:
    links: list[Link] = []
    for index, finding in enumerate(findings):
        ecosystem = LANGUAGE_ECOSYSTEMS.get(finding.language or "")
        if finding.usage == "dependency_only" or not finding.library or ecosystem is None:
            continue
        directory = finding.file_path.rsplit("/", 1)[0] if "/" in finding.file_path else ""
        candidates = [
            (candidate_index, dependency)
            for candidate_index, dependency in enumerate(dependencies)
            if dependency.ecosystem == ecosystem
            and _contains(dependency.directory, directory)
            and _supplies(dependency, finding.library)
        ]
        if not candidates:
            continue
        nearest = max(len(dependency.directory) for _index, dependency in candidates)
        for candidate_index, dependency in candidates:
            if len(dependency.directory) == nearest:
                links.append(
                    Link(RelationshipType.FINDING_USES_DEPENDENCY.value, candidate_index, finding_index=index)
                )
    return links


def _transitive_links(dependencies: list[DeclaredDependency]) -> list[Link]:
    by_manifest: dict[tuple[str, str], list[int]] = {}
    for index, dependency in enumerate(dependencies):
        by_manifest.setdefault((dependency.manifest_file, dependency.normalized_name), []).append(index)
    links: list[Link] = []
    for parent_index, parent in enumerate(dependencies):
        for name in parent.requires:
            key = (parent.manifest_file, _normalized(parent, name))
            for child_index in by_manifest.get(key, []):
                if child_index != parent_index:
                    links.append(
                        Link(
                            RelationshipType.TRANSITIVE_DEPENDENCY.value,
                            child_index,
                            source_dependency_index=parent_index,
                        )
                    )
    for child_index, child in enumerate(dependencies):
        for name in child.required_by:
            key = (child.manifest_file, _normalized(child, name))
            for parent_index in by_manifest.get(key, []):
                if parent_index != child_index:
                    links.append(
                        Link(
                            RelationshipType.TRANSITIVE_DEPENDENCY.value,
                            child_index,
                            source_dependency_index=parent_index,
                        )
                    )
    return links


def _normalized(reference: DeclaredDependency, name: str) -> str:
    return normalize_name(reference.ecosystem, name)


def _contains(manifest_directory: str, source_directory: str) -> bool:
    if not manifest_directory:
        return True
    return source_directory == manifest_directory or source_directory.startswith(f"{manifest_directory}/")


def _supplies(dependency: DeclaredDependency, source_library: str) -> bool:
    package = lookup_package(dependency.ecosystem, dependency.name)
    return package is not None and supplies_library(package, source_library)
