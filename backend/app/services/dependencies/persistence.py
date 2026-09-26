"""Build ORM rows for the dependency inventory and its relationships."""

import hashlib
import json

from app.models.dependency import Dependency, DependencyRelationship
from app.services.dependencies.linking import Link
from app.services.dependencies.types import DeclaredDependency


def dependency_row(project_id: int, scan_id: int, dependency: DeclaredDependency) -> Dependency:
    payload = {
        "manifest_file": dependency.manifest_file,
        "source_line": dependency.source_line,
        "ecosystem": dependency.ecosystem,
        "name": dependency.normalized_name,
        "version": dependency.version,
        "version_constraint": dependency.version_constraint,
    }
    return Dependency(
        project_id=project_id,
        scan_id=scan_id,
        name=dependency.name[:255],
        ecosystem=dependency.ecosystem,
        version=_bounded(dependency.version),
        version_constraint=_bounded(dependency.version_constraint),
        dependency_type=dependency.dependency_type,
        direct_or_transitive=dependency.direct_or_transitive,
        crypto_relevance=dependency.crypto_relevance,
        library=dependency.library,
        manifest_file=dependency.manifest_file,
        source_line=dependency.source_line,
        evidence=(dependency.raw_declaration or "[dependency]")[:512],
        metadata_json=json.dumps(dependency.metadata, sort_keys=True),
        fingerprint=hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest(),
    )


def relationship_rows(
    scan_id: int,
    links: list[Link],
    finding_ids: list[int],
    dependency_ids: list[int],
) -> list[DependencyRelationship]:
    return [
        DependencyRelationship(
            scan_id=scan_id,
            relationship_type=link.relationship_type,
            dependency_id=dependency_ids[link.dependency_index],
            finding_id=finding_ids[link.finding_index] if link.finding_index is not None else None,
            source_dependency_id=(
                dependency_ids[link.source_dependency_index]
                if link.source_dependency_index is not None
                else None
            ),
        )
        for link in links
    ]


def _bounded(value: str | None) -> str | None:
    return value[:128] if value else value
