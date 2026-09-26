"""Dependency-manifest findings.

A listed package is evidence that a cryptographic library is declared.
It is not evidence that an algorithm is used, so these findings never carry
an algorithm.
"""

from app.core.config import Settings
from app.services.dependencies.inventory import build_inventory
from app.services.dependencies.parsers import parse_manifest
from app.services.dependencies.types import CryptoRelevance, DeclaredDependency
from app.services.scanner.findings import RawFinding


def detect_dependencies(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    parsed = parse_manifest(source, file_path, settings)
    return dependency_findings(build_inventory(parsed.dependencies, {file_path: parsed.attributes}))


def dependency_findings(dependencies: list[DeclaredDependency]) -> list[RawFinding]:
    return [
        _finding(dependency)
        for dependency in dependencies
        if dependency.crypto_relevance == CryptoRelevance.CRYPTOGRAPHIC_LIBRARY.value
    ]


def _finding(dependency: DeclaredDependency) -> RawFinding:
    metadata = {
        "package": dependency.name,
        "ecosystem": dependency.ecosystem,
        "direct_or_transitive": dependency.direct_or_transitive,
    }
    if dependency.version_constraint:
        metadata["version_constraint"] = dependency.version_constraint
    return RawFinding(
        file_path=dependency.manifest_file,
        line_start=dependency.source_line,
        line_end=dependency.source_line,
        language=None,
        algorithm=None,
        algorithm_family=None,
        library=dependency.library,
        library_version=dependency.version,
        usage="dependency_only",
        key_size=None,
        curve=None,
        mode=None,
        evidence=dependency.raw_declaration or "[dependency]",
        detection_method="dependency_detection",
        confidence="low",
        metadata=metadata,
    )
