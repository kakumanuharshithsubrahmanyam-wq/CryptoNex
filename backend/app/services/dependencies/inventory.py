"""Turn parsed declarations into a classified dependency inventory."""

from app.services.dependencies.registry import lookup_package
from app.services.dependencies.types import CryptoRelevance, DeclaredDependency, Directness

# A lockfile's direct entries are the ones its sibling declaration file lists.
_DECLARATION_FOR_LOCK = {
    "package-lock.json": "package.json",
    "yarn.lock": "package.json",
    "pnpm-lock.yaml": "package.json",
    "poetry.lock": "pyproject.toml",
    "cargo.lock": "cargo.toml",
    "go.sum": "go.mod",
}
WORKSPACES_ATTRIBUTE = "workspaces"


def build_inventory(
    dependencies: list[DeclaredDependency],
    manifests: dict[str, dict[str, str]],
) -> list[DeclaredDependency]:
    """Classify each dependency and resolve lockfile directness from sibling manifests.

    `manifests` maps every parsed manifest path to parser-reported attributes,
    so a declaration file with no dependencies still counts as present.
    """
    declared = _declarations(dependencies)
    attributes = {_key(path): values for path, values in manifests.items()}
    for dependency in dependencies:
        if dependency.direct_or_transitive == Directness.UNKNOWN.value:
            dependency.direct_or_transitive = _lock_directness(dependency, declared, attributes)
        _classify(dependency)
    return sorted(
        dependencies,
        key=lambda item: (item.manifest_file, item.source_line, item.normalized_name, item.version or ""),
    )


def _classify(dependency: DeclaredDependency) -> None:
    package = lookup_package(dependency.ecosystem, dependency.name)
    if package is None:
        dependency.crypto_relevance = CryptoRelevance.NON_CRYPTO.value
        dependency.library = None
        return
    dependency.crypto_relevance = package.relevance
    dependency.library = package.library


def _key(path: str) -> tuple[str, str]:
    directory, _, filename = path.rpartition("/")
    return directory, filename.lower()


def _declarations(dependencies: list[DeclaredDependency]) -> dict[tuple[str, str], dict[str, str]]:
    index: dict[tuple[str, str], dict[str, str]] = {}
    for dependency in dependencies:
        if dependency.filename not in _DECLARATION_FOR_LOCK.values():
            continue
        names = index.setdefault((dependency.directory, dependency.filename), {})
        names.setdefault(dependency.normalized_name, dependency.direct_or_transitive)
    return index


def _lock_directness(
    dependency: DeclaredDependency,
    declared: dict[tuple[str, str], dict[str, str]],
    attributes: dict[tuple[str, str], dict[str, str]],
) -> str:
    sibling = _DECLARATION_FOR_LOCK.get(dependency.filename)
    if sibling is None:
        return Directness.UNKNOWN.value
    key = (dependency.directory, sibling)
    if key not in attributes:
        return Directness.UNKNOWN.value
    names = declared.get(key, {})
    if dependency.normalized_name in names:
        recorded = names[dependency.normalized_name]
        return recorded if recorded != Directness.UNKNOWN.value else Directness.DIRECT.value
    # Workspace members declare their own dependencies in nested package.json files.
    if attributes[key].get(WORKSPACES_ATTRIBUTE) == "true":
        return Directness.UNKNOWN.value
    return Directness.TRANSITIVE.value
