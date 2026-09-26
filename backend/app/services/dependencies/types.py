"""Dependency records produced by manifest parsers."""

import re
from dataclasses import dataclass, field
from enum import Enum


class Ecosystem(str, Enum):
    PYTHON = "python"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    GO = "go"
    RUST = "rust"
    CPP = "cpp"


class DependencyType(str, Enum):
    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    TEST = "test"
    OPTIONAL = "optional"
    PEER = "peer"
    PROVIDED = "provided"
    BUILD = "build"
    UNKNOWN = "unknown"


class Directness(str, Enum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class CryptoRelevance(str, Enum):
    CRYPTOGRAPHIC_LIBRARY = "cryptographic_library"
    CRYPTO_RELATED = "crypto_related"
    NON_CRYPTO = "non_crypto"
    UNKNOWN = "unknown"


class RelationshipType(str, Enum):
    DECLARED_DEPENDENCY = "declared_dependency"
    DETECTED_CRYPTO_LIBRARY = "detected_crypto_library"
    FINDING_USES_DEPENDENCY = "finding_uses_dependency"
    TRANSITIVE_DEPENDENCY = "transitive_dependency"
    DEPENDENCY_ONLY = "dependency_only"


_PYTHON_SEPARATORS = re.compile(r"[-_.]+")


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == Ecosystem.PYTHON.value:
        return _PYTHON_SEPARATORS.sub("-", name).lower()
    if ecosystem in {Ecosystem.JAVASCRIPT.value, Ecosystem.RUST.value, Ecosystem.CPP.value}:
        return name.lower()
    return name


@dataclass
class DeclaredDependency:
    name: str
    ecosystem: str
    manifest_file: str
    source_line: int
    raw_declaration: str
    version: str | None = None
    version_constraint: str | None = None
    dependency_type: str = DependencyType.UNKNOWN.value
    direct_or_transitive: str = Directness.UNKNOWN.value
    # Names this package depends on, as recorded by a lockfile entry.
    requires: tuple[str, ...] = ()
    # Names recorded as pulling this package in (pip-compile "# via" notes).
    required_by: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)
    crypto_relevance: str = CryptoRelevance.NON_CRYPTO.value
    library: str | None = None

    @property
    def normalized_name(self) -> str:
        return normalize_name(self.ecosystem, self.name)

    @property
    def directory(self) -> str:
        return self.manifest_file.rsplit("/", 1)[0] if "/" in self.manifest_file else ""

    @property
    def filename(self) -> str:
        return self.manifest_file.rsplit("/", 1)[-1].lower()


@dataclass
class ManifestParse:
    dependencies: list[DeclaredDependency] = field(default_factory=list)
    malformed: bool = False
    # Facts about the manifest itself that affect how siblings are read.
    attributes: dict[str, str] = field(default_factory=dict)
