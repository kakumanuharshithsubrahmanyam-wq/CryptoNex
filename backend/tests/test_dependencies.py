"""Static dependency inventory and finding-to-dependency links."""

from dataclasses import asdict
from pathlib import Path

import pytest

from app.core.config import Settings
from app.services.dependencies.inventory import build_inventory
from app.services.dependencies.linking import apply_declared_versions, link_all
from app.services.dependencies.parsers import parse_manifest
from app.services.dependencies.types import DeclaredDependency
from app.services.ingestion.manifest import build_manifest
from app.services.scanner.engine import scan_manifest

REQUIREMENTS = """\
cryptography==42.0.5
requests>=2.31,<3
flask
cryptography==42.0.5
pyjwt[crypto]==2.8.0 ; python_version >= "3.8"
private-pkg @ git+https://alice:secret-token@github.com/org/private.git
-e git+https://bob:other-token@github.com/org/editable.git#egg=editable
git+https://carol:third-token@github.com/org/raw.git
"""

PIP_COMPILE = """\
cffi==1.16.0
    # via cryptography
cryptography==42.0.5
    # via
    #   -r requirements.in
    #   paramiko
"""

PYPROJECT = """\
[project]
name = "demo"
dependencies = [
  "cryptography>=42,<44",
  "pynacl==1.5.0",
]

[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.poetry.dependencies]
python = "^3.11"
pycryptodome = "3.20.0"
bcrypt = "^4.1"
"""

POETRY_LOCK = """\
[[package]]
name = "cffi"
version = "1.16.0"

[[package]]
name = "cryptography"
version = "42.0.5"

[package.dependencies]
cffi = ">=1.12"
"""

PIPFILE = """\
[packages]
cryptography = "==42.0.5"
requests = "*"

[dev-packages]
pytest = ">=8"
"""

POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <version>1.0.0</version>
  <properties>
    <bc.version>1.78</bc.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.70</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${bc.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>[4.12,5.0)</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>unversioned</artifactId>
    </dependency>
  </dependencies>
</project>
"""

GRADLE = """\
dependencies {
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78'
    testImplementation "junit:junit:4.13.2"
    // implementation 'com.google.crypto.tink:tink:1.12.0'
    implementation "com.google.guava:guava:$guavaVersion"
    implementation 'io.jsonwebtoken:jjwt-api:0.12.+'
}
"""

PACKAGE_JSON = """\
{
  "name": "web",
  "dependencies": {
    "crypto-js": "^4.2.0",
    "express": "4.19.2"
  },
  "devDependencies": {
    "typescript": "~5.4.0"
  }
}
"""

PACKAGE_LOCK = """\
{
  "name": "web",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "web",
      "dependencies": {
        "crypto-js": "^4.2.0",
        "express": "4.19.2"
      },
      "devDependencies": {
        "typescript": "~5.4.0"
      }
    },
    "node_modules/crypto-js": {
      "version": "4.2.0"
    },
    "node_modules/express": {
      "version": "4.19.2",
      "dependencies": {
        "node-forge": "^1.3.0"
      }
    },
    "node_modules/express/node_modules/crypto-js": {
      "version": "3.3.0"
    },
    "node_modules/node-forge": {
      "version": "1.3.1"
    },
    "node_modules/typescript": {
      "version": "5.4.5",
      "dev": true
    }
  }
}
"""

YARN_PACKAGE_JSON = '{"dependencies": {"tweetnacl": "^1.0.3"}}\n'

YARN_LOCK = """\
# yarn lockfile v1


"@noble/hashes@^1.3.0":
  version "1.3.3"
  resolved "https://registry.yarnpkg.com/@noble/hashes/-/hashes-1.3.3.tgz"

tweetnacl@^1.0.3:
  version "1.0.3"
  dependencies:
    "@noble/hashes" "^1.3.0"
"""

PNPM_PACKAGE_JSON = '{"dependencies": {"jose": "^5.2.0"}}\n'

PNPM_LOCK = """\
lockfileVersion: '6.0'

dependencies:
  jose:
    specifier: ^5.2.0
    version: 5.2.0

packages:

  /jose@5.2.0:
    resolution: {integrity: sha512-abc}
    dev: false
    dependencies:
      '@noble/hashes': 1.3.3

  /@noble/hashes@1.3.3:
    resolution: {integrity: sha512-def}
    dev: false
"""

GO_MOD = """\
module example.com/svc

go 1.22

require (
\tgolang.org/x/crypto v0.28.0
\tgithub.com/google/uuid v1.6.0 // indirect
)

require github.com/cloudflare/circl v1.3.7
"""

GO_SUM = """\
golang.org/x/crypto v0.28.0 h1:aaaa=
golang.org/x/crypto v0.28.0/go.mod h1:bbbb=
golang.org/x/sys v0.26.0 h1:cccc=
"""

CARGO_TOML = """\
[package]
name = "svc"
version = "0.1.0"

[dependencies]
ring = "0.17"
sha2 = { version = "=0.10.8" }
serde = "1"

[dev-dependencies]
hex = "0.4"
"""

CARGO_LOCK = """\
version = 3

[[package]]
name = "cc"
version = "1.0.90"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "ring"
version = "0.17.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "cc",
]

[[package]]
name = "svc"
version = "0.1.0"
dependencies = [
 "ring",
]
"""


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


def _inventory(tmp_path: Path, files: dict[str, str]) -> list[DeclaredDependency]:
    settings = _settings(tmp_path)
    parsed = {path: parse_manifest(text, path, settings) for path, text in files.items()}
    dependencies = [item for result in parsed.values() for item in result.dependencies]
    return build_inventory(dependencies, {path: result.attributes for path, result in parsed.items()})


def _dep(dependencies: list[DeclaredDependency], name: str, manifest: str | None = None, **expected):
    matches = [
        item
        for item in dependencies
        if item.name == name
        and (manifest is None or item.manifest_file == manifest)
        and all(getattr(item, key) == value for key, value in expected.items())
    ]
    assert matches, [(item.name, item.manifest_file, item.version) for item in dependencies]
    return matches[0]


def _scan(tmp_path: Path, files: dict[str, str]):
    root = tmp_path / "source"
    for relative, content in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    settings = _settings(tmp_path)
    return scan_manifest(root, build_manifest(root, settings), settings)


def test_requirements_versions_constraints_and_duplicates(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"requirements.txt": REQUIREMENTS})
    cryptography = [item for item in deps if item.name == "cryptography"]
    assert len(cryptography) == 1
    assert cryptography[0].version == "42.0.5"
    assert cryptography[0].version_constraint is None
    assert cryptography[0].source_line == 1
    assert cryptography[0].raw_declaration == "cryptography==42.0.5"
    assert cryptography[0].ecosystem == "python"
    assert cryptography[0].crypto_relevance == "cryptographic_library"
    assert cryptography[0].direct_or_transitive == "unknown"

    requests = _dep(deps, "requests", version=None)
    assert requests.version_constraint == ">=2.31,<3"
    assert requests.crypto_relevance == "non_crypto"
    assert requests.library is None
    flask = _dep(deps, "flask")
    assert (flask.version, flask.version_constraint) == (None, None)
    assert _dep(deps, "pyjwt").version == "2.8.0"
    assert _dep(deps, "pyjwt").crypto_relevance == "crypto_related"
    private = _dep(deps, "private-pkg")
    assert private.metadata == {"source": "direct_reference"}
    assert "secret-token" not in private.raw_declaration
    assert {item.name for item in deps} == {"cryptography", "requests", "flask", "pyjwt", "private-pkg"}


def test_pip_compile_annotations_set_direct_and_transitive(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"requirements.txt": PIP_COMPILE})
    assert _dep(deps, "cryptography").direct_or_transitive == "direct"
    cffi = _dep(deps, "cffi")
    assert cffi.direct_or_transitive == "transitive"
    links = link_all([], deps)
    edges = {
        (deps[link.source_dependency_index].name, deps[link.dependency_index].name)
        for link in links
        if link.relationship_type == "transitive_dependency"
    }
    assert ("cryptography", "cffi") in edges


def test_pyproject_pep621_and_poetry(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"pyproject.toml": PYPROJECT})
    cryptography = _dep(deps, "cryptography")
    assert (cryptography.version, cryptography.version_constraint) == (None, ">=42,<44")
    assert cryptography.source_line == 4
    assert cryptography.dependency_type == "runtime"
    assert cryptography.direct_or_transitive == "direct"
    assert _dep(deps, "pynacl").version == "1.5.0"
    assert _dep(deps, "pytest").dependency_type == "optional"
    assert _dep(deps, "pycryptodome").version == "3.20.0"
    assert _dep(deps, "pycryptodome").source_line == 13
    assert _dep(deps, "bcrypt").version_constraint == "^4.1"
    assert not [item for item in deps if item.name == "python"]


def test_poetry_lock_uses_pyproject_for_directness(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"pyproject.toml": PYPROJECT, "poetry.lock": POETRY_LOCK})
    locked = _dep(deps, "cryptography", "poetry.lock")
    assert locked.version == "42.0.5"
    assert locked.direct_or_transitive == "direct"
    assert locked.source_line == 6
    assert 'version = "42.0.5"' in locked.raw_declaration
    cffi = _dep(deps, "cffi", "poetry.lock")
    assert cffi.direct_or_transitive == "transitive"
    edges = [link for link in link_all([], deps) if link.relationship_type == "transitive_dependency"]
    assert any(deps[link.dependency_index].name == "cffi" and deps[link.source_dependency_index].name == "cryptography" for link in edges)


def test_poetry_lock_without_pyproject_is_unknown(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"poetry.lock": POETRY_LOCK})
    assert {item.direct_or_transitive for item in deps} == {"unknown"}


def test_pipfile(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"Pipfile": PIPFILE})
    assert _dep(deps, "cryptography").version == "42.0.5"
    requests = _dep(deps, "requests")
    assert (requests.version, requests.version_constraint) == (None, None)
    assert _dep(deps, "pytest").dependency_type == "development"
    assert _dep(deps, "pytest").version_constraint == ">=8"


def test_pom_properties_scopes_and_management(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"pom.xml": POM})
    bouncy = _dep(deps, "org.bouncycastle:bcprov-jdk18on")
    assert bouncy.version == "1.78"
    assert bouncy.library == "Bouncy Castle"
    assert bouncy.source_line == 20
    assert "bcprov-jdk18on" in bouncy.raw_declaration
    assert len([item for item in deps if item.name == "org.bouncycastle:bcprov-jdk18on"]) == 1
    junit = _dep(deps, "junit:junit")
    assert (junit.version, junit.version_constraint) == (None, "[4.12,5.0)")
    assert junit.dependency_type == "test"
    assert _dep(deps, "com.example:unversioned").version is None


def test_pom_with_doctype_is_rejected(tmp_path: Path) -> None:
    hostile = '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x "boom">]><project>&x;</project>'
    parsed = parse_manifest(hostile, "pom.xml", _settings(tmp_path))
    assert parsed.malformed
    assert parsed.dependencies == []


def test_gradle(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"build.gradle": GRADLE})
    bouncy = _dep(deps, "org.bouncycastle:bcprov-jdk18on")
    assert (bouncy.version, bouncy.source_line, bouncy.dependency_type) == ("1.78", 2, "runtime")
    assert _dep(deps, "junit:junit").dependency_type == "test"
    guava = _dep(deps, "com.google.guava:guava")
    assert guava.version is None
    assert guava.metadata == {"version_expression": "$guavaVersion"}
    jjwt = _dep(deps, "io.jsonwebtoken:jjwt-api")
    assert jjwt.version_constraint == "0.12.+"
    assert jjwt.crypto_relevance == "crypto_related"
    assert not [item for item in deps if "tink" in item.name]


def test_package_json_and_lock(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"web/package.json": PACKAGE_JSON, "web/package-lock.json": PACKAGE_LOCK})
    declared = _dep(deps, "crypto-js", "web/package.json")
    assert (declared.version, declared.version_constraint) == (None, "^4.2.0")
    assert declared.dependency_type == "runtime"
    assert declared.direct_or_transitive == "direct"
    assert declared.source_line == 4
    assert _dep(deps, "express", "web/package.json").version == "4.19.2"
    assert _dep(deps, "typescript", "web/package.json").dependency_type == "development"

    locked = _dep(deps, "crypto-js", "web/package-lock.json", version="4.2.0")
    assert locked.direct_or_transitive == "direct"
    nested = _dep(deps, "crypto-js", "web/package-lock.json", version="3.3.0")
    assert nested.direct_or_transitive == "transitive"
    forge = _dep(deps, "node-forge", "web/package-lock.json")
    assert forge.direct_or_transitive == "transitive"
    assert forge.crypto_relevance == "cryptographic_library"
    assert _dep(deps, "typescript", "web/package-lock.json").dependency_type == "development"
    edges = {
        (deps[link.source_dependency_index].name, deps[link.dependency_index].name)
        for link in link_all([], deps)
        if link.relationship_type == "transitive_dependency"
    }
    assert ("express", "node-forge") in edges


def test_yarn_lock_directness_from_package_json(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"app/package.json": YARN_PACKAGE_JSON, "app/yarn.lock": YARN_LOCK})
    tweetnacl = _dep(deps, "tweetnacl", "app/yarn.lock")
    assert (tweetnacl.version, tweetnacl.direct_or_transitive) == ("1.0.3", "direct")
    noble = _dep(deps, "@noble/hashes", "app/yarn.lock")
    assert (noble.version, noble.direct_or_transitive) == ("1.3.3", "transitive")
    assert noble.source_line == 4
    assert tweetnacl.requires == ("@noble/hashes",)


def test_pnpm_lock(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"app/package.json": PNPM_PACKAGE_JSON, "app/pnpm-lock.yaml": PNPM_LOCK})
    jose = _dep(deps, "jose", "app/pnpm-lock.yaml")
    assert (jose.version, jose.direct_or_transitive, jose.crypto_relevance) == ("5.2.0", "direct", "crypto_related")
    noble = _dep(deps, "@noble/hashes", "app/pnpm-lock.yaml")
    assert (noble.version, noble.direct_or_transitive) == ("1.3.3", "transitive")
    assert jose.requires == ("@noble/hashes",)


def test_workspace_root_leaves_undeclared_lock_entries_unknown(tmp_path: Path) -> None:
    deps = _inventory(
        tmp_path,
        {"package.json": '{"workspaces": ["packages/*"]}', "package-lock.json": '{"dependencies": {"left-pad": {"version": "1.3.0"}}}'},
    )
    assert _dep(deps, "left-pad").direct_or_transitive == "unknown"


def test_go_mod_and_go_sum(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"svc/go.mod": GO_MOD, "svc/go.sum": GO_SUM})
    crypto = _dep(deps, "golang.org/x/crypto", "svc/go.mod")
    assert (crypto.version, crypto.direct_or_transitive, crypto.source_line) == ("v0.28.0", "direct", 6)
    assert crypto.library == "golang.org/x/crypto"
    uuid = _dep(deps, "github.com/google/uuid", "svc/go.mod")
    assert uuid.direct_or_transitive == "transitive"
    assert uuid.crypto_relevance == "non_crypto"
    assert _dep(deps, "github.com/cloudflare/circl").direct_or_transitive == "direct"
    summed = [item for item in deps if item.manifest_file == "svc/go.sum"]
    assert [(item.name, item.version) for item in summed] == [
        ("golang.org/x/crypto", "v0.28.0"),
        ("golang.org/x/sys", "v0.26.0"),
    ]
    assert _dep(deps, "golang.org/x/crypto", "svc/go.sum").direct_or_transitive == "direct"
    assert _dep(deps, "golang.org/x/sys", "svc/go.sum").direct_or_transitive == "transitive"
    assert "h1:" not in _dep(deps, "golang.org/x/sys").raw_declaration


def test_cargo_toml_and_lock(tmp_path: Path) -> None:
    deps = _inventory(tmp_path, {"Cargo.toml": CARGO_TOML, "Cargo.lock": CARGO_LOCK})
    ring = _dep(deps, "ring", "Cargo.toml")
    assert (ring.version, ring.version_constraint, ring.crypto_relevance) == (None, "0.17", "cryptographic_library")
    sha2 = _dep(deps, "sha2", "Cargo.toml")
    assert (sha2.version, sha2.version_constraint) == ("0.10.8", None)
    assert _dep(deps, "hex").dependency_type == "development"
    assert _dep(deps, "serde").crypto_relevance == "non_crypto"
    locked_ring = _dep(deps, "ring", "Cargo.lock")
    assert (locked_ring.version, locked_ring.direct_or_transitive) == ("0.17.8", "direct")
    assert _dep(deps, "cc", "Cargo.lock").direct_or_transitive == "transitive"
    assert not [item for item in deps if item.name == "svc"]


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("package.json", "{not json"),
        ("package-lock.json", "[1, 2"),
        ("pyproject.toml", "[project\nname ="),
        ("Pipfile", "[packages\n"),
        ("poetry.lock", "[[package]\n"),
        ("Cargo.toml", "[dependencies\nring ="),
        ("Cargo.lock", "[[package\n"),
        ("pom.xml", "<project><dependencies>"),
    ],
)
def test_malformed_manifests_are_reported(tmp_path: Path, path: str, text: str) -> None:
    parsed = parse_manifest(text, path, _settings(tmp_path))
    assert parsed.malformed
    assert parsed.dependencies == []


def test_malformed_manifest_is_counted_and_scan_continues(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"package.json": "{broken", "requirements.txt": "cryptography==42.0.5\n"})
    assert run.malformed_manifests == 1
    assert [item.name for item in run.dependencies] == ["cryptography"]


def test_finding_links_to_declared_dependency_and_version(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "requirements.txt": "cryptography==42.0.5\n",
            "src/auth.py": (
                "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            ),
        },
    )
    links = link_all(run.findings, run.dependencies)
    apply_declared_versions(run.findings, run.dependencies, links)
    rsa_index = next(index for index, item in enumerate(run.findings) if item.algorithm == "RSA")
    dependency_index = next(index for index, item in enumerate(run.findings) if item.usage == "dependency_only")
    usage = [link for link in links if link.finding_index == rsa_index]
    assert [(link.relationship_type, run.dependencies[link.dependency_index].name) for link in usage] == [
        ("finding_uses_dependency", "cryptography")
    ]
    assert run.findings[rsa_index].library_version == "42.0.5"
    only = [link for link in links if link.finding_index == dependency_index]
    assert [link.relationship_type for link in only] == ["dependency_only"]
    assert run.findings[dependency_index].algorithm is None


def test_constraint_only_declaration_links_without_version(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "x"\ndependencies = ["cryptography>=42"]\n',
            "app.py": "from cryptography.hazmat.primitives import hashes\nhashes.SHA256()\n",
        },
    )
    links = link_all(run.findings, run.dependencies)
    apply_declared_versions(run.findings, run.dependencies, links)
    finding = next(item for item in run.findings if item.algorithm == "SHA-256")
    assert any(link.relationship_type == "finding_uses_dependency" for link in links)
    assert finding.library_version is None


def test_links_prefer_nearest_manifest_and_ignore_sibling_projects(tmp_path: Path) -> None:
    source = "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(key_size=2048, public_exponent=3)\n"
    run = _scan(
        tmp_path,
        {
            "requirements.txt": "cryptography==41.0.0\n",
            "services/a/requirements.txt": "cryptography==42.0.5\n",
            "services/a/app.py": source,
            "services/b/requirements.txt": "cryptography==43.0.0\n",
            "tools/app.py": source,
        },
    )
    links = link_all(run.findings, run.dependencies)
    apply_declared_versions(run.findings, run.dependencies, links)
    by_file = {item.file_path: item for item in run.findings if item.algorithm == "RSA"}
    assert by_file["services/a/app.py"].library_version == "42.0.5"
    assert by_file["tools/app.py"].library_version == "41.0.0"
    targets = {
        run.dependencies[link.dependency_index].manifest_file
        for link in links
        if link.relationship_type == "finding_uses_dependency"
    }
    assert "services/b/requirements.txt" not in targets


def test_platform_apis_do_not_link_to_packages(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "package.json": '{"dependencies": {"crypto": "1.0.1"}}\n',
            "index.js": 'const crypto = require("crypto");\ncrypto.createHash("sha256");\n',
            "go.mod": "module x\nrequire golang.org/x/crypto v0.28.0\n",
            "main.go": 'package main\nimport "crypto/sha256"\nfunc f() { sha256.New() }\n',
        },
    )
    links = link_all(run.findings, run.dependencies)
    assert not [link for link in links if link.relationship_type == "finding_uses_dependency"]
    npm_crypto = next(item for item in run.dependencies if item.name == "crypto")
    assert npm_crypto.crypto_relevance == "unknown"


def test_go_extended_package_links_to_module(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "go.mod": "module x\nrequire golang.org/x/crypto v0.28.0\n",
            "main.go": 'package main\nimport "golang.org/x/crypto/chacha20poly1305"\nfunc f() { chacha20poly1305.New(k) }\n',
        },
    )
    links = link_all(run.findings, run.dependencies)
    apply_declared_versions(run.findings, run.dependencies, links)
    finding = next(item for item in run.findings if item.algorithm == "ChaCha20-Poly1305")
    assert finding.library_version == "v0.28.0"


def test_non_crypto_dependencies_do_not_create_findings(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"requirements.txt": "requests==2.32.0\ncryptocurrency-tools==1.0\nsecure-auth==2.0\n"})
    assert run.findings == []
    assert {item.crypto_relevance for item in run.dependencies} == {"non_crypto"}


def test_repeated_parsing_is_identical(tmp_path: Path) -> None:
    files = {
        "requirements.txt": REQUIREMENTS,
        "pyproject.toml": PYPROJECT,
        "poetry.lock": POETRY_LOCK,
        "web/package.json": PACKAGE_JSON,
        "web/package-lock.json": PACKAGE_LOCK,
        "svc/go.mod": GO_MOD,
        "svc/go.sum": GO_SUM,
        "Cargo.toml": CARGO_TOML,
        "Cargo.lock": CARGO_LOCK,
        "pom.xml": POM,
        "build.gradle": GRADLE,
    }
    first = [asdict(item) for item in _inventory(tmp_path, files)]
    second = [asdict(item) for item in _inventory(tmp_path, dict(reversed(list(files.items()))))]
    assert first == second
    assert first
