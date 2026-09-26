"""Static C/C++ dependency parsing and Botan configure.py limitation."""

from pathlib import Path

from app.core.config import Settings
from app.services.ingestion.manifest import build_manifest
from app.services.scanner.engine import scan_manifest

CMAKE = """
cmake_minimum_required(VERSION 3.16)
project(demo)
find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)
FetchContent_Declare(
  botan
  GIT_REPOSITORY https://github.com/randombit/botan.git
  GIT_TAG 3.4.0
)
pkg_check_modules(SODIUM libsodium)
"""

CONAN_TXT = """
[requires]
openssl/3.2.0
botan/3.4.0
boost/1.84.0
[tool_requires]
cmake/3.27.0
"""

CONAN_PY = """
from conan import ConanFile
class Demo(ConanFile):
    def requirements(self):
        self.requires("openssl/3.1.0")
        self.requires("mbedtls/3.5.0")
"""

VCPKG = """
{
  "dependencies": [
    "openssl",
    {"name": "botan", "version>=": "3.0.0"},
    {"name": "zlib", "version": "1.3"}
  ]
}
"""

CONFIGURE_ONLY = """
#!/usr/bin/env python3
# Botan-style configure script. Not a declarative dependency manifest.
import sys
print("this file is never executed by the scanner")
"""


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


def _scan(tmp_path: Path, files: dict[str, str]):
    root = tmp_path / "source"
    for relative, content in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    settings = _settings(tmp_path)
    return scan_manifest(root, build_manifest(root, settings), settings)


def _dep(run, name: str):
    matches = [item for item in run.dependencies if item.name.lower() == name.lower()]
    assert matches, [item.name for item in run.dependencies]
    return matches[0]


def test_cmake_conan_and_vcpkg_are_parsed_statically(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "CMakeLists.txt": CMAKE,
            "conanfile.txt": CONAN_TXT,
            "conanfile.py": CONAN_PY,
            "vcpkg.json": VCPKG,
        },
    )
    openssl = _dep(run, "OpenSSL")
    assert openssl.ecosystem == "cpp"
    assert openssl.version_constraint == "3.0"
    assert openssl.version is None
    assert openssl.direct_or_transitive == "direct"
    assert openssl.crypto_relevance == "cryptographic_library"
    assert openssl.library == "OpenSSL"
    botan = next(item for item in run.dependencies if item.name.lower() == "botan" and "CMakeLists" in item.manifest_file)
    assert botan.version == "3.4.0"
    assert botan.library == "Botan"
    assert _dep(run, "libsodium").library == "libsodium"
    conan_openssl = next(item for item in run.dependencies if item.name == "openssl" and item.manifest_file == "conanfile.txt")
    assert conan_openssl.version == "3.2.0"
    py_openssl = next(item for item in run.dependencies if item.manifest_file == "conanfile.py" and item.name == "openssl")
    assert py_openssl.version == "3.1.0"
    vcpkg_botan = next(item for item in run.dependencies if item.manifest_file == "vcpkg.json" and item.name == "botan")
    assert vcpkg_botan.version is None
    assert vcpkg_botan.version_constraint == ">=3.0.0"
    zlib = _dep(run, "zlib")
    assert zlib.crypto_relevance == "non_crypto"
    assert zlib.version == "1.3"
    assert all(item.algorithm is None for item in run.findings if item.usage == "dependency_only")


def test_configure_py_is_not_a_cpp_dependency_manifest(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"configure.py": CONFIGURE_ONLY, "readme.rst": "Build with configure.py\n"})
    assert run.dependencies == []
    assert not any(item.usage == "dependency_only" for item in run.findings)


def test_botan_workspace_uses_configure_py_not_third_party_manifests(tmp_path: Path) -> None:
    botan = Path(__file__).resolve().parents[1] / "workspaces/projects/7/source"
    if not botan.is_dir():
        run = _scan(tmp_path, {"configure.py": CONFIGURE_ONLY})
        assert run.dependencies == []
        return
    tracked = [
        path.relative_to(botan).as_posix()
        for path in botan.rglob("*")
        if path.is_file() and ".git" not in path.parts
    ]
    names = {Path(path).name.lower() for path in tracked}
    assert (botan / "configure.py").is_file()
    assert "vcpkg.json" not in names
    assert "conanfile.txt" not in names
    assert "conanfile.py" not in names
    cmake = [path for path in tracked if Path(path).name.lower() == "cmakelists.txt"]
    assert cmake == ["src/scripts/ci/cmake_tests/CMakeLists.txt"]
    run = _scan(tmp_path, {"src/scripts/ci/cmake_tests/CMakeLists.txt": (botan / cmake[0]).read_text(encoding="utf-8")})
    botan_deps = [item for item in run.dependencies if item.name.lower() == "botan"]
    assert botan_deps
    assert all(item.ecosystem == "cpp" for item in botan_deps)
    assert all(item.version is None or not item.version.startswith("$") for item in botan_deps)
