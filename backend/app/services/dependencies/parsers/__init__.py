"""Dispatch a dependency manifest to its ecosystem parser."""

from collections.abc import Callable

from app.core.config import Settings
from app.services.dependencies.parsers.common import dedupe_in_file
from app.services.dependencies.parsers.go import parse_go_mod, parse_go_sum
from app.services.dependencies.parsers.java import parse_gradle, parse_pom
from app.services.dependencies.parsers.javascript import (
    parse_package_json,
    parse_package_lock,
    parse_pnpm_lock,
    parse_yarn_lock,
)
from app.services.dependencies.parsers.python import (
    parse_pipfile,
    parse_poetry_lock,
    parse_pyproject,
    parse_requirements,
)
from app.services.dependencies.parsers.rust import parse_cargo_lock, parse_cargo_toml
from app.services.dependencies.types import ManifestParse

Parser = Callable[[str, str, Settings], ManifestParse]

_PARSERS: dict[str, Parser] = {
    "pyproject.toml": parse_pyproject,
    "pipfile": parse_pipfile,
    "poetry.lock": parse_poetry_lock,
    "pom.xml": parse_pom,
    "build.gradle": parse_gradle,
    "build.gradle.kts": parse_gradle,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "cargo.toml": parse_cargo_toml,
    "cargo.lock": parse_cargo_lock,
}


def parser_for(file_path: str) -> Parser | None:
    name = file_path.rsplit("/", 1)[-1].lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements
    return _PARSERS.get(name)


def is_dependency_manifest(file_path: str) -> bool:
    return parser_for(file_path) is not None


def parse_manifest(text: str, file_path: str, settings: Settings) -> ManifestParse:
    parser = parser_for(file_path)
    if parser is None:
        return ManifestParse()
    parsed = parser(text, file_path, settings)
    parsed.dependencies = dedupe_in_file(parsed.dependencies)
    return parsed
