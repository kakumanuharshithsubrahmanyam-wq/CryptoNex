"""pom.xml, build.gradle, and build.gradle.kts."""

import re
import xml.etree.ElementTree as ElementTree

from app.core.config import Settings
from app.services.dependencies.parsers.common import line_at, line_evidence
from app.services.dependencies.types import (
    DeclaredDependency,
    DependencyType,
    Directness,
    Ecosystem,
    ManifestParse,
)
from app.services.scanner.evidence import mask_comments, snippet

_JAVA = Ecosystem.JAVA.value
_UNSAFE_XML = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
_PROPERTY = re.compile(r"^\$\{([^}]+)\}$")
_EXCLUDED_BLOCKS = re.compile(
    r"<(dependencyManagement|build|profiles|reporting)\b.*?</\1\s*>", re.DOTALL
)
_MAVEN_SCOPES = {
    "test": DependencyType.TEST,
    "provided": DependencyType.PROVIDED,
    "system": DependencyType.PROVIDED,
    "runtime": DependencyType.RUNTIME,
    "compile": DependencyType.RUNTIME,
    "import": DependencyType.UNKNOWN,
}
_GRADLE_CONFIGURATIONS = {
    "implementation": DependencyType.RUNTIME,
    "api": DependencyType.RUNTIME,
    "compile": DependencyType.RUNTIME,
    "runtime": DependencyType.RUNTIME,
    "runtimeOnly": DependencyType.RUNTIME,
    "compileOnly": DependencyType.PROVIDED,
    "annotationProcessor": DependencyType.BUILD,
    "kapt": DependencyType.BUILD,
    "classpath": DependencyType.BUILD,
    "testImplementation": DependencyType.TEST,
    "testCompile": DependencyType.TEST,
    "testRuntimeOnly": DependencyType.TEST,
    "testCompileOnly": DependencyType.TEST,
    "androidTestImplementation": DependencyType.TEST,
}
_GRADLE_STRING = re.compile(
    r"""^\s*(\w+)\s*\(?\s*["']([^"':\s]+):([^"':\s]+)(?::([^"'\s@]+))?(?:@\w+)?["']"""
)
_GRADLE_MAP = re.compile(
    r"""^\s*(\w+)\s*\(?\s*group\s*[:=]\s*["']([^"']+)["']\s*,\s*name\s*[:=]\s*["']([^"']+)["']"""
    r"""(?:\s*,\s*version\s*[:=]\s*["']([^"']+)["'])?"""
)


def parse_pom(text: str, file_path: str, settings: Settings) -> ManifestParse:
    if _UNSAFE_XML.search(text):
        return ManifestParse(malformed=True)
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return ManifestParse(malformed=True)
    _strip_namespaces(root)
    is_project = root.tag == "project"
    # A document without a <project> root is not a valid POM, but its
    # <dependency> elements are still declarations worth recording.
    elements = root.findall("./dependencies/dependency") if is_project else [
        element for element in root.iter() if element.tag == "dependency"
    ]
    properties = _properties(root) if is_project else {}
    directness = Directness.DIRECT if is_project else Directness.UNKNOWN
    searchable = _EXCLUDED_BLOCKS.sub(lambda match: " " * len(match.group(0)), text)
    lines = text.splitlines()
    result = ManifestParse(malformed=not is_project)
    cursor = 0
    for dependency in elements:
        group = (dependency.findtext("groupId") or "").strip()
        artifact = (dependency.findtext("artifactId") or "").strip()
        if not artifact:
            continue
        version, constraint, metadata = _maven_version((dependency.findtext("version") or "").strip(), properties)
        scope = (dependency.findtext("scope") or "compile").strip().lower()
        dependency_type = _MAVEN_SCOPES.get(scope, DependencyType.UNKNOWN)
        if (dependency.findtext("optional") or "").strip().lower() == "true":
            dependency_type = DependencyType.OPTIONAL
        match = re.compile(rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>").search(searchable, cursor)
        line = line_at(text, match.start()) if match else 1
        if match:
            cursor = match.end()
        result.dependencies.append(
            DeclaredDependency(
                name=f"{group}:{artifact}" if group else artifact,
                ecosystem=_JAVA,
                manifest_file=file_path,
                source_line=line,
                raw_declaration=_pom_evidence(text, match.start() if match else None, lines, line, settings),
                version=version,
                version_constraint=constraint,
                dependency_type=dependency_type.value,
                direct_or_transitive=directness.value,
                metadata=metadata,
            )
        )
    return result


def parse_gradle(text: str, file_path: str, settings: Settings) -> ManifestParse:
    masked, _spans = mask_comments(text, "c")
    lines = text.splitlines()
    result = ManifestParse()
    for number, line in enumerate(masked.splitlines(), start=1):
        match = _GRADLE_STRING.match(line) or _GRADLE_MAP.match(line)
        if not match:
            continue
        configuration = match.group(1)
        if configuration not in _GRADLE_CONFIGURATIONS:
            continue
        version, constraint, metadata = _gradle_version(match.group(4))
        result.dependencies.append(
            DeclaredDependency(
                name=f"{match.group(2)}:{match.group(3)}",
                ecosystem=_JAVA,
                manifest_file=file_path,
                source_line=number,
                raw_declaration=line_evidence(lines, number, settings),
                version=version,
                version_constraint=constraint,
                dependency_type=_GRADLE_CONFIGURATIONS[configuration].value,
                direct_or_transitive=Directness.DIRECT.value,
                metadata=metadata,
            )
        )
    return result


def _strip_namespaces(root: ElementTree.Element) -> None:
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]


def _properties(root: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    block = root.find("properties")
    if block is not None:
        for child in block:
            if isinstance(child.tag, str) and child.text:
                values[child.tag] = child.text.strip()
    project_version = root.findtext("version")
    if project_version:
        values["project.version"] = project_version.strip()
    return values


def _maven_version(raw: str, properties: dict[str, str]) -> tuple[str | None, str | None, dict[str, str]]:
    if not raw:
        return None, None, {}
    reference = _PROPERTY.match(raw)
    if reference:
        resolved = properties.get(reference.group(1))
        if resolved is None or "${" in resolved:
            return None, None, {"version_expression": raw}
        raw = resolved
    if "${" in raw:
        return None, None, {"version_expression": raw}
    if raw[0] in "[(" or "," in raw:
        return None, raw, {}
    return raw, None, {}


def _gradle_version(raw: str | None) -> tuple[str | None, str | None, dict[str, str]]:
    if not raw:
        return None, None, {}
    if "$" in raw:
        return None, None, {"version_expression": raw}
    if "+" in raw or raw[0] in "[(" or raw.startswith("latest."):
        return None, raw, {}
    return raw, None, {}


def _pom_evidence(text: str, offset: int | None, lines: list[str], line: int, settings: Settings) -> str:
    if offset is None:
        return line_evidence(lines, line, settings)
    start = text.rfind("<dependency>", max(0, offset - 400), offset)
    end = text.find("</dependency>", offset, offset + 400)
    if start < 0 or end < 0:
        return line_evidence(lines, line, settings)
    return snippet(text, line_at(text, start), line_at(text, end), settings)
