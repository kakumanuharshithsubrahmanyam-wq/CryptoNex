"""Read CBOM, inventory, and graph documents for a scan."""

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models.artifact import SecurityArtifact
from app.models.cbom import Cbom, CbomComponent, CbomRelationship
from app.models.dependency import Dependency, DependencyRelationship
from app.models.project import Project
from app.models.scan import CryptoFinding, Scan
from app.schemas.cbom import CbomResponse, GraphResponse, InventoryResponse
from app.services.cbom.builder import build_cbom_document
from app.services.graph.builder import build_graph, filter_graph


def get_cbom(session: Session, scan: Scan) -> CbomResponse:
    row = session.scalar(select(Cbom).where(Cbom.scan_id == scan.id))
    if row is None:
        document = _rebuild(session, scan)
    else:
        document = json.loads(row.payload_json)
    return CbomResponse.model_validate(document)


def export_cbom_bytes(session: Session, scan: Scan) -> bytes:
    document = get_cbom(session, scan).model_dump()
    return json.dumps(document, indent=2, sort_keys=True).encode("utf-8")


def inventory(session: Session, scan: Scan) -> InventoryResponse:
    """List algorithms actually used in stored CryptoFinding rows.

    Inventory algorithms come only from findings whose algorithm is set and
    whose usage is not dependency_only. Certificate, key, protocol, and
    cipher-suite artifact algorithms are excluded here; they remain on the
    graph and artifact list with evidence_origins other than crypto_finding.
    """
    findings = session.scalars(select(CryptoFinding).where(CryptoFinding.scan_id == scan.id)).all()
    dependencies = session.scalars(select(Dependency).where(Dependency.scan_id == scan.id)).all()
    artifacts = session.scalars(select(SecurityArtifact).where(SecurityArtifact.scan_id == scan.id)).all()
    algorithms: dict[str, int] = {}
    libraries: set[str] = set()
    locations: set[str] = set()
    for finding in findings:
        if finding.algorithm and finding.usage != "dependency_only":
            algorithms[finding.algorithm] = algorithms.get(finding.algorithm, 0) + 1
        if finding.library:
            libraries.add(finding.library)
        locations.add(finding.file_path)
    protocols: dict[str, int] = {}
    suites: set[str] = set()
    certificates = 0
    for artifact in artifacts:
        locations.add(artifact.file_path)
        if artifact.artifact_type == "certificate":
            certificates += 1
        if artifact.artifact_type in {"protocol", "ssh_config"} and artifact.protocol:
            meta = json.loads(artifact.metadata_json or "{}")
            label = f"{artifact.protocol} {meta['tls_version']}" if meta.get("tls_version") else artifact.protocol
            protocols[label] = protocols.get(label, 0) + 1
        if artifact.cipher_suite:
            suites.add(artifact.cipher_suite)
    return InventoryResponse(
        scan_id=scan.id,
        algorithms={name: algorithms[name] for name in sorted(algorithms)},
        libraries=sorted(libraries),
        dependencies=sorted({item.name for item in dependencies}),
        certificates=certificates,
        protocols={name: protocols[name] for name in sorted(protocols)},
        cipher_suites=sorted(suites),
        source_locations=sorted(locations),
    )


def graph(
    session: Session,
    scan: Scan,
    node_type: str | None = None,
    algorithm: str | None = None,
    file_path: str | None = None,
    dependency: str | None = None,
) -> GraphResponse:
    project = session.get(Project, scan.project_id)
    if project is None:
        raise AppError("SCAN_NOT_FOUND", "Scan not found.", status_code=404)
    findings = session.scalars(select(CryptoFinding).where(CryptoFinding.scan_id == scan.id)).all()
    dependencies = session.scalars(select(Dependency).where(Dependency.scan_id == scan.id)).all()
    artifacts = session.scalars(select(SecurityArtifact).where(SecurityArtifact.scan_id == scan.id)).all()
    links = session.scalars(select(DependencyRelationship).where(DependencyRelationship.scan_id == scan.id)).all()
    cbom = session.scalar(select(Cbom).where(Cbom.scan_id == scan.id))
    components = []
    relationships = []
    if cbom is not None:
        components = session.scalars(select(CbomComponent).where(CbomComponent.cbom_id == cbom.id)).all()
        relationships = session.scalars(select(CbomRelationship).where(CbomRelationship.cbom_id == cbom.id)).all()
    document = build_graph(project, scan, list(findings), list(dependencies), list(artifacts), list(links), cbom, list(components), list(relationships))
    filtered = filter_graph(document, node_type, algorithm, file_path, dependency)
    return GraphResponse.model_validate(filtered)


def _rebuild(session: Session, scan: Scan) -> dict:
    findings = session.scalars(select(CryptoFinding).where(CryptoFinding.scan_id == scan.id)).all()
    dependencies = session.scalars(select(Dependency).where(Dependency.scan_id == scan.id)).all()
    artifacts = session.scalars(select(SecurityArtifact).where(SecurityArtifact.scan_id == scan.id)).all()
    links = session.scalars(select(DependencyRelationship).where(DependencyRelationship.scan_id == scan.id)).all()
    return build_cbom_document(scan, list(findings), list(dependencies), list(artifacts), list(links))
