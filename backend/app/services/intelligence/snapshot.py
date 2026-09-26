"""Load stored scan records used by migration, AI, policy, and report services."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models.artifact import SecurityArtifact
from app.models.cbom import Cbom, CbomComponent, CbomRelationship
from app.models.dependency import Dependency, DependencyRelationship
from app.models.project import Project
from app.models.scan import CryptoFinding, Scan
from app.services.graph.builder import build_graph


@dataclass
class ScanSnapshot:
    project: Project
    scan: Scan
    findings: list[CryptoFinding]
    dependencies: list[Dependency]
    links: list[DependencyRelationship]
    artifacts: list[SecurityArtifact]
    cbom: Cbom | None
    components: list[CbomComponent]
    cbom_relationships: list[CbomRelationship]
    graph: dict

    def finding(self, finding_id: int) -> CryptoFinding:
        for row in self.findings:
            if row.id == finding_id:
                return row
        raise AppError("FINDING_NOT_FOUND", "Finding not found in this scan.", status_code=404)

    def finding_map(self) -> dict[int, CryptoFinding]:
        return {row.id: row for row in self.findings}

    def dependency_map(self) -> dict[int, Dependency]:
        return {row.id: row for row in self.dependencies}


def load_snapshot(session: Session, scan: Scan) -> ScanSnapshot:
    project = session.get(Project, scan.project_id)
    if project is None:
        raise AppError("SCAN_NOT_FOUND", "Scan not found.", status_code=404)
    findings = list(
        session.scalars(select(CryptoFinding).where(CryptoFinding.scan_id == scan.id).order_by(CryptoFinding.id))
    )
    dependencies = list(
        session.scalars(select(Dependency).where(Dependency.scan_id == scan.id).order_by(Dependency.id))
    )
    links = list(
        session.scalars(
            select(DependencyRelationship).where(DependencyRelationship.scan_id == scan.id).order_by(DependencyRelationship.id)
        )
    )
    artifacts = list(
        session.scalars(select(SecurityArtifact).where(SecurityArtifact.scan_id == scan.id).order_by(SecurityArtifact.id))
    )
    cbom = session.scalar(select(Cbom).where(Cbom.scan_id == scan.id))
    components: list[CbomComponent] = []
    relationships: list[CbomRelationship] = []
    if cbom is not None:
        components = list(
            session.scalars(select(CbomComponent).where(CbomComponent.cbom_id == cbom.id).order_by(CbomComponent.id))
        )
        relationships = list(
            session.scalars(
                select(CbomRelationship).where(CbomRelationship.cbom_id == cbom.id).order_by(CbomRelationship.id)
            )
        )
    graph = build_graph(
        project,
        scan,
        findings,
        dependencies,
        artifacts,
        links,
        cbom,
        components,
        relationships,
    )
    return ScanSnapshot(
        project=project,
        scan=scan,
        findings=findings,
        dependencies=dependencies,
        links=links,
        artifacts=artifacts,
        cbom=cbom,
        components=components,
        cbom_relationships=relationships,
        graph=graph,
    )
