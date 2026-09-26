"""Stored scan, finding, and dependency inventory routes."""

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.artifact import ArtifactListResponse
from app.schemas.cbom import CbomResponse, GraphResponse, InventoryResponse
from app.schemas.dependency import DependencyListResponse
from app.schemas.intelligence import (
    ArchitectRequest,
    AskRequest,
    MigrationPlanRequest,
    PatchRequest,
    PolicyCheckRequest,
    RootCauseRequest,
    WhatIfRequest,
)
from app.schemas.scan import FindingListResponse, ScanDetailResponse
from app.services.ai.architect import architect_answer
from app.services.ai.qa import ask
from app.services.ai.root_cause import explain_root_causes
from app.services.artifacts.queries import list_artifacts
from app.services.cbom.queries import export_cbom_bytes, get_cbom, graph, inventory
from app.services.dependencies.queries import list_dependencies
from app.services.intelligence.snapshot import load_snapshot
from app.services.migration.queries import custom_migration_plan, finding_blast_radius, migration_for_finding, migrations
from app.services.patches.service import create_finding_patch, read_finding_patch
from app.services.policy.engine import evaluate_scan
from app.services.pqc.agility import analyze_agility
from app.services.pqc.registry import list_pqc, pqc_as_dict
from app.services.pqc.simulator import hybrid_plan, what_if
from app.services.reports.builder import build_report, export_report
from app.services.scanner.queries import get_scan, list_findings, scan_detail

router = APIRouter(prefix="/scans")

_MAX_PAGE = 500


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def read_scan(scan_id: int, session: Session = Depends(get_db)) -> ScanDetailResponse:
    return scan_detail(get_scan(session, scan_id))


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
def read_findings(
    scan_id: int,
    limit: int = Query(100, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> FindingListResponse:
    return list_findings(session, get_scan(session, scan_id), limit, offset)


@router.get("/{scan_id}/dependencies", response_model=DependencyListResponse)
def read_dependencies(
    scan_id: int,
    limit: int = Query(100, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> DependencyListResponse:
    return list_dependencies(session, get_scan(session, scan_id), limit, offset)


@router.get("/{scan_id}/artifacts", response_model=ArtifactListResponse)
def read_artifacts(
    scan_id: int,
    limit: int = Query(100, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> ArtifactListResponse:
    return list_artifacts(session, get_scan(session, scan_id), limit, offset)


@router.get("/{scan_id}/cbom", response_model=CbomResponse)
def read_cbom(scan_id: int, session: Session = Depends(get_db)) -> CbomResponse:
    return get_cbom(session, get_scan(session, scan_id))


@router.get("/{scan_id}/cbom/export")
def export_cbom(scan_id: int, session: Session = Depends(get_db)) -> Response:
    scan = get_scan(session, scan_id)
    payload = export_cbom_bytes(session, scan)
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="cryptonex-cbom-{scan.id}.json"'},
    )


@router.get("/{scan_id}/inventory", response_model=InventoryResponse)
def read_inventory(scan_id: int, session: Session = Depends(get_db)) -> InventoryResponse:
    return inventory(session, get_scan(session, scan_id))


@router.get("/{scan_id}/graph", response_model=GraphResponse)
def read_graph(
    scan_id: int,
    node_type: str | None = None,
    algorithm: str | None = None,
    file_path: str | None = None,
    dependency: str | None = None,
    session: Session = Depends(get_db),
) -> GraphResponse:
    return graph(session, get_scan(session, scan_id), node_type, algorithm, file_path, dependency)


@router.get("/{scan_id}/migrations")
def read_migrations(scan_id: int, session: Session = Depends(get_db)) -> dict:
    return migrations(session, get_scan(session, scan_id))


@router.get("/{scan_id}/migrations/{finding_id}")
def read_migration(scan_id: int, finding_id: int, session: Session = Depends(get_db)) -> dict:
    return migration_for_finding(session, get_scan(session, scan_id), finding_id)


@router.post("/{scan_id}/migration-plan")
def create_migration_plan(
    scan_id: int, body: MigrationPlanRequest, session: Session = Depends(get_db)
) -> dict:
    return custom_migration_plan(session, get_scan(session, scan_id), body.finding_id, body.replacement)


@router.post("/{scan_id}/migrations/{finding_id}/patch")
def create_migration_patch(
    scan_id: int,
    finding_id: int,
    request: Request,
    body: PatchRequest = Body(default_factory=PatchRequest),
    session: Session = Depends(get_db),
) -> dict:
    return create_finding_patch(
        session,
        get_scan(session, scan_id),
        finding_id,
        request.app.state.settings,
        body.replacement,
        body.mode,
    )


@router.get("/{scan_id}/migrations/{finding_id}/patch")
def read_migration_patch(scan_id: int, finding_id: int, session: Session = Depends(get_db)) -> dict:
    return read_finding_patch(session, get_scan(session, scan_id), finding_id)


@router.get("/{scan_id}/blast-radius/{finding_id}")
def read_blast_radius(scan_id: int, finding_id: int, session: Session = Depends(get_db)) -> dict:
    return finding_blast_radius(session, get_scan(session, scan_id), finding_id)


@router.post("/{scan_id}/ai/architect")
def ai_architect(
    scan_id: int,
    request: Request,
    body: ArchitectRequest,
    session: Session = Depends(get_db),
) -> dict:
    snapshot = load_snapshot(session, get_scan(session, scan_id))
    return architect_answer(snapshot, request.app.state.settings, body.question)


@router.post("/{scan_id}/ai/root-cause")
def ai_root_cause(
    scan_id: int,
    request: Request,
    body: RootCauseRequest,
    session: Session = Depends(get_db),
) -> dict:
    snapshot = load_snapshot(session, get_scan(session, scan_id))
    items = explain_root_causes(snapshot, body.finding_id)
    architect = architect_answer(
        snapshot,
        request.app.state.settings,
        "Explain the root cause of the cryptographic findings using only supplied evidence.",
    )
    return {
        "scan_id": scan_id,
        "items": items,
        "explanation": architect["answer"],
        "source": architect["source"],
        "provider_available": architect["provider_available"],
        "caveats": architect["caveats"],
    }


@router.post("/{scan_id}/ask")
def ask_scan(
    scan_id: int,
    request: Request,
    body: AskRequest,
    session: Session = Depends(get_db),
) -> dict:
    snapshot = load_snapshot(session, get_scan(session, scan_id))
    return ask(snapshot, request.app.state.settings, body.question)


@router.get("/{scan_id}/pqc")
def read_pqc_registry(scan_id: int, session: Session = Depends(get_db)) -> dict:
    get_scan(session, scan_id)
    return {"scan_id": scan_id, "algorithms": [pqc_as_dict(item) for item in list_pqc()]}


@router.post("/{scan_id}/what-if")
def simulate_what_if(scan_id: int, body: WhatIfRequest, session: Session = Depends(get_db)) -> dict:
    snapshot = load_snapshot(session, get_scan(session, scan_id))
    return what_if(snapshot, body.finding_id, body.replacement, body.mode)


@router.get("/{scan_id}/hybrid/{finding_id}")
def read_hybrid(scan_id: int, finding_id: int, session: Session = Depends(get_db)) -> dict:
    snapshot = load_snapshot(session, get_scan(session, scan_id))
    return hybrid_plan(snapshot, snapshot.finding(finding_id))


@router.get("/{scan_id}/agility")
def read_agility(scan_id: int, session: Session = Depends(get_db)) -> dict:
    return analyze_agility(load_snapshot(session, get_scan(session, scan_id)))


@router.post("/{scan_id}/policy/check")
def check_policy(
    scan_id: int,
    body: PolicyCheckRequest = Body(default_factory=PolicyCheckRequest),
    session: Session = Depends(get_db),
) -> dict:
    return evaluate_scan(session, get_scan(session, scan_id), body.policy_yaml)


@router.get("/{scan_id}/report")
def read_report(scan_id: int, session: Session = Depends(get_db)) -> dict:
    return build_report(session, get_scan(session, scan_id))


@router.get("/{scan_id}/report/export")
def export_scan_report(
    scan_id: int,
    format: str = Query("json"),
    session: Session = Depends(get_db),
) -> Response:
    scan = get_scan(session, scan_id)
    fmt = "markdown" if format.lower() in {"md", "markdown"} else "json"
    payload, media_type, filename = export_report(session, scan, fmt)
    return Response(
        content=payload,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
