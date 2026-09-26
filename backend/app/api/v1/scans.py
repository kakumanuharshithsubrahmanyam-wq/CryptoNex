"""Stored scan, finding, and dependency inventory routes."""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.artifact import ArtifactListResponse
from app.schemas.cbom import CbomResponse, GraphResponse, InventoryResponse
from app.schemas.dependency import DependencyListResponse
from app.schemas.scan import FindingListResponse, ScanDetailResponse
from app.services.artifacts.queries import list_artifacts
from app.services.cbom.queries import export_cbom_bytes, get_cbom, graph, inventory
from app.services.dependencies.queries import list_dependencies
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
