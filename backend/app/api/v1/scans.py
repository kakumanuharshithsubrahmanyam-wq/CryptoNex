"""Stored scan, finding, and dependency inventory routes."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.dependency import DependencyListResponse
from app.schemas.scan import FindingListResponse, ScanDetailResponse
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
