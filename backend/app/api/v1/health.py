"""Health route."""

from fastapi import APIRouter

from app.schemas.health import HealthResponse
from app.services.health import HealthService

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def read_health() -> HealthResponse:
    return HealthService().check()
