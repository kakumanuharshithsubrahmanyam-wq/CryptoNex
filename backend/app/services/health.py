"""Health check behavior kept outside the route handler."""

from app.schemas.health import HealthResponse

SERVICE_NAME = "cryptonex-api"


class HealthService:
    def check(self) -> HealthResponse:
        return HealthResponse(status="ok", service=SERVICE_NAME)
