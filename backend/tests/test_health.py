"""Application startup and health endpoint."""

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def test_application_startup(settings: Settings) -> None:
    application = create_app(settings)
    with TestClient(application) as test_client:
        response = test_client.get("/api/v1/health")
    assert response.status_code == 200
    assert application.state.session_factory is not None


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "cryptonex-api"}
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
