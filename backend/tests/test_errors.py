"""API error envelope."""

from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.config import Settings
from app.main import create_app


def test_not_found_uses_error_envelope(client: TestClient) -> None:
    response = client.get("/api/v1/missing")
    assert response.status_code == 404
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message", "details"}
    assert body["error"]["code"] == "NOT_FOUND"
    assert isinstance(body["error"]["message"], str)
    assert body["error"]["message"]
    assert "Traceback" not in response.text


def test_validation_error_omits_submitted_values(settings: Settings) -> None:
    application = create_app(settings)

    class Payload(BaseModel):
        name: str

    @application.post("/api/v1/_validation")
    def _validation(payload: Payload) -> dict[str, str]:
        return {"name": payload.name}

    secret = "super-secret-value"
    with TestClient(application) as test_client:
        response = test_client.post("/api/v1/_validation", json={"name": 1, "token": secret})

    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["details"]["errors"]
    assert secret not in response.text
    assert "Traceback" not in response.text


def test_unhandled_exception_hides_internal_details(settings: Settings) -> None:
    application = create_app(settings)

    @application.get("/api/v1/_raise")
    def _raise() -> None:
        raise RuntimeError("db password=super-secret")

    with TestClient(application, raise_server_exceptions=False) as test_client:
        response = test_client.get("/api/v1/_raise")

    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert body["error"]["message"] == "An unexpected error occurred"
    assert "super-secret" not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text


def test_disallowed_origin_is_not_reflected(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"Origin": "https://evil.example"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") != "https://evil.example"
    assert response.headers.get("access-control-allow-origin") != "*"
