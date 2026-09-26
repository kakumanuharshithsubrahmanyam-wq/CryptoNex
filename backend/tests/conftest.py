"""Shared API test fixtures."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.main import create_app


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings(tmp_path) -> Settings:
    database_path = tmp_path / "cryptonex.db"
    return Settings(
        database_url=f"sqlite:///{database_path}",
        cors_origins="http://localhost:5173",
        environment="test",
        log_level="WARNING",
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    application = create_app(settings)
    with TestClient(application) as test_client:
        yield test_client
