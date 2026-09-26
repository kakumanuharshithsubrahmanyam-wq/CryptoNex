"""Configuration loading from the environment."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./from-env.db")
    monkeypatch.setenv("CORS_ORIGINS", "https://app.example.com, https://admin.example.com")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LOG_LEVEL", "warning")
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.database_url == "sqlite:///./from-env.db"
    assert settings.environment == "production"
    assert settings.log_level == "WARNING"
    assert settings.cors_origin_list == [
        "https://app.example.com",
        "https://admin.example.com",
    ]


def test_development_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DATABASE_URL", "CORS_ORIGINS", "ENVIRONMENT", "LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)

    settings = Settings(_env_file=None)

    assert settings.database_url == "sqlite:///./cryptonex.db"
    assert settings.environment == "development"
    assert settings.log_level == "INFO"
    assert settings.cors_origin_list == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


def test_production_rejects_wildcard_cors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CORS_ORIGINS", "*")
    get_settings.cache_clear()

    with pytest.raises(ValidationError):
        get_settings()


def test_production_rejects_empty_cors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CORS_ORIGINS", "")
    get_settings.cache_clear()

    with pytest.raises(ValidationError):
        get_settings()
