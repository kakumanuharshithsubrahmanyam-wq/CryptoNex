"""Environment-backed application settings."""

from functools import lru_cache

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_DEV_CORS_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite:///./cryptonex.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    environment: str = "development"
    log_level: str = "INFO"
    workspace_root: str = "./workspaces"
    git_executable: str = "git"
    max_repository_size_mb: int = 100
    max_file_count: int = 10000
    max_file_size_mb: int = 10
    clone_timeout_seconds: int = 120
    max_zip_size_mb: int = 50
    max_zip_extracted_size_mb: int = 200
    scan_excluded_directories: str = (
        "node_modules,vendor,dist,build,.git,__pycache__,.venv,venv,target"
    )
    evidence_max_chars: int = 240
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_timeout_seconds: int = 30

    @field_validator("database_url")
    @classmethod
    def database_url_must_be_present(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("DATABASE_URL must not be empty")
        return stripped

    @field_validator("environment")
    @classmethod
    def normalize_environment(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("ENVIRONMENT must not be empty")
        return normalized

    @field_validator("workspace_root")
    @classmethod
    def workspace_root_must_be_present(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("WORKSPACE_ROOT must not be empty")
        return stripped

    @field_validator("git_executable")
    @classmethod
    def git_executable_must_be_a_single_token(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped or any(character in stripped for character in " \t\n;&|$`<>"):
            raise ValueError("GIT_EXECUTABLE must be a single executable name or path")
        return stripped

    @field_validator(
        "max_repository_size_mb",
        "max_file_count",
        "max_file_size_mb",
        "clone_timeout_seconds",
        "max_zip_size_mb",
        "max_zip_extracted_size_mb",
    )
    @classmethod
    def limits_must_be_positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("Ingestion limits must be at least 1")
        return value

    @field_validator("evidence_max_chars")
    @classmethod
    def evidence_limit_must_be_positive(cls, value: int) -> int:
        if value < 40:
            raise ValueError("EVIDENCE_MAX_CHARS must be at least 40")
        return value

    @field_validator("openai_api_key", "openai_model", "openai_base_url")
    @classmethod
    def strip_openai_settings(cls, value: str) -> str:
        return value.strip()

    @field_validator("openai_timeout_seconds")
    @classmethod
    def openai_timeout_must_be_positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("OPENAI_TIMEOUT_SECONDS must be at least 1")
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in _LOG_LEVELS:
            allowed = ", ".join(sorted(_LOG_LEVELS))
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return normalized

    @property
    def parsed_cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        origins = self.parsed_cors_origins
        if self.environment == "production":
            if not origins or "*" in origins:
                raise ValueError(
                    "CORS_ORIGINS must be an explicit allowlist when ENVIRONMENT=production"
                )
            return origins
        if not origins:
            return list(_DEV_CORS_ORIGINS)
        return origins

    @model_validator(mode="after")
    def reject_unrestricted_production_cors(self) -> "Settings":
        # Accessing the property fails fast when production CORS is unsafe.
        self.cors_origin_list
        return self


@lru_cache
def get_settings() -> Settings:
    """Return process settings. Environment variables override .env files."""
    return Settings()
