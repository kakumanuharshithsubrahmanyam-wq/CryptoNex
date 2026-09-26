"""SQLAlchemy engine, session, and schema initialization."""

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    """Base class for ORM models."""


def create_db_engine(database_url: str) -> Engine:
    """Create an engine. SQLite is the local-development default."""
    connect_args: dict[str, object] = {}
    engine_kwargs: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if database_url in {"sqlite://", "sqlite:///:memory:"}:
            engine_kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, connect_args=connect_args, **engine_kwargs)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


_PROJECT_COLUMN_UPGRADES = (
    ("repository_url", "ALTER TABLE projects ADD COLUMN repository_url VARCHAR(512)"),
    (
        "source_type",
        "ALTER TABLE projects ADD COLUMN source_type VARCHAR(16) NOT NULL DEFAULT 'github'",
    ),
    (
        "status",
        "ALTER TABLE projects ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'created'",
    ),
    ("workspace_path", "ALTER TABLE projects ADD COLUMN workspace_path VARCHAR(1024)"),
    ("manifest_json", "ALTER TABLE projects ADD COLUMN manifest_json TEXT"),
)


def _upgrade_project_columns(engine: Engine) -> None:
    """Add Phase 1 columns to a database created before those fields existed."""
    inspector = inspect(engine)
    if "projects" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("projects")}
    with engine.begin() as connection:
        for name, statement in _PROJECT_COLUMN_UPGRADES:
            if name not in existing:
                connection.execute(text(statement))


def init_db(engine: Engine) -> None:
    """Create tables for models imported by app.models."""
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _upgrade_project_columns(engine)


def get_db(request: Request) -> Iterator[Session]:
    """Yield a request-scoped session and always close it."""
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()
