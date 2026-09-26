"""FastAPI application factory."""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.database import create_db_engine, create_session_factory, init_db
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)

if sys.version_info < (3, 11):
    raise RuntimeError("CryptoNex backend requires Python 3.11 or newer")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the API application. Tests pass explicit settings."""
    app_settings = settings or get_settings()
    configure_logging(app_settings.log_level)
    engine = create_db_engine(app_settings.database_url)
    session_factory = create_session_factory(engine)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        logger.info("Starting cryptonex-api environment=%s", app_settings.environment)
        init_db(engine)
        yield
        engine.dispose()

    app = FastAPI(title="CryptoNex API", version="0.1.0", lifespan=lifespan, debug=False)
    app.state.settings = app_settings
    app.state.engine = engine
    app.state.session_factory = session_factory

    register_exception_handlers(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
