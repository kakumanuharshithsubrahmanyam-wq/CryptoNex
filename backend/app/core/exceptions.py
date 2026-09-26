"""Central API exception handlers.

Responses use a stable error envelope and never include stack traces.
"""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from app.schemas.error import ErrorBody, ErrorResponse

logger = logging.getLogger(__name__)

_CLIENT_ERROR_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
}


class AppError(Exception):
    """Expected application failure that can be returned to the client."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    payload = ErrorResponse(
        error=ErrorBody(code=code, message=message, details=details or {})
    )
    return JSONResponse(status_code=status_code, content=payload.model_dump())


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        return error_response(exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = [
            {
                "loc": [str(part) for part in err.get("loc", [])],
                "message": str(err.get("msg", "Invalid value")),
                "type": str(err.get("type", "value_error")),
            }
            for err in exc.errors()
        ]
        return error_response(
            422,
            "VALIDATION_ERROR",
            "Request validation failed",
            {"errors": errors},
        )

    @app.exception_handler(HTTPException)
    async def handle_http_exception(_request: Request, exc: HTTPException) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error("HTTP error status=%s", exc.status_code)
            return error_response(exc.status_code, "INTERNAL_ERROR", "An unexpected error occurred")
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        code = _CLIENT_ERROR_CODES.get(exc.status_code, "HTTP_ERROR")
        return error_response(exc.status_code, code, message)

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "Unhandled %s on %s",
            type(exc).__name__,
            request.url.path,
        )
        return error_response(500, "INTERNAL_ERROR", "An unexpected error occurred")
