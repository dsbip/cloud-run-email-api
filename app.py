import logging
import uuid
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from routes import router
from utilities.logging_config import setup_logging
from utilities.bq_audit_logger import log_audit

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    setup_logging()

    app = FastAPI(title="Email Sending API", version="2.1.0")

    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        """Attach a unique request_id to every incoming request."""
        request.state.request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["x-request-id"] = request.state.request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Log Pydantic validation errors with full details and audit to BQ."""
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
        requestor = request.headers.get("x-requestor-system", "unknown")
        client_ip = request.client.host if request.client else "unknown"

        errors = exc.errors()

        def _make_serializable(obj):
            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            if isinstance(obj, bytes):
                return obj.decode("utf-8", errors="replace")
            if isinstance(obj, dict):
                return {k: _make_serializable(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_make_serializable(v) for v in obj]
            return str(obj)

        sanitized = _make_serializable(errors)
        logger.error(
            f"Validation error on {request.method} {request.url.path}: {sanitized}",
            exc_info=exc,
        )

        error_summary = "; ".join(e.get("msg", "") for e in sanitized) if isinstance(sanitized, list) else str(sanitized)
        log_audit(requestor, client_ip, [], [], "failure", 422, error_summary,
                  request_id=request_id)

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": sanitized, "request_id": request_id},
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Log HTTP exceptions with status code and detail."""
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

        if exc.status_code >= 500:
            cause = exc.__cause__ if exc.__cause__ else exc
            logger.error(
                f"HTTP {exc.status_code} on {request.method} {request.url.path}: {exc.detail}",
                exc_info=cause,
            )
        else:
            logger.warning(
                f"HTTP {exc.status_code} on {request.method} {request.url.path}: {exc.detail}"
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "request_id": request_id},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """Catch-all for unhandled exceptions - log full traceback and audit to BQ."""
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
        requestor = request.headers.get("x-requestor-system", "unknown")
        client_ip = request.client.host if request.client else "unknown"

        logger.critical(
            f"Unhandled exception on {request.method} {request.url.path}: {str(exc)}",
            exc_info=exc,
        )

        log_audit(requestor, client_ip, [], [], "failure", 500, str(exc),
                  request_id=request_id)

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred", "request_id": request_id},
        )

    app.include_router(router)

    return app
