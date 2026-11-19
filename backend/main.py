"""
FastAPI Main Application for ECDAT Module M7 (Backend API & Orchestration).
"""
from contextlib import asynccontextmanager
import logging
import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.auth import AccessControlMiddleware
from backend.database import init_db, SessionLocal
from backend.engine.jobs import JobWorker
from backend.input_limits import get_input_limits
from backend.logging_config import configure_logging, get_request_id
from backend.metrics import render_metrics
from backend.middleware import RequestContextMiddleware
from backend.ratelimit import RateLimitMiddleware
from backend.retention import prune_expired_scans

from backend.api.scans import router as scans_router
from backend.api.assets import router as assets_router
from backend.api.cbom import router as cbom_router
from backend.api.reports import router as reports_router
from backend.api.config_routes import router as config_router
from backend.api.standards import router as standards_router
from backend.api.roadmap import router as roadmap_router

from backend.version import VERSION

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    get_input_limits()  # Reject invalid environment settings before accepting scans.
    init_db()
    with SessionLocal() as db:
        prune_expired_scans(db)  # Apply retention once at start-up.
    worker = JobWorker()
    worker.start()
    app.state.worker = worker
    try:
        yield
    finally:
        worker.stop()


app = FastAPI(
    title="ECDAT Backend API (Module M7)",
    description=(
        "Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) Backend API.\n"
        "Coordinates discovery scanning, Mosca quantum risk assessment, PQC recommendations, "
        "and CycloneDX 1.6 Cryptography Bill of Materials (CBOM) export."
    ),
    version=VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Enable CORS for Frontend (M8)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ECDAT_CORS_ORIGINS", "http://127.0.0.1:3000,http://127.0.0.1:3001,http://localhost:3000").split(","),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(AccessControlMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestContextMiddleware)

# Register API Routers
app.include_router(scans_router)
app.include_router(assets_router)
app.include_router(cbom_router)
app.include_router(reports_router)
app.include_router(config_router)
app.include_router(standards_router)
app.include_router(roadmap_router)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Return one error envelope for every failed request."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "statusCode": exc.status_code,
            "requestId": get_request_id(),
        },
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Request validation failed.",
            "statusCode": 422,
            "requestId": get_request_id(),
            "errors": jsonable_errors(exc),
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Never leak a stack trace to a client; keep it in the log with the request id."""
    log.exception(
        "unhandled error",
        extra={"context": {"requestId": get_request_id(), "path": request.url.path}},
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error.",
            "statusCode": 500,
            "requestId": get_request_id(),
        },
    )


def jsonable_errors(exc: RequestValidationError) -> list:
    """Reduce validation errors to JSON-serialisable field/issue pairs."""
    errors = []
    for err in exc.errors():
        errors.append({
            "field": ".".join(str(part) for part in err.get("loc", [])),
            "issue": err.get("msg", ""),
            "type": err.get("type", ""),
        })
    return errors


@app.get("/health", tags=["System"])
def health_check():
    """Liveness probe — the process is up and serving requests."""
    return {
        "status": "healthy",
        "service": "ECDAT Backend API (M7)",
        "version": VERSION,
        "requestId": get_request_id(),
    }


@app.get("/health/ready", tags=["System"])
def readiness_check():
    """Readiness probe — dependencies the API needs are reachable and loaded."""
    from backend.database import engine
    from backend.engine.standards import get_registry
    from backend.scanners.source.config import load_signals

    checks = {}

    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        checks["database"] = "ok"
    except Exception as exc:  # pragma: no cover - depends on the host filesystem
        checks["database"] = f"error: {exc}"

    try:
        registry = get_registry()
        checks["standardsRegistry"] = "ok"
        registry_meta = {
            "version": registry.get("registryVersion"),
            "reviewedOn": registry.get("reviewedOn"),
            "entryCount": len(registry.get("entries", [])),
        }
    except Exception as exc:  # pragma: no cover - registry ships with the app
        checks["standardsRegistry"] = f"error: {exc}"
        registry_meta = {}

    try:
        checks["detectionSignals"] = "ok"
        signal_meta = {"count": len(load_signals())}
    except Exception as exc:  # pragma: no cover - signals ship with the app
        checks["detectionSignals"] = f"error: {exc}"
        signal_meta = {}

    worker = getattr(app.state, "worker", None)
    checks["scanWorker"] = "running" if worker is not None and worker.thread.is_alive() else "stopped"

    ready = all(value == "ok" for key, value in checks.items() if key != "scanWorker")
    return {
        "status": "ready" if ready else "not-ready",
        "version": VERSION,
        "checks": checks,
        "standardsRegistry": registry_meta,
        "detectionSignals": signal_meta,
        "build": {
            "commit": os.getenv("ECDAT_BUILD_COMMIT", "unknown"),
            "builtAt": os.getenv("ECDAT_BUILD_DATE", "unknown"),
        },
        "requestId": get_request_id(),
    }


@app.get("/metrics", tags=["System"], response_class=PlainTextResponse)
def metrics_endpoint():
    """Prometheus-format metrics. Token-protected like every other data route."""
    return Response(
        content=render_metrics(version=VERSION),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
