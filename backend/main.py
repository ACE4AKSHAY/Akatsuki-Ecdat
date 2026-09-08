"""
FastAPI Main Application for ECDAT Module M7 (Backend API & Orchestration).
"""
from contextlib import asynccontextmanager
import os
from backend.auth import AccessControlMiddleware
from backend.engine.jobs import JobWorker
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database import init_db
from backend.api.scans import router as scans_router
from backend.api.assets import router as assets_router
from backend.api.cbom import router as cbom_router
from backend.api.reports import router as reports_router
from backend.api.config_routes import router as config_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database schema
    init_db()
    worker = JobWorker()
    worker.start()
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
    version="1.0.0",
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

# Register API Routers
app.include_router(scans_router)
app.include_router(assets_router)
app.include_router(cbom_router)
app.include_router(reports_router)
app.include_router(config_router)


@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "ECDAT Backend API (M7)", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
