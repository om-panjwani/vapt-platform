from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.config import get_settings
from backend.logging_config import setup_logging, get_logger

settings = get_settings()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    setup_logging()
    logger.info("application_starting", version=settings.APP_VERSION)

    from database import init_db
    await init_db()

    logger.info("application_started")
    yield
    logger.info("application_shutting_down")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Automated Vulnerability Assessment & Reconnaissance Platform API",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from backend.api import (
        projects,
        targets,
        scans,
        hosts,
        findings,
        reports,
        dashboard,
    )

    app.include_router(projects.router, prefix="/api/v1/projects", tags=["Projects"])
    app.include_router(targets.router, prefix="/api/v1", tags=["Targets"])
    app.include_router(scans.router, prefix="/api/v1", tags=["Scans"])
    app.include_router(hosts.router, prefix="/api/v1", tags=["Hosts"])
    app.include_router(findings.router, prefix="/api/v1", tags=["Findings"])
    app.include_router(reports.router, prefix="/api/v1", tags=["Reports"])
    app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])

    @app.get("/api/health")
    async def health_check():
        return {"status": "healthy", "version": settings.APP_VERSION}

    return app


app = create_app()