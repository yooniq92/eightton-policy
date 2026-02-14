"""Eightton Policy Service - Standalone FastAPI Application."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from eightton.config import settings
from eightton.util.database import connect_to_mongodb, close_mongodb_connection

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Eightton Policy Service...")
    await connect_to_mongodb()
    logger.info("Connected to MongoDB")

    yield

    logger.info("Shutting down Eightton Policy Service...")
    await close_mongodb_connection()
    logger.info("Disconnected from MongoDB")


def create_app() -> FastAPI:
    """Create FastAPI application for policy service."""
    from eightton.api.policy import router as policy_router

    app = FastAPI(
        title="Eightton Policy Service",
        version=settings.app_version,
        description="Eightton Policy Check Service - Code policy validation gate",
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include policy router
    app.include_router(policy_router)

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "eightton-policy"}

    @app.get("/")
    async def root():
        return {
            "name": "Eightton Policy Service",
            "version": settings.app_version,
            "status": "running",
            "endpoints": {
                "policy": "/policy",
            },
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "eightton.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
