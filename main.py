import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from routes import (
    auth,
    users,
    tenants,
    marketplace,
    subscriptions,
    notifications,
    admin,
    ai_chatbot,
    ai_resume,
    ai_document,
)

# ---------------------------
# Logging configuration
# ---------------------------
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(settings.APP_NAME)

# ---------------------------
# FastAPI app instance
# ---------------------------
app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Backend API for FastAPI App",
)

# ---------------------------
# CORS configuration
# ---------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Global exception handling
# ---------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.method} {request.url}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."},
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "Resource not found"},
    )


# ---------------------------
# Health & Version endpoints
# ---------------------------
@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok"}


@app.get("/version", tags=["System"])
def version():
    return {"app_name": settings.APP_NAME, "version": "1.0.0"}