from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from auth_service.api import auth as auth_router
from auth_service.api import health as health_router
from auth_service.api import oauth as oauth_router
from auth_service.config import settings
from auth_service.logging import configure_logging, log
from auth_service.security.jwt import load_keys


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(settings.log_level)
    app.state.jwt_keys = load_keys()
    log.info("auth_service.startup", env=settings.app_env, kid=settings.jwt_kid)
    yield
    log.info("auth_service.shutdown")


app = FastAPI(title="auth-service", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    structlog.contextvars.bind_contextvars(request_id=request_id)
    try:
        response = await call_next(request)
    finally:
        structlog.contextvars.clear_contextvars()
    response.headers["x-request-id"] = request_id
    return response


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled_exception", path=request.url.path)
    return JSONResponse(status_code=500, content={"detail": "internal server error"})


app.include_router(auth_router.router, tags=["auth"])
app.include_router(oauth_router.router, tags=["oauth"])
app.include_router(health_router.router, tags=["health"])
