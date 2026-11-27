from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from athena import __version__
from athena.api.deps import REQUEST_SESSION_ATTR
from athena.api.events import broker
from athena.api.routers import (
    assets,
    audit,
    auth,
    code,
    control,
    events,
    exports,
    findings,
    health,
    jobs,
    metrics,
    nodes,
    notifications,
    suppressions,
    users,
)

log = structlog.get_logger(__name__)


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    broker.start()
    log.info("api.started", version=__version__)
    yield
    await broker.stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Athena Core",
        version=__version__,
        description="Autonomous security investigation, human-controlled remediation.",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    @app.middleware("http")
    async def transaction(request: Request, call_next):
        def close(commit: bool) -> None:
            session = getattr(request.state, REQUEST_SESSION_ATTR, None)
            if session is None:
                return
            try:
                if commit:
                    session.commit()
                else:
                    session.rollback()
            finally:
                session.close()
                setattr(request.state, REQUEST_SESSION_ATTR, None)

        try:
            response = await call_next(request)
        except Exception:
            await run_in_threadpool(close, False)
            raise

        await run_in_threadpool(close, response.status_code < 400)
        return response

    app.include_router(health.router)
    for r in (
        auth.router, assets.router, findings.router, nodes.router,
        jobs.router, audit.router, events.router, suppressions.router,
        notifications.router, metrics.router, exports.router, code.router,
        users.router, control.router,
    ):
        app.include_router(r, prefix="/api/v1")

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error("api.unhandled", path=request.url.path, error=str(exc))
        return JSONResponse(
            status_code=500,
            content={"type": "about:blank", "title": "Internal Server Error", "status": 500},
        )

    return app


app = create_app()
