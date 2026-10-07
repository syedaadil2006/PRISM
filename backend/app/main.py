"""PRISM FastAPI application.

Run it with:

    uvicorn app.main:app --reload --port 8000

Interactive API docs live at /docs, the OpenAPI schema at /openapi.json. If a
production frontend build exists at frontend/dist it is served from / so the
whole prototype runs from one process.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.agent_routes import router as agent_router
from app.api.live_routes import router as live_router
from app.api.routes import router
from app.core.config import PROJECT_ROOT, get_settings
from app.core.logging_config import configure_logging, get_logger
from app.services.investigation_service import InvestigationService
from app.services.soc_state import SocState

DESCRIPTION = """
PRISM correlates authentication, DNS and endpoint events into a single
attack story: where an intrusion started, how it moved, where the attacker is
now, and which host it is likely to reach next.

Every result is labelled with how it was derived:

* **observed**   - taken directly from a source log record
* **correlated** - events grouped by shared identity, host, address or timing
* **inferred**   - produced by the lateral-movement rule engine
* **predicted**  - graph-based next-target scoring, never a statement of fact
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = get_logger("app.main")

    state = SocState(settings)
    state.bootstrap()
    app.state.soc = state

    investigations = InvestigationService(settings, state)
    app.state.investigations = investigations
    logger.info(
        "prism ready",
        extra={
            "events": len(state.analysis.events),
            "chains": len(state.analysis.chains),
            "demo_mode": settings.demo_mode,
            "agents_enabled": settings.agents.enabled,
            "narrator": investigations.provider_name,
        },
    )
    if settings.simulation_autostart:
        await state.start_simulation(restart=True)
    state.start_live_loop()

    try:
        yield
    finally:
        await investigations.shutdown()
        state.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description=DESCRIPTION,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    app.include_router(agent_router)
    app.include_router(live_router)

    frontend_dist = PROJECT_ROOT / "frontend" / "dist"
    if frontend_dist.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=frontend_dist / "assets"),
            name="assets",
        )

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(frontend_dist / "index.html")

        # response_model=None because this route returns a bare Response, which
        # FastAPI must not try to turn into a Pydantic response model.
        @app.get("/{path:path}", include_in_schema=False, response_model=None)
        def spa(path: str) -> Response:
            """Serve the SPA for client-side routes, 404 for unknown API paths."""
            if path.startswith("api/"):
                return JSONResponse({"detail": "not found"}, status_code=404)
            candidate = frontend_dist / path
            if candidate.is_file() and frontend_dist in candidate.resolve().parents:
                return FileResponse(candidate)
            return FileResponse(frontend_dist / "index.html")

    return app


app = create_app()
