"""PRISM FastAPI application.

Run it with:

    uvicorn app.main:app --reload --port 8000

Interactive API docs live at /docs, the OpenAPI schema at /openapi.json. If a
production frontend build exists at frontend/dist it is served from / so the
whole prototype runs from one process.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.agent_routes import router as agent_router
from app.api.live_routes import router as live_router
from app.api.auth_routes import router as auth_router
from app.api.siem_routes import router as siem_router
from app.api.ocsf_routes import router as ocsf_router
from app.api.admin_routes import router as admin_router
from app.api.ops_routes import router as ops_router
from app.api.detection_routes import router as detection_router
from app.detection.engine import build as build_detections, install as install_detections
from app.core.metrics import MetricsMiddleware, RequestMetrics
from app.services.backup import create_backup
from app.core.auth import AuthMiddleware, SecurityHeadersMiddleware, resolve_token
from app.core.db import is_postgres, postgres_host
from app.core.local_only import LocalOnlyMiddleware, is_loopback
from app.core.security_store import SecurityStore
from app.api.routes import router
from app.core.config import PROJECT_ROOT, get_settings
from app.core.logging_config import configure_logging, get_logger
from app.services.investigation_service import InvestigationService
from app.services.soc_state import SocState
from app.services.syslog_receiver import SyslogReceiver

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


async def _maintenance(state: SocState) -> None:
    """Hourly retention clean-up and scheduled backups, off the request path."""
    logger = get_logger("app.maintenance")
    settings = state.settings
    last_backup = time.monotonic()
    last_purge = 0.0
    while True:
        try:
            now = time.monotonic()
            if settings.storage.retention_days > 0 and now - last_purge >= 3600:
                last_purge = now
                cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.storage.retention_days)).isoformat()
                events, investigations = await asyncio.to_thread(state.store.purge_older_than, cutoff)
                if events or investigations:
                    logger.info("retention clean-up", extra={"events": events, "investigations": investigations})
            interval = settings.backup.interval_hours * 3600
            if interval > 0 and now - last_backup >= interval:
                last_backup = now
                await asyncio.to_thread(create_backup, settings, "scheduled")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - maintenance must keep running
            logger.warning("maintenance task failed", extra={"error": str(exc)})
        await asyncio.sleep(60)


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
    maintenance = asyncio.create_task(_maintenance(state))

    if settings.local_only and settings.syslog.host not in {"127.0.0.1", "::1", "localhost"}:
        logger.warning("local-only mode: syslog receiver pinned to 127.0.0.1", extra={"requested": settings.syslog.host})
        settings.syslog.host = "127.0.0.1"
    syslog = SyslogReceiver(state)
    app.state.syslog = syslog
    if settings.syslog.enabled:
        try:
            await syslog.start()
        except OSError as exc:
            logger.warning("syslog receiver could not start", extra={"error": str(exc)})

    try:
        yield
    finally:
        await syslog.stop()
        if getattr(app.state, "security", None) is not None:
            app.state.security.close()
        maintenance.cancel()
        await investigations.shutdown()
        state.shutdown()


def _check_database_locations(settings) -> None:  # noqa: ANN001
    """Local-only mode: a PostgreSQL database must be on this computer too."""
    if not settings.local_only:
        return
    for name, url in (("PRISM_STORAGE_URL", settings.storage.url), ("PRISM_AUTH_DB_URL", settings.auth.db_url)):
        if url and is_postgres(url) and not is_loopback(postgres_host(url)):
            raise RuntimeError(
                f"{name} points to another computer, but local-only mode keeps all data on this one. "
                "Use a database on this computer, or set PRISM_LOCAL_ONLY=false."
            )


def create_app() -> FastAPI:
    settings = get_settings()
    _check_database_locations(settings)
    install_detections(build_detections(settings.detection))
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

    # Sign-in, roles and auditing. Added after CORS so it runs first on requests.
    app.state.auth_enabled = settings.auth.enabled
    app.state.auth_token = resolve_token(settings.auth) if settings.auth.enabled else ""
    app.state.auth_cookie_max_age = settings.auth.cookie_max_age_seconds
    app.state.access_code_enabled = settings.auth.access_code_enabled
    app.state.security = SecurityStore(settings.auth) if settings.auth.enabled else None
    if app.state.security is not None and app.state.security.ensure_default_admin():
        get_logger("app.main").warning(
            "fresh installation: created the default admin account; its first sign-in must set a new password",
            extra={"username": settings.auth.default_admin_username},
        )
    if settings.auth.enabled:
        app.add_middleware(AuthMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.request_metrics = RequestMetrics()
    app.add_middleware(MetricsMiddleware, metrics=app.state.request_metrics)
    # Added last so it runs first: other machines are refused before anything else.
    if settings.local_only:
        app.add_middleware(LocalOnlyMiddleware, local_networks=settings.local_networks)

    app.include_router(router)
    app.include_router(agent_router)
    app.include_router(live_router)
    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(ops_router)
    app.include_router(detection_router)
    app.include_router(siem_router)
    app.include_router(ocsf_router)

    frontend_dist = PROJECT_ROOT / "frontend" / "dist"
    if frontend_dist.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=frontend_dist / "assets"),
            name="assets",
        )

        # The page shell is never cached, so a browser always picks up the
        # dashboard that matches the running server (hashed assets still cache).
        no_cache = {"Cache-Control": "no-cache"}

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(frontend_dist / "index.html", headers=no_cache)

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
            return FileResponse(frontend_dist / "index.html", headers=no_cache)

    return app


app = create_app()
