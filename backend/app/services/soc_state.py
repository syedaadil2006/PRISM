"""The SOC state service: one place that owns events, graph and analysis.

Everything the API returns is derived here. Ingesting a file, stepping the demo
simulation and resetting all share a single recompute path, so the dashboard can
never show a graph that disagrees with the chain list.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import networkx as nx
from pydantic import BaseModel

from app.core.config import Settings
from app.core.logging_config import get_logger
from app.engine.attack_chain import build_chains
from app.engine.correlation import correlate
from app.graph.builder import build_entity_graph
from app.graph.neo4j_store import Neo4jGraphStore, Neo4jUnavailable
from app.graph.presenter import build_presentation_graph
from app.ingest.loader import ingest_directory, ingest_payload, load_inventory, normalize_all
from app.models.analysis import AttackChain, Correlation, DashboardStats
from app.models.events import IngestSummary, NormalizedEvent
from app.models.graph import GraphPayload
from app.models.inventory import Inventory

logger = get_logger(__name__)


class SimulationStatus(BaseModel):
    """Progress of the demo attack simulation."""

    state: str = "idle"  # idle | running | paused | completed
    revealed: int = 0
    total: int = 0
    tick_seconds: float = 1.2
    events_per_tick: int = 1
    current_time: datetime | None = None
    #: True while the simulation is gating which events are visible.
    gating: bool = False


@dataclass
class Analysis:
    """The full analysis of the currently visible events."""

    events: list[NormalizedEvent] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    graph: nx.MultiDiGraph = field(default_factory=nx.MultiDiGraph)
    computed_at: datetime | None = None

    def chain(self, chain_id: str) -> AttackChain | None:
        for candidate in self.chains:
            if candidate.attack_chain_id == chain_id:
                return candidate
        return None


class SocState:
    """Owns all PRISM state for the lifetime of the process."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.inventory: Inventory = Inventory()
        self.analysis = Analysis()
        self.sources: list[str] = []
        self.ingest_errors: list[str] = []

        self._all_events: list[NormalizedEvent] = []
        self._revealed = 0
        self._gating = False
        self._sim_state = "idle"
        self._sim_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._neo4j = Neo4jGraphStore(settings.neo4j)

    # ----------------------------------------------------------------- setup --

    def bootstrap(self) -> None:
        """Load inventory, the demo dataset if enabled, and connect Neo4j."""
        self.inventory = load_inventory(Path(self.settings.inventory_file))

        if self.settings.neo4j.enabled:
            try:
                self._neo4j.connect()
            except (Neo4jUnavailable, Exception) as exc:  # noqa: BLE001
                logger.warning(
                    "neo4j unavailable, continuing on networkx", extra={"error": str(exc)}
                )

        if self.settings.demo_mode:
            events, errors = ingest_directory(Path(self.settings.demo_dir), self.inventory)
            self._all_events = normalize_all(events)
            self.ingest_errors = errors
            self.sources = sorted({e.source_log for e in self._all_events})
            self._gating = self.settings.simulation_autostart
            self._revealed = 0 if self._gating else len(self._all_events)
            logger.info(
                "demo dataset loaded",
                extra={"events": len(self._all_events), "errors": len(errors)},
            )

        self.recompute()

    def shutdown(self) -> None:
        if self._sim_task is not None and not self._sim_task.done():
            self._sim_task.cancel()
        self._neo4j.close()

    # ------------------------------------------------------------- pipeline --

    def visible_events(self) -> list[NormalizedEvent]:
        """Events the analysis is allowed to see right now."""
        if self._gating:
            return self._all_events[: self._revealed]
        return list(self._all_events)

    def recompute(self) -> Analysis:
        """Re-run the whole pipeline over the visible events."""
        events = self.visible_events()
        correlations = correlate(events, self.settings.correlation)
        graph = build_entity_graph(events, self.inventory)
        chains = build_chains(events, correlations, graph, self.inventory, self.settings)

        self.analysis = Analysis(
            events=events,
            correlations=correlations,
            chains=chains,
            graph=graph,
            computed_at=datetime.now().astimezone(),
        )

        if self._neo4j.enabled:
            try:
                self._neo4j.sync(graph)
            except Exception as exc:  # noqa: BLE001 - mirroring must not break analysis
                logger.warning("neo4j sync failed", extra={"error": str(exc)})

        logger.info(
            "analysis recomputed",
            extra={
                "events": len(events),
                "correlations": len(correlations),
                "chains": len(chains),
            },
        )
        return self.analysis

    # -------------------------------------------------------------- ingest ---

    async def ingest_files(
        self, payloads: list[tuple[str, bytes]], log_format: str | None = None
    ) -> IngestSummary:
        """Normalize and absorb one or more uploaded log files."""
        accepted: list[NormalizedEvent] = []
        errors: list[str] = []
        for filename, raw in payloads:
            events, file_errors = ingest_payload(raw, filename, self.inventory, log_format)
            accepted.extend(events)
            errors.extend(file_errors)

        async with self._lock:
            known = {e.event_id for e in self._all_events}
            fresh = [e for e in accepted if e.event_id not in known]
            self._all_events = normalize_all(self._all_events + fresh)
            if not self._gating:
                self._revealed = len(self._all_events)
            self.sources = sorted({e.source_log for e in self._all_events})
            self.ingest_errors = errors
            self.recompute()

        return IngestSummary(
            accepted=len(fresh),
            rejected=len(accepted) - len(fresh) + len(errors),
            total_events=len(self._all_events),
            errors=errors,
            sources=self.sources,
        )

    async def clear(self) -> None:
        """Drop everything and reload the configured dataset."""
        async with self._lock:
            await self._stop_task()
            self._all_events = []
            self._revealed = 0
            self._gating = False
            self._sim_state = "idle"
            self.ingest_errors = []
            self.sources = []
            self.bootstrap()

    # ---------------------------------------------------------- simulation ---

    def simulation_status(self) -> SimulationStatus:
        events = self.visible_events()
        return SimulationStatus(
            state=self._sim_state,
            revealed=len(events),
            total=len(self._all_events),
            tick_seconds=self.settings.simulation_tick_seconds,
            events_per_tick=self.settings.simulation_events_per_tick,
            current_time=events[-1].timestamp if events else None,
            gating=self._gating,
        )

    async def _stop_task(self) -> None:
        if self._sim_task is not None and not self._sim_task.done():
            self._sim_task.cancel()
            try:
                await self._sim_task
            except asyncio.CancelledError:
                pass
        self._sim_task = None

    async def start_simulation(self, restart: bool = True) -> SimulationStatus:
        """Reveal the dataset progressively, recomputing after every tick."""
        async with self._lock:
            await self._stop_task()
            self._gating = True
            if restart or self._revealed >= len(self._all_events):
                self._revealed = 0
            self._sim_state = "running"
            self.recompute()
        self._sim_task = asyncio.create_task(self._run_simulation())
        return self.simulation_status()

    async def _run_simulation(self) -> None:
        while self._revealed < len(self._all_events):
            await asyncio.sleep(self.settings.simulation_tick_seconds)
            async with self._lock:
                if self._sim_state != "running":
                    return
                self._revealed = min(
                    len(self._all_events),
                    self._revealed + max(1, self.settings.simulation_events_per_tick),
                )
                self.recompute()
        async with self._lock:
            self._sim_state = "completed"

    async def pause_simulation(self) -> SimulationStatus:
        async with self._lock:
            if self._sim_state == "running":
                self._sim_state = "paused"
        await self._stop_task()
        return self.simulation_status()

    async def resume_simulation(self) -> SimulationStatus:
        if self._sim_state == "completed":
            return self.simulation_status()
        return await self.start_simulation(restart=False)

    async def step_simulation(self, count: int = 1) -> SimulationStatus:
        """Advance the simulation manually, for presenting at your own pace."""
        async with self._lock:
            await self._stop_task()
            self._gating = True
            if self._sim_state in {"idle", "completed"} and self._revealed >= len(self._all_events):
                self._revealed = 0
            self._revealed = min(len(self._all_events), self._revealed + max(1, count))
            self._sim_state = "completed" if self._revealed >= len(self._all_events) else "paused"
            self.recompute()
        return self.simulation_status()

    async def reset_simulation(self, show_all: bool = False) -> SimulationStatus:
        """Rewind to the start, or drop gating and show the full dataset."""
        async with self._lock:
            await self._stop_task()
            self._gating = not show_all
            self._revealed = len(self._all_events) if show_all else 0
            self._sim_state = "idle"
            self.recompute()
        return self.simulation_status()

    # --------------------------------------------------------------- views ---

    def graph_payload(self, chain_id: str | None = None) -> GraphPayload:
        return build_presentation_graph(
            self.analysis.chains, self.analysis.events, self.inventory, chain_id
        )

    def stats(self) -> DashboardStats:
        """The headline numbers, framed around fragmentation reduction."""
        analysis = self.analysis
        chains = analysis.chains
        correlated_ids = {eid for c in chains for eid in c.event_ids}
        compromised = {h.upper() for c in chains for h in c.hosts}
        targets = {p.host.upper() for c in chains for p in c.predictions}
        techniques = {m.technique_id for c in chains for m in c.mitre}
        raw_alerts = sum(1 for e in analysis.events if e.is_notable)

        return DashboardStats(
            active_attack_chains=sum(1 for c in chains if c.status == "active"),
            correlated_events=len(correlated_ids),
            total_events=len(analysis.events),
            compromised_hosts=len(compromised),
            lateral_movements=sum(len(c.lateral_movements) for c in chains),
            potential_targets=len(targets),
            mitre_techniques=len(techniques),
            raw_alert_count=raw_alerts,
            # Reduction only means something once something has been
            # consolidated. With no chains yet, nothing has been reduced --
            # reporting 100% there would be the opposite of the truth.
            alert_reduction_ratio=(
                round(1 - (len(chains) / raw_alerts), 4)
                if raw_alerts and chains
                else 0.0
            ),
        )
