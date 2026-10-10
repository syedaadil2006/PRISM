"""The SOC state service: one place that owns events, graph and analysis.

Everything the API returns is derived here. Ingesting a file, stepping the demo
simulation and resetting all share a single recompute path, so the dashboard can
never show a graph that disagrees with the chain list.

Scaling model (one process, no external queue):

* **Ingestion is a fast queue.** Live events are parsed off the event loop,
  de-duplicated against a running set of ids, saved to storage (when enabled,
  so a restart loses nothing) and appended to a pending list. That is all.
* **Analysis runs in a worker thread.** The background loop merges the pending
  events and re-runs the pipeline in a thread, then swaps the result in. The
  API keeps answering from the previous analysis meanwhile.
* **Backpressure.** When more than ``live.max_pending`` events are waiting for
  analysis, new batches are refused with :class:`IngestBusy` (HTTP 429 with
  Retry-After) instead of growing memory without limit.
* **Locks.** ``_analysis_lock`` lets one analysis or state change run at a
  time; ``_lock`` guards the short critical sections. Always take
  ``_analysis_lock`` first.
"""

from __future__ import annotations

import asyncio
import threading
import time
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
from app.ingest.parsers import LogRecord
from app.models.analysis import AttackChain, Correlation, DashboardStats
from app.models.events import IngestSummary, NormalizedEvent
from app.models.graph import GraphPayload
from app.models.inventory import Inventory
from app.services.live_feed import LiveFeed, LiveIngestResult, LiveStatus
from app.services.forwarder import Forwarder
from app.services.storage import Store

logger = get_logger(__name__)


FEEDBACK_META = "detection_feedback"


class IngestBusy(Exception):
    """Too many events are waiting for analysis; the sender should retry later."""

    def __init__(self, pending: int, retry_after: int) -> None:
        super().__init__(f"{pending} events are waiting for analysis")
        self.pending = pending
        self.retry_after = retry_after


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
        self._analysis_lock = asyncio.Lock()
        #: Serialises parsing: each stream's parser context is not thread-safe.
        self._parse_lock = threading.Lock()
        #: Live events received but not yet merged into the analysed set.
        self._pending: list[NormalizedEvent] = []
        self._known_ids: set[str] = set()
        #: True while an analysis runs in the worker thread.
        self._analysing = False
        #: Counters for /api/metrics.
        self.counters: dict[str, float] = {
            "analysis_runs": 0, "analysis_seconds": 0.0, "ingest_batches": 0, "ingest_busy": 0,
        }
        self._neo4j = Neo4jGraphStore(settings.neo4j)

        self.store = Store(settings.storage)
        self.forwarder = Forwarder(settings.forward, settings.version, local_only=settings.local_only)
        self.live = LiveFeed(settings.live, live_only=settings.dataset == "live")
        self._live_task: asyncio.Task[None] | None = None
        self._dirty = False
        self._last_analysis_at: datetime | None = None
        self._last_analysis_ms: float | None = None

    # ----------------------------------------------------------------- setup --

    def bootstrap(self) -> None:
        """Load inventory, the demo dataset if enabled, and connect Neo4j."""
        from app.detection.engine import current

        try:  # analyst feedback (false-positive suppressions) survives restarts
            current().import_feedback(self.store.get_meta(FEEDBACK_META))
        except ValueError as exc:
            logger.warning("stored analyst feedback unreadable", extra={"error": str(exc)})
        self.inventory = (
            load_inventory(Path(self.settings.inventory_file))
            if self.settings.inventory_file is not None
            else Inventory()
        )

        if self.settings.neo4j.enabled:
            try:
                self._neo4j.connect()
            except (Neo4jUnavailable, Exception) as exc:  # noqa: BLE001
                logger.warning(
                    "neo4j unavailable, continuing on networkx", extra={"error": str(exc)}
                )

        if self.settings.demo_mode and self.settings.demo_dir is not None and not self.live.live_only:
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

        self._restore_stored_events()
        self._pending = []
        self._known_ids = {e.event_id for e in self._all_events}
        self.recompute()

    @property
    def storage_scope(self) -> str:
        """Stored events belong to one data choice, so modes never mix."""
        return self.settings.dataset + (":live-only" if self.live.live_only else "")

    def _restore_stored_events(self) -> None:
        """Add back uploads and live events kept from earlier runs of this data choice."""
        stored = self.store.load_events(self.settings.live.max_events, self.storage_scope)
        if not stored:
            return
        known = {e.event_id for e in self._all_events}
        fresh = [e for e in stored if e.event_id not in known]
        if fresh:
            self._all_events = normalize_all(self._all_events + fresh)
            if not self._gating:
                self._revealed = len(self._all_events)
            self.sources = sorted({e.source_log for e in self._all_events})
        logger.info("restored stored events", extra={"events": len(fresh)})

    def shutdown(self) -> None:
        if self._sim_task is not None and not self._sim_task.done():
            self._sim_task.cancel()
        if self._live_task is not None and not self._live_task.done():
            self._live_task.cancel()
        self._neo4j.close()
        self.store.close()

    # ------------------------------------------------------------- pipeline --

    def visible_events(self) -> list[NormalizedEvent]:
        """Events the analysis is allowed to see right now."""
        if self._gating:
            return self._all_events[: self._revealed]
        return list(self._all_events)

    def _compute(self, events: list[NormalizedEvent]) -> tuple[Analysis, float]:
        """The pipeline itself. Pure apart from enriching events; safe in a thread."""
        started = time.perf_counter()
        correlations = correlate(events, self.settings.correlation)
        graph = build_entity_graph(events, self.inventory)
        chains = build_chains(events, correlations, graph, self.inventory, self.settings)
        analysis = Analysis(
            events=events,
            correlations=correlations,
            chains=chains,
            graph=graph,
            computed_at=datetime.now().astimezone(),
        )
        return analysis, round((time.perf_counter() - started) * 1000, 1)

    def _merge(self, base: list[NormalizedEvent], pending: list[NormalizedEvent]) -> tuple[list[NormalizedEvent], bool]:
        """``base`` plus ``pending`` in order, capped at live.max_events. Returns (events, trimmed)."""
        if not pending:
            return base, False
        merged = normalize_all(base + pending)
        overflow = len(merged) - max(1, self.settings.live.max_events)
        if overflow > 0:
            merged = merged[overflow:]  # drop the oldest
            self.store.trim_events(self.settings.live.max_events, self.storage_scope)
        return merged, overflow > 0

    def _adopt(self, merged: list[NormalizedEvent], trimmed: bool) -> None:
        """Make ``merged`` the event set (call with ``_lock`` held, or from sync code)."""
        changed = merged is not self._all_events
        self._all_events = merged
        if not self._gating:
            self._revealed = len(merged)
        if changed:
            self.sources = sorted({e.source_log for e in merged})
        if trimmed:
            self._known_ids = {e.event_id for e in merged} | {e.event_id for e in self._pending}

    def recompute(self) -> Analysis:
        """Re-run the whole pipeline over the visible events (blocking)."""
        self._dirty = False
        pending, self._pending = self._pending, []
        self._adopt(*self._merge(self._all_events, pending))
        return self._apply(*self._compute(self.visible_events()))

    async def recompute_async(self) -> Analysis:
        """Merge pending events and re-run the pipeline in a worker thread.

        Call with ``_analysis_lock`` held. Only live ingestion can run meanwhile,
        and it only appends to ``_pending``, so swapping the result in is safe.
        """
        async with self._lock:
            self._dirty = False
            pending, self._pending = self._pending, []
            base, gating, revealed = self._all_events, self._gating, self._revealed

        def work() -> tuple[list[NormalizedEvent], bool, Analysis, float]:
            merged, trimmed = self._merge(base, pending)
            visible = merged[:revealed] if gating else merged
            return (merged, trimmed, *self._compute(visible))

        self._analysing = True
        try:
            merged, trimmed, analysis, ms = await asyncio.to_thread(work)
        finally:
            self._analysing = False
        async with self._lock:
            self._adopt(merged, trimmed)
            return self._apply(analysis, ms)

    async def reanalyse(self) -> Analysis:
        """Re-run detection over every event (rules, intel or feedback changed), then analyse."""
        async with self._analysis_lock:
            async with self._lock:
                self._dirty = False
                pending, self._pending = self._pending, []
                base, gating, revealed = list(self._all_events), self._gating, self._revealed

            def work() -> tuple[list[NormalizedEvent], Analysis, float]:
                merged = normalize_all(base + pending)
                visible = merged[:revealed] if gating else merged
                return (merged, *self._compute(visible))

            self._analysing = True
            try:
                merged, analysis, ms = await asyncio.to_thread(work)
            finally:
                self._analysing = False
            async with self._lock:
                self._all_events = merged
                if not gating:
                    self._revealed = len(merged)
                self.sources = sorted({e.source_log for e in merged})
                return self._apply(analysis, ms)

    def save_feedback(self) -> None:
        from app.detection.engine import current

        self.store.set_meta(FEEDBACK_META, current().export_feedback())

    def _apply(self, analysis: Analysis, ms: float) -> Analysis:
        self.analysis = analysis
        self._last_analysis_at = analysis.computed_at
        self._last_analysis_ms = ms
        self.counters["analysis_runs"] += 1
        self.counters["analysis_seconds"] += ms / 1000
        events, correlations, chains, graph = analysis.events, analysis.correlations, analysis.chains, analysis.graph
        # New or changed chains are pushed to any configured SIEM (background thread).
        self.forwarder.notify(chains)

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
        def parse() -> tuple[list[NormalizedEvent], list[str]]:
            accepted: list[NormalizedEvent] = []
            errors: list[str] = []
            for filename, raw in payloads:
                events, file_errors = ingest_payload(raw, filename, self.inventory, log_format)
                accepted.extend(events)
                errors.extend(file_errors)
            return accepted, errors

        accepted, errors = await asyncio.to_thread(parse)
        async with self._analysis_lock:
            async with self._lock:
                fresh = self._take_new(accepted)
                self.ingest_errors = errors
            await asyncio.to_thread(self.store.save_events, fresh, "upload", self.storage_scope)
            await self.recompute_async()

        return IngestSummary(
            accepted=len(fresh),
            rejected=len(accepted) - len(fresh) + len(errors),
            total_events=len(self._all_events),
            errors=errors,
            sources=self.sources,
        )

    def _take_new(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        """Queue the events not seen before (call with ``_lock`` held)."""
        fresh: list[NormalizedEvent] = []
        for event in events:
            if event.event_id not in self._known_ids:
                self._known_ids.add(event.event_id)
                fresh.append(event)
        if fresh:
            self._pending.extend(fresh)
            self._dirty = True
        return fresh

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    async def clear(self) -> None:
        """Drop everything and reload the configured dataset."""
        async with self._analysis_lock, self._lock:
            await self._stop_task()
            self._all_events = []
            self._revealed = 0
            self._gating = False
            self._sim_state = "idle"
            self.ingest_errors = []
            self.sources = []
            self.store.clear_events(self.storage_scope)
            self.live.live_only = self.settings.dataset == "live"
            self.bootstrap()

    # ---------------------------------------------------------------- live ---

    async def ingest_live(
        self,
        records: list[LogRecord],
        stream: str,
        log_format: str | None = None,
    ) -> LiveIngestResult:
        """Absorb records that arrived in real time.

        The analysis is not re-run here: the live loop catches up in the
        background, at most once per recompute interval, so a fast sender gets
        an immediate answer and the pipeline is never re-run per record.
        """
        limit = self.settings.live.max_pending
        if limit and len(self._pending) >= limit:
            self.counters["ingest_busy"] += 1
            retry = max(1, round(2 * (self._last_analysis_ms or 1000) / 1000))
            raise IngestBusy(len(self._pending), retry)

        def parse() -> tuple[list[NormalizedEvent], list[str]]:
            with self._parse_lock:
                return self.live.parse(records, stream, self.inventory, log_format)

        events, errors = await asyncio.to_thread(parse)
        async with self._lock:
            fresh = self._take_new(events)
            self.counters["ingest_batches"] += 1
            self.live.record_arrival(
                stream,
                received=len(records),
                accepted=len(fresh),
                duplicates=len(events) - len(fresh),
                rejected=len(errors),
            )
            total = len(self._all_events) + len(self._pending)
        if fresh:
            # Kept on disk before the sender is answered, so a restart loses nothing.
            await asyncio.to_thread(self.store.save_events, fresh, "live", self.storage_scope)
        return LiveIngestResult(
            stream=stream,
            received=len(records),
            accepted=len(fresh),
            duplicates=len(events) - len(fresh),
            rejected=len(errors),
            errors=errors[:20],
            total_events=total,
        )

    async def flush_live(self) -> None:
        """Bring the analysis up to date with every live event received."""
        async with self._analysis_lock:
            if self._dirty:
                await self.recompute_async()

    async def poll_live_files(self) -> int:
        """Ingest whatever was appended to the watched folder; returns events accepted."""
        accepted = 0
        for stream, records, errors in self.live.poll_files():
            if errors:
                self.live.recent_errors.extend(errors[:5])
            if records:
                try:
                    result = await self.ingest_live(records, stream)
                except IngestBusy:
                    # Files can wait: they are re-read from the same position next time.
                    self.live.recent_errors.append("watched folder: analysis busy, records skipped")
                    break
                accepted += result.accepted
        return accepted

    def start_live_loop(self) -> None:
        if self.settings.live.enabled and (self._live_task is None or self._live_task.done()):
            self._live_task = asyncio.create_task(self._live_loop())

    async def _live_loop(self) -> None:
        """Tail the watched folder and re-run the analysis when events arrived.

        Re-analysis waits at least the configured interval, and at least twice
        as long as the previous run took, so a large dataset is not re-analysed
        back to back.
        """
        live = self.settings.live
        tick = max(0.2, min(live.watch_interval_seconds, live.recompute_interval_seconds))
        last_run = 0.0
        while True:
            try:
                await self.poll_live_files()
                gap = max(live.recompute_interval_seconds, 2 * (self._last_analysis_ms or 0) / 1000)
                if self._dirty and time.monotonic() - last_run >= gap:
                    await self.flush_live()
                    last_run = time.monotonic()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - the feed must keep running
                logger.warning("live feed error", extra={"error": str(exc)})
                self.live.recent_errors.append("live loop: {}".format(exc))
            await asyncio.sleep(tick)

    async def go_live(self, clear: bool = True) -> LiveStatus:
        """Switch to live analysis, optionally dropping the bundled dataset."""
        async with self._analysis_lock, self._lock:
            await self._stop_task()
            self._gating = False
            self._sim_state = "idle"
            if clear:
                self._all_events = []
                self.sources = []
                self.ingest_errors = []
                self.live.live_only = True
                self.store.clear_events(self.storage_scope)
                self._pending = []
                self._known_ids = set()
            self._revealed = len(self._all_events)
            self.recompute()
        return self.live_status()

    def live_status(self) -> LiveStatus:
        status = self.live.status(self._dirty or self._analysing, self._last_analysis_at, self._last_analysis_ms)
        status.queued = len(self._pending)
        status.max_queued = self.settings.live.max_pending
        return status

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
        async with self._analysis_lock, self._lock:
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
            async with self._analysis_lock, self._lock:
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
        async with self._analysis_lock, self._lock:
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
        async with self._analysis_lock, self._lock:
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
