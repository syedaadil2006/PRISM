"""Optional Neo4j persistence for the entity graph.

PRISM runs entirely on NetworkX by default so the prototype has no
external dependencies. Set PRISM_NEO4J_ENABLED=true (plus URI and
credentials) to additionally mirror the graph into Neo4j, where the schema in
docs/neo4j_schema.cypher applies.

The driver is imported lazily: the neo4j package is an optional extra, and an
unreachable database must degrade to a warning rather than break ingestion.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from app.core.config import Neo4jSettings
from app.core.logging_config import get_logger

logger = get_logger(__name__)

#: Graph node kinds mapped onto Neo4j labels.
_LABELS = {
    "user": "User",
    "host": "Host",
    "ip": "IPAddress",
    "domain": "Domain",
    "process": "Process",
    "file": "File",
    "event": "Event",
    "attack": "Attack",
}


class Neo4jUnavailable(RuntimeError):
    """Raised when Neo4j is requested but cannot be used."""


class Neo4jGraphStore:
    """Thin write-through mirror of the NetworkX graph."""

    def __init__(self, settings: Neo4jSettings) -> None:
        self.settings = settings
        self._driver: Any | None = None

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    def connect(self) -> None:
        if not self.settings.enabled:
            return
        try:
            from neo4j import GraphDatabase  # imported lazily: optional extra
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise Neo4jUnavailable(
                "neo4j support requires 'pip install -r requirements-neo4j.txt'"
            ) from exc

        self._driver = GraphDatabase.driver(
            self.settings.uri,
            auth=(self.settings.user, self.settings.password),
        )
        self._driver.verify_connectivity()
        logger.info("connected to neo4j", extra={"uri": self.settings.uri})

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def sync(self, graph: nx.MultiDiGraph) -> int:
        """Replace the stored graph with the current one. Returns rows written."""
        if self._driver is None:
            return 0

        written = 0
        with self._driver.session(database=self.settings.database) as session:
            session.run("MATCH (n:PRISM) DETACH DELETE n")

            for node_id, data in graph.nodes(data=True):
                label = _LABELS.get(str(data.get("kind")), "Entity")
                session.run(
                    "MERGE (n:PRISM {uid: $uid}) "
                    "SET n:" + label + ", n.label = $label, n.kind = $kind, n.props = $props",
                    uid=node_id,
                    label=data.get("label"),
                    kind=data.get("kind"),
                    props={k: _scalar(v) for k, v in data.items() if k not in {"label", "kind"}},
                )
                written += 1

            for source, target, data in graph.edges(data=True):
                session.run(
                    "MATCH (a:PRISM {uid: $source}), (b:PRISM {uid: $target}) "
                    "MERGE (a)-[r:RELATES {kind: $kind}]->(b) "
                    "SET r.weight = $weight, r.event_ids = $event_ids",
                    source=source,
                    target=target,
                    kind=data.get("kind"),
                    weight=data.get("weight", 1),
                    event_ids=list(data.get("event_ids", [])),
                )
                written += 1

        logger.info("synced graph to neo4j", extra={"rows": written})
        return written


def _scalar(value: Any) -> Any:
    """Neo4j properties must be primitives or lists of primitives."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_scalar(v) for v in value]
    return str(value)
