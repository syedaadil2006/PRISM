"""Graph payload models handed to the Cytoscape.js frontend.

The frontend renders whatever the backend puts in here; no topology or
relationship is hardcoded client side.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class NodeKind(str, Enum):
    USER = "user"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    PROCESS = "process"
    FILE = "file"
    EVENT = "event"
    ATTACK = "attack"


class NodeState(str, Enum):
    """Visual state, driven entirely by backend analysis."""

    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    CURRENT_POSITION = "current_position"
    POTENTIAL_TARGET = "potential_target"


class EdgeKind(str, Enum):
    LOGGED_INTO = "LOGGED_INTO"
    ACCESSES = "ACCESSES"
    RESOLVED = "RESOLVED"
    EXECUTED = "EXECUTED"
    CONNECTED_TO = "CONNECTED_TO"
    GENERATED = "GENERATED"
    OCCURRED_ON = "OCCURRED_ON"
    INVOLVES = "INVOLVES"
    PART_OF = "PART_OF"
    DROPPED = "DROPPED"
    PREDICTED_MOVE = "PREDICTED_MOVE"
    LATERAL_MOVE = "LATERAL_MOVE"


class GraphNode(BaseModel):
    id: str
    label: str
    kind: NodeKind
    state: NodeState = NodeState.NORMAL
    #: observed / correlated / inferred / predicted
    assurance: str = "observed"
    attack_chain_ids: list[str] = Field(default_factory=list)
    stage_order: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    kind: EdgeKind
    label: str = ""
    assurance: str = "observed"
    predicted: bool = False
    attack_chain_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphPayload(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    generated_at: str | None = None
    stats: dict[str, int] = Field(default_factory=dict)
