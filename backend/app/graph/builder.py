"""NetworkX construction of the PRISM entity graph.

Two graphs are produced from the same data:

* the **entity graph** (this module) is a NetworkX MultiDiGraph of users, hosts,
  IPs, domains, processes, files and events, plus the inventory-derived
  entitlement and reachability edges. All graph analytics (connectivity, path
  proximity) run against it.
* the **presentation graph** (app.graph.presenter) is the trimmed,
  analysis-annotated payload the Cytoscape.js frontend renders.
"""

from __future__ import annotations

import networkx as nx

from app.models.events import EventType, NormalizedEvent
from app.models.graph import EdgeKind, NodeKind
from app.models.inventory import Inventory


def host_id(name: str) -> str:
    return "host:" + name.upper()


def user_id(name: str) -> str:
    return "user:" + name.lower()


def ip_id(addr: str) -> str:
    return "ip:" + addr


def domain_id(name: str) -> str:
    return "domain:" + name.lower()


def process_id(name: str, host: str | None) -> str:
    return "process:" + name.lower() + "@" + (host or "unknown").upper()


def file_id(name: str, host: str | None) -> str:
    return "file:" + name.lower() + "@" + (host or "unknown").upper()


def event_id(evt: str) -> str:
    return "event:" + evt


def _add_node(graph: nx.MultiDiGraph, node: str, kind: NodeKind, label: str, **attrs: object) -> str:
    if node in graph:
        graph.nodes[node].update({k: v for k, v in attrs.items() if v is not None})
    else:
        graph.add_node(node, kind=kind.value, label=label, **attrs)
    return node


def _add_edge(
    graph: nx.MultiDiGraph,
    source: str,
    target: str,
    kind: EdgeKind,
    event: NormalizedEvent | None = None,
    **attrs: object,
) -> None:
    """Add or reinforce an edge, accumulating the events that produced it."""
    key = kind.value
    if graph.has_edge(source, target, key=key):
        data = graph.edges[source, target, key]
        data["weight"] = data.get("weight", 1) + 1
        if event is not None:
            data.setdefault("event_ids", []).append(event.event_id)
        data.update({k: v for k, v in attrs.items() if v is not None})
        return
    graph.add_edge(
        source,
        target,
        key=key,
        kind=kind.value,
        weight=1,
        event_ids=[event.event_id] if event is not None else [],
        **attrs,
    )


def _add_inventory_context(graph: nx.MultiDiGraph, inventory: Inventory) -> None:
    """Seed the graph with assets, identities, entitlements and reachability."""
    for host in inventory.hosts:
        _add_node(
            graph,
            host_id(host.name),
            NodeKind.HOST,
            host.name,
            role=host.role,
            criticality=host.criticality,
            critical_infrastructure=host.is_critical_infrastructure,
            zone=host.zone,
            os=host.os,
            ip=host.ip,
            from_inventory=True,
        )
        if host.ip:
            _add_node(graph, ip_id(host.ip), NodeKind.IP, host.ip, from_inventory=True)
            _add_edge(graph, host_id(host.name), ip_id(host.ip), EdgeKind.INVOLVES)

    for host in inventory.hosts:
        for peer in host.reachable_hosts:
            if host_id(peer) in graph:
                _add_edge(
                    graph, host_id(host.name), host_id(peer), EdgeKind.CONNECTED_TO, inventory=True
                )

    for user in inventory.users:
        _add_node(
            graph,
            user_id(user.name),
            NodeKind.USER,
            user.name,
            display_name=user.display_name,
            privilege=user.privilege,
            privileged=user.is_privileged,
            department=user.department,
            groups=list(user.groups),
            from_inventory=True,
        )
        for host_name in user.accessible_hosts:
            if host_id(host_name) in graph:
                _add_edge(
                    graph, user_id(user.name), host_id(host_name), EdgeKind.ACCESSES, entitlement=True
                )


def build_entity_graph(events: list[NormalizedEvent], inventory: Inventory) -> nx.MultiDiGraph:
    """Build the full entity graph from normalized events plus inventory."""
    graph = nx.MultiDiGraph()
    _add_inventory_context(graph, inventory)

    for event in events:
        evt_node = _add_node(
            graph,
            event_id(event.event_id),
            NodeKind.EVENT,
            event.action.value,
            timestamp=event.timestamp.isoformat(),
            event_type=event.event_type.value,
            action=event.action.value,
            severity=event.severity.value,
            suspicious=event.suspicious,
            summary=event.summary(),
        )

        primary = event.primary_host
        if primary:
            _add_node(graph, host_id(primary), NodeKind.HOST, primary)
            _add_edge(graph, evt_node, host_id(primary), EdgeKind.OCCURRED_ON, event)

        if event.user:
            _add_node(graph, user_id(event.user), NodeKind.USER, event.user)
            _add_edge(graph, evt_node, user_id(event.user), EdgeKind.INVOLVES, event)

        for addr in event.ips():
            _add_node(graph, ip_id(addr), NodeKind.IP, addr)
            _add_edge(graph, evt_node, ip_id(addr), EdgeKind.INVOLVES, event)

        if event.event_type is EventType.AUTHENTICATION:
            if event.user and event.destination_host:
                _add_node(graph, host_id(event.destination_host), NodeKind.HOST, event.destination_host)
                _add_edge(
                    graph,
                    user_id(event.user),
                    host_id(event.destination_host),
                    EdgeKind.LOGGED_INTO,
                    event,
                    outcome=event.outcome,
                    method=event.action.value,
                )
            if event.source_host and event.destination_host and event.source_host != event.destination_host:
                _add_edge(
                    graph,
                    host_id(event.source_host),
                    host_id(event.destination_host),
                    EdgeKind.CONNECTED_TO,
                    event,
                    observed=True,
                    method=event.action.value,
                )

        if event.event_type is EventType.DNS and event.domain:
            _add_node(
                graph, domain_id(event.domain), NodeKind.DOMAIN, event.domain, suspicious=event.suspicious
            )
            if primary:
                _add_edge(graph, host_id(primary), domain_id(event.domain), EdgeKind.RESOLVED, event)
            if event.process:
                proc = _add_node(graph, process_id(event.process, primary), NodeKind.PROCESS, event.process)
                _add_edge(graph, proc, domain_id(event.domain), EdgeKind.GENERATED, event)

        if event.event_type is EventType.ENDPOINT:
            if event.process and primary:
                proc = _add_node(
                    graph,
                    process_id(event.process, primary),
                    NodeKind.PROCESS,
                    event.process,
                    command_line=event.command_line,
                    suspicious=event.suspicious,
                )
                _add_edge(graph, host_id(primary), proc, EdgeKind.EXECUTED, event)
                if event.user:
                    _add_edge(graph, user_id(event.user), proc, EdgeKind.EXECUTED, event)
                if event.parent_process:
                    parent = _add_node(
                        graph,
                        process_id(event.parent_process, primary),
                        NodeKind.PROCESS,
                        event.parent_process,
                    )
                    _add_edge(graph, parent, proc, EdgeKind.EXECUTED, event, parent_child=True)
            if event.file_name and primary:
                node = _add_node(graph, file_id(event.file_name, primary), NodeKind.FILE, event.file_name)
                _add_edge(graph, host_id(primary), node, EdgeKind.DROPPED, event)

    return graph


def host_subgraph(graph: nx.MultiDiGraph) -> nx.Graph:
    """Undirected host-only projection used for connectivity and path maths."""
    hosts = [n for n, d in graph.nodes(data=True) if d.get("kind") == NodeKind.HOST.value]
    projection = nx.Graph()
    projection.add_nodes_from(hosts)
    for source, target, data in graph.edges(data=True):
        if data.get("kind") != EdgeKind.CONNECTED_TO.value:
            continue
        if source in projection and target in projection:
            projection.add_edge(source, target)
    return projection


def connectivity_scores(graph: nx.MultiDiGraph) -> dict[str, float]:
    """Normalised 0-1 degree centrality, keyed by host name."""
    projection = host_subgraph(graph)
    if projection.number_of_nodes() < 2:
        return {}
    centrality = nx.degree_centrality(projection)
    if not centrality:
        return {}
    peak = max(centrality.values()) or 1.0
    return {node.split(":", 1)[1]: value / peak for node, value in centrality.items()}


def hops_between(projection: nx.Graph, source: str, target: str) -> int | None:
    """Shortest host-to-host distance in hops, or None when unreachable."""
    src, dst = host_id(source), host_id(target)
    if src not in projection or dst not in projection:
        return None
    try:
        return nx.shortest_path_length(projection, src, dst)
    except nx.NetworkXNoPath:
        return None
