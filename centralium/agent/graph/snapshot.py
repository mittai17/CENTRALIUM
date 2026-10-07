"""Graph snapshot extraction and persistence for dashboard telemetry.

Persists bounded, incident-centered JSON views ``{nodes, edges}`` to the
``graph_snapshots`` table (JSON column ``snapshot``).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from centralium.agent.storage import Database

_NODE_KIND = {
    "Process": "process",
    "IP": "network",
    "Domain": "network",
    "File": "file",
    "RegistryKey": "registry",
    "User": "user",
    "Host": "host",
    "Incident": "incident",
}
_EDGE_KIND = {"SPAWNED": "spawned", "CONNECTED_TO": "connected"}


def graph_snapshot(adapter: Any, *, max_nodes: int = 300, max_edges: int = 800) -> dict[str, Any]:
    """Export a bounded, incident-centred JSON view ``{nodes, edges}`` of the live graph.

    Incident-linked nodes (and their 2-hop neighbourhood) are taken first, then the most
    recently seen process/network nodes. File nodes are capped so a ransomware burst does not
    swamp the picture. Works for the Kuzu adapter (``.mem``) and the in-memory adapter.
    """
    mem = getattr(adapter, "mem", adapter)
    if not hasattr(mem, "nodes"):
        return {"nodes": [], "edges": []}
    with mem._lock:
        nodes = dict(mem.nodes)
        edges = list(mem.edges.values())
    adj: dict[str, list[Any]] = {}
    for e in edges:
        adj.setdefault(e.src, []).append(e)
        adj.setdefault(e.dst, []).append(e)
    chosen: dict[str, int] = {}

    def take(nid: str) -> bool:
        n = nodes.get(nid)
        if n is None or nid in chosen or len(chosen) >= max_nodes:
            return False
        if n.ntype == "File" and sum(1 for k in chosen if nodes[k].ntype == "File") >= max(
            10, max_nodes // 5
        ):
            return False
        chosen[nid] = len(chosen)
        return True

    seeds = [nid for nid, n in nodes.items() if n.ntype == "Incident"]
    seeds.sort(key=lambda i: nodes[i].last_seen, reverse=True)
    frontier = list(seeds)
    for nid in seeds:
        take(nid)
    for _ in range(2):
        nxt: list[str] = []
        for nid in frontier:
            for e in adj.get(nid, []):
                other = e.dst if e.src == nid else e.src
                if take(other):
                    nxt.append(other)
        frontier = nxt
    recent = sorted(
        (n for n in nodes.values() if n.ntype in ("Process", "IP", "Domain")),
        key=lambda n: n.last_seen,
        reverse=True,
    )
    for n in recent:
        take(n.node_id)
    out_nodes = []
    for nid in chosen:
        n = nodes[nid]
        out_nodes.append(
            {
                "id": n.node_id,
                "type": _NODE_KIND.get(n.ntype, n.ntype.lower()),
                "kind": n.ntype,
                "label": n.label,
                "first_seen": n.first_seen,
                "last_seen": n.last_seen,
                "props": {
                    k: v for k, v in list(n.props.items())[:8] if isinstance(v, (str, int, float, bool))
                },
            }
        )
    out_edges = []
    for e in sorted(edges, key=lambda x: x.ts, reverse=True):
        if e.src in chosen and e.dst in chosen:
            out_edges.append(
                {
                    "source": e.src,
                    "target": e.dst,
                    "type": _EDGE_KIND.get(e.etype, e.etype.lower()),
                    "kind": e.etype,
                    "ts": e.ts,
                }
            )
            if len(out_edges) >= max_edges:
                break
    return {"nodes": out_nodes, "edges": out_edges}


def write_graph_snapshot(db: Database, adapter: Any, host_id: str = "localhost") -> int:
    """Persist a snapshot the dashboard's /api/graph reads (``graph_snapshots.snapshot`` JSON)."""
    snap = graph_snapshot(adapter)
    if not snap["nodes"]:
        return 0
    now_ts = getattr(db, "now", None)
    created_at = now_ts() if callable(now_ts) else "now"
    db.insert(
        "graph_snapshots",
        {
            "host_id": host_id,
            "created_at": created_at,
            "node_count": len(snap["nodes"]),
            "edge_count": len(snap["edges"]),
            "snapshot": json.dumps(snap, default=str),
        },
    )
    # bounded retention: keep the 20 newest snapshots
    db.execute(
        "DELETE FROM graph_snapshots WHERE snapshot_id NOT IN "
        "(SELECT snapshot_id FROM graph_snapshots ORDER BY snapshot_id DESC LIMIT 20)"
    )
    return len(snap["nodes"])
