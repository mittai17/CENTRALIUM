"""Kuzu-backed GraphAdapter (embedded, on-disk) behind the adapter boundary.

Hot path: the in-memory ``MemoryGraph`` correlates every event (identical behaviour to the
fallback adapter). Persistence: nodes/relationships/event records are buffered and written
to Kuzu in batched transactions (``batch_size`` events, or ``flush()``). Cold path:
``chain_for`` for an event no longer in memory (e.g. after restart) rebuilds the
neighbourhood from Kuzu by time window and runs the very same analysis.

Cypher text only interpolates identifiers from the fixed ``NODE_TYPES``/``REL_SCHEMA``
whitelists; every value is a bound parameter.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from centralium.agent.graph.core import (
    NODE_TYPES,
    REL_SCHEMA,
    ChainAnalysis,
    EventRec,
    GEdge,
    GNode,
    MemoryGraph,
    StagePrediction,
    tags_from_json,
    tags_to_json,
)
from centralium.agent.models import Finding, GraphSignal, Incident, NormalizedEvent

log = logging.getLogger("centralium.graph.kuzu")


class KuzuUnavailableError(RuntimeError):
    pass


class KuzuGraphAdapter:
    def __init__(
        self,
        path: str | Path,
        *,
        batch_size: int = 500,
        hydrate_window_sec: float = 3600.0,
        **memory_kwargs: Any,
    ) -> None:
        try:
            import kuzu
        except ImportError as exc:  # pragma: no cover - depends on env
            raise KuzuUnavailableError("kuzu is not installed") from exc
        self._kuzu = kuzu
        self.batch_size = max(1, batch_size)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._memory_kwargs = {"window_sec": hydrate_window_sec, **memory_kwargs}
        self._window_ms = int(hydrate_window_sec * 1000)
        self.mem = MemoryGraph(**self._memory_kwargs)
        try:
            self._db = kuzu.Database(str(self.path))
            self._conn = kuzu.Connection(self._db)
            self._init_schema()
        except Exception as exc:
            raise KuzuUnavailableError(f"cannot open kuzu database at {self.path}: {exc}") from exc
        self._closed = False
        self._hydrate_recent()

    # ------------------------------------------------------------------ schema
    def _init_schema(self) -> None:
        for t in NODE_TYPES:
            self._ddl(
                f"CREATE NODE TABLE IF NOT EXISTS {t}(id STRING PRIMARY KEY, label STRING, "
                "first_seen INT64, last_seen INT64, props STRING)"
            )
        self._ddl(
            "CREATE NODE TABLE IF NOT EXISTS EventRecord(id STRING PRIMARY KEY, ts INT64, etype STRING, "
            "proc_id STRING, host STRING, label STRING, score DOUBLE, known BOOLEAN, tags STRING, "
            "flags STRING, structural BOOLEAN)"
        )
        for rel, pairs in REL_SCHEMA.items():
            clauses = ", ".join(f"FROM {a} TO {b}" for a, b in pairs)
            self._ddl(
                f"CREATE REL TABLE IF NOT EXISTS {rel}({clauses}, eid STRING, ts INT64, "
                "event_id STRING, props STRING)"
            )

    def _ddl(self, q: str) -> None:
        self._conn.execute(q)

    # ------------------------------------------------------------------ GraphAdapter
    def ingest(self, event: NormalizedEvent, findings: list[Finding]) -> GraphSignal:
        sig = self.mem.ingest(event, findings)
        if self.mem.pending_count() >= self.batch_size:
            self.flush()
        return sig

    def attach_incident(self, incident: Incident) -> None:
        self.mem.attach_incident(incident)

    def chain_for(self, event_id: str) -> list[str]:
        if event_id in self.mem.events:
            return self.mem.chain_for(event_id)
        tmp = self._rebuild_around(event_id)
        return tmp.chain_for(event_id) if tmp is not None else []

    def analyze(self, event_id: str) -> ChainAnalysis | None:
        if event_id in self.mem.events:
            return self.mem.analyze(event_id)
        tmp = self._rebuild_around(event_id)
        return tmp.analyze(event_id) if tmp is not None else None

    def stage_for(self, event_id: str) -> StagePrediction | None:
        a = self.analyze(event_id)
        return a.prediction if a else None

    def stats(self) -> dict[str, int]:
        return self.mem.stats()

    def flush(self) -> None:
        with self._lock:
            if self._closed:
                return
            nodes, edges, recs = self.mem.drain()
            if not (nodes or edges or recs):
                return
            try:
                self._write(nodes, edges, recs)
            except Exception:
                log.exception("kuzu batch write failed; batch re-queued")
                self.mem.requeue(nodes, edges, recs)
                raise

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self.flush()
            finally:
                self._closed = True
                self._conn.close()
                self._db.close()

    # ------------------------------------------------------------------ writes
    def _write(self, nodes: list[GNode], edges: list[GEdge], recs: list[EventRec]) -> None:
        c = self._conn
        c.execute("BEGIN TRANSACTION")
        try:
            for n in nodes:
                if n.ntype not in NODE_TYPES:
                    continue
                c.execute(
                    f"MERGE (x:{n.ntype} {{id: $id}}) ON CREATE SET x.label = $l, x.first_seen = $f, "
                    "x.last_seen = $s, x.props = $p ON MATCH SET x.last_seen = $s, x.props = $p",
                    {
                        "id": n.node_id,
                        "l": n.label,
                        "f": n.first_seen,
                        "s": n.last_seen,
                        "p": json.dumps(n.props, default=str),
                    },
                )
            for e in edges:
                if (e.src_type, e.dst_type) not in REL_SCHEMA.get(e.etype, ()):
                    log.warning("skipping illegal edge %s", e.eid)
                    continue
                c.execute(
                    f"MATCH (a:{e.src_type} {{id: $a}}), (b:{e.dst_type} {{id: $b}}) "
                    f"CREATE (a)-[:{e.etype} {{eid: $eid, ts: $ts, event_id: $ev, props: $p}}]->(b)",
                    {
                        "a": e.src,
                        "b": e.dst,
                        "eid": e.eid,
                        "ts": e.ts,
                        "ev": e.event_id,
                        "p": json.dumps(e.props, default=str),
                    },
                )
            for r in recs:
                c.execute(
                    "MERGE (x:EventRecord {id: $id}) ON CREATE SET x.ts = $ts, x.etype = $et, x.proc_id = $pid, "  # noqa: E501
                    "x.host = $h, x.label = $l, x.score = $sc, x.known = $k, x.tags = $t, x.flags = $fl, "
                    "x.structural = $st",
                    {
                        "id": r.event_id, "ts": r.ts, "et": r.etype, "pid": r.proc_id or "", "h": r.host,
                        "l": r.label, "sc": float(r.score), "k": r.known, "t": tags_to_json(r.tags),
                        "fl": json.dumps(r.flags), "st": r.structural,
                    },
                )  # fmt: skip
            c.execute("COMMIT")
        except Exception:
            try:
                c.execute("ROLLBACK")
            except Exception:
                log.exception("rollback failed")
            raise

    # ------------------------------------------------------------------ reads
    def _query(self, q: str, params: dict[str, Any]) -> list[list[Any]]:
        with self._lock:
            res = self._conn.execute(q, params)
            rows: list[list[Any]] = []
            while res.has_next():  # type: ignore[union-attr]
                rows.append(list(res.get_next()))  # type: ignore[union-attr]
            return rows

    def _load_window(self, g: MemoryGraph, lo: int, hi: int, limit: int = 100_000) -> None:
        rows = self._query(
            "MATCH (a)-[r]->(b) WHERE r.ts >= $lo AND r.ts <= $hi "
            "RETURN label(r), label(a), a.id, a.label, a.first_seen, a.last_seen, a.props, "
            "label(b), b.id, b.label, b.first_seen, b.last_seen, b.props, r.eid, r.ts, r.event_id, r.props "
            "LIMIT $lim",
            {"lo": lo, "hi": hi, "lim": limit},
        )
        for row in rows:
            (rt, at, aid, al, af, als, ap, bt, bid, bl, bf, bls, bp, eid, ts, evid, rp) = row
            an = GNode(aid, at, al, af, als, _loads(ap))
            bn = GNode(bid, bt, bl, bf, bls, _loads(bp))
            g.load_edge(GEdge(eid, rt, aid, bid, at, bt, ts, evid, _loads(rp)), an, bn)
        recs = self._query(
            "MATCH (x:EventRecord) WHERE x.ts >= $lo AND x.ts <= $hi "
            "RETURN x.id, x.ts, x.etype, x.proc_id, x.host, x.label, x.score, x.known, x.tags, x.flags, x.structural "  # noqa: E501
            "ORDER BY x.ts LIMIT $lim",
            {"lo": lo, "hi": hi, "lim": limit},
        )
        for rid, ts, et, pid, host, label, score, known, tags, flags, struct in recs:
            g.load_event(
                EventRec(rid, ts, et, pid or None, host, label, float(score), bool(known),
                         tags_from_json(tags), list(_loads_list(flags)), bool(struct))
            )  # fmt: skip

    def _hydrate_recent(self) -> None:
        """Warm the hot index from the most recent window already on disk."""
        try:
            rows = self._query("MATCH (x:EventRecord) RETURN max(x.ts)", {})
            newest = rows[0][0] if rows and rows[0][0] is not None else None
            if newest is None:
                return
            self._load_window(self.mem, newest - self._window_ms, newest)
        except Exception:
            log.exception("graph hydration failed; starting with an empty hot index")

    def _rebuild_around(self, event_id: str) -> MemoryGraph | None:
        self.flush()
        rows = self._query("MATCH (x:EventRecord {id: $id}) RETURN x.ts", {"id": event_id})
        if not rows:
            return None
        ts = rows[0][0]
        tmp = MemoryGraph(**self._memory_kwargs)
        self._load_window(tmp, ts - self._window_ms, ts + self._window_ms)
        return tmp if event_id in tmp.events else None

    def query_edges(self, event_id: str) -> list[tuple[str, str, str]]:
        """Persisted ``(src_id, rel, dst_id)`` triples for an event (flushes first). For tests/dashboard."""
        self.flush()
        rows = self._query(
            "MATCH (a)-[r]->(b) WHERE r.event_id = $ev RETURN a.id, label(r), b.id", {"ev": event_id}
        )
        return [(r[0], r[1], r[2]) for r in rows]

    def persisted_counts(self) -> dict[str, int]:
        self.flush()
        out: dict[str, int] = {}
        for t in NODE_TYPES:
            out[t] = int(self._query(f"MATCH (x:{t}) RETURN count(*)", {})[0][0])
        for rel in REL_SCHEMA:
            out[rel] = int(self._query(f"MATCH ()-[r:{rel}]->() RETURN count(*)", {})[0][0])
        return out


def _loads(text: Any) -> dict[str, Any]:
    try:
        v = json.loads(text) if text else {}
    except (TypeError, ValueError):
        return {}
    return v if isinstance(v, dict) else {}


def _loads_list(text: Any) -> list[str]:
    try:
        v = json.loads(text) if text else []
    except (TypeError, ValueError):
        return []
    return [str(x) for x in v] if isinstance(v, list) else []
