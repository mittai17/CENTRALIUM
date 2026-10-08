"""Cross-host correlation and enterprise fleet threat hunting.

Aggregates shared IOC sightings across endpoints, tracks cross-host lateral
movement graphs, performs fleet-wide whitelisted threat hunting, and generates
unified fleet incident views.
"""

from __future__ import annotations

import collections
import ipaddress
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from centralium.agent.storage import Database
from dashboard.backend.hunting import HuntQuery, build

log = logging.getLogger("centralium.fleet.correlation")


@dataclass
class SharedIOCSighting:
    ioc_type: str  # "hash_sha256", "ip", "domain"
    value: str
    hosts: list[str]
    first_seen: str
    last_seen: str
    hit_count: int
    severity: str = "medium"
    sample_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_private_or_loopback_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def aggregate_shared_iocs(
    events: list[dict[str, Any]],
    findings: list[dict[str, Any]] | None = None,
    min_hosts: int = 2,
    include_private_ips: bool = False,
) -> list[SharedIOCSighting]:
    """Aggregate IOC sightings across multiple hosts."""
    # (ioc_type, value) -> list of events
    ioc_map: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)

    # Helper to ingest an indicator
    def add_ioc(ioc_type: str, val: str | None, ev: dict[str, Any]) -> None:
        if not val or not isinstance(val, str):
            return
        clean_val = val.strip().lower()
        if not clean_val or clean_val in ("unknown", "null", "none"):
            return
        if ioc_type == "ip" and not include_private_ips and _is_private_or_loopback_ip(clean_val):
            return
        ioc_map[(ioc_type, clean_val)].append(ev)

    for ev in events:
        if ev.get("hash_sha256"):
            add_ioc("hash_sha256", ev["hash_sha256"], ev)
        if ev.get("destination_ip"):
            add_ioc("ip", ev["destination_ip"], ev)
        if ev.get("domain"):
            add_ioc("domain", ev["domain"], ev)

    findings_list = findings or []
    for f in findings_list:
        ev_id = f.get("event_id")
        f_host = f.get("host_id") or "unknown"
        f_synthetic_ev = {
            "event_id": ev_id or f.get("finding_id"),
            "host_id": f_host,
            "timestamp": f.get("timestamp", datetime.now(UTC).isoformat()),
            "severity": f.get("severity", "medium"),
        }
        # Check if details has iocs
        details = f.get("details")
        if isinstance(details, dict):
            if details.get("hash_sha256"):
                add_ioc("hash_sha256", details["hash_sha256"], f_synthetic_ev)
            if details.get("ip"):
                add_ioc("ip", details["ip"], f_synthetic_ev)
            if details.get("domain"):
                add_ioc("domain", details["domain"], f_synthetic_ev)

    results: list[SharedIOCSighting] = []
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for (ioc_type, val), ev_list in ioc_map.items():
        hosts = sorted({e.get("host_id", "unknown") for e in ev_list})
        if len(hosts) < min_hosts:
            continue

        timestamps = [e.get("timestamp", "") for e in ev_list if e.get("timestamp")]
        first_seen = min(timestamps) if timestamps else datetime.now(UTC).isoformat()
        last_seen = max(timestamps) if timestamps else datetime.now(UTC).isoformat()

        # Compute severity based on host breadth and matched finding severities
        sev_score = 2  # medium
        if len(hosts) >= 3:
            sev_score = 3  # high
        if len(hosts) >= 5 or ioc_type == "hash_sha256":
            sev_score = max(sev_score, 3)

        for e in ev_list:
            e_sev = e.get("severity", "medium").lower()
            if severity_order.get(e_sev, 1) > sev_score:
                sev_score = severity_order[e_sev]

        sev_label = "medium"
        for label, score in severity_order.items():
            if score == sev_score:
                sev_label = label
                break

        results.append(
            SharedIOCSighting(
                ioc_type=ioc_type,
                value=val,
                hosts=hosts,
                first_seen=first_seen,
                last_seen=last_seen,
                hit_count=len(ev_list),
                severity=sev_label,
                sample_events=ev_list[:5],
            )
        )

    results.sort(key=lambda s: (severity_order.get(s.severity, 0), len(s.hosts)), reverse=True)
    return results


@dataclass
class LateralMovementEdge:
    source_host: str
    target_host: str
    protocol: str  # "ssh", "rdp", "smb", "winrm", "wmi", "custom"
    source_user: str | None
    target_user: str | None
    timestamp: str
    technique: str
    evidence_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LateralMovementGraph:
    """Builds and analyzes cross-host lateral movement relationships."""

    LATERAL_PORTS: dict[int, tuple[str, str]] = {
        22: ("ssh", "T1021.004 - SSH"),
        3389: ("rdp", "T1021.001 - Remote Desktop Protocol"),
        445: ("smb", "T1021.002 - SMB/Windows Admin Shares"),
        139: ("smb", "T1021.002 - SMB/NetBIOS"),
        5985: ("winrm", "T1021.006 - Windows Remote Management"),
        5986: ("winrm", "T1021.006 - Windows Remote Management (HTTPS)"),
        135: ("wmi", "T1047 - Windows Management Instrumentation"),
    }

    def __init__(self, host_ip_map: dict[str, str] | None = None) -> None:
        # IP -> host_id mapping
        self.ip_to_host: dict[str, str] = dict(host_ip_map or {})
        self.edges: list[LateralMovementEdge] = []
        self.nodes: set[str] = set()

    def register_host(self, host_id: str, ip_address_val: str) -> None:
        self.ip_to_host[ip_address_val] = host_id
        self.nodes.add(host_id)

    def add_edge(self, edge: LateralMovementEdge) -> None:
        self.edges.append(edge)
        self.nodes.add(edge.source_host)
        self.nodes.add(edge.target_host)

    def ingest_network_event(self, event: dict[str, Any]) -> LateralMovementEdge | None:
        """Infer cross-host lateral movement from network connections."""
        src_host = event.get("host_id")
        dst_ip = event.get("destination_ip")
        dst_port = event.get("destination_port")
        if not src_host or not dst_ip or not dst_port:
            return None

        # Check if dst_ip belongs to known fleet host
        target_host = self.ip_to_host.get(dst_ip)
        port_num = int(dst_port)

        protocol, technique = self.LATERAL_PORTS.get(port_num, ("unknown", "T1021 - Remote Services"))
        if not target_host and port_num not in self.LATERAL_PORTS:
            return None

        dest_name = target_host or f"host_at_{dst_ip}"
        if dest_name == src_host:
            return None  # Loopback on same host

        edge = LateralMovementEdge(
            source_host=src_host,
            target_host=dest_name,
            protocol=protocol,
            source_user=event.get("user"),
            target_user=None,
            timestamp=event.get("timestamp", datetime.now(UTC).isoformat()),
            technique=technique,
            evidence_event_ids=[event.get("event_id", "")],
        )
        self.add_edge(edge)
        return edge

    def detect_pivot_hosts(self) -> list[str]:
        """Detect pivot endpoints (hosts that received inbound and launched outbound lateral movement)."""
        inbound = collections.defaultdict(set)
        outbound = collections.defaultdict(set)
        for e in self.edges:
            inbound[e.target_host].add(e.source_host)
            outbound[e.source_host].add(e.target_host)

        pivots: list[str] = []
        for host in self.nodes:
            if inbound.get(host) and outbound.get(host):
                pivots.append(host)
        return sorted(pivots)

    def find_paths(self, start_host: str, max_depth: int = 5) -> list[list[str]]:
        """Breadth-first search finding lateral movement propagation paths from a start host."""
        adj: dict[str, set[str]] = collections.defaultdict(set)
        for e in self.edges:
            adj[e.source_host].add(e.target_host)

        paths: list[list[str]] = []
        queue: collections.deque[list[str]] = collections.deque([[start_host]])
        while queue:
            current_path = queue.popleft()
            if len(current_path) > max_depth:
                continue
            curr = current_path[-1]
            neighbors = adj.get(curr, set())
            if not neighbors:
                if len(current_path) > 1:
                    paths.append(current_path)
                continue
            extended = False
            for nxt in neighbors:
                if nxt not in current_path:  # avoid cycles
                    queue.append([*current_path, nxt])
                    extended = True
            if not extended and len(current_path) > 1:
                paths.append(current_path)
        return paths

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": sorted(self.nodes),
            "edges": [e.to_dict() for e in self.edges],
            "pivots": self.detect_pivot_hosts(),
        }


class FleetThreatHunter:
    """Executes fleet-wide threat hunting queries using the whitelisted query builder."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def execute_hunt(
        self,
        query: HuntQuery,
        host_ids: list[str] | None = None,
        max_rows: int = 500,
    ) -> dict[str, Any]:
        """Execute parameterized query across fleet data, enforcing strict query builder safety."""
        sql, params, _, _ = build(query)

        # Apply host-scoping if specified
        if host_ids:
            # Safely inject host_id IN (...) condition into the generated whitelisted SQL
            placeholders = ",".join("?" for _ in host_ids)
            if "WHERE" in sql:
                sql = sql.replace("WHERE", f"WHERE host_id IN ({placeholders}) AND", 1)
            elif "ORDER BY" in sql:
                sql = sql.replace("ORDER BY", f"WHERE host_id IN ({placeholders}) ORDER BY", 1)
            else:
                sql += f" WHERE host_id IN ({placeholders})"
            params = [*host_ids, *params]

        rows = self.db.query(sql, params)
        limited_rows = rows[:max_rows]

        hits_by_host: dict[str, int] = collections.defaultdict(int)
        for r in limited_rows:
            r_dict = dict(r) if not isinstance(r, dict) else r
            h = r_dict.get("host_id") or "unknown"
            hits_by_host[h] += 1

        return {
            "source": query.source,
            "total_hits": len(limited_rows),
            "hits_by_host": dict(hits_by_host),
            "items": limited_rows,
            "applied_clauses_count": len(query.filters),
        }


@dataclass
class FleetIncident:
    fleet_incident_id: str
    title: str
    severity: str
    status: str
    affected_hosts: list[str]
    host_incident_ids: list[str]
    correlated_iocs: list[str]
    lateral_movement_paths: list[dict[str, Any]]
    finding_count: int
    mitre_techniques: list[str]
    first_seen: str
    last_seen: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def correlate_fleet_incidents(
    host_incidents: list[dict[str, Any]],
    shared_iocs: list[SharedIOCSighting] | None = None,
    lateral_edges: list[LateralMovementEdge] | None = None,
) -> list[FleetIncident]:
    """Correlate host-level incidents into an enterprise-wide unified fleet incident view."""
    if not host_incidents:
        return []

    # Map IOCs to host incidents
    ioc_to_incidents: dict[str, set[str]] = collections.defaultdict(set)
    for inc in host_incidents:
        inc_id = inc.get("incident_id", "")
        # Inspect incident summary or actions for IOC values
        summary = str(inc.get("summary", "")).lower()
        if shared_iocs:
            for s in shared_iocs:
                if s.value.lower() in summary:
                    ioc_to_incidents[s.value].add(inc_id)

    # Disjoint-set union to cluster incidents
    parent: dict[str, str] = {}

    def find(i: str) -> str:
        parent.setdefault(i, i)
        if parent[i] != i:
            parent[i] = find(parent[i])
        return parent[i]

    def union(i1: str, i2: str) -> None:
        r1, r2 = find(i1), find(i2)
        if r1 != r2:
            parent[r1] = r2

    # Group incidents by shared IOCs
    for inc_set in ioc_to_incidents.values():
        if len(inc_set) > 1:
            first = next(iter(inc_set))
            for other in inc_set:
                union(first, other)

    # Group incidents across hosts that share lateral movement links
    if lateral_edges:
        host_to_incs: dict[str, set[str]] = collections.defaultdict(set)
        for inc in host_incidents:
            h = inc.get("host_id")
            if h:
                host_to_incs[h].add(inc.get("incident_id", ""))

        for edge in lateral_edges:
            src_incs = host_to_incs.get(edge.source_host, set())
            dst_incs = host_to_incs.get(edge.target_host, set())
            for si in src_incs:
                for di in dst_incs:
                    union(si, di)

    # Collect clusters
    clusters: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for inc in host_incidents:
        inc_id = inc.get("incident_id", "")
        root = find(inc_id)
        clusters[root].append(inc)

    fleet_incidents: list[FleetIncident] = []
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    for cluster_incs in clusters.values():
        affected_hosts: list[str] = sorted(
            {str(inc.get("host_id")) for inc in cluster_incs if inc.get("host_id")}
        )
        inc_ids = [inc.get("incident_id", "") for inc in cluster_incs]

        # Aggregate MITRE techniques
        all_techniques: set[str] = set()
        for inc in cluster_incs:
            raw_tech = inc.get("mitre_techniques")
            if isinstance(raw_tech, list):
                all_techniques.update(raw_tech)
            elif isinstance(raw_tech, str) and raw_tech:
                try:
                    import json

                    loaded = json.loads(raw_tech)
                    if isinstance(loaded, list):
                        all_techniques.update(loaded)
                except Exception:
                    all_techniques.add(raw_tech)

        # Collect correlated IOCs
        matched_iocs: list[str] = []
        if shared_iocs:
            for s in shared_iocs:
                if any(h in affected_hosts for h in s.hosts):
                    matched_iocs.append(f"{s.ioc_type}:{s.value}")

        # Collect lateral paths between affected hosts
        lat_paths: list[dict[str, Any]] = []
        if lateral_edges:
            for edge in lateral_edges:
                if edge.source_host in affected_hosts and edge.target_host in affected_hosts:
                    lat_paths.append(edge.to_dict())

        # Determine severity
        max_sev = "medium"
        for inc in cluster_incs:
            s = inc.get("band", inc.get("severity", "medium")).lower()
            if severity_rank.get(s, 1) > severity_rank.get(max_sev, 1):
                max_sev = s
        if len(affected_hosts) > 1 and max_sev in ("medium", "low"):
            max_sev = "high"
        if len(affected_hosts) >= 3 or lat_paths:
            max_sev = "critical"

        # Determine earliest and latest timestamps
        timestamps: list[str] = []
        for inc in cluster_incs:
            if inc.get("created_at"):
                timestamps.append(inc["created_at"])
            if inc.get("updated_at"):
                timestamps.append(inc["updated_at"])

        first_seen = min(timestamps) if timestamps else datetime.now(UTC).isoformat()
        last_seen = max(timestamps) if timestamps else datetime.now(UTC).isoformat()

        f_id = f"fleet_inc_{uuid.uuid4().hex[:10]}"
        title = f"Multi-host Activity across {len(affected_hosts)} endpoint(s)"
        if cluster_incs:
            first_title = cluster_incs[0].get("title")
            if first_title:
                title = f"{first_title} (Fleet Campaign: {len(affected_hosts)} hosts)"

        summary = (
            f"Enterprise campaign affecting {len(affected_hosts)} hosts: {', '.join(affected_hosts)}. "
            f"Correlated {len(inc_ids)} host incidents with {len(matched_iocs)} shared indicators "
            f"and {len(lat_paths)} lateral movements."
        )

        fleet_incidents.append(
            FleetIncident(
                fleet_incident_id=f_id,
                title=title,
                severity=max_sev,
                status="open",
                affected_hosts=affected_hosts,
                host_incident_ids=inc_ids,
                correlated_iocs=matched_iocs,
                lateral_movement_paths=lat_paths,
                finding_count=sum(len(inc.get("finding_ids", [])) for inc in cluster_incs),
                mitre_techniques=sorted(all_techniques),
                first_seen=first_seen,
                last_seen=last_seen,
                summary=summary,
            )
        )

    fleet_incidents.sort(key=lambda fi: severity_rank.get(fi.severity, 0), reverse=True)
    return fleet_incidents
