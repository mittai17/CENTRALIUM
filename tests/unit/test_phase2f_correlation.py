"""Unit tests for Phase 2F: Cross-host correlation, lateral movement graph, and fleet threat hunting."""

from __future__ import annotations

import json
from pathlib import Path

from centralium.agent.storage import Database
from centralium.fleet.correlation import (
    FleetThreatHunter,
    LateralMovementGraph,
    aggregate_shared_iocs,
    correlate_fleet_incidents,
)
from dashboard.backend.hunting import HuntFilter, HuntQuery


def test_shared_ioc_sightings_aggregation():
    """Test aggregating shared IOC sightings across multiple hosts."""
    events = [
        # Host A sees malicious SHA-256 and C2 domain
        {
            "event_id": "ev_01",
            "host_id": "host-srv-alpha",
            "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "domain": "evil-c2-infrastructure.com",
            "destination_ip": "198.51.100.20",
            "timestamp": "2026-10-08T01:00:00Z",
            "severity": "high",
        },
        # Host B sees same SHA-256 and private IP (which should be skipped)
        {
            "event_id": "ev_02",
            "host_id": "host-srv-beta",
            "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "destination_ip": "10.0.0.5",  # private IP
            "timestamp": "2026-10-08T01:05:00Z",
            "severity": "medium",
        },
        # Host C sees same C2 domain and same C2 IP
        {
            "event_id": "ev_03",
            "host_id": "host-srv-gamma",
            "domain": "evil-c2-infrastructure.com",
            "destination_ip": "198.51.100.20",
            "timestamp": "2026-10-08T01:10:00Z",
            "severity": "critical",
        },
    ]

    shared = aggregate_shared_iocs(events, min_hosts=2)
    assert len(shared) >= 2  # hash_sha256 and domain and c2 ip

    hash_sighting = next(s for s in shared if s.ioc_type == "hash_sha256")
    assert sorted(hash_sighting.hosts) == ["host-srv-alpha", "host-srv-beta"]
    assert hash_sighting.hit_count == 2
    assert hash_sighting.severity in ("high", "critical")

    domain_sighting = next(s for s in shared if s.ioc_type == "domain")
    assert sorted(domain_sighting.hosts) == ["host-srv-alpha", "host-srv-gamma"]

    # Private IP 10.0.0.5 should not be in shared sightings
    assert not any(s.value == "10.0.0.5" for s in shared)


def test_lateral_movement_graph_and_pivot_detection():
    """Test cross-host lateral movement graph construction, pathing, and pivot detection."""
    graph = LateralMovementGraph(
        host_ip_map={
            "10.0.1.10": "host-jumpbox",
            "10.0.1.20": "host-app-server",
            "10.0.1.30": "host-database",
        }
    )

    # 1. External -> jumpbox -> app server over SSH
    ev1 = {
        "event_id": "ev_ssh_1",
        "host_id": "host-jumpbox",
        "destination_ip": "10.0.1.20",
        "destination_port": 22,
        "user": "root",
        "timestamp": "2026-10-08T02:00:00Z",
    }
    graph.ingest_network_event(ev1)

    # 2. App server -> database over SMB (port 445)
    ev2 = {
        "event_id": "ev_smb_2",
        "host_id": "host-app-server",
        "destination_ip": "10.0.1.30",
        "destination_port": 445,
        "user": "admin",
        "timestamp": "2026-10-08T02:05:00Z",
    }
    graph.ingest_network_event(ev2)

    assert len(graph.edges) == 2
    assert graph.edges[0].technique == "T1021.004 - SSH"
    assert graph.edges[1].technique == "T1021.002 - SMB/Windows Admin Shares"

    # Pivot detection: host-app-server received inbound and made outbound connection
    pivots = graph.detect_pivot_hosts()
    assert pivots == ["host-app-server"]

    # Propagation path finding
    paths = graph.find_paths("host-jumpbox")
    assert len(paths) == 1
    assert paths[0] == ["host-jumpbox", "host-app-server", "host-database"]


def test_fleet_wide_threat_hunting_with_whitelisted_builder(tmp_path: Path):
    """Test fleet hunting across endpoints using whitelisted parameterized query model."""
    db = Database(tmp_path / "fleet_events.db")

    # Insert test events across multiple hosts
    db.execute(
        """INSERT INTO events
           (event_id, timestamp, event_type, host_id, user, pid, process_name, executable_path, command_line)
           VALUES
           ('ev_h1', '2026-10-08T01:00:00Z', 'process_create', 'host-alpha', 'analyst', 101, 'powershell.exe',
            '/bin/powershell', 'powershell.exe -enc dGVzdA=='),
           ('ev_h2', '2026-10-08T01:01:00Z', 'process_create', 'host-beta', 'admin', 102, 'powershell.exe',
            '/bin/powershell', 'powershell.exe -enc dGVzdA=='),
           ('ev_h3', '2026-10-08T01:02:00Z', 'process_create', 'host-gamma', 'user', 103, 'bash',
            '/bin/bash', 'bash -c ls')"""
    )

    hunter = FleetThreatHunter(db)

    # Build whitelisted query hunting for powershell executions
    query = HuntQuery(
        source="events",
        filters=[HuntFilter(field="process_name", op="eq", value="powershell.exe")],
        limit=50,
    )

    # Execute hunt fleet-wide
    result = hunter.execute_hunt(query)
    assert result["total_hits"] == 2
    assert result["hits_by_host"]["host-alpha"] == 1
    assert result["hits_by_host"]["host-beta"] == 1

    # Execute hunt scoped to host-alpha only
    scoped_result = hunter.execute_hunt(query, host_ids=["host-alpha"])
    assert scoped_result["total_hits"] == 1
    assert "host-beta" not in scoped_result["hits_by_host"]


def test_unified_fleet_incident_view():
    """Test correlating host-level incidents into an enterprise fleet campaign."""
    host_incidents = [
        {
            "incident_id": "inc_h1",
            "host_id": "host-sales-01",
            "title": "Phishing Payload Executed",
            "severity": "high",
            "summary": "Observed execution of malware with sha256:abcd1234deadbeef",
            "mitre_techniques": json.dumps(["T1566.001", "T1059.001"]),
            "created_at": "2026-10-08T01:00:00Z",
            "updated_at": "2026-10-08T01:30:00Z",
        },
        {
            "incident_id": "inc_h2",
            "host_id": "host-dc-01",
            "title": "Credential Dumping",
            "severity": "critical",
            "summary": "LSASS dumped using payload matching sha256:abcd1234deadbeef",
            "mitre_techniques": json.dumps(["T1003.001", "T1021.002"]),
            "created_at": "2026-10-08T02:00:00Z",
            "updated_at": "2026-10-08T02:45:00Z",
        },
    ]

    from centralium.fleet.correlation import LateralMovementEdge, SharedIOCSighting

    shared_iocs = [
        SharedIOCSighting(
            ioc_type="hash_sha256",
            value="abcd1234deadbeef",
            hosts=["host-sales-01", "host-dc-01"],
            first_seen="2026-10-08T01:00:00Z",
            last_seen="2026-10-08T02:00:00Z",
            hit_count=2,
            severity="critical",
        )
    ]

    lateral_edges = [
        LateralMovementEdge(
            source_host="host-sales-01",
            target_host="host-dc-01",
            protocol="smb",
            source_user="svc_backup",
            target_user="Administrator",
            timestamp="2026-10-08T01:45:00Z",
            technique="T1021.002",
        )
    ]

    fleet_incidents = correlate_fleet_incidents(
        host_incidents=host_incidents,
        shared_iocs=shared_iocs,
        lateral_edges=lateral_edges,
    )

    assert len(fleet_incidents) == 1
    fi = fleet_incidents[0]
    assert fi.severity == "critical"
    assert sorted(fi.affected_hosts) == ["host-dc-01", "host-sales-01"]
    assert len(fi.host_incident_ids) == 2
    assert "T1003.001" in fi.mitre_techniques
    assert "T1566.001" in fi.mitre_techniques
    assert len(fi.lateral_movement_paths) == 1
    assert "hash_sha256:abcd1234deadbeef" in fi.correlated_iocs
