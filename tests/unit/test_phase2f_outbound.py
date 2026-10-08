"""Unit tests for Phase 2F: Outbound SIEM/SOAR/Ticketing export forwarders."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from centralium.agent.integrations.outbound import (
    ForwarderConfig,
    OutboundIntegrationsConfig,
    OutboundQueueManager,
    compute_webhook_signature,
    format_cef,
    format_elastic_bulk,
    format_splunk_hec,
    format_ticket_json,
    format_webhook_payload,
)
from centralium.agent.sync.queue import DurableSyncQueue as SyncQueue


def test_cef_formatter():
    """Test ArcSight CEF formatting, delimiter escaping, and extension mapping."""
    item = {
        "event_id": "ev-12345",
        "rule_id": "RULE-RANSOMWARE-DETECT",
        "title": "Suspicious Canary File Modification",
        "severity": "high",
        "host_id": "workstation-09",
        "destination_ip": "198.51.100.55",
        "destination_port": 443,
        "user": "developer_alice",
        "executable_path": "/usr/bin/python3",
        "hash_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "mitre_techniques": "T1486",
        "summary": "Process modified canary file in C:\\ProgramData|Temp",
    }

    cef_str = format_cef(item)
    assert cef_str.startswith("CEF:0|Centralium|EDR|1.0|RULE-RANSOMWARE-DETECT|")
    assert "|8|" in cef_str  # High severity mapped to 8
    assert "externalId=ev-12345" in cef_str
    assert "shost=workstation-09" in cef_str
    assert "dst=198.51.100.55" in cef_str
    assert "dpt=443" in cef_str
    assert "suser=developer_alice" in cef_str
    assert "cs1=T1486" in cef_str
    # Escaping check for pipe in summary
    assert "C:\\ProgramData\\|Temp" in cef_str or "C:\\\\ProgramData\\|Temp" in cef_str


def test_splunk_hec_and_elastic_bulk_formatters():
    """Test Splunk HEC JSON payload and Elastic _bulk NDJSON formatting."""
    event = {
        "event_id": "ev_splunk_1",
        "host_id": "host-srv-1",
        "timestamp": "2026-10-08T01:30:00Z",
        "process_name": "curl",
        "severity": "low",
    }

    # Splunk HEC
    hec = format_splunk_hec(event, host_id="host-srv-1", index="security_alerts")
    assert hec["source"] == "centralium"
    assert hec["sourcetype"] == "centralium:edr"
    assert hec["index"] == "security_alerts"
    assert hec["event"]["event_id"] == "ev_splunk_1"
    assert isinstance(hec["time"], (int, float))

    # Elastic bulk
    bulk_str = format_elastic_bulk([event], index_name="centralium-siem")
    lines = bulk_str.strip().split("\n")
    assert len(lines) == 2
    action_doc = json.loads(lines[0])
    source_doc = json.loads(lines[1])
    assert action_doc["index"]["_index"] == "centralium-siem"
    assert source_doc["@timestamp"] == "2026-10-08T01:30:00Z"
    assert source_doc["process_name"] == "curl"


def test_webhook_and_ticket_json_formatters():
    """Test generic webhook formatting with HMAC signature and ServiceNow/Jira ticketing JSON."""
    finding = {
        "finding_id": "f_99",
        "incident_id": "inc_777",
        "title": "Ransomware Encryption Observed",
        "severity": "CRITICAL",
        "host_id": "db-prod-01",
        "mitre_techniques": ["T1486"],
        "summary": "Volume shadow copies deleted and .locked files detected.",
    }

    # Ticket JSON
    ticket = format_ticket_json(finding)
    assert ticket["issue_type"] == "Security Incident"
    assert ticket["priority"] == "P1"  # Critical mapped to P1
    assert ticket["severity"] == "CRITICAL"
    assert ticket["affected_host"] == "db-prod-01"
    assert "centralium" in ticket["labels"]

    # Webhook payload & HMAC signature
    wh_payload = format_webhook_payload(finding, event_type="alert.critical")
    assert wh_payload["event_type"] == "alert.critical"
    assert wh_payload["severity"] == "CRITICAL"

    raw_bytes = json.dumps(wh_payload).encode("utf-8")
    sig = compute_webhook_signature(raw_bytes, secret_token="supersecret-webhook-key")
    assert sig.startswith("sha256=")


def test_https_security_enforcement():
    """Test outbound forwarders enforce HTTPS-only endpoints in production."""
    insecure_cfg = ForwarderConfig(
        enabled=True,
        endpoint_url="http://insecure-collector.internal/api",
        credential_env="COLLECTOR_TOKEN",
        allow_insecure_http_for_tests=False,
    )
    with pytest.raises(ValueError) as exc:
        insecure_cfg.validate_security()
    assert "require HTTPS" in str(exc.value)

    # Valid HTTPS configuration
    secure_cfg = ForwarderConfig(
        enabled=True,
        endpoint_url="https://secure-hec.splunk.internal:8088/services/collector",
        credential_env="COLLECTOR_TOKEN",
    )
    secure_cfg.validate_security()  # Should not raise


def test_outbound_queue_non_blocking_behavior(tmp_path: Path):
    """Test that outbound queueing is strictly non-blocking and never halts detection."""
    queue_db = tmp_path / "test_sync_queue.db"
    queue = SyncQueue(queue_db)

    config = OutboundIntegrationsConfig(
        syslog_cef=ForwarderConfig(enabled=True, endpoint_url="https://syslog.internal:6514"),
        splunk_hec=ForwarderConfig(
            enabled=True,
            endpoint_url="https://splunk.internal:8088/hec",
            credential_env="SPLUNK_HEC_TOKEN",
        ),
    )

    mgr = OutboundQueueManager(config=config, queue=queue)

    event = {
        "event_id": "ev_nonblock_1",
        "host_id": "host-alpha",
        "title": "Test Detection",
        "severity": "medium",
    }

    # Normal enqueue
    res = mgr.enqueue_for_forwarding(event)
    assert res.get("syslog_cef") is True
    assert res.get("splunk_hec") is True
    assert mgr.enqueued_count == 2
    assert mgr.dropped_count == 0

    # Ensure queue actually received the items
    stats = queue.stats()
    assert stats["by_status"].get("pending") == 2

    # Simulate broken queue: corrupt the database / fail enqueue
    def broken_enqueue(*args, **kwargs):
        raise sqlite3.DatabaseError("database disk image is malformed")

    queue.enqueue = broken_enqueue

    # Enqueue should catch any exception and NOT raise out to caller
    res2 = mgr.enqueue_for_forwarding(event)
    # The call did not raise!
    assert res2.get("syslog_cef") in (False, None)
