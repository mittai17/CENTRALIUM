from __future__ import annotations

import pytest

from tests.unit.dashboard_conftest_helpers import hdr, make_client, populate

INJECTIONS = [
    "x' OR '1'='1",
    "'; DROP TABLE events; --",
    "1 UNION SELECT * FROM audit_log",
    "%' --",
    '" OR ""="',
]


@pytest.fixture
def client(tmp_path):
    c = make_client(tmp_path)
    populate(tmp_path / "d.db")
    return c


def hunt(c, body, role="analyst"):
    return c.post("/api/hunt", json=body, headers=hdr(role))


def test_basic_hunt_and_count_by(client):
    r = hunt(
        client,
        {"source": "events", "filters": [{"field": "process_name", "op": "contains", "value": "power"}]},
    ).json()
    assert r["total"] == 2 and r["items"][0]["process_name"] == "powershell"
    r = hunt(client, {"source": "events", "count_by": "event_type"}).json()
    assert {i["value"]: i["count"] for i in r["items"]} == {"process_start": 1, "network_connect": 1}
    r = hunt(
        client,
        {"source": "network", "filters": [{"field": "destination_port", "op": "in", "value": [443, 80]}]},
    ).json()
    assert r["total"] == 1


def test_unknown_field_source_op_rejected(client):
    assert hunt(client, {"source": "audit_log"}).status_code == 422
    assert (
        hunt(
            client, {"source": "events", "filters": [{"field": "raw_metadata", "op": "eq", "value": "x"}]}
        ).status_code
        == 422
    )
    assert (
        hunt(
            client, {"source": "events", "filters": [{"field": "1=1; --", "op": "eq", "value": "x"}]}
        ).status_code
        == 422
    )
    assert (
        hunt(
            client, {"source": "events", "filters": [{"field": "pid", "op": "contains", "value": "1"}]}
        ).status_code
        == 422
    )
    assert (
        hunt(
            client, {"source": "events", "filters": [{"field": "pid", "op": "eq", "value": "abc"}]}
        ).status_code
        == 422
    )
    assert (
        hunt(
            client, {"source": "events", "filters": [{"field": "pid", "op": "OR 1=1", "value": 1}]}
        ).status_code
        == 422
    )
    assert hunt(client, {"source": "events", "count_by": "pid) FROM audit_log --"}).status_code == 422
    assert hunt(client, {"source": "events", "sql": "SELECT * FROM audit_log"}).status_code == 422
    assert hunt(client, {"source": "events", "limit": 100000}).status_code == 422
    assert hunt(client, {"source": "events", "since": "yesterday"}).status_code == 422


@pytest.mark.parametrize("payload", INJECTIONS)
def test_injection_payloads_are_inert_values(client, payload):
    for op in ("eq", "contains", "startswith", "ne"):
        r = hunt(
            client, {"source": "events", "filters": [{"field": "process_name", "op": op, "value": payload}]}
        )
        assert r.status_code == 200
        if op in ("eq", "contains", "startswith"):
            assert r.json()["total"] == 0
    r = hunt(
        client, {"source": "events", "filters": [{"field": "process_name", "op": "in", "value": [payload]}]}
    )
    assert r.status_code == 200 and r.json()["total"] == 0
    # data still intact
    assert client.get("/api/overview", headers=hdr("viewer")).json()["counts"]["events"] == 2


def test_like_wildcards_escaped(client):
    r = hunt(
        client, {"source": "events", "filters": [{"field": "process_name", "op": "contains", "value": "%"}]}
    ).json()
    assert r["total"] == 0
    r = hunt(
        client, {"source": "events", "filters": [{"field": "process_name", "op": "contains", "value": "_"}]}
    ).json()
    assert r["total"] == 0


def test_builder_never_uses_client_identifiers():
    from dashboard.backend import hunting

    q = hunting.HuntQuery(source="events", filters=[hunting.HuntFilter(field="pid", op="eq", value=7731)])
    sql, params, _, _ = hunting.build(q)
    assert "7731" not in sql and params[0] == 7731
    assert hunting.build(hunting.HuntQuery(source="files"))[0].startswith('SELECT "path"')
