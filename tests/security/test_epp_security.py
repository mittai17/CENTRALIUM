from __future__ import annotations

import os
from pathlib import Path

import pytest

from centralium.agent.epp import DefaultEPPEngine, build_epp_stack
from centralium.agent.models import EventType, NormalizedEvent

pytestmark = pytest.mark.security
RULES = Path(__file__).resolve().parents[2] / "rules"


def test_huge_file_is_not_hashed(make_event, tmp_path) -> None:
    p = tmp_path / "big"
    with open(p, "wb") as f:
        f.truncate(300 * 1024 * 1024)  # sparse
    e = DefaultEPPEngine(max_hash_bytes=1024 * 1024)
    assert e._sha(make_event(event_type=EventType.FILE_CREATE, file_path=str(p)), str(p)) is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="posix only")
def test_fifo_and_device_do_not_hang(make_event, tmp_path) -> None:
    fifo = tmp_path / "ff"
    os.mkfifo(fifo)
    e = DefaultEPPEngine()
    assert e.inspect(make_event(event_type=EventType.FILE_CREATE, file_path=str(fifo))) == []
    assert e.inspect(make_event(event_type=EventType.FILE_CREATE, file_path="/dev/zero")) == []


@pytest.mark.parametrize(
    "path",
    [
        "a\x00b",
        "",
        "/",
        "..",
        "../" * 100,
        "C:",
        "\\\\?\\",
        "/tmp/" + "A" * 5000,
        "\u202e/tmp/x",
        "%00",
        "/tmp/\n/x",
    ],
)
def test_malformed_paths_never_raise(make_event, db, path) -> None:
    stack = build_epp_stack(db, RULES)
    for et in (EventType.PROCESS_START, EventType.FILE_CREATE, EventType.MODULE_LOAD):
        stack.epp.inspect(make_event(event_type=et, executable_path=path, file_path=path))


def test_traversal_cannot_hide_tmp_exec_or_fake_allowlist(db, make_event) -> None:
    from centralium.agent.storage import Repository

    repo = Repository(db)
    repo.add_allowlist("path", "/opt/safe/app")
    e = DefaultEPPEngine(repo=repo, list_cache_ttl_s=0)
    f = e.inspect(make_event(executable_path="/opt/safe/app/../../../tmp/evil"))
    assert any(x.rule_id == "EPP-PATH-LNX-TMP" for x in f)
    assert all(x.source.value != "allowlist" for x in f)


def test_hostile_event_fields_are_data_only(db, make_event) -> None:
    stack = build_epp_stack(db, RULES)
    ev = make_event(
        command_line="'; DROP TABLE ioc_cache; -- http://" + "a" * 3000 + ".example.test/x " * 50,
        domain="x'); DROP TABLE blocklist;--.example.test",
        process_name="$(touch /tmp/pwned)",
    )
    stack.epp.inspect(ev)
    assert db.count("ioc_cache") > 0 and not Path("/tmp/pwned").exists()


def test_event_model_rejects_bad_hash() -> None:
    with pytest.raises(ValueError):
        NormalizedEvent(event_type=EventType.OTHER, hash_sha256="xyz")


def test_poisoned_feed_cannot_blocklist_loopback(db, make_event) -> None:
    from centralium.agent.threat_intel import CachedIOCStore, parse_threatfox

    body = '{"query_status":"ok","data":[{"ioc":"127.0.0.1:1","ioc_type":"ip:port"},{"ioc":"0.0.0.0:1","ioc_type":"ip:port"}]}'
    store = CachedIOCStore(db)
    assert store.add_records(parse_threatfox(body).records) == 0
    assert DefaultEPPEngine(intel=store).inspect(make_event(destination_ip="127.0.0.1")) == []
