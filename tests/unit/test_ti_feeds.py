from __future__ import annotations

from pathlib import Path

import pytest

from centralium.agent.threat_intel import (
    CachedIOCStore,
    FeedParseError,
    FeedSpec,
    FeedUpdater,
    parse_feed,
    parse_feodo,
    parse_malwarebazaar,
    parse_threatfox,
    parse_urlhaus,
)
from centralium.agent.threat_intel.feeds import normalize_domain, normalize_ip, normalize_url, parse_timestamp

FX = Path(__file__).parent / "ti_fixtures"
REPO_IOC = Path(__file__).resolve().parents[2] / "rules" / "ioc"
EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_malwarebazaar_csv() -> None:
    r = parse_malwarebazaar((FX / "malwarebazaar_recent.csv").read_bytes())
    assert [x.value[:2] for x in r.records] == ["aa", "bb"]  # uppercase normalized
    assert r.rejected == 1
    assert r.records[0].threat_type == "FixtureLoader"
    assert r.records[0].first_seen == "2024-05-01T10:11:12+00:00"
    assert r.records[0].source == "malwarebazaar"
    assert r.records[1].threat_type == "malware"


def test_malwarebazaar_json_api() -> None:
    doc = (
        '{"query_status":"ok","data":[{"sha256_hash":"%s","first_seen":"2024-01-01 00:00:00","signature":"X"}]}'
        % ("d" * 64)
    )
    assert parse_malwarebazaar(doc).records[0].threat_type == "X"
    with pytest.raises(FeedParseError):
        parse_malwarebazaar('{"query_status":"illegal_hash"}')


def test_threatfox_validation() -> None:
    r = parse_threatfox((FX / "threatfox.json").read_text())
    by_type = {(x.ioc_type, x.value): x for x in r.records}
    assert ("ip", "198.51.100.77") in by_type
    assert by_type[("ip", "198.51.100.77")].metadata["port"] == "4443"
    assert by_type[("ip", "198.51.100.77")].confidence == 0.9
    assert ("domain", "bad.example.test") in by_type
    assert ("url", "http://dl.example.test/a.bin") in by_type  # fragment stripped
    assert ("sha256", "c" * 64) in by_type
    assert len(r.records) == 4
    assert r.rejected == 5  # md5, loopback, unspecified, javascript:, garbage row


def test_threatfox_error_and_garbage() -> None:
    with pytest.raises(FeedParseError):
        parse_threatfox((FX / "threatfox_error.json").read_text())
    with pytest.raises(FeedParseError):
        parse_threatfox((FX / "garbage.html").read_text())


def test_urlhaus() -> None:
    r = parse_urlhaus((FX / "urlhaus_recent.csv").read_bytes())
    urls = {x.value: x for x in r.records}
    assert "http://payload.example.test/Dropper.bin" in urls
    assert urls["http://payload.example.test/Dropper.bin"].confidence == 0.9
    assert urls["https://198.51.100.9:8080/x.sh"].confidence == 0.6
    assert len(r.records) == 3 and r.rejected == 2


def test_feodo_json_and_text() -> None:
    r = parse_feodo((FX / "feodo_ipblocklist.json").read_bytes())
    assert [x.value for x in r.records] == ["192.0.2.10", "192.0.2.11"]
    assert r.records[0].threat_type == "Emotet" and r.rejected == 2
    t = parse_feodo((FX / "feodo_ipblocklist.txt").read_bytes())
    assert [x.value for x in t.records] == ["192.0.2.20", "192.0.2.21"] and t.rejected == 1


def test_parse_feed_unknown_format() -> None:
    with pytest.raises(FeedParseError):
        parse_feed("nope", "")


@pytest.mark.parametrize("bad", ["", "a", "-x.com", "a..b", "x" * 64 + ".com", "1.2.3.4", "a b.com", None, 5])
def test_domain_rejects(bad: object) -> None:
    assert normalize_domain(bad) is None


def test_other_validators() -> None:
    assert normalize_ip("::1") is None and normalize_ip("169.254.1.1") is None
    assert normalize_ip("2001:db8::1") == "2001:db8::1"
    assert normalize_url("http://a.example.test:99999/") is None
    assert normalize_url("http://a.example.test/\x00") is None
    assert parse_timestamp("2024-01-01 00:00:00 UTC") == "2024-01-01T00:00:00+00:00"
    assert parse_timestamp("garbage") is None and parse_timestamp(1_700_000_000) is not None


def test_bundled_ioc_set_loads(db) -> None:
    store = CachedIOCStore(db)
    assert store.load_directory(REPO_IOC) >= 6
    assert store.match_hash(EICAR_SHA.upper())[0].threat_type == "eicar_test_file"
    assert store.match_ip("192.0.2.66") and store.match_ip("198.51.100.23")
    assert store.match_domain("deep.sub.malicious.example.test")  # parent-domain match
    assert store.match_url("http://payload.example.test/dropper.bin")


def test_store_miss_and_invalid_inputs(db) -> None:
    store = CachedIOCStore(db)
    store.load_directory(REPO_IOC)
    assert store.match_hash("0" * 64) == []
    assert store.match_hash("zz") == [] and store.match_ip("not-ip") == [] and store.match_domain("") == []
    assert store.match_ip("192.0.2.67") == []
    assert store.match_domain("example.test") == []  # TLD-ish parent must not match children-only IOCs


def test_lru_cache_and_invalidation(db) -> None:
    store = CachedIOCStore(db, cache_size=16)
    assert store.match_ip("192.0.2.66") == []
    store.match_ip("192.0.2.66")
    assert store.cache_hits >= 1
    store.load_directory(REPO_IOC)  # write invalidates negative cache
    assert store.match_ip("192.0.2.66")
    for i in range(100):
        store.match_ip(f"192.0.2.{i}")
    assert len(store._cache) <= 16


def test_expired_iocs_ignored(db) -> None:
    from centralium.agent.threat_intel import IOCRecord

    store = CachedIOCStore(db)
    store.add_records([IOCRecord("ip", "192.0.2.5", "t", expires_at="2000-01-01T00:00:00+00:00")])
    assert store.match_ip("192.0.2.5") == []
    assert store.purge_expired() == 1


def test_updater_offline_by_default(db) -> None:
    store = CachedIOCStore(db)
    calls: list[str] = []
    up = FeedUpdater(
        store,
        [FeedSpec("urlhaus", "urlhaus", url="https://example.test/x")],
        fetcher=lambda *a: calls.append("x") or b"",
    )
    rep = up.run_once()
    assert rep.feeds["urlhaus"] == "skipped:offline" and calls == [] and store.count() == 0


def test_updater_local_file_and_rate_limit(db) -> None:
    now = [0.0]
    store = CachedIOCStore(db)
    spec = FeedSpec("feodo-local", "feodo", path=str(FX / "feodo_ipblocklist.json"), min_interval_s=100)
    up = FeedUpdater(store, [spec], clock=lambda: now[0])
    assert up.run_once().added == 2
    assert up.run_once().feeds["feodo-local"] == "skipped:rate-limited"
    now[0] = 101
    assert up.run_once().feeds["feodo-local"].startswith("ok:")
    assert store.match_ip("192.0.2.10")


def test_updater_network_failure_is_contained_with_backoff(db) -> None:
    now = [0.0]

    def boom(url: str, headers: dict[str, str], timeout: float, mx: int) -> bytes:
        raise OSError("network unreachable")

    store = CachedIOCStore(db, updater=None)
    spec = FeedSpec("urlhaus", "urlhaus", url="https://example.test/x", min_interval_s=10)
    up = FeedUpdater(store, [spec], allow_network=True, fetcher=boom, clock=lambda: now[0])
    assert up.run_once().feeds["urlhaus"].startswith("error:")
    st = up.state("urlhaus")
    assert st.failures == 1
    now[0] = 15  # within backoff (20s)
    assert up.run_once().feeds["urlhaus"] == "skipped:rate-limited"
    now[0] = 50
    assert up.run_once().feeds["urlhaus"].startswith("error:") and st.failures == 2


def test_updater_bad_payload_contained(db) -> None:
    store = CachedIOCStore(db)
    up = FeedUpdater(
        store,
        [FeedSpec("tf", "threatfox", url="https://example.test/x")],
        allow_network=True,
        fetcher=lambda *a: b"<html>captcha</html>",
    )
    assert up.run_once().feeds["tf"].startswith("error:") and store.count() == 0


def test_store_update_never_raises(db) -> None:
    def bad() -> int:
        raise RuntimeError("x")

    assert CachedIOCStore(db, updater=bad).update() == 0
    assert CachedIOCStore(db).update() == 0


def test_http_fetch_refuses_non_https() -> None:
    from centralium.agent.threat_intel.scheduler import http_fetch

    with pytest.raises(ValueError):
        http_fetch("http://example.test/", {}, 1.0, 10)
    with pytest.raises(ValueError):
        http_fetch("file:///etc/passwd", {}, 1.0, 10)
