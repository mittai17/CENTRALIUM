"""Convenience wiring of the EPP / YARA / static / threat-intel stack for the pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from centralium.agent.epp.engine import DefaultEPPEngine, EntryLists, SignerVerifier
from centralium.agent.malware_analysis import StaticFileAnalyzer
from centralium.agent.storage import Database, Repository
from centralium.agent.threat_intel import DEFAULT_FEEDS, CachedIOCStore, FeedSpec, FeedUpdater
from centralium.agent.yara import YaraManager


@dataclass(slots=True)
class EPPStack:
    epp: DefaultEPPEngine
    yara: YaraManager
    static: StaticFileAnalyzer
    threat_intel: CachedIOCStore
    updater: FeedUpdater


def build_epp_stack(
    db: Database,
    rules_dir: str | Path = "rules",
    *,
    max_scan_mb: int = 64,
    allow_network: bool = False,
    feeds: tuple[FeedSpec, ...] = DEFAULT_FEEDS,
    signer_verifier: SignerVerifier | None = None,
    load_bundled_iocs: bool = True,
) -> EPPStack:
    """Build all four components. Safe offline: nothing touches the network unless ``allow_network``."""
    rd = Path(rules_dir)
    updater_holder: list[FeedUpdater] = []
    store = CachedIOCStore(db, updater=lambda: updater_holder[0].run_once().added if updater_holder else 0)
    updater = FeedUpdater(store, feeds, allow_network=allow_network)
    updater_holder.append(updater)
    if load_bundled_iocs:
        store.load_directory(rd / "ioc")
    yara_mgr = YaraManager(db, rd / "yara", max_scan_bytes=max_scan_mb * 1024 * 1024)
    epp = DefaultEPPEngine(
        intel=store,
        repo=Repository(db),
        yara=yara_mgr,
        file_allowlist=EntryLists.from_directory(rd / "allowlist"),
        file_blocklist=EntryLists.from_directory(rd / "blocklist"),
        signer_verifier=signer_verifier,
        max_hash_bytes=max_scan_mb * 1024 * 1024,
    )
    return EPPStack(
        epp, yara_mgr, StaticFileAnalyzer(max_parse_bytes=max_scan_mb * 1024 * 1024), store, updater
    )
