"""Unit tests for FileNotifyCollector (inotify/fanotify file monitor)."""

from __future__ import annotations

import sys
import time

import pytest

from centralium.agent.collectors.file_notify import FileNotifyCollector
from centralium.agent.models import EventType, NormalizedEvent


def wait_for(cond, timeout: float = 3.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify only supported on Linux")
def test_file_notify_live_events(tmp_path):
    watch_dir = tmp_path / "protected"
    watch_dir.mkdir()
    canary_file = watch_dir / "canary.txt"
    canary_file.write_text("initial")

    events: list[NormalizedEvent] = []
    collector = FileNotifyCollector(
        watch_paths=[str(watch_dir)],
        canary_paths=[str(canary_file)],
        poll_interval=0.05,
    )
    collector.start(lambda ev: events.append(ev))

    try:
        assert collector.is_running()
        ok, reason = collector.health()
        assert ok
        assert "monitoring" in reason

        # 1. Modify canary file
        canary_file.write_text("modified canary")
        assert wait_for(lambda: any(e.event_type == EventType.FILE_MODIFY for e in events))

        canary_evs = [e for e in events if e.raw_metadata.get("is_canary")]
        assert len(canary_evs) >= 1
        assert canary_evs[0].file_path == str(canary_file)

        # 2. Create new file
        new_file = watch_dir / "new_file.doc"
        new_file.write_text("hello")
        assert wait_for(lambda: any(e.event_type == EventType.FILE_CREATE for e in events))

        # 3. Rename file
        renamed_file = watch_dir / "new_file.doc.locked"
        new_file.rename(renamed_file)
        assert wait_for(lambda: any(e.file_path == str(renamed_file) for e in events))

        # 4. Delete file
        renamed_file.unlink()
        assert wait_for(lambda: any(e.event_type == EventType.FILE_DELETE for e in events))
    finally:
        collector.stop()


def test_file_notify_bounded_queue_and_backpressure():
    collector = FileNotifyCollector(
        watch_paths=[],
        queue_size=5,
    )
    # Directly test emit_event queue bounds
    for i in range(25):
        ev = NormalizedEvent(
            event_type=EventType.FILE_MODIFY,
            file_path=f"/tmp/file_{i}",
            source="inotify",
        )
        collector.emit_event(ev)

    assert collector.queue_depth() == 5
    assert collector.stats["emitted"] == 5
    assert collector.stats["dropped_queue_full"] == 20


def test_file_notify_rate_limiting():
    collector = FileNotifyCollector(
        watch_paths=[],
        queue_size=1000,
        max_events_per_sec=10.0,
    )
    for i in range(100):
        ev = NormalizedEvent(
            event_type=EventType.FILE_CREATE,
            file_path=f"/tmp/canary_{i}",
            source="inotify",
        )
        collector.emit_event(ev)

    assert collector.stats["emitted"] <= 12
    assert collector.stats["dropped_rate"] >= 88


def test_file_notify_health_on_missing_dir(tmp_path):
    missing_dir = str(tmp_path / "nonexistent_dir")
    collector = FileNotifyCollector(watch_paths=[missing_dir])
    collector.start(lambda ev: None)
    try:
        ok, reason = collector.health()
        assert not ok
        assert "none of the configured watch paths exist" in reason or "not available" in reason
    finally:
        collector.stop()
