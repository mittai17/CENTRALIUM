from __future__ import annotations

from collections.abc import Iterator

import pytest

from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.storage import Database


@pytest.fixture
def db(tmp_path) -> Iterator[Database]:
    d = Database(tmp_path / "t.db")
    yield d
    d.close()


@pytest.fixture
def make_event():
    def _make(**kw) -> NormalizedEvent:
        kw.setdefault("event_type", EventType.PROCESS_START)
        kw.setdefault("process_name", "bash")
        kw.setdefault("source", "test")
        return NormalizedEvent(**kw)

    return _make
