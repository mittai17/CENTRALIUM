from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from centralium.agent.runtime import Runtime
from tests.e2e.helpers import make_rt, sandbox_cfg

pytestmark = pytest.mark.e2e


@pytest.fixture
def rt(tmp_path: Path) -> Iterator[Runtime]:
    runtime = make_rt(sandbox_cfg(tmp_path))
    yield runtime
    runtime.close()
