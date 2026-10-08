"""Pipeline hot-path profiling script using cProfile.
Profiles processing events through normalization, EPP, ML, and graph stages.
"""

from __future__ import annotations

import cProfile
import io
import pstats
import tempfile
import time
from pathlib import Path

from centralium.agent.benchmark import _stream
from centralium.agent.config import load_config
from centralium.agent.demo import build_scenarios
from centralium.agent.runtime import build_runtime


def run_profiler(num_events: int = 1000) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        cfg = load_config(
            None,
            env={},
            test_mode=True,
            paths={"data_dir": str(tmp_path / "data")},
        )
        rt = build_runtime(cfg)

        scenarios = build_scenarios()
        events = _stream(scenarios, num_events)

        pr = cProfile.Profile()
        pr.enable()
        t0 = time.perf_counter()

        for ev in events:
            rt.pipeline.process(ev)
        rt.graph.flush()

        t1 = time.perf_counter()
        pr.disable()

        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s)
        ps.strip_dirs()

        s.write(
            f"=== PIPELINE PROFILE SUMMARY ({num_events} events, {t1 - t0:.3f}s, "
            f"{num_events / (t1 - t0):.1f} eps) ===\n\n"
        )

        s.write("--- TOP 25 BY CUMULATIVE TIME ---\n")
        ps.sort_stats(pstats.SortKey.CUMULATIVE).print_stats(25)

        s.write("\n--- TOP 25 BY TOTAL (INTERNAL) TIME ---\n")
        ps.sort_stats(pstats.SortKey.TIME).print_stats(25)

        stats_snap = rt.pipeline.stats.snapshot()
        s.write(f"\nPipeline Funnel Snapshot: {stats_snap}\n")

        return s.getvalue()


if __name__ == "__main__":
    report = run_profiler(1000)
    print(report[:4000])
