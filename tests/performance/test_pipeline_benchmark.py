"""Smoke-runs the measured benchmark at small scale. Numbers are recorded, never asserted against
hard thresholds (hardware varies); only structural sanity is checked."""

from __future__ import annotations

import json

import pytest

from centralium.agent.benchmark import run_benchmark, write_reports
from centralium.agent.config import load_config

pytestmark = pytest.mark.performance


def test_benchmark_runs_and_reports_only_measured_values(tmp_path, record_property):
    cfg = load_config(None, env={}, test_mode=True, paths={"data_dir": str(tmp_path / "d")})
    res = run_benchmark(cfg, events=300, llm_runs=0)
    for name, w in res["workloads"].items():
        assert w["events"] == 300 and w["events_per_s"] > 0 and w["errors"] == {}, name
        f = w["funnel"]
        assert f["raw"] == 300 and f["epp"] == 300 and f["graph"] == 300
        assert f["ml"] <= f["epp"] and f["llm"] == 0  # LLM disabled in the throughput runs
        record_property(f"events_per_s_{name}", w["events_per_s"])
    micro = res["micro"]
    for key in ("normalization_generic_dict", "hash_lookup_ioc_cache_miss", "yara_scan_64KiB_benign",
                "graph_ingest", "graph_chain_query", "rag_retrieve_first_call"):  # fmt: skip
        assert micro[key]["mean_ms"] >= 0
    # the LLM is only reported as measured when a real model answered
    assert res["llm"]["status"] in ("measured", "not measured")
    if res["llm"]["status"] == "not measured":
        assert "reason" in res["llm"]
    md, js = tmp_path / "B.md", tmp_path / "b.json"
    write_reports(res, md, js)
    text = md.read_text()
    assert ("Event funnel" in text and "Not measured" in text) or "Measured with" in text
    assert json.loads(js.read_text())["hardware"]["cpu_count_logical"] >= 1
