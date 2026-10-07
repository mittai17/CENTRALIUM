# ruff: noqa: E501
"""Measured performance benchmark (``centralium benchmark``).

Only numbers produced by this run are reported. Anything that could not be measured on the
current machine (e.g. the real LLM when no ``llama-server`` is reachable) is reported as
``not measured`` with the reason. All work happens in a throw-away sandbox directory in test
mode (simulated executor): nothing real is touched.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psutil

from centralium.agent.config import CentraliumConfig
from centralium.agent.demo import build_scenarios, clone_events, run_demo
from centralium.agent.demo.scenarios import DemoScenario
from centralium.agent.interfaces import LLMRequest
from centralium.agent.models import EventType, NormalizedEvent
from centralium.agent.normalization import EventNormalizer
from centralium.agent.runtime import Runtime, build_runtime
from centralium.agent.sync import DurableSyncQueue, measure_throughput


def _pct(vals: list[float], p: float) -> float:
    s = sorted(vals)
    return s[min(len(s) - 1, int(len(s) * p))]


def _lat(fn: Any, n: int, warmup: int = 5) -> dict[str, float]:
    """Latency of ``fn(i)`` over ``n`` calls (ms)."""
    for i in range(min(warmup, n)):
        fn(i)
    vals: list[float] = []
    for i in range(n):
        t0 = time.perf_counter()
        fn(i)
        vals.append((time.perf_counter() - t0) * 1000.0)
    return {
        "n": float(n),
        "mean_ms": statistics.fmean(vals),
        "p50_ms": _pct(vals, 0.5),
        "p95_ms": _pct(vals, 0.95),
        "max_ms": max(vals),
    }


def _cpu_model() -> str:
    m = platform.processor()
    if m:
        return m
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        return "unknown"
    return "unknown"


def hardware() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count_logical": os.cpu_count(),
        "cpu_model": _cpu_model(),
        "ram_total_gb": round(vm.total / 1024**3, 1),
        "ram_available_gb_at_start": round(vm.available / 1024**3, 1),
        "gpu_used": False,
    }


def _stream(scenarios: list[DemoScenario], n: int) -> list[NormalizedEvent]:
    """``n`` events by cycling the scenarios' events with fresh ids and later timestamps."""
    base = [e for s in scenarios for e in s.events]
    out: list[NormalizedEvent] = []
    cycle = 0
    span = max(e.timestamp for e in base) - min(e.timestamp for e in base) + timedelta(minutes=5)
    while len(out) < n:
        out.extend(clone_events(base, span * cycle))
        cycle += 1
    return out[:n]


def _sandbox_cfg(cfg: CentraliumConfig, root: Path, name: str) -> CentraliumConfig:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    paths = cfg.paths.model_copy(
        update={"data_dir": d, "db_path": None, "graph_dir": None, "quarantine_dir": None, "log_dir": None}
    )
    return cfg.model_copy(update={"paths": paths.resolved(), "test_mode": True, "demo_mode": False})


def _proc_snapshot() -> tuple[float, int]:
    p = psutil.Process()
    ct = p.cpu_times()
    return ct.user + ct.system, p.memory_info().rss


def _peak_rss_mb() -> float | None:
    try:
        import resource

        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)  # KiB on Linux
    except ImportError:  # Windows
        return None


def _workload(rt: Runtime, events: list[NormalizedEvent]) -> dict[str, Any]:
    cpu0, rss0 = _proc_snapshot()
    t0 = time.perf_counter()
    for ev in events:
        rt.pipeline.process(ev)
    wall = time.perf_counter() - t0
    rt.graph.flush()
    cpu1, rss1 = _proc_snapshot()
    snap = rt.pipeline.stats.snapshot()
    db_path = Path(str(rt.db.path))
    wal = Path(str(db_path) + "-wal")
    return {
        "events": len(events),
        "wall_s": round(wall, 3),
        "events_per_s": round(len(events) / wall, 1),
        "cpu_seconds": round(cpu1 - cpu0, 3),
        "cpu_percent_of_one_core": round(100.0 * (cpu1 - cpu0) / wall, 1),
        "rss_mb_before": round(rss0 / 1024**2, 1),
        "rss_mb_after": round(rss1 / 1024**2, 1),
        "sqlite_mb": round(
            (db_path.stat().st_size + (wal.stat().st_size if wal.exists() else 0)) / 1024**2, 2
        ),
        "sqlite_rows": {
            t: rt.db.count(t) for t in ("events", "findings", "incidents", "ml_results", "response_actions")
        },
        "funnel": snap["funnel"],
        "counters": snap["counters"],
        "latency_ms": {
            k: {m: round(v, 3) for m, v in d.items() if m != "count"}
            for k, d in snap["latency"].items()
            if k
            in (
                "end_to_end",
                "normalize",
                "epp",
                "yara",
                "static",
                "behavior",
                "ml",
                "graph",
                "novelty",
                "risk",
                "policy",
                "persist",
                "llm",
                "rag",
            )
        },
        "errors": snap["errors"],
    }


def run_benchmark(cfg: CentraliumConfig, events: int = 2000, llm_runs: int = 3) -> dict[str, Any]:
    started = datetime.now(UTC).isoformat()
    result: dict[str, Any] = {"measured_at": started, "hardware": hardware(), "notes": []}
    with tempfile.TemporaryDirectory(prefix="centralium-bench-") as td:
        root = Path(td)
        scenarios = build_scenarios()
        # ---------------------------------------------------------------- throughput workloads
        for name, names in (
            ("benign_dominated", ["normal_browser", "developer_workflow", "admin_backup_script"]),
            ("mixed_attack_heavy", None),
        ):
            sc = [s for s in scenarios if names is None or s.name in names]
            wcfg = _sandbox_cfg(cfg, root, f"wl_{name}")
            with build_runtime(
                wcfg, llm_mode="off", auto_install_models=True, enable_self_protection=False
            ) as rt:
                evs = _stream(sc, events)
                result.setdefault("workloads", {})[name] = _workload(rt, evs)
                if name == "mixed_attack_heavy":
                    rt.snapshot_graph()
        # ---------------------------------------------------------------- micro benchmarks
        mcfg = _sandbox_cfg(cfg, root, "micro")
        with build_runtime(
            mcfg, llm_mode="off", auto_install_models=True, enable_self_protection=False
        ) as rt:
            micro: dict[str, Any] = {}
            norm = EventNormalizer("bench")
            raws = [e.model_dump(mode="json") for s in scenarios for e in s.events]
            micro["normalization_generic_dict"] = _lat(lambda i: norm.normalize(raws[i % len(raws)]), 3000)
            # hash lookup: IOC cache (cold-ish: distinct hashes) and EPP hash path
            store = rt.epp_stack.threat_intel
            hashes = [f"{i:064x}" for i in range(2000)]
            micro["hash_lookup_ioc_cache_miss"] = _lat(
                lambda i: store.match_hash(hashes[i % len(hashes)]), 2000
            )
            micro["hash_lookup_ioc_cache_hit_eicar"] = _lat(
                lambda i: store.match_hash(
                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                ),
                2000,
            )
            # YARA on a 64 KiB benign file and on the EICAR file
            benign = root / "yara_benign.bin"
            benign.write_bytes(os.urandom(65536))
            eicar = root / "yara_eicar.com"
            eicar.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            ev0 = NormalizedEvent(event_type=EventType.FILE_CREATE, file_path=str(benign), source="bench")
            micro["yara_scan_64KiB_benign"] = _lat(lambda i: rt.epp_stack.yara.scan_file(benign, ev0), 300)
            micro["yara_scan_eicar"] = _lat(lambda i: rt.epp_stack.yara.scan_file(eicar, ev0), 300)
            micro["static_analysis_64KiB"] = _lat(lambda i: rt.epp_stack.static.analyze(benign), 200)
            # ML inference through the real adapter (behavior features -> ML)
            from centralium.agent.interfaces import BehaviorResult

            beh = rt.pipeline.behavior
            samples = []
            for s in scenarios:
                for e in s.events:
                    r = beh.analyze(e, [])
                    samples.append((e, BehaviorResult(features=r.features, ml_eligible=True)))
            if rt.ml.available():
                micro["ml_inference_from_behavior_features"] = _lat(
                    lambda i: rt.ml.predict(*samples[i % len(samples)]), 1500
                )
            else:
                micro["ml_inference_from_behavior_features"] = "not measured: no ML models"
            # graph insert (fresh in-memory-backed adapter ingest) and query
            gevs = _stream(scenarios, 1500)
            gi = _lat(lambda i: rt.graph.ingest(gevs[i], []), 1500, warmup=0)
            micro["graph_ingest"] = gi
            t0 = time.perf_counter()
            rt.graph.flush()
            micro["graph_flush_batch_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
            ids = [e.event_id for e in gevs[-300:]]
            micro["graph_chain_query"] = _lat(lambda i: rt.graph.chain_for(ids[i % len(ids)]), 300)
            # RAG retrieval (cold queries + cached repeat)
            queries = [
                "powershell encoded command spawned by office application",
                "ransomware shadow copy deletion and mass file rename",
                "scheduled task persistence in user profile",
                "certutil urlcache download lolbin",
                "beaconing to rare external ip over unusual port",
            ]
            micro["rag_retrieve_first_call"] = _lat(
                lambda i: rt.rag.retrieve(f"{queries[i % 5]} variant {i}", 4), 100, warmup=0
            )
            micro["rag_retrieve_repeat_cached"] = _lat(lambda i: rt.rag.retrieve(queries[i % 5], 4), 200)
            micro["rag_info"] = rt.rag.info()
            # sync queue throughput on a scratch queue
            q = DurableSyncQueue(root / "bench_queue.db")
            micro["sync_queue_throughput"] = measure_throughput(q, 3000)
            result["micro"] = micro
        # ---------------------------------------------------------------- resource profiles (LLM process measured separately)
        profiles: dict[str, Any] = {}
        for pname in ("low-resource", "balanced", "analysis"):
            base = _sandbox_cfg(cfg, root, f"prof_{pname}").model_copy(update={"profile": pname})
            pcfg = base.apply_resource_profile()
            with build_runtime(
                pcfg, llm_mode="off", auto_install_models=True, enable_self_protection=False
            ) as rt:
                prof = rt.config.resource_profile
                w = _workload(
                    rt,
                    _stream(
                        [
                            s
                            for s in scenarios
                            if s.name
                            in (
                                "normal_browser",
                                "developer_workflow",
                                "office_powershell_chain",
                                "c2_beacon",
                            )
                        ],
                        max(500, events // 3),
                    ),
                )
                profiles[pname] = {
                    "scan_depth": prof.scan_depth,
                    "llm_enabled_in_profile": prof.llm_enabled,
                    "llm_ctx": prof.llm_ctx,
                    "llm_threads": prof.llm_threads,
                    "event_queue_size": prof.event_queue_size,
                    "events": w["events"],
                    "events_per_s": w["events_per_s"],
                    "rss_mb_after_agent_only": w["rss_mb_after"],
                    "cpu_percent_of_one_core": w["cpu_percent_of_one_core"],
                    "funnel": w["funnel"],
                }
        result["profiles"] = profiles
        result["llm_server_rss_mb"] = _llama_server_rss_mb()
        # ---------------------------------------------------------------- funnel with the demo scenarios (mock LLM, labelled)
        fcfg = _sandbox_cfg(cfg, root, "funnel").model_copy(
            update={"demo_mode": True, "test_mode": False, "mode": cfg.mode}
        )
        with build_runtime(
            fcfg, llm_mode="mock", auto_install_models=True, enable_self_protection=False
        ) as rt:
            rep = run_demo(rt)
            result["demo_funnel"] = {
                "funnel": rep.funnel,
                "counters": rep.counters,
                "llm": {"kind": rep.llm_kind, "label": rep.llm_label},
                "events": sum(r.events for r in rep.results) + rep.baseline_events,
                "latency_end_to_end_ms": rep.latency_e2e,
            }
        # ---------------------------------------------------------------- real LLM
        if llm_runs > 0:
            with build_runtime(
                fcfg, llm_mode="auto", auto_install_models=True, enable_self_protection=False
            ) as rt_llm:
                result["llm"] = _llm_bench(rt_llm, scenarios, llm_runs)
        else:
            result["llm"] = {"status": "not measured", "reason": "llm_runs=0"}
    result["peak_rss_mb_process"] = _peak_rss_mb()
    result["headline"] = _headline(result)
    return result


def _llama_server_rss_mb() -> float | None:
    """RSS of a running llama-server (the model process), if one is visible on this machine."""
    for p in psutil.process_iter(["name", "memory_info"]):
        try:
            if p.info["name"] == "llama-server" and p.info["memory_info"]:
                return float(round(p.info["memory_info"].rss / 1024**2, 1))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def _llm_bench(rt: Runtime, scenarios: list[DemoScenario], runs: int) -> dict[str, Any]:
    if rt.llm_kind not in ("llama-server", "llama-cpp-python"):
        return {
            "status": "not measured",
            "reason": f"no real local model reachable (LLM kind: {rt.llm_kind}); set CENTRALIUM_LLM_SERVER_URL "
            "and run scripts/llm_server.sh to measure",
        }
    if runs <= 0:
        return {"status": "not measured", "reason": "llm_runs=0"}
    chain = next(s for s in scenarios if s.name == "office_powershell_chain")
    ev = chain.events[2]
    from centralium.agent.models import Finding, FindingSource, Severity

    finding = Finding(
        event_id=ev.event_id,
        source=FindingSource.LOLBIN,
        rule_id="LOLBIN-POWERSHELL-CONTEXT",
        title="PowerShell spawned by Office with hidden encoded command",
        severity=Severity.HIGH,
        score=78.0,
        confidence=0.95,
        mitre_techniques=["T1059.001"],
    )
    docs = rt.rag.retrieve("powershell encoded command spawned by office", 4)
    req = LLMRequest(event=ev, findings=[finding], rag_docs=docs, pre_risk=70.0)
    lats: list[float] = []
    ok = 0
    for _ in range(runs):
        t0 = time.perf_counter()
        a = rt.llm.analyze(req)
        lats.append((time.perf_counter() - t0) * 1000.0)
        ok += int(a.available and a.verdict is not None)
    return {
        "status": "measured",
        "model": rt.llm_label,
        "backend": rt.llm_kind,
        "runs": runs,
        "valid_verdicts": ok,
        "mean_ms": round(statistics.fmean(lats), 0),
        "min_ms": round(min(lats), 0),
        "max_ms": round(max(lats), 0),
        "per_run_ms": [round(x) for x in lats],
    }


def _headline(r: dict[str, Any]) -> dict[str, Any]:
    wl = r.get("workloads", {})
    return {
        "events_per_s_benign_dominated": wl.get("benign_dominated", {}).get("events_per_s"),
        "events_per_s_mixed_attack_heavy": wl.get("mixed_attack_heavy", {}).get("events_per_s"),
        "end_to_end_p50_ms_benign": wl.get("benign_dominated", {})
        .get("latency_ms", {})
        .get("end_to_end", {})
        .get("p50_ms"),
        "end_to_end_p95_ms_benign": wl.get("benign_dominated", {})
        .get("latency_ms", {})
        .get("end_to_end", {})
        .get("p95_ms"),
        "llm": r.get("llm", {}).get("status"),
    }


# --------------------------------------------------------------------------- reports
def _row(name: str, d: Any) -> str:
    if isinstance(d, str):
        return f"| {name} | {d} | | | |"
    if isinstance(d, dict) and "mean_ms" in d:
        return f"| {name} | {d['mean_ms']:.4f} | {d['p50_ms']:.4f} | {d['p95_ms']:.4f} | {d['max_ms']:.3f} |"
    return f"| {name} | {json.dumps(d, default=str)} | | | |"


def write_reports(result: dict[str, Any], md_path: Path, json_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    hw = result["hardware"]
    L: list[str] = [
        "# Centralium benchmarks (measured)",
        "",
        f"Generated by `centralium benchmark` at {result['measured_at']}. Every number below was produced by that run on the",
        "hardware listed; nothing is estimated. Workloads are SYNTHETIC replay events (see `centralium/agent/demo/scenarios.py`),",
        "so absolute rates say nothing about a specific production fleet. Re-run on your hardware before sizing anything.",
        "",
        "## Hardware / software",
        "",
        *(f"- {k}: {v}" for k, v in hw.items()),
        f"- peak RSS of the benchmark process (includes all workloads): {result.get('peak_rss_mb_process')} MB",
        "",
        "## Pipeline throughput and latency (LLM disabled, test mode, simulated executor)",
        "",
        "| workload | events | events/s | e2e mean ms | e2e p50 ms | e2e p95 ms | CPU % of one core | RSS MB after | SQLite MB |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, w in result["workloads"].items():
        e2e = w["latency_ms"].get("end_to_end", {})
        L.append(
            f"| {name} | {w['events']} | {w['events_per_s']} | {e2e.get('mean_ms')} | {e2e.get('p50_ms')} | "
            f"{e2e.get('p95_ms')} | {w['cpu_percent_of_one_core']} | {w['rss_mb_after']} | {w['sqlite_mb']} |"
        )
    L += ["", "### Per-stage latency inside the pipeline (ms, from the same runs)", ""]
    for name, w in result["workloads"].items():
        L += [f"**{name}**", "", "| stage | mean | p50 | p95 | max |", "|---|---|---|---|---|"]
        for st, d in w["latency_ms"].items():
            L.append(f"| {st} | {d['mean_ms']} | {d['p50_ms']} | {d['p95_ms']} | {d['max_ms']} |")
        L.append("")
    L += ["## Event funnel (events reaching each stage)", ""]
    L += [
        "| workload | raw | fast EPP | ML | graph/novelty | LLM | incidents |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, w in result["workloads"].items():
        f = w["funnel"]
        L.append(
            f"| {name} (LLM off) | {f['raw']} | {f['epp']} | {f['ml']} | {f['graph']} | {f['llm']} | {f['incidents']} |"
        )
    df = result["demo_funnel"]
    f = df["funnel"]
    L.append(
        f"| demo scenarios ({df['llm']['kind']} LLM) | {f['raw']} | {f['epp']} | {f['ml']} | {f['graph']} | {f['llm']} | {f['incidents']} |"
    )
    L += [
        "",
        f"Demo funnel LLM column uses: {df['llm']['label']}. The LLM column counts actual model calls (a recent analysis of the",
        "same process lineage is reused, see `llm_cached` in the counters).",
        "",
        "### Funnel reduction statistics and rates",
        "",
        "| stream | transition stage | input events | pass events | pass-through % | reduction % | operational role |",
        "|---|---|---|---|---|---|---|",
    ]
    bw = result.get("workloads", {}).get("benign_dominated", {}).get("funnel", {})
    if bw:
        r_b, e_b, m_b = bw.get("raw", 0), bw.get("epp", 0), bw.get("ml", 0)
        L.append(
            f"| benign stream | raw -> fast EPP | {r_b} | {e_b} | {100.0 * e_b / r_b if r_b else 0:.1f}% | {100.0 * (1 - e_b / r_b) if r_b else 0:.1f}% | 100% evaluated by fast signature/rule checks |"
        )
        L.append(
            f"| benign stream | EPP -> ML anomaly | {e_b} | {m_b} | {100.0 * m_b / e_b if e_b else 0:.1f}% | {100.0 * (1 - m_b / e_b) if e_b else 0:.1f}% | Filters non-suspicious benign events from ML inference |"
        )
    if f:
        r_d, e_d, m_d, g_d, l_d, inc_d = (
            f.get("raw", 0),
            f.get("epp", 0),
            f.get("ml", 0),
            f.get("graph", 0),
            f.get("llm", 0),
            f.get("incidents", 0),
        )
        L.append(
            f"| demo scenarios | raw -> fast EPP | {r_d} | {e_d} | {100.0 * e_d / r_d if r_d else 0:.1f}% | {100.0 * (1 - e_d / r_d) if r_d else 0:.1f}% | Complete IOC/YARA fast evaluation |"
        )
        L.append(
            f"| demo scenarios | EPP -> ML anomaly | {e_d} | {m_d} | {100.0 * m_d / e_d if e_d else 0:.1f}% | {100.0 * (1 - m_d / e_d) if e_d else 0:.1f}% | Behavior engine gates scannable process/network actions |"
        )
        L.append(
            f"| demo scenarios | ML -> graph | {m_d} | {g_d} | {100.0 * g_d / r_d if r_d else 0:.1f}% | 0.0% | Ingests and correlates all nodes in attack lineage |"
        )
        L.append(
            f"| demo scenarios | pre-risk -> LLM | {r_d} | {l_d} | {100.0 * l_d / r_d if r_d else 0:.1f}% | {100.0 * (1 - l_d / r_d) if r_d else 0:.1f}% | Strict gating: pre-risk threshold, novelty & lineage cache |"
        )
        L.append(
            f"| demo scenarios | LLM -> incidents | {r_d} | {inc_d} | {100.0 * inc_d / r_d if r_d else 0:.1f}% | {100.0 * (1 - inc_d / r_d) if r_d else 0:.1f}% | Lineage aggregation groups alerts into actionable incidents |"
        )
    L += [
        "",
        "## Component micro-benchmarks (ms per call unless noted)",
        "",
        "| component | mean | p50 | p95 | max |",
        "|---|---|---|---|---|",
    ]
    for name, d in result["micro"].items():
        if name in ("sync_queue_throughput", "rag_info", "graph_flush_batch_ms"):
            continue
        L.append(_row(name, d))
    sq = result["micro"].get("sync_queue_throughput", {})
    L += [
        "",
        f"- graph batched flush (1500 events buffered, Kuzu write): {result['micro'].get('graph_flush_batch_ms')} ms total",
        f"- durable sync queue (SQLite WAL, 200-byte payloads, n={sq.get('n')}): enqueue {sq.get('enqueue_per_s', 0):.0f}/s, "
        f"claim+ack {sq.get('claim_ack_per_s', 0):.0f}/s",
        f"- RAG index: {json.dumps(result['micro'].get('rag_info'), default=str)}",
        "",
        "## Local LLM",
        "",
    ]
    llm = result["llm"]
    if llm.get("status") == "measured":
        L += [
            f"Measured with {llm['model']} via {llm['backend']} (CPU): {llm['runs']} analyses, {llm['valid_verdicts']} schema-valid,",
            f"mean {llm['mean_ms']:.0f} ms, min {llm['min_ms']:.0f} ms, max {llm['max_ms']:.0f} ms (per run: {llm['per_run_ms']} ms).",
        ]
    else:
        L += [f"**Not measured**: {llm.get('reason')}"]
    L += ["", "## Profiles (agent process only, LLM disabled during the run; measured)", ""]
    L += [
        "| profile | scan depth | LLM in profile | LLM ctx / threads | queue size | events/s | agent RSS MB | CPU % of one core |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for pn, pv in result.get("profiles", {}).items():
        L.append(
            f"| {pn} | {pv['scan_depth']} | {pv['llm_enabled_in_profile']} | {pv['llm_ctx']} / {pv['llm_threads']} | "
            f"{pv['event_queue_size']} | {pv['events_per_s']} | {pv['rss_mb_after_agent_only']} | {pv['cpu_percent_of_one_core']} |"
        )
    srv = result.get("llm_server_rss_mb")
    L += [
        "",
        f"- llama-server (Gemma 3 1B Q4_K_M, model process) resident memory while running: "
        f"{srv if srv is not None else 'not measured (no llama-server visible)'} MB. Total for a profile with the LLM = agent RSS + this.",
        "- The low-resource profile disables the LLM and YARA/static (scan depth 1); balanced/analysis enable them.",
        "",
        "## Notes",
        "",
        "- Throughput is single-process, synchronous per event (2 worker threads exist in `centralium run`; this benchmark",
        "  drives the pipeline from one thread to keep numbers reproducible).",
        "- CPU % is process CPU time / wall time over the workload (can exceed 100% of one core if native code uses threads).",
        "- Latency percentiles come from the pipeline's own timers (last 2048 samples per stage window).",
    ]
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text("\n".join(L) + "\n", encoding="utf-8")
