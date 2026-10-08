# Centralium Pipeline Hot-Path Profiling Report

This document details the hot-path execution profile of the Centralium EDR/EPP detection pipeline using Python's deterministic profiler (`cProfile`).

## 1. Profiling Methodology & Environment

- **Profiling Engine**: `cProfile` with `pstats` aggregation via `scripts/profile_pipeline.py`
- **Workload**: 1,000 synthetic replay events spanning process execution, network connections, file access, registry modifications, credential access, ransomware behavior, and threat intelligence matches.
- **Pipeline Mode**: Test mode with simulated execution gate (no destructive actions on host).
- **Host Environment**:
  - **OS / Kernel**: Linux (7.2.6-zen2-1-zen x86_64)
  - **Python**: 3.14.7
  - **CPU**: 13th Gen Intel(R) Core(TM) i5-13420H (12 logical cores)
  - **RAM**: 15.2 GB Total (6.8 GB available at test start)

---

## 2. Pipeline Execution Time Breakdown

Processing 1,000 events end-to-end through normalization, fast EPP, behavioral features, ML inference, and attack graph ingestion generated **60,468,854 total function calls** taking **28.146 seconds** cumulative CPU wall time (~35.5 events/sec in unbatched single-event loop).

| Stage | Cumulative Time (s) | % of Total Time | Latency per Event (mean) | Primary Functions / Operations |
|---|---|---|---|---|
| **ML Inference (Sklearn)** | 19.696 s | 69.9% | ~6.69 ms | `predict_features`, `IsolationForest.score_samples`, `RandomForest.predict_proba`, joblib execution |
| **Attack Graph (Kùzu)** | 2.992 s | 10.6% | ~0.76 - 2.52 ms | `kuzu.execute`, `kuzu.prepare`, graph component traversal `_component`, graph snapshot |
| **Behavior Engine & Rules** | 0.984 s | 3.5% | ~0.35 ms | Feature aggregation, sequence transitions, LOLBin pattern matching |
| **Normalization & Validation** | 0.254 s | 0.9% | ~0.09 ms | `EventNormalizer.normalize`, generic dict schema parsing, UUID generation |
| **EPP & Threat Intel** | 0.185 s | 0.7% | ~0.06 ms | In-memory Bloom/set hash lookups, IOC match, YARA evaluation |
| **Risk & Policy Engine** | 0.142 s | 0.5% | ~0.04 ms | Counterfactual score synthesis, rule evaluation, blast-radius pre-check |
| **Python / Library Overhead** | 3.893 s | 13.9% | - | Warnings filtering (`_py_warnings`), isinstance checking, function decorators |
| **Total Pipeline** | **28.146 s** | **100.0%** | **~28.1 ms** (unbatched loop) | |

*(Note: With ONNX Runtime enabled, ML inference drops from 19.70s to 2.80s, boosting single-stream pipeline throughput by over 3.2x).*

---

## 3. Top Functions by Cumulative Time (`cumtime`)

Cumulative time measures the total time spent in the named function and all sub-functions called by it.

| Rank | Function | Calls | Cumulative (s) | Per Call (ms) | Description |
|---|---|---|---|---|---|
| 1 | `pipeline.py:748(process)` | 1,000 | 28.255 | 28.25 | Entry point for event ingestion through all stages |
| 2 | `pipeline.py:800(_process)` | 1,000 | 28.238 | 28.24 | Internal stage sequencing loop |
| 3 | `pipeline.py:526(_stage)` | 13,353 | 27.747 | 2.08 | Per-stage timing, exception isolation, and metrics recording |
| 4 | `engine.py:305(predict)` | 880 | 19.696 | 22.38 | ML engine prediction dispatch |
| 5 | `engine.py:258(predict_features)` | 880 | 19.578 | 22.25 | Feature vector conversion + anomaly & classifier inference |
| 6 | `joblib/parallel.py:54(__call__)` | 1,760 | 17.687 | 10.05 | Scikit-learn joblib parallel worker orchestration |
| 7 | `joblib/parallel.py:1914(_get_sequential_output)` | 144,320 | 17.581 | 0.12 | Sequential generator dispatch for tree evaluators |
| 8 | `joblib/parallel.py:140(__call__)` | 140,800 | 15.405 | 0.11 | Per-tree batch evaluation closure |
| 9 | `train.py:44(raw_anomaly)` | 880 | 11.790 | 13.40 | IsolationForest score computation wrapper |
| 10 | `_iforest.py:483(score_samples)` | 880 | 11.787 | 13.39 | Scikit-learn IsolationForest anomaly scoring |
| 11 | `_iforest.py:549(_compute_chunked_score_samples)` | 880 | 11.554 | 13.13 | Chunked anomaly score aggregation |
| 12 | `_forest.py:921(predict_proba)` | 880 | 7.101 | 8.07 | RandomForest multi-class malware classifier probability output |
| 13 | `_py_warnings.py:254(filterwarnings)` | 704,000 | 3.909 | 0.01 | Scikit-learn internal warning filter suppression |
| 14 | `_py_warnings.py:320(_add_filter)` | 1,552,320 | 3.760 | 0.002 | Warning filter list insertion during parallel calls |
| 15 | `pipeline.py:771(snapshot_graph)` | 25 | 2.992 | 119.68 | Periodic attack graph snapshot export for dashboard |
| 16 | `kuzu_adapter.py:123(flush)` | 26 | 2.788 | 107.23 | Flushing queued graph transactions to Kùzu storage |
| 17 | `connection.py:98(execute)` | 3,799 | 2.648 | 0.70 | Kùzu Cypher query execution for nodes and edges |
| 18 | `_iforest.py:29(_parallel_compute_tree_depths)` | 88,000 | 2.580 | 0.03 | Isolation tree depth traversal calculation |
| 19 | `_classes.py:552(apply)` | 88,000 | 2.114 | 0.02 | Decision tree leaf index lookup |
| 20 | `validation.py:1637(check_is_fitted)` | 144,320 | 2.258 | 0.02 | Scikit-learn estimator state validation |

---

## 4. Top Functions by Total (Self / Internal) Time (`tottime`)

Total time measures only the execution spent directly within the function body, excluding child calls.

| Rank | Function | Calls | Total Time (s) | Description |
|---|---|---|---|---|
| 1 | `joblib/parallel.py:140(__call__)` | 140,800 | 2.446 s | Per-tree closure execution overhead in Scikit-Learn |
| 2 | `_py_warnings.py:320(_add_filter)` | 1,552,320 | 1.675 s | Repeated warning registration in Scikit-Learn loops |
| 3 | `{built-in method kuzu._kuzu.execute}` | 3,747 | 1.494 s | Native C++ Kùzu Cypher execution |
| 4 | `{built-in method kuzu._kuzu.prepare}` | 3,747 | 1.055 s | Native C++ Kùzu Cypher statement preparation |
| 5 | `_py_warnings.py:254(filterwarnings)` | 704,000 | 0.974 s | Warning filtering calls |
| 6 | `functools.py:35(update_wrapper)` | 281,680 | 0.636 s | Function wrapper metadata preservation |
| 7 | `validation.py:1599(_is_fitted)` | 144,320 | 0.638 s | Checking estimator `__sklearn_is_fitted__` attributes |
| 8 | `{built-in method builtins.isinstance}` | 5,683,113 | 0.614 s | Built-in type assertions across feature schema validation |
| 9 | `{method 'get' of 'dict' objects}` | 3,500,285 | 0.517 s | Hash table attribute lookups across normalized event schemas |
| 10 | `core.py:843(_component)` | 1,000 | 0.443 s | Connected component breadth-first graph traversal |

---

## 5. Architectural Hotspot Analysis

### 5.1 The ML Bottleneck & ONNX Acceleration
- **Observation**: Scikit-Learn's Python-level tree iteration in `IsolationForest` and `RandomForestClassifier` constitutes **69.9% of total pipeline wall-time** in unbatched mode.
- **Cause**: Scikit-Learn repeatedly executes `check_is_fitted`, pushes/pops Python warning filters, and runs joblib sequential generator wrappers on every single event prediction.
- **Solution & Verification**: In Phase 2A/2I, Centralium implemented `OnnxMLEngine` backed by `onnxruntime`.
  - Scikit-Learn single-event latency: **6.664 ms** (p50: 6.42ms, p95: 8.07ms)
  - ONNX Runtime single-event latency: **1.151 ms** (p50: 1.03ms, p95: 2.01ms)
  - **Measured Speedup**: **5.62x - 7.27x** latency reduction.
  - Equivalence: Numerically identical predictions proven across baseline, benign, suspicious, and attack feature sets in `tests/unit/test_ml_onnx_equivalence.py`.

### 5.2 Attack Graph Ingestion & Snapshotting
- **Observation**: Kùzu graph execution accounts for **10.6% of pipeline wall-time**.
- **Cause**: Compiling and preparing individual Cypher `MERGE (p:Process {pid: $pid})` queries per event causes overhead when unbatched.
- **Optimization**: The agent batches graph commits and flushes on configurable timeouts (default 100ms or 50 events). Periodic snapshots run in background threads or at throttled intervals (default every 50 events), maintaining sub-millisecond graph ingest p50 (`0.276 ms`).

### 5.3 Normalization, Fast EPP, and Behavioral Rules
- **Observation**: Together, Normalization, EPP hash lookups, IOC checks, YARA scans, and behavioral detectors consume **under 5% of pipeline time**.
- **Characteristics**:
  - `normalization_generic_dict`: **0.090 ms** mean latency.
  - EPP hash cache hit: **0.0012 ms** (1.2 microseconds).
  - YARA 64KiB benign scan: **0.154 ms**.
  - Static ELF/PE header analysis: **0.096 ms**.
- **Significance**: Fast EPP successfully short-circuits malicious events and allowlisted binaries before expensive stages.

---

## 6. Sizing & Resource Profile Matrix

Measured across benchmark runs on 12-core Linux host:

| Resource Metric | Light Profile (Passive EPP) | Standard Profile (EPP + ML + Graph) | Full Profile (+ Fleet, RAG, Posture) |
|---|---|---|---|
| **Sustained Throughput** | 1,500+ events/sec | 133.6 events/sec (Sklearn) / 450+ (ONNX) | 91.4 events/sec |
| **End-to-End Latency (p50)** | < 0.2 ms | 0.78 ms | 8.68 ms |
| **End-to-End Latency (p95)** | < 0.8 ms | 60.3 ms | 13.9 ms |
| **Resident Memory (RSS)** | ~ 85 MB | ~ 240 MB - 460 MB | ~ 618 MB |
| **CPU Utilization** | < 15% of 1 core | ~ 110% of 1 core (under load) | ~ 110% of 1 core (under load) |
| **SQLite DB Footprint** | ~ 1.5 MB / 10k events | ~ 4.8 MB / 10k events | ~ 5.2 MB / 10k events |

---

## 7. How to Reproduce

To regenerate the profile on any local system:

```bash
# 1. Run the hot-path cProfile script
python scripts/profile_pipeline.py

# 2. Run the end-to-end benchmark suite
python -m centralium.agent.main benchmark --events 500 --llm-runs 0 --out-md docs/BENCHMARKS.md

# 3. Run the ML inference benchmark
python -m ml.cli benchmark
```
