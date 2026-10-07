"""The BehaviorEngine's feature names/scales must map onto the ML schema, otherwise ``vectorize``
silently drops features (imputing benign defaults)."""

from __future__ import annotations

import pytest

from centralium.agent.behavior import DefaultBehaviorEngine
from centralium.agent.behavior.features import FEATURE_NAMES as BEHAVIOR_FEATURES
from centralium.agent.models import EventType, NormalizedEvent
from ml.features.behavior_adapter import RENAMES, behavior_to_schema
from ml.features.schema import FEATURE_NAMES as ML_FEATURES
from ml.features.schema import vectorize
from tests.e2e.helpers import scenario

pytestmark = pytest.mark.ml


def test_every_ml_feature_is_produced_from_behavior_features():
    ev = scenario("office_powershell_chain").events[2]
    feats = DefaultBehaviorEngine().analyze(ev, []).features
    assert set(feats) == set(BEHAVIOR_FEATURES)
    adapted = behavior_to_schema(feats, ev.command_line)
    assert set(ML_FEATURES) <= set(adapted), sorted(set(ML_FEATURES) - set(adapted))
    _, coverage = vectorize(adapted)
    assert coverage == 1.0


def test_raw_behavior_names_overlap_ml_schema_only_partially_so_adapter_is_required():
    """Documents the original problem: without the adapter most ML inputs are dropped."""
    overlap = set(BEHAVIOR_FEATURES) & set(ML_FEATURES)
    _, raw_coverage = vectorize(dict.fromkeys(BEHAVIOR_FEATURES, 0.5))
    assert raw_coverage < 0.6
    assert len(overlap) < len(ML_FEATURES)


def test_adapter_source_names_exist_in_behavior_engine_and_targets_in_schema():
    assert set(RENAMES) <= set(BEHAVIOR_FEATURES)
    assert set(RENAMES.values()) <= set(ML_FEATURES)
    assert len(set(RENAMES.values())) == len(RENAMES)  # no two sources collide on a target


def test_scales_are_inverted_correctly():
    feats = dict.fromkeys(BEHAVIOR_FEATURES, 0.0)
    feats.update({"net_conn_count": 4.0, "file_modify_rate": 3.0, "file_entropy": 0.75, "proc_rarity": 0.25})
    a = behavior_to_schema(feats, "powershell -enc " + "QUJD" * 8)
    assert a["net_conn_count"] == pytest.approx(53.598, rel=1e-3)  # expm1(4)
    assert a["file_modify_rate"] == pytest.approx(30.0)  # ops/s * 10 s window
    assert a["file_write_entropy"] == pytest.approx(6.0)  # bits/8 -> bits
    assert a["proc_frequency"] == pytest.approx(0.75)
    assert a["encoded_command"] == 1.0 and a["cmdline_length"] > 20


def test_attack_features_move_ml_inputs_in_the_expected_direction():
    eng = DefaultBehaviorEngine()
    benign = NormalizedEvent(
        event_type=EventType.PROCESS_START, pid=2, ppid=1, process_name="notepad.exe", signer="Microsoft",
        executable_path=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe a.txt", source="test",
    )  # fmt: skip
    attack = scenario("office_powershell_chain").events[2]
    fb = behavior_to_schema(eng.analyze(benign, []).features, benign.command_line)
    fa = behavior_to_schema(DefaultBehaviorEngine().analyze(attack, []).features, attack.command_line)
    for k in ("powershell_use", "encoded_command", "cmdline_length", "lolbin_use"):
        assert fa[k] > fb[k], k


def test_ml_engine_predict_with_behavior_result_achieves_full_coverage():
    """Verify that MLEngine.predict receives fully adapted features with 100% coverage."""
    from centralium.agent.ml.engine import SklearnMLEngine
    from ml.features.behavior_adapter import adapt_for_event

    eng = DefaultBehaviorEngine()
    ev = scenario("office_powershell_chain").events[2]
    beh = eng.analyze(ev, [])
    assert beh.features

    adapted = adapt_for_event(beh.features, ev)
    _, cov = vectorize(adapted)
    assert cov == 1.0, f"Expected 100% schema coverage, got {cov}"

    # Verify every single schema feature has a mapped value in adapted
    for feat_name in ML_FEATURES:
        assert feat_name in adapted, f"Feature {feat_name} missing from adapted dictionary"

    engine = SklearnMLEngine()
    res = engine.predict(ev, beh)
    if engine.available():
        assert res is not None
        assert res.feature_version is not None


def test_all_event_types_generate_full_ml_schema_coverage():
    """Verify that behavior features for different event types all map to 100% ML schema coverage."""
    from ml.features.behavior_adapter import adapt_for_event

    eng = DefaultBehaviorEngine()
    events = [
        NormalizedEvent(
            event_type=EventType.PROCESS_START, pid=10, process_name="proc.exe",
            command_line="proc.exe --flag", source="test",
        ),
        NormalizedEvent(
            event_type=EventType.NETWORK_CONNECT, pid=10, process_name="proc.exe",
            destination_ip="93.184.216.34", destination_port=443, source="test",
        ),
        NormalizedEvent(
            event_type=EventType.FILE_CREATE, pid=10, process_name="proc.exe",
            file_path="/tmp/test.txt", source="test",
        ),
        NormalizedEvent(
            event_type=EventType.DNS_QUERY, pid=10, process_name="proc.exe",
            domain="example.com", source="test",
        ),
    ]
    for ev in events:
        beh = eng.analyze(ev, [])
        adapted = adapt_for_event(beh.features, ev)
        _, cov = vectorize(adapted)
        assert cov == 1.0, f"Event type {ev.event_type} produced coverage {cov} < 1.0"

