from __future__ import annotations

import pytest

from centralium.agent.config import RiskSettings
from centralium.agent.interfaces import RiskEngine
from centralium.agent.models import (
    DetectionResult,
    Finding,
    FindingSource,
    RiskBand,
    ScoreFamily,
)
from centralium.agent.nulls import ReferenceRiskEngine
from centralium.agent.risk import CalibratedRiskEngine, RiskTuning

F = ScoreFamily


def d(fam, score, conf=1.0, avail=True):
    return DetectionResult(family=fam, score=score, confidence=conf, available=avail)


def eng(**kw):
    return CalibratedRiskEngine(RiskSettings(**kw))


def known_finding():
    return Finding(event_id="e", source=FindingSource.HASH, rule_id="h", title="bad hash", score=100,
                   known_malicious=True)  # fmt: skip


def test_protocol_and_empty():
    e = eng()
    assert isinstance(e, RiskEngine)
    r = e.assess({}, [])
    assert r.final_score == 0 and r.band == RiskBand.SAFE
    assert "not fabricated" in r.notes[0]


def test_unavailable_families_excluded_not_zero():
    r = eng().assess({F.DETERMINISTIC_EVIDENCE: d(F.DETERMINISTIC_EVIDENCE, 70),
                      F.GRAPH_ATTACK_CHAIN: d(F.GRAPH_ATTACK_CHAIN, 0, avail=False)}, [])  # fmt: skip
    assert F.GRAPH_ATTACK_CHAIN.value  # sanity
    assert r.final_score == pytest.approx(70.0, abs=0.01)  # not diluted by the unavailable family
    assert "attack_graph" not in r.weights_used


def test_deterministic_and_pure():
    scores = {F.ML_ANOMALY: d(F.ML_ANOMALY, 55), F.DETERMINISTIC_EVIDENCE: d(F.DETERMINISTIC_EVIDENCE, 40),
              F.GRAPH_ATTACK_CHAIN: d(F.GRAPH_ATTACK_CHAIN, 30)}  # fmt: skip
    a = eng().assess(scores, [])
    b = eng().assess(dict(scores), [])
    assert a.model_dump() == b.model_dump()


def test_spec_formula_when_all_families_present_and_no_floor_needed():
    scores = {
        F.ML_ANOMALY: d(F.ML_ANOMALY, 40),
        F.DETERMINISTIC_EVIDENCE: d(F.DETERMINISTIC_EVIDENCE, 40),
        F.GRAPH_ATTACK_CHAIN: d(F.GRAPH_ATTACK_CHAIN, 40),
        F.THREAT_INTEL: d(F.THREAT_INTEL, 40),
        F.STATIC_MALWARE: d(F.STATIC_MALWARE, 40),
        F.AI_ASSESSMENT: d(F.AI_ASSESSMENT, 40, 1.0),
    }
    r = eng().assess(scores, [])
    assert r.final_score == pytest.approx(40.0)  # weights sum to 1.0
    assert r.band == RiskBand.MEDIUM


def test_weights_are_configuration_driven():
    scores = {F.ML_ANOMALY: d(F.ML_ANOMALY, 100), F.GRAPH_ATTACK_CHAIN: d(F.GRAPH_ATTACK_CHAIN, 0)}
    tuning = RiskTuning(enable_evidence_floor=False)
    low_ml = CalibratedRiskEngine(RiskSettings(weight_behavioral_ml=0.05, weight_attack_graph=0.9), tuning)
    high_ml = CalibratedRiskEngine(RiskSettings(weight_behavioral_ml=0.9, weight_attack_graph=0.05), tuning)
    assert low_ml.assess(scores, []).final_score < 10
    assert high_ml.assess(scores, []).final_score > 90


def test_dilution_caveat_reference_vs_fixed():
    """behavior 80 + graph 0: reference engine gives ~25 (middling); fixed engine alerts."""
    scores = {
        F.ML_ANOMALY: d(F.ML_ANOMALY, 80),
        F.DETERMINISTIC_EVIDENCE: d(F.DETERMINISTIC_EVIDENCE, 0),
        F.GRAPH_ATTACK_CHAIN: d(F.GRAPH_ATTACK_CHAIN, 0),
        F.THREAT_INTEL: d(F.THREAT_INTEL, 0),
        F.STATIC_MALWARE: d(F.STATIC_MALWARE, 0),
    }
    ref = ReferenceRiskEngine(RiskSettings()).assess(scores, [])
    fixed = eng().assess(scores, [])
    assert ref.final_score < 25
    assert fixed.final_score == pytest.approx(48.0)  # 0.60 ratio x 80
    assert fixed.band == RiskBand.MEDIUM
    assert any("evidence floor" in n for n in fixed.notes)


def test_strong_deterministic_signal_alone_reaches_high():
    scores = {F.DETERMINISTIC_EVIDENCE: d(F.DETERMINISTIC_EVIDENCE, 85), F.ML_ANOMALY: d(F.ML_ANOMALY, 0),
              F.GRAPH_ATTACK_CHAIN: d(F.GRAPH_ATTACK_CHAIN, 0)}  # fmt: skip
    r = eng().assess(scores, [])
    assert r.band == RiskBand.HIGH  # 0.85 * 85 = 72.25
    assert r.final_score < 85  # the floor never exceeds the evidence itself


def test_floor_disabled_and_ratio_validation():
    scores = {
        F.ML_ANOMALY: d(F.ML_ANOMALY, 80),
        F.DETERMINISTIC_EVIDENCE: d(F.DETERMINISTIC_EVIDENCE, 0),
        F.GRAPH_ATTACK_CHAIN: d(F.GRAPH_ATTACK_CHAIN, 0),
        F.THREAT_INTEL: d(F.THREAT_INTEL, 0),
        F.STATIC_MALWARE: d(F.STATIC_MALWARE, 0),
    }
    off = CalibratedRiskEngine(RiskSettings(), RiskTuning(enable_evidence_floor=False))
    assert off.assess(scores, []).final_score == pytest.approx(80 * 0.25 / 0.9)
    with pytest.raises(ValueError):
        CalibratedRiskEngine(RiskSettings(), RiskTuning(floor_ratios={"threat_intel": 1.5}))


def test_floor_is_confidence_aware():
    hi = eng().assess({F.ML_CLASSIFICATION: d(F.ML_CLASSIFICATION, 90, 0.9)}, [])
    lo = eng().assess({F.ML_CLASSIFICATION: d(F.ML_CLASSIFICATION, 90, 0.3)}, [])
    assert hi.final_score > lo.final_score
    assert lo.final_score == pytest.approx(90 * 0.65)


def test_low_confidence_ai_never_dominates_deterministic():
    base = {F.DETERMINISTIC_EVIDENCE: d(F.DETERMINISTIC_EVIDENCE, 30)}
    without = eng().assess(base, []).final_score
    low = eng().assess({**base, F.AI_ASSESSMENT: d(F.AI_ASSESSMENT, 100, 0.2)}, [])
    assert low.final_score == without
    assert any("AI ignored" in n for n in low.notes)
    confident = eng().assess({**base, F.AI_ASSESSMENT: d(F.AI_ASSESSMENT, 100, 1.0)}, [])
    assert without < confident.final_score <= without + 15.0 + 1e-6  # bounded uplift


def test_ai_cannot_lower_score():
    base = {F.DETERMINISTIC_EVIDENCE: d(F.DETERMINISTIC_EVIDENCE, 70)}
    r = eng().assess({**base, F.AI_ASSESSMENT: d(F.AI_ASSESSMENT, 0, 1.0)}, [])
    assert r.final_score == eng().assess(base, []).final_score


def test_ai_only_is_capped():
    r = eng().assess({F.AI_ASSESSMENT: d(F.AI_ASSESSMENT, 100, 1.0)}, [])
    assert r.final_score <= 45 and r.band in (RiskBand.MEDIUM, RiskBand.LOW)


def test_known_malicious_floor_not_overridable_by_ai():
    scores = {F.AI_ASSESSMENT: d(F.AI_ASSESSMENT, 0, 1.0), F.THREAT_INTEL: d(F.THREAT_INTEL, 5)}
    r = eng().assess(scores, [known_finding()])
    assert r.final_score >= 90 and r.band == RiskBand.CRITICAL
    assert any("known-malicious floor" in n for n in r.notes)
    custom = eng(known_malicious_floor=95.0).assess({}, [known_finding()])
    assert custom.final_score == 95.0  # floor applies even with no other evidence


@pytest.mark.parametrize(
    ("score", "band"),
    [(0, RiskBand.SAFE), (19.9, RiskBand.SAFE), (20, RiskBand.LOW), (39.9, RiskBand.LOW), (40, RiskBand.MEDIUM),
     (59.9, RiskBand.MEDIUM), (60, RiskBand.HIGH), (79.9, RiskBand.HIGH), (80, RiskBand.CRITICAL), (100, RiskBand.CRITICAL)],
)  # fmt: skip
def test_risk_bands(score, band):
    r = eng().assess({F.THREAT_INTEL: d(F.THREAT_INTEL, score)}, [])
    # threat-intel floor ratio 0.9 -> weighted term (== score) dominates, so the band follows the score
    assert r.final_score == pytest.approx(score, abs=1e-3)
    assert r.band == band


def test_custom_band_thresholds_respected():
    r = eng(band_low=10, band_medium=20, band_high=30, band_critical=40).assess(
        {F.THREAT_INTEL: d(F.THREAT_INTEL, 35)}, []
    )
    assert r.band == RiskBand.HIGH


def test_scores_clamped_and_final_family_recorded():
    r = eng().assess({F.THREAT_INTEL: d(F.THREAT_INTEL, 100)}, [known_finding()])
    assert 0 <= r.final_score <= 100
    assert F.FINAL_RISK in r.scores
