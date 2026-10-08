"""Explainability trace: per-decision "why this score" trace detailing the contribution
of each score family, top ML features with baseline deviations, graph traversal path,
policy rules fired, and counterfactuals.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import (
    Finding,
    GraphSignal,
    MLResult,
    PolicyDecision,
    RiskAssessment,
    RiskBand,
    ScoreFamily,
)


class MLFeatureDeviation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature_name: str
    observed_value: float
    baseline_value: float
    deviation: float
    direction: str  # higher_than_normal | lower_than_normal | normal


class PolicyRuleTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_name: str
    action_proposed: str
    allowed: bool
    reason: str


class ScoreFamilyContribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family: str
    raw_score: float
    confidence: float
    weight: float
    effective_points: float
    percentage_contribution: float


class ExplainabilityTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    final_score: float
    band: RiskBand
    summary: str
    family_contributions: dict[str, ScoreFamilyContribution] = Field(default_factory=dict)
    top_ml_features: list[MLFeatureDeviation] = Field(default_factory=list)
    graph_path: list[str] = Field(default_factory=list)
    policy_rules_fired: list[PolicyRuleTrace] = Field(default_factory=list)
    counterfactuals: list[str] = Field(default_factory=list)


# Typical baseline values for behavioral features (heuristic defaults)
DEFAULT_FEATURE_BASELINES: dict[str, float] = {
    "proc_entropy": 4.5,
    "cmd_length": 45.0,
    "child_proc_count": 1.0,
    "net_conn_count": 0.0,
    "file_mod_rate": 0.0,
    "anomaly_score": 0.05,
    "privilege_level": 0.0,
    "unusual_parent_ratio": 0.0,
}


FAMILY_MAP: dict[ScoreFamily | str, str] = {
    ScoreFamily.ML_ANOMALY: "behavioral_ml",
    ScoreFamily.ML_CLASSIFICATION: "behavioral_ml",
    ScoreFamily.DETERMINISTIC_EVIDENCE: "deterministic_evidence",
    ScoreFamily.GRAPH_ATTACK_CHAIN: "attack_graph",
    ScoreFamily.THREAT_INTEL: "threat_intel",
    ScoreFamily.STATIC_MALWARE: "static_malware",
    ScoreFamily.AI_ASSESSMENT: "ai_assessment",
    "A": "behavioral_ml",
    "B": "behavioral_ml",
    "C": "deterministic_evidence",
    "D": "attack_graph",
    "E": "threat_intel",
    "F": "static_malware",
    "G": "ai_assessment",
}


def build_explainability_trace(
    event_id: str,
    risk: RiskAssessment,
    findings: list[Finding] | None = None,
    ml_res: MLResult | None = None,
    graph_sig: GraphSignal | None = None,
    decision: PolicyDecision | None = None,
    baselines: dict[str, float] | None = None,
) -> ExplainabilityTrace:
    """Construct an explainability trace detailing why the event received its score."""
    findings = findings or []
    base_map = {**DEFAULT_FEATURE_BASELINES, **(baselines or {})}

    # 1. Family contributions
    total_score = risk.final_score
    weights = risk.weights_used
    contributions: dict[str, ScoreFamilyContribution] = {}

    total_weighted_points = 0.0
    family_points: dict[str, tuple[float, float, float, float]] = {}

    for fam, det in risk.scores.items():
        if fam == ScoreFamily.FINAL_RISK or not det.available:
            continue
        fam_name = FAMILY_MAP.get(fam, fam.name.lower() if hasattr(fam, "name") else str(fam))
        w = weights.get(fam_name, weights.get(getattr(fam, "value", str(fam)), 0.2))
        eff_pts = det.score * (det.confidence if det.confidence > 0 else 1.0) * (w if w > 0 else 0.2)
        family_points[fam_name] = (det.score, det.confidence, w, eff_pts)
        total_weighted_points += eff_pts

    for fam_name, (score, conf, w, eff_pts) in family_points.items():
        pct = (eff_pts / total_weighted_points * 100.0) if total_weighted_points > 0 else 0.0
        contributions[fam_name] = ScoreFamilyContribution(
            family=fam_name,
            raw_score=round(score, 2),
            confidence=round(conf, 2),
            weight=round(w, 4),
            effective_points=round(eff_pts, 2),
            percentage_contribution=round(pct, 1),
        )

    # 2. ML feature deviations
    top_features: list[MLFeatureDeviation] = []
    if ml_res is not None and ml_res.top_features:
        for feat_name, obs_val in ml_res.top_features[:6]:
            base_val = base_map.get(feat_name, 0.0)
            dev = obs_val - base_val
            if abs(dev) < 1e-4:
                direction = "normal"
            elif dev > 0:
                direction = "higher_than_normal"
            else:
                direction = "lower_than_normal"
            top_features.append(
                MLFeatureDeviation(
                    feature_name=feat_name,
                    observed_value=round(obs_val, 3),
                    baseline_value=round(base_val, 3),
                    deviation=round(dev, 3),
                    direction=direction,
                )
            )

    # 3. Graph path
    graph_path: list[str] = []
    if graph_sig is not None:
        graph_path = list(graph_sig.chain)

    # 4. Policy rules
    policy_traces: list[PolicyRuleTrace] = []
    if decision is not None and decision.action is not None:
        policy_traces.append(
            PolicyRuleTrace(
                rule_name=decision.reason or "policy_rule",
                action_proposed=decision.action.value,
                allowed=decision.allowed,
                reason=decision.reason,
            )
        )

    # 5. Counterfactuals
    counterfactuals: list[str] = []
    if contributions and total_score > 20.0:
        top_fam = max(contributions.values(), key=lambda c: c.effective_points)
        # Simulate removing top contributor
        simulated_pts = max(0.0, total_score - top_fam.effective_points)
        simulated_band = "MEDIUM" if simulated_pts >= 40 else ("LOW" if simulated_pts >= 20 else "SAFE")
        counterfactuals.append(
            f"Risk score would be {simulated_band} ({simulated_pts:.1f}) instead of {risk.band.value} "
            f"({total_score:.1f}) without the {top_fam.family} signal."
        )

    for f in findings:
        if f.known_malicious:
            counterfactuals.append(f"Known malicious indicator ({f.rule_id}) enforces a minimum risk floor.")
            break

    # 6. Narrative summary
    top_fam_names = sorted(
        contributions.keys(),
        key=lambda k: contributions[k].effective_points,
        reverse=True,
    )[:2]
    fam_summary = ", ".join(top_fam_names) if top_fam_names else "baseline"
    summary = (
        f"Event scored {total_score:.1f} ({risk.band.value}), driven primarily by {fam_summary}. "
        f"{len(findings)} findings attached."
    )

    return ExplainabilityTrace(
        event_id=event_id,
        final_score=round(total_score, 2),
        band=risk.band,
        summary=summary,
        family_contributions=contributions,
        top_ml_features=top_features,
        graph_path=graph_path,
        policy_rules_fired=policy_traces,
        counterfactuals=counterfactuals,
    )
