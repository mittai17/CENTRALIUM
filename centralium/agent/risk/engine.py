"""Calibrated, deterministic risk engine implementing ``RiskEngine``.

Pipeline (all pure functions of the inputs - no randomness, no clock):

1. Collect components. ML families A/B fold into ``behavioral_ml`` (best of ``score*conf``);
   families with ``available=False`` are EXCLUDED, never counted as zero risk. If nothing
   is available the result is 0 / SAFE with an explicit note: scores are never fabricated.
2. Weighted average over available components (spec formula), weights from
   ``RiskSettings``; each weight is scaled by the component's confidence and each score is
   shrunk by ``0.5 + 0.5 * confidence`` (so a lone low-confidence family cannot read as certain). With
   ``normalize_weights`` the average is re-normalised over the weights actually present.
3. **Evidence floor (fix for the re-normalisation dilution caveat).**
   A weighted average makes one very strong family look middling when the others read 0
   (behavior 80, graph 0 -> ~25 in the reference engine) because absent-evidence families are
   *present with score 0*. Real EDR evidence is mostly asymmetric: a single strong signal
   should be enough to alert. So each non-AI family ``i`` gets a floor
   ``floor_ratio[i] * score_i * confidence_i`` and ``final = max(weighted, max_i floor_i)``.
   Ratios are < 1 and family-specific (deterministic/intel high, ML low) so a lone ML
   score of 80 lands MEDIUM (48) while a lone deterministic 80 lands HIGH (68);
   corroboration from other families lifts the weighted term above the floor. The floor
   can never exceed the evidence that produced it (ratio <= 1), is confidence-scaled, and
   deterministic. All ratios are tunable (``RiskTuning.floor_ratios``).
4. AI calibration. AI contributes only if its confidence >= ``ai_min_confidence``. It may
   *raise* the non-AI score by at most ``ai_max_uplift`` points and can never lower it. If no
   non-AI evidence exists, an AI-only result is capped at ``ai_only_cap`` (never above MEDIUM
   by default) - the LLM never dominates deterministic evidence.
5. Known-malicious floor: any ``Finding.known_malicious`` (hash/IOC/YARA) forces
   ``>= known_malicious_floor``; nothing (including the AI) can lower it afterwards.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.config import RiskSettings
from centralium.agent.models import DetectionResult, Finding, RiskAssessment, ScoreFamily

_NON_AI = ("behavioral_ml", "deterministic_evidence", "attack_graph", "threat_intel", "static_malware")


class RiskTuning(BaseModel):
    """Calibration knobs beyond ``RiskSettings`` (kept local; propose adding to config)."""

    model_config = ConfigDict(extra="forbid")

    floor_ratios: dict[str, float] = Field(
        default_factory=lambda: {
            "threat_intel": 0.90,
            "deterministic_evidence": 0.85,
            "static_malware": 0.70,
            "attack_graph": 0.75,
            "behavioral_ml": 0.60,
        }
    )
    enable_evidence_floor: bool = True
    ai_max_uplift: float = Field(default=15.0, ge=0, le=100)
    ai_only_cap: float = Field(default=45.0, ge=0, le=100)
    min_component_confidence: float = Field(default=0.0, ge=0, le=1)  # components below are ignored


class CalibratedRiskEngine:
    def __init__(self, settings: RiskSettings | None = None, tuning: RiskTuning | None = None) -> None:
        self.s = settings or RiskSettings()
        self.t = tuning or RiskTuning()
        for k, v in self.t.floor_ratios.items():
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"floor ratio for {k} must be within 0..1")

    # ------------------------------------------------------------------ components
    def _components(self, scores: dict[ScoreFamily, DetectionResult]) -> dict[str, tuple[float, float]]:
        """name -> (effective score 0-100, confidence 0-1) for AVAILABLE families only."""
        comp: dict[str, tuple[float, float]] = {}
        ml = [
            r
            for r in (scores.get(ScoreFamily.ML_ANOMALY), scores.get(ScoreFamily.ML_CLASSIFICATION))
            if r is not None and r.available
        ]
        if ml:
            best = max(
                ml,
                key=lambda r: r.score * (r.confidence if r.family == ScoreFamily.ML_CLASSIFICATION else 1.0),
            )
            comp["behavioral_ml"] = (
                best.score,
                best.confidence if best.family == ScoreFamily.ML_CLASSIFICATION else 1.0,
            )
        for name, fam in (
            ("deterministic_evidence", ScoreFamily.DETERMINISTIC_EVIDENCE),
            ("attack_graph", ScoreFamily.GRAPH_ATTACK_CHAIN),
            ("threat_intel", ScoreFamily.THREAT_INTEL),
            ("static_malware", ScoreFamily.STATIC_MALWARE),
            ("ai_assessment", ScoreFamily.AI_ASSESSMENT),
        ):
            r = scores.get(fam)
            if r is not None and r.available:
                comp[name] = (r.score, r.confidence)
        return {
            k: v for k, v in comp.items() if v[1] >= self.t.min_component_confidence or k == "ai_assessment"
        }

    def _weighted(
        self, comp: dict[str, tuple[float, float]], weights: dict[str, float]
    ) -> tuple[float, dict[str, float]]:
        eff: dict[str, float] = {}
        num = den = 0.0
        for k, (score, conf) in comp.items():
            w = weights.get(k, 0.0) * conf
            eff[k] = w
            num += w * score * (0.5 + 0.5 * conf)  # confidence shrinks a score by at most half
            den += w
        if den <= 0:
            return 0.0, eff
        if self.s.normalize_weights:
            return num / den, {k: v / den for k, v in eff.items()}
        return num, eff

    # ------------------------------------------------------------------ assess
    def assess(self, scores: dict[ScoreFamily, DetectionResult], findings: list[Finding]) -> RiskAssessment:
        weights = self.s.weights()
        comp = self._components(scores)
        notes: list[str] = []
        non_ai = {k: v for k, v in comp.items() if k in _NON_AI}
        ai = comp.get("ai_assessment")

        if not comp:
            notes.append("no evidence families available; score not fabricated")
        base, used = self._weighted(non_ai, weights)
        if non_ai:
            notes.append(f"weighted evidence score {base:.1f} over {', '.join(sorted(non_ai))}")

        total = base
        if self.t.enable_evidence_floor and non_ai:
            floors = {
                k: self.t.floor_ratios.get(k, 0.0) * score * conf for k, (score, conf) in non_ai.items()
            }
            top = max(floors, key=lambda k: (floors[k], k))
            if floors[top] > total + 1e-9:
                notes.append(
                    f"evidence floor from {top}: {floors[top]:.1f} "
                    f"(ratio {self.t.floor_ratios.get(top, 0.0):.2f} x score {non_ai[top][0]:.0f} x conf {non_ai[top][1]:.2f}) "  # noqa: E501
                    f"> weighted {base:.1f}"
                )
                total = floors[top]

        if ai is not None:
            ai_score, ai_conf = ai
            if ai_conf < self.s.ai_min_confidence:
                notes.append(f"AI ignored: confidence {ai_conf:.2f} < {self.s.ai_min_confidence:.2f}")
            elif non_ai:
                with_ai, used_ai = self._weighted(comp, weights)
                uplift = max(0.0, min(with_ai - total, self.t.ai_max_uplift))
                if uplift > 0:
                    notes.append(f"AI raised score by {uplift:.1f} (cap {self.t.ai_max_uplift:g})")
                total += uplift
                used = used_ai
            else:
                capped = min(ai_score * ai_conf, self.t.ai_only_cap)
                notes.append(f"AI-only evidence capped at {self.t.ai_only_cap:g}")
                total = max(total, capped)
                used = {"ai_assessment": 1.0}
            if ai_score < total and ai_conf >= self.s.ai_min_confidence:
                notes.append("AI score cannot lower non-AI risk")

        known = [f for f in findings if f.known_malicious]
        if known:
            floor = self.s.known_malicious_floor
            if total < floor:
                notes.append(f"known-malicious floor {floor:g} applied ({known[0].rule_id})")
                total = floor
        total = round(max(0.0, min(100.0, total)), 4)
        final = DetectionResult(family=ScoreFamily.FINAL_RISK, score=total, confidence=1.0)
        return RiskAssessment(
            final_score=total,
            band=self.s.band_for(total),
            scores={**scores, ScoreFamily.FINAL_RISK: final},
            weights_used={k: round(v, 6) for k, v in used.items()},
            notes=notes,
        )
