"""Behavior engine: feature extraction + deterministic behavior findings.

Imports are lazy (PEP 562) so ``ransomware``/``lolbins``/``persistence`` can depend on
``behavior.state`` / ``behavior.signals`` without circular-import problems.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from centralium.agent.behavior.engine import DefaultBehaviorEngine
    from centralium.agent.behavior.features import (
        FEATURE_NAMES,
        FEATURE_SCHEMA_VERSION,
        extract_features,
    )
    from centralium.agent.behavior.state import BehaviorState

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "BehaviorState",
    "DefaultBehaviorEngine",
    "extract_features",
]


def __getattr__(name: str) -> Any:
    if name == "DefaultBehaviorEngine":
        from centralium.agent.behavior import engine

        return engine.DefaultBehaviorEngine
    if name in {"FEATURE_NAMES", "FEATURE_SCHEMA_VERSION", "extract_features"}:
        from centralium.agent.behavior import features

        return getattr(features, name)
    if name == "BehaviorState":
        from centralium.agent.behavior import state

        return state.BehaviorState
    raise AttributeError(name)
