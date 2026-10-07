"""Reconcile the BehaviorEngine feature vector with the authoritative ML schema.

The behavior engine (``centralium.agent.behavior.features``) and the ML schema
(``ml.features.schema``) were built independently and use different names and scales.
``vectorize`` silently ignores unknown keys, so without this adapter nearly every ML input
would be imputed with benign defaults.  This module is the single place where the two are
mapped; ``tests/integration/test_feature_reconciliation.py`` asserts full schema coverage.

Mapping rules (documented, deterministic, no learned parameters):

* 1:1 renames (``exe_rarity`` -> ``executable_rarity`` ...).
* ``log1p`` counts emitted by the behavior engine are inverted with ``expm1`` to the raw counts
  the schema expects (``net_conn_count``, ``net_unique_dest``).
* File *rates* are ops/second over a 10 s window in the behavior engine; the schema's
  ``file_*_rate`` features are ops per window, hence ``* 10``.
* ``file_entropy`` is bits/8 in the behavior engine and bits (0-8) in the schema.
* ``proc_frequency`` (schema, unit) = ``1 - proc_rarity``.
* Features the behavior engine does not expose (``encoded_command``, ``cmdline_entropy``,
  ``cmdline_length``) are derived from the event command line, which the ML engine receives.
* Burst/ext-change magnitudes are squashed to [0, 1] with ``1 - exp(-x / k)``; the constants
  ``k`` are heuristics, not fitted values.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

from ml.features.schema import FEATURE_NAMES

#: Behavior-engine name -> ML-schema name (pure renames, same scale).
RENAMES: dict[str, str] = {
    "parent_child_rarity": "parent_child_rarity",
    "child_count": "child_count",
    "proc_rarity": "process_rarity",
    "exe_rarity": "executable_rarity",
    "unsigned": "unsigned_binary",
    "path_risk": "path_risk",
    "privilege_context": "privileged_context",
    "net_dest_rarity": "net_dest_rarity",
    "net_port_rarity": "net_port_rarity",
    "net_domain_rarity": "net_domain_rarity",
    "net_dns_entropy": "dns_entropy",
    "net_ip_reputation": "ip_reputation_risk",
    "file_suspicious_dir": "suspicious_dir_write",
    "file_exec_creation": "executable_created",
    "beh_powershell": "powershell_use",
    "beh_lolbin": "lolbin_use",
    "beh_script_interpreter": "script_interpreter_use",
    "beh_persistence_mod": "persistence_modification",
    "beh_priv_change": "privilege_change",
    "beh_injection": "injection_indicator",
    "beh_unusual_parent_child": "unusual_parent_child",
    "beh_download_execute": "download_execute_sequence",
    "rw_write_burst": "write_burst",
    "rw_rename_burst": "rename_burst",
    "rw_ext_mutation": "ext_mutation",
    "rw_entropy_increase": "entropy_increase",
    "rw_shadow_copy": "shadow_copy_activity",
}
FILE_WINDOW_SEC = 10.0  # must equal behavior.features._FILE_RATE_WINDOW
_B64 = re.compile(r"(?:-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{16,})|(?:frombase64string)", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def behavior_to_schema(
    behavior_features: Mapping[str, float], command_line: str | None = None
) -> dict[str, float]:
    """Convert a BehaviorEngine feature dict to ML-schema names/scales.

    Only features whose evidence exists are emitted for the structural groups; every schema
    feature is emitted for event kinds where it is meaningful (so coverage is 1.0).
    """
    bf = behavior_features
    out: dict[str, float] = {}
    for src, dst in RENAMES.items():
        out[dst] = float(bf.get(src, 0.0))
    out["proc_frequency"] = max(0.0, 1.0 - float(bf.get("proc_rarity", 0.0)))
    out["net_conn_count"] = math.expm1(float(bf.get("net_conn_count", 0.0)))
    out["net_unique_dest"] = math.expm1(float(bf.get("net_unique_dest", 0.0)))
    burst = math.expm1(float(bf.get("net_conn_burst", 0.0)))
    out["net_conn_burst"] = 1.0 - math.exp(-burst / 20.0)
    for src, dst in (
        ("file_create_rate", "file_create_rate"),
        ("file_modify_rate", "file_modify_rate"),
        ("file_delete_rate", "file_delete_rate"),
        ("file_rename_rate", "file_rename_rate"),
    ):
        out[dst] = float(bf.get(src, 0.0)) * FILE_WINDOW_SEC
    out["file_ext_change_rate"] = 1.0 - math.exp(-math.expm1(float(bf.get("file_ext_changes", 0.0))) / 10.0)
    out["file_write_entropy"] = float(bf.get("file_entropy", 0.0)) * 8.0
    cmd = command_line or ""
    out["cmdline_length"] = float(len(cmd))
    out["cmdline_entropy"] = _entropy(cmd)
    out["encoded_command"] = 1.0 if _B64.search(cmd) else 0.0
    return out


def adapt_for_event(behavior_features: Mapping[str, float], event: Any) -> dict[str, float]:
    return behavior_to_schema(behavior_features, getattr(event, "command_line", None))


def schema_coverage(adapted: Mapping[str, float]) -> float:
    return len(set(adapted) & set(FEATURE_NAMES)) / len(FEATURE_NAMES)
