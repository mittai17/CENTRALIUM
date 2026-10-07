"""ML feature extraction (stable schema).

Public contract for the ML engineer::

    from centralium.agent.behavior.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, extract_features

* ``FEATURE_NAMES`` is the ordered list of every feature; ``extract_features`` always returns
  *exactly* these keys (all floats, finite, missing evidence = 0.0).
* ``extract_features(event, state)`` is READ-ONLY with respect to ``state``: call
  ``state.observe(event)`` first (the :class:`DefaultBehaviorEngine` does this). Counts then
  include the current event, so "rarity" = 1/count is 1.0 for something never seen before.
* Any change to names/order/semantics MUST bump ``FEATURE_SCHEMA_VERSION``.

Feature families follow the spec: PROCESS, NETWORK, FILE, BEHAVIOR, RANSOMWARE (+ event-kind one-hots).
"""

from __future__ import annotations

import math

from centralium.agent.behavior.signals import (
    SCRIPT_INTERPRETERS,
    ancestry_risk,
    is_exec_path,
    norm_name,
    path_risk,
)
from centralium.agent.behavior.state import FILE_EVENT_TYPES, BehaviorState
from centralium.agent.lolbins.detector import LolbinAssessment, LolbinContext, LolbinDetector
from centralium.agent.models import EventType, Finding, NormalizedEvent
from centralium.agent.normalization.common import shannon_entropy
from centralium.agent.persistence.detector import PersistenceDetector
from centralium.agent.ransomware.scorer import RansomwareAssessment, RansomwareScorer

FEATURE_SCHEMA_VERSION = "1.0.0"

FEATURE_NAMES: list[str] = [
    # event kind
    "evt_process",
    "evt_network",
    "evt_file",
    "evt_registry",
    "evt_other",
    # PROCESS
    "proc_frequency",
    "proc_rarity",
    "parent_child_frequency",
    "parent_child_rarity",
    "child_count",
    "exe_rarity",
    "unsigned",
    "path_risk",
    "privilege_context",
    # NETWORK
    "net_conn_count",
    "net_unique_dest",
    "net_dest_rarity",
    "net_port_rarity",
    "net_domain_rarity",
    "net_dns_entropy",
    "net_ip_reputation",
    "net_conn_burst",
    # FILE
    "file_create_rate",
    "file_modify_rate",
    "file_delete_rate",
    "file_rename_rate",
    "file_ext_changes",
    "file_entropy",
    "file_suspicious_dir",
    "file_exec_creation",
    # BEHAVIOR
    "beh_powershell",
    "beh_lolbin",
    "beh_lolbin_context_score",
    "beh_script_interpreter",
    "beh_persistence_mod",
    "beh_priv_change",
    "beh_injection",
    "beh_unusual_parent_child",
    "beh_download_execute",
    # RANSOMWARE
    "rw_write_burst",
    "rw_rename_burst",
    "rw_ext_mutation",
    "rw_entropy_increase",
    "rw_shadow_copy",
    "rw_composite_score",
]

_PRIV_USERS = {
    "root",
    "system",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
}
_FILE_RATE_WINDOW = 10.0  # seconds; rates are ops/sec over this window
_PS = {"powershell", "pwsh", "powershell_ise"}
_DEFAULT_LOLBIN = LolbinDetector()
_DEFAULT_PERSIST = PersistenceDetector()
_DEFAULT_RW = RansomwareScorer()


def _rarity(count: int) -> float:
    return 1.0 / count if count > 0 else 1.0


def lolbin_context(event: NormalizedEvent, state: BehaviorState) -> LolbinContext:
    """Build the frequency/destination context the LOLBin detector scores against."""
    parent = state.resolve_parent_name(event)
    name = (event.process_name or "").lower()
    pair = f"{(parent or '').lower()}>{name}"
    dest = state.dest_counts.get(event.destination_ip) if event.destination_ip else 0
    return LolbinContext(
        pair_count=state.pair_counts.get(pair) if parent else 0,
        proc_count=state.proc_counts.get(name),
        dest_rarity=_rarity(dest) if event.destination_ip else 0.0,
        parent_name=parent,
    )


def extract_features(
    event: NormalizedEvent,
    state: BehaviorState,
    *,
    lolbin: LolbinAssessment | None = None,
    persistence: list[Finding] | None = None,
    ransomware: RansomwareAssessment | None = None,
) -> dict[str, float]:
    """Compute the full feature vector for ``event`` (see module docstring).

    The keyword arguments let the engine reuse detector results it already computed.
    """
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    et = event.event_type
    meta = event.raw_metadata or {}
    name = (event.process_name or "").lower()
    pname = norm_name(event.process_name or event.executable_path)

    if et in {
        EventType.PROCESS_START,
        EventType.PROCESS_EXIT,
        EventType.PROCESS_INJECT,
        EventType.MODULE_LOAD,
        EventType.PRIVILEGE_CHANGE,
    }:
        f["evt_process"] = 1.0
    elif et in {EventType.NETWORK_CONNECT, EventType.NETWORK_LISTEN, EventType.DNS_QUERY}:
        f["evt_network"] = 1.0
    elif et in FILE_EVENT_TYPES:
        f["evt_file"] = 1.0
    elif et in {EventType.REGISTRY_CREATE, EventType.REGISTRY_MODIFY, EventType.REGISTRY_DELETE}:
        f["evt_registry"] = 1.0
    else:
        f["evt_other"] = 1.0

    with state.lock:
        # ---------------------------------------------------------------- PROCESS
        parent = state.resolve_parent_name(event)
        pc = state.proc_counts.get(name) if name else 0
        pair_n = state.pair_counts.get(f"{(parent or '').lower()}>{name}") if parent and name else 0
        f["proc_frequency"] = math.log1p(pc)
        f["proc_rarity"] = _rarity(pc) if name else 0.0
        f["parent_child_frequency"] = math.log1p(pair_n)
        f["parent_child_rarity"] = _rarity(pair_n) if pair_n else (1.0 if parent and name else 0.0)
        f["child_count"] = float(
            max(state.children_in_window(event.pid), state.children_in_window(event.ppid))
        )
        exe_n = state.exe_counts.get(event.executable_path.lower()) if event.executable_path else 0
        f["exe_rarity"] = _rarity(exe_n) if event.executable_path else 0.0
        if et == EventType.PROCESS_START or event.executable_path:
            signed_meta = meta.get("signed")
            f["unsigned"] = (
                0.0 if (event.signer or signed_meta is True or str(signed_meta).lower() == "true") else 1.0
            )
        f["path_risk"] = path_risk(event.executable_path)
        f["privilege_context"] = float(
            (event.user or "").lower() in _PRIV_USERS
            or str(meta.get("integrity_level", "")).lower() in {"high", "system"}
            or str(meta.get("euid", "")) == "0"
            or et == EventType.PRIVILEGE_CHANGE
        )

        # ---------------------------------------------------------------- NETWORK
        ns = state.net_stats()
        f["net_conn_count"] = math.log1p(ns["count"])
        f["net_unique_dest"] = math.log1p(ns["unique_dest"])
        f["net_conn_burst"] = math.log1p(ns["burst"])
        if et in {EventType.NETWORK_CONNECT, EventType.NETWORK_LISTEN, EventType.DNS_QUERY}:
            if event.destination_ip:
                f["net_dest_rarity"] = _rarity(state.dest_counts.get(event.destination_ip))
            if event.destination_port is not None:
                f["net_port_rarity"] = _rarity(state.port_counts.get(str(event.destination_port)))
            if event.domain:
                f["net_domain_rarity"] = _rarity(state.domain_counts.get(event.domain))
                first = event.domain.split(".")[0]
                f["net_dns_entropy"] = shannon_entropy(first)
            rep = meta.get("ip_reputation")
            if isinstance(rep, (int, float)) and not isinstance(rep, bool):
                f["net_ip_reputation"] = min(1.0, max(0.0, float(rep)))

        # ---------------------------------------------------------------- FILE
        fkey = state.pid_key(event)
        fs = state.file_stats(fkey, window_sec=_FILE_RATE_WINDOW)
        f["file_create_rate"] = fs.creates / _FILE_RATE_WINDOW
        f["file_modify_rate"] = fs.modifies / _FILE_RATE_WINDOW
        f["file_delete_rate"] = fs.deletes / _FILE_RATE_WINDOW
        f["file_rename_rate"] = fs.renames / _FILE_RATE_WINDOW
        f["file_ext_changes"] = math.log1p(fs.ext_changes)
        f["file_entropy"] = fs.avg_entropy_after / 8.0 if fs.entropy_samples else 0.0
        if et in FILE_EVENT_TYPES:
            f["file_suspicious_dir"] = path_risk(event.file_path)
            f["file_exec_creation"] = float(et == EventType.FILE_CREATE and is_exec_path(event.file_path))

        # ---------------------------------------------------------------- BEHAVIOR
        lb = lolbin
        if lb is None:
            lb = _DEFAULT_LOLBIN.assess(event, lolbin_context(event, state))
        f["beh_powershell"] = float(pname in _PS)
        f["beh_lolbin"] = float(lb.is_lolbin)
        f["beh_lolbin_context_score"] = lb.score / 100.0 if lb.is_lolbin else 0.0
        f["beh_script_interpreter"] = float(pname in SCRIPT_INTERPRETERS)
        pers = persistence if persistence is not None else _DEFAULT_PERSIST.evaluate(event)
        f["beh_persistence_mod"] = max((p.score for p in pers), default=0.0) / 100.0
        f["beh_priv_change"] = float(et == EventType.PRIVILEGE_CHANGE)
        f["beh_injection"] = float(et == EventType.PROCESS_INJECT)
        if et == EventType.PROCESS_START:
            static = ancestry_risk(parent, event.process_name, event.executable_path)
            first_seen = 0.3 if (parent and pair_n <= 1) else 0.0
            f["beh_unusual_parent_child"] = max(static, first_seen)
            created, via_net = state.created_recently(event.executable_path)
            f["beh_download_execute"] = 1.0 if (created and via_net) else 0.6 if created else 0.0

        # ---------------------------------------------------------------- RANSOMWARE
        rw = ransomware if ransomware is not None else _DEFAULT_RW.assess(event, state)
        comps = rw.components
        f["rw_write_burst"] = comps.get("write_burst", 0.0)
        f["rw_rename_burst"] = comps.get("rename_burst", 0.0)
        f["rw_ext_mutation"] = comps.get("extension_mutation", 0.0)
        f["rw_entropy_increase"] = comps.get("entropy_increase", 0.0)
        f["rw_shadow_copy"] = comps.get("shadow_copy", 0.0)
        f["rw_composite_score"] = rw.score / 100.0

    return {k: float(v) if math.isfinite(v) else 0.0 for k, v in f.items()}
