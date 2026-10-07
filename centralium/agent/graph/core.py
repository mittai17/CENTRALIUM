"""Backend-independent attack-graph engine (in-memory hot index + deterministic analysis).

Design
------
``MemoryGraph`` is both the *in-memory fallback adapter* and the hot working set of the
Kuzu adapter, so both give byte-identical correlation/scoring behaviour. Analysis only
consumes data the graph persists (edges, node labels and per-event ``EventRec`` tags), so a
chain can be rebuilt from storage after a restart.

Everything here is deterministic: no randomness, no clocks (event time is used), no ML.
Scores are evidence-based and capped; a lone event without multi-step evidence scores low.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import logging
import threading
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from centralium.agent.graph import mitre
from centralium.agent.models import (
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    GraphSignal,
    Incident,
    NormalizedEvent,
)

log = logging.getLogger("centralium.graph")

NODE_TYPES: tuple[str, ...] = ("User", "Process", "File", "IP", "Domain", "RegistryKey", "Host", "Incident")

# rel type -> allowed (src node type, dst node type). RUNS_ON / EXECUTED_FROM are documented
# extensions to the spec list (needed to link a dropped file to the process that ran it).
REL_SCHEMA: dict[str, tuple[tuple[str, str], ...]] = {
    "SPAWNED": (("Process", "Process"),),
    "CREATED_FILE": (("Process", "File"),),
    "MODIFIED_FILE": (("Process", "File"),),
    "DELETED_FILE": (("Process", "File"),),
    "CONNECTED_TO": (("Process", "IP"),),
    "RESOLVED": (("Process", "Domain"),),
    "RESOLVES_TO": (("Domain", "IP"),),
    "CREATED_REG": (("Process", "RegistryKey"),),
    "MODIFIED_REG": (("Process", "RegistryKey"),),
    "AUTHENTICATED_AS": (("Process", "User"), ("Host", "User")),
    "PART_OF_INCIDENT": (
        ("Process", "Incident"),
        ("File", "Incident"),
        ("IP", "Incident"),
        ("Domain", "Incident"),
        ("RegistryKey", "Incident"),
    ),
    "EXECUTED_FROM": (("Process", "File"),),
    "RUNS_ON": (("Process", "Host"),),
}

STAGE_ORDER: tuple[AttackStage, ...] = (
    AttackStage.INITIAL_ACCESS,
    AttackStage.EXECUTION,
    AttackStage.PERSISTENCE,
    AttackStage.PRIVILEGE_ESCALATION,
    AttackStage.DEFENSE_EVASION,
    AttackStage.CREDENTIAL_ACCESS,
    AttackStage.DISCOVERY,
    AttackStage.LATERAL_MOVEMENT,
    AttackStage.COLLECTION,
    AttackStage.COMMAND_AND_CONTROL,
    AttackStage.EXFILTRATION,
    AttackStage.IMPACT,
)
_STAGE_INDEX = {s.value: i for i, s in enumerate(STAGE_ORDER)}

# deterministic successor priors (heuristic, NOT learned; used only for 'next stage' hints)
NEXT_STAGE_PRIORS: dict[AttackStage, tuple[tuple[AttackStage, float], ...]] = {
    AttackStage.INITIAL_ACCESS: ((AttackStage.EXECUTION, 0.5),),
    AttackStage.EXECUTION: (
        (AttackStage.COMMAND_AND_CONTROL, 0.3),
        (AttackStage.PERSISTENCE, 0.25),
        (AttackStage.DISCOVERY, 0.25),
        (AttackStage.DEFENSE_EVASION, 0.2),
    ),
    AttackStage.PERSISTENCE: (
        (AttackStage.COMMAND_AND_CONTROL, 0.3),
        (AttackStage.PRIVILEGE_ESCALATION, 0.2),
        (AttackStage.DEFENSE_EVASION, 0.2),
    ),
    AttackStage.PRIVILEGE_ESCALATION: (
        (AttackStage.CREDENTIAL_ACCESS, 0.3),
        (AttackStage.DEFENSE_EVASION, 0.2),
        (AttackStage.DISCOVERY, 0.2),
    ),
    AttackStage.DEFENSE_EVASION: (
        (AttackStage.CREDENTIAL_ACCESS, 0.2),
        (AttackStage.DISCOVERY, 0.2),
        (AttackStage.COMMAND_AND_CONTROL, 0.2),
    ),
    AttackStage.CREDENTIAL_ACCESS: ((AttackStage.LATERAL_MOVEMENT, 0.35), (AttackStage.DISCOVERY, 0.2)),
    AttackStage.DISCOVERY: (
        (AttackStage.LATERAL_MOVEMENT, 0.25),
        (AttackStage.COLLECTION, 0.25),
        (AttackStage.CREDENTIAL_ACCESS, 0.15),
    ),
    AttackStage.LATERAL_MOVEMENT: ((AttackStage.COLLECTION, 0.3), (AttackStage.EXECUTION, 0.2)),
    AttackStage.COLLECTION: ((AttackStage.EXFILTRATION, 0.45), (AttackStage.COMMAND_AND_CONTROL, 0.25)),
    AttackStage.COMMAND_AND_CONTROL: (
        (AttackStage.EXFILTRATION, 0.3),
        (AttackStage.COLLECTION, 0.2),
        (AttackStage.IMPACT, 0.2),
        (AttackStage.DISCOVERY, 0.15),
    ),
    AttackStage.EXFILTRATION: ((AttackStage.IMPACT, 0.3),),
}

_OFFICE = frozenset(
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrord32.exe",
        "soffice.bin", "libreoffice", "evince", "thunderbird", "msedge.exe", "chrome.exe",
        "firefox.exe", "chrome", "firefox",
    }
)  # fmt: skip
_BROWSERS = frozenset(
    {"msedge.exe", "chrome.exe", "firefox.exe", "chrome", "firefox", "brave", "iexplore.exe"}
)
_HUB_PROCESSES = frozenset(
    {
        "systemd", "init", "explorer.exe", "services.exe", "svchost.exe", "wininit.exe", "winlogon.exe",
        "sshd", "cron", "crond", "launchd", "gnome-shell", "kthreadd", "system", "smss.exe", "userinit.exe",
    }
)  # fmt: skip
_EXEC_EXT = (
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".sh", ".elf", ".so", ".jar", ".msi",  # noqa: E501
)  # fmt: skip
_RANSOM_EXT = (
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypted",
    ".enc",
    ".ryk",
    ".lockbit",
    ".wncry",
    ".pay2key",
)
_REMOTE_LOGON = frozenset(
    {"3", "10", "network", "remote_interactive", "remoteinteractive", "ssh", "rdp", "smb"}
)

_PERSIST_PATH_MARKERS: tuple[tuple[str, str], ...] = (
    ("/etc/cron", "T1053.003"),
    ("/var/spool/cron", "T1053.003"),
    ("/etc/systemd/system", "T1543.002"),
    ("/usr/lib/systemd/system", "T1543.002"),
    (".config/systemd/user", "T1543.002"),
    ("/etc/init.d", "T1543"),
    ("authorized_keys", "T1098.004"),
    (".bashrc", "T1546.004"),
    (".bash_profile", "T1546.004"),
    (".zshrc", "T1546.004"),
    ("/etc/profile", "T1546.004"),
    (".config/autostart", "T1547"),
    ("start menu/programs/startup", "T1547.001"),
    ("\\start menu\\programs\\startup", "T1547.001"),
    ("\\system32\\tasks\\", "T1053.005"),
)
_PERSIST_REG_MARKERS: tuple[tuple[str, str], ...] = (
    ("\\currentversion\\run", "T1547.001"),
    ("\\winlogon\\", "T1547.001"),
    ("\\image file execution options\\", "T1546"),
    ("\\currentcontrolset\\services\\", "T1543.003"),
)
_TEMP_MARKERS = ("/tmp/", "/var/tmp/", "/dev/shm/", "\\temp\\", "\\appdata\\", "/downloads/", "\\downloads\\")  # noqa: S108 - matching drop locations, not creating temp files


def _ms(dt: datetime) -> int:
    d = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return int(d.timestamp() * 1000)


def _norm_proc(name: str | None) -> str:
    return (name or "").strip().lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _is_global_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------- records
@dataclass
class GNode:
    node_id: str
    ntype: str
    label: str
    first_seen: int
    last_seen: int
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class GEdge:
    eid: str
    etype: str
    src: str
    dst: str
    src_type: str
    dst_type: str
    ts: int
    event_id: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass
class Tag:
    """One piece of stage evidence on an event. ``source`` is 'finding' or 'heuristic'."""

    stage: str
    technique: str
    source: str

    def to_json(self) -> list[str]:
        return [self.stage, self.technique, self.source]


@dataclass
class EventRec:
    event_id: str
    ts: int
    etype: str
    proc_id: str | None
    host: str
    label: str
    score: float = 0.0
    known: bool = False
    tags: list[Tag] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)  # office_spawn|dropper_file|dropped_exec|dropped_net
    structural: bool = False  # worth showing in a chain even without stage tags


@dataclass
class StagePrediction:
    """Observed + predicted stages. Confidence is a heuristic in [0, 0.9]; never 1.0."""

    current: AttackStage | None
    current_confidence: float
    observed: list[tuple[AttackStage, float]]
    next_likely: list[tuple[AttackStage, float]]
    basis: str = "deterministic sequence evidence + heuristic transition priors"


@dataclass
class ChainAnalysis:
    score: float
    reasons: list[str]
    events: list[EventRec]
    path: str
    techniques: list[str]
    prediction: StagePrediction


# --------------------------------------------------------------------------- scoring
_STAGE_POINTS = (0, 8, 22, 40, 55, 68, 78, 85, 90)


def _stage_confidence(tags: list[Tag]) -> float:
    n = len(tags)
    if n == 0:
        return 0.0
    finding_backed = any(t.source == "finding" for t in tags)
    techs = {t.technique for t in tags if t.technique}
    conf = 0.3 + 0.12 * min(n, 5) + (0.1 if finding_backed else 0.0) + 0.05 * min(len(techs), 3)
    return round(min(0.9, conf), 3)


def predict_stage(events: list[EventRec]) -> StagePrediction:
    by_stage: dict[str, list[Tag]] = defaultdict(list)
    latest: tuple[int, int, str] | None = None  # (ts, stage idx, stage)
    for rec in sorted(events, key=lambda r: (r.ts, r.event_id)):
        for tag in rec.tags:
            if tag.stage not in _STAGE_INDEX:
                continue
            by_stage[tag.stage].append(tag)
            cand = (rec.ts, _STAGE_INDEX[tag.stage], tag.stage)
            if latest is None or cand >= latest:
                latest = cand
    observed = sorted(
        ((AttackStage(s), _stage_confidence(t)) for s, t in by_stage.items()),
        key=lambda x: _STAGE_INDEX[x[0].value],
    )
    if latest is None:
        return StagePrediction(None, 0.0, [], [])
    cur = AttackStage(latest[2])
    cur_conf = _stage_confidence(by_stage[latest[2]])
    seen = {s for s, _ in observed}
    nxt = sorted(
        ((s, round(min(0.6, p * cur_conf), 3)) for s, p in NEXT_STAGE_PRIORS.get(cur, ()) if s not in seen),
        key=lambda x: (-x[1], _STAGE_INDEX[x[0].value]),
    )
    return StagePrediction(cur, cur_conf, observed, nxt)


def score_chain(events: list[EventRec]) -> tuple[float, list[str]]:
    """Deterministic 0-100 attack-chain score + human-readable reasons."""
    reasons: list[str] = []
    ordered = sorted(events, key=lambda r: (r.ts, r.event_id))
    seq: list[str] = []
    for rec in ordered:
        for st in sorted(
            {t.stage for t in rec.tags if t.stage in _STAGE_INDEX}, key=_STAGE_INDEX.__getitem__
        ):
            if not seq or seq[-1] != st:
                seq.append(st)
    distinct = sorted(set(seq), key=_STAGE_INDEX.__getitem__)
    total = float(_STAGE_POINTS[min(len(distinct), len(_STAGE_POINTS) - 1)])
    if distinct:
        reasons.append(f"{len(distinct)} distinct stage(s): {', '.join(distinct)} (+{total:g})")
    forward = sum(1 for a, b in itertools.pairwise(seq) if _STAGE_INDEX[b] > _STAGE_INDEX[a])
    if forward:
        bonus = float(min(12, 3 * forward))
        total += bonus
        reasons.append(f"{forward} forward stage transition(s) in time order (+{bonus:g})")
    flags = {f for rec in events for f in rec.flags}
    for flag, pts, text in (
        ("office_spawn", 12, "document/browser process spawned a script interpreter"),
        ("dropped_exec", 12, "process executed a file dropped by an interpreter/document process"),
        ("dropped_net", 12, "dropped executable performed network activity"),
    ):
        if flag in flags:
            total += pts
            reasons.append(f"{text} (+{pts})")
    stage_set = set(distinct)
    if AttackStage.IMPACT.value in stage_set:
        total += 15
        reasons.append("impact stage observed (+15)")
    if AttackStage.EXFILTRATION.value in stage_set:
        total += 10
        reasons.append("exfiltration stage observed (+10)")
    if AttackStage.PERSISTENCE.value in stage_set and AttackStage.EXECUTION.value in stage_set:
        total += 8
        reasons.append("persistence together with execution (+8)")
    top = max((r.score for r in events), default=0.0)
    if top > 0:
        fp = min(25.0, 0.3 * top)
        total += fp
        reasons.append(f"strongest member finding {top:.0f} (+{fp:.1f})")
    if any(r.known for r in events):
        total += 15
        reasons.append("chain contains a known-malicious artifact (+15)")
    return round(max(0.0, min(100.0, total)), 2), reasons


# --------------------------------------------------------------------------- in-memory graph
class MemoryGraph:
    """In-memory graph + analysis. Thread-safe. Also a complete GraphAdapter."""

    def __init__(
        self,
        *,
        max_events: int = 50_000,
        window_sec: float = 3600.0,
        hub_degree: int = 30,
        max_chain_events: int = 40,
        max_chain_nodes: int = 300,
    ) -> None:
        self.max_events = max_events
        self.window_ms = int(window_sec * 1000)
        self.hub_degree = hub_degree
        self.max_chain_events = max_chain_events
        self.max_chain_nodes = max_chain_nodes
        self._lock = threading.RLock()
        self.nodes: dict[str, GNode] = {}
        self.edges: dict[str, GEdge] = {}
        self.adj: dict[str, set[str]] = defaultdict(set)
        self.events: OrderedDict[str, EventRec] = OrderedDict()
        self.event_edges: dict[str, list[str]] = defaultdict(list)
        self._inc: dict[tuple[str, int], int] = {}
        self._started: set[str] = set()
        self._file_creators: dict[str, tuple[str, bool]] = {}  # path -> (proc_id, creator_suspicious)
        self._seq = 0
        self._incident_links: set[tuple[str, str]] = set()
        # write-behind buffers drained by persistent adapters
        self._dirty_nodes: dict[str, GNode] = {}
        self._pending_edges: list[GEdge] = []
        self._pending_events: list[EventRec] = []

    # -- persistence hooks ------------------------------------------------------------
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending_edges) + len(self._pending_events)

    def drain(self) -> tuple[list[GNode], list[GEdge], list[EventRec]]:
        with self._lock:
            out = (list(self._dirty_nodes.values()), self._pending_edges, self._pending_events)
            self._dirty_nodes, self._pending_edges, self._pending_events = {}, [], []
            return out

    def requeue(self, nodes: list[GNode], edges: list[GEdge], recs: list[EventRec]) -> None:
        """Put back a failed batch (persistent adapter retry)."""
        with self._lock:
            for n in nodes:
                self._dirty_nodes.setdefault(n.node_id, n)
            self._pending_edges = edges + self._pending_edges
            self._pending_events = recs + self._pending_events

    # -- node/edge primitives ---------------------------------------------------------
    def _node(self, nid: str, ntype: str, label: str, ts: int, props: dict[str, Any] | None = None) -> GNode:
        n = self.nodes.get(nid)
        if n is None:
            n = GNode(nid, ntype, label[:512], ts, ts, dict(props or {}))
            self.nodes[nid] = n
        else:
            n.last_seen = max(n.last_seen, ts)
            if props:
                n.props.update(props)
        self._dirty_nodes[nid] = n
        return n

    def _edge(self, etype: str, src: GNode, dst: GNode, ts: int, event_id: str, **props: Any) -> GEdge:
        if (src.ntype, dst.ntype) not in REL_SCHEMA[etype]:
            raise ValueError(f"illegal relationship {src.ntype}-[{etype}]->{dst.ntype}")
        self._seq += 1
        e = GEdge(
            f"{event_id}:{etype}:{self._seq}",
            etype,
            src.node_id,
            dst.node_id,
            src.ntype,
            dst.ntype,
            ts,
            event_id,
            props,
        )
        self._add_edge(e)
        self._pending_edges.append(e)
        return e

    def _add_edge(self, e: GEdge) -> None:
        self.edges[e.eid] = e
        self.adj[e.src].add(e.eid)
        self.adj[e.dst].add(e.eid)
        self.event_edges[e.event_id].append(e.eid)

    def _proc_id(self, host: str, pid: int | None, name: str | None) -> str:
        if pid is None:
            return f"proc:{host}:n:{_norm_proc(name) or 'unknown'}"
        return f"proc:{host}:{pid}:{self._inc.get((host, pid), 0)}"

    def _proc(self, host: str, pid: int | None, name: str | None, ts: int, **props: Any) -> GNode:
        label = f"{name or 'unknown'}({pid})" if pid is not None else (name or "unknown")
        return self._node(self._proc_id(host, pid, name), "Process", label, ts, props)

    # -- ingest ------------------------------------------------------------------------
    def ingest(self, event: NormalizedEvent, findings: list[Finding]) -> GraphSignal:
        with self._lock:
            if event.event_id in self.events:  # idempotent replay
                return self._signal(event.event_id)
            self._apply(event, findings)
            self._evict()
            return self._signal(event.event_id)

    def _apply(self, ev: NormalizedEvent, findings: list[Finding]) -> EventRec:
        ts = _ms(ev.timestamp)
        host = ev.host_id or "localhost"
        et = ev.event_type
        pname = ev.process_name
        pnorm = _norm_proc(pname)
        host_node = self._node(f"host:{host}", "Host", host, ts)
        rec = EventRec(ev.event_id, ts, et.value, None, host, f"{et.value} {pname or ''}".strip())
        rec.score = max((f.score for f in findings), default=0.0)
        rec.known = any(f.known_malicious for f in findings)
        eid = ev.event_id

        proc: GNode | None = None
        if ev.pid is not None or pname:
            if et == EventType.PROCESS_START and ev.pid is not None:
                key = (host, ev.pid)
                cur = self._proc_id(host, ev.pid, pname)
                if cur in self._started or (cur in self.nodes and self.nodes[cur].props.get("exited")):
                    self._inc[key] = self._inc.get(key, 0) + 1
                self._started.add(self._proc_id(host, ev.pid, pname))
            props: dict[str, Any] = {}
            if ev.executable_path:
                props["exe"] = ev.executable_path
            if ev.command_line:
                props["cmd"] = ev.command_line[:512]
            proc = self._proc(host, ev.pid, pname, ts, **props)
            rec.proc_id = proc.node_id
            if not any(self.edges[x].etype == "RUNS_ON" for x in self.adj.get(proc.node_id, ())):
                self._edge("RUNS_ON", proc, host_node, ts, eid)
            if ev.user and not proc.props.get("user"):
                proc.props["user"] = ev.user
                u = self._node(f"user:{host}:{ev.user}", "User", ev.user, ts)
                self._edge("AUTHENTICATED_AS", proc, u, ts, eid)

        tags: list[Tag] = []
        flags: list[str] = []
        suspicious_proc = (
            bool(proc and proc.props.get("dropped")) or pnorm in mitre.INTERPRETERS or pnorm in _OFFICE
        )
        parent: GNode | None = None
        if et == EventType.PROCESS_START and proc is not None:
            if ev.ppid is not None:
                parent = self._proc(host, ev.ppid, ev.parent_process, ts)
                self._edge("SPAWNED", parent, proc, ts, eid)
                rec.label = f"{parent.label} SPAWNED {proc.label}"
            else:
                rec.label = f"{proc.label} started"
            rec.structural = True
            ppnorm = _norm_proc(ev.parent_process)
            if pnorm in mitre.INTERPRETERS and ppnorm in _OFFICE:
                tags.append(Tag(AttackStage.INITIAL_ACCESS.value, "T1566.001", "heuristic"))
                tags.append(
                    Tag(
                        AttackStage.EXECUTION.value,
                        mitre.technique_for_process(pnorm) or "T1059",
                        "heuristic",
                    )
                )
                flags.append("office_spawn")
            exe_key = (ev.executable_path or "").lower()
            creator = self._file_creators.get(exe_key) if exe_key else None
            if creator is not None:
                fnode = self.nodes.get(f"file:{host}:{exe_key}")
                if fnode is not None:
                    self._edge("EXECUTED_FROM", proc, fnode, ts, eid)
                if creator[1]:
                    proc.props["dropped"] = True
                    tags.append(Tag(AttackStage.EXECUTION.value, "T1204.002", "heuristic"))
                    flags.append("dropped_exec")
            elif any(m in exe_key for m in _TEMP_MARKERS) and exe_key.endswith(_EXEC_EXT):
                tags.append(Tag(AttackStage.EXECUTION.value, "T1204.002", "heuristic"))
            if pnorm in mitre.INTERPRETERS and not tags and ev.command_line:
                pass  # plain interpreter start is not evidence by itself
        elif et == EventType.PROCESS_EXIT and proc is not None:
            proc.props["exited"] = True
            rec.label = f"{proc.label} exited"
        elif et in (
            EventType.FILE_CREATE,
            EventType.FILE_MODIFY,
            EventType.FILE_DELETE,
            EventType.FILE_RENAME,
        ):
            self._file_event(ev, host, ts, proc, rec, tags, flags, suspicious_proc, pnorm)
        elif et in (EventType.NETWORK_CONNECT, EventType.NETWORK_LISTEN, EventType.DNS_QUERY):
            self._net_event(ev, ts, proc, rec, tags, flags, suspicious_proc, pnorm)
        elif (
            et in (EventType.REGISTRY_CREATE, EventType.REGISTRY_MODIFY, EventType.REGISTRY_DELETE)
            and ev.registry_key
        ):
            self._reg_event(ev, ts, proc, rec, tags, host)
        elif et in (EventType.PERSISTENCE, EventType.SERVICE_CHANGE, EventType.SCHEDULED_TASK):
            self._persist_event(ev, host, ts, proc, rec, tags)
        elif et == EventType.PRIVILEGE_CHANGE:
            tags.append(Tag(AttackStage.PRIVILEGE_ESCALATION.value, "T1548", "heuristic"))
            rec.label = f"{proc.label if proc else 'process'} privilege change"
            rec.structural = True
        elif et == EventType.AUTH:
            self._auth_event(ev, host, ts, proc, host_node, rec, tags)
        elif et == EventType.PROCESS_INJECT:
            tags.append(Tag(AttackStage.DEFENSE_EVASION.value, "T1055", "heuristic"))
            rec.label = f"{proc.label if proc else 'process'} injected into another process"
            rec.structural = True
        elif et == EventType.TAMPER:
            tags.append(Tag(AttackStage.DEFENSE_EVASION.value, "T1562.001", "heuristic"))
            rec.label = f"tamper attempt by {proc.label if proc else 'unknown'}"
            rec.structural = True

        for tech, stage in mitre.map_command_line(ev.command_line):
            tags.append(Tag(stage.value, tech, "heuristic"))
        for f in findings:
            stages: list[AttackStage] = (
                [f.attack_stage] if f.attack_stage and f.attack_stage != AttackStage.UNKNOWN else []
            )
            if f.source == FindingSource.RANSOMWARE:
                stages.append(AttackStage.IMPACT)
            for t in f.mitre_techniques:
                for st in mitre.stages_for(t)[:1]:
                    if st not in stages:
                        stages.append(st)
            if not stages and f.mitre_techniques:
                continue
            for st in stages:
                tags.append(Tag(st.value, (f.mitre_techniques or [""])[0], "finding"))
        # dedupe tags while keeping order
        seen_tags: set[tuple[str, str, str]] = set()
        for tg in tags:
            k = (tg.stage, tg.technique, tg.source)
            if k not in seen_tags:
                seen_tags.add(k)
                rec.tags.append(tg)
        rec.flags = sorted(set(flags))
        rec.structural = rec.structural or bool(rec.tags)
        self.events[eid] = rec
        self._pending_events.append(rec)
        return rec

    # -- per-type helpers -------------------------------------------------------------
    def _file_event(
        self,
        ev: NormalizedEvent,
        host: str,
        ts: int,
        proc: GNode | None,
        rec: EventRec,
        tags: list[Tag],
        flags: list[str],
        suspicious: bool,
        pnorm: str,
    ) -> None:
        if not ev.file_path:
            return
        path = ev.file_path
        low = path.lower().replace("\\", "/")
        fnode = self._node(f"file:{host}:{path.lower()}", "File", path, ts)
        etype = {
            EventType.FILE_CREATE: "CREATED_FILE",
            EventType.FILE_DELETE: "DELETED_FILE",
        }.get(ev.event_type, "MODIFIED_FILE")
        persist = next((t for m, t in _PERSIST_PATH_MARKERS if m.replace("\\", "/") in low), None)
        if proc is not None:
            self._edge(etype, proc, fnode, ts, ev.event_id, **({"persistence": True} if persist else {}))
        verb = {"CREATED_FILE": "CREATED_FILE", "DELETED_FILE": "DELETED_FILE"}.get(etype, "MODIFIED_FILE")
        rec.label = f"{proc.label if proc else 'unknown'} {verb} {path}"
        if etype == "CREATED_FILE":
            exec_like = low.endswith(_EXEC_EXT)
            creator_susp = suspicious or pnorm in mitre.LOLBIN_TRANSFER
            if exec_like and proc is not None:
                self._file_creators[path.lower()] = (proc.node_id, creator_susp)
                if creator_susp:
                    tags.append(Tag(AttackStage.COMMAND_AND_CONTROL.value, "T1105", "heuristic"))
                    flags.append("dropper_file")
                    rec.structural = True
            elif creator_susp and any(m in low for m in _TEMP_MARKERS):
                rec.structural = True
        if persist:
            tags.append(Tag(AttackStage.PERSISTENCE.value, persist, "heuristic"))
            rec.structural = True
        if low.endswith(_RANSOM_EXT) and ev.event_type in (
            EventType.FILE_CREATE,
            EventType.FILE_RENAME,
            EventType.FILE_MODIFY,
        ):
            tags.append(Tag(AttackStage.IMPACT.value, "T1486", "heuristic"))
        if ev.event_type == EventType.FILE_DELETE and any(
            m in low for m in ("/var/log/", "/windows/system32/winevt")
        ):
            tags.append(Tag(AttackStage.DEFENSE_EVASION.value, "T1070.004", "heuristic"))

    def _net_event(
        self,
        ev: NormalizedEvent,
        ts: int,
        proc: GNode | None,
        rec: EventRec,
        tags: list[Tag],
        flags: list[str],
        suspicious: bool,
        pnorm: str,
    ) -> None:
        pl = proc.label if proc else "unknown"
        ip_node = dom_node = None
        if ev.destination_ip:
            port = f":{ev.destination_port}" if ev.destination_port is not None else ""
            ip_node = self._node(f"ip:{ev.destination_ip}", "IP", ev.destination_ip, ts)
            if proc is not None and ev.event_type != EventType.DNS_QUERY:
                self._edge(
                    "CONNECTED_TO",
                    proc,
                    ip_node,
                    ts,
                    ev.event_id,
                    port=ev.destination_port,
                    proto=ev.protocol,
                )
            rec.label = f"{pl} CONNECTED_TO {ev.destination_ip}{port}"
        if ev.domain:
            dom_node = self._node(f"dom:{ev.domain.lower()}", "Domain", ev.domain.lower(), ts)
            if proc is not None:
                self._edge("RESOLVED", proc, dom_node, ts, ev.event_id)
            rec.label = f"{pl} RESOLVED {ev.domain}" + (
                f" -> {ev.destination_ip}" if ev.destination_ip else ""
            )
            if ip_node is not None:
                self._edge("RESOLVES_TO", dom_node, ip_node, ts, ev.event_id)
        resolved = ev.raw_metadata.get("resolved_ip") if ev.event_type == EventType.DNS_QUERY else None
        if dom_node is not None and isinstance(resolved, str) and _is_ip(resolved):
            self._edge(
                "RESOLVES_TO", dom_node, self._node(f"ip:{resolved}", "IP", resolved, ts), ts, ev.event_id
            )
        rec.structural = True
        dropped = bool(proc and proc.props.get("dropped"))
        notable = dropped or pnorm in mitre.INTERPRETERS or pnorm in mitre.LOLBIN_TRANSFER or pnorm in _OFFICE
        if pnorm in _BROWSERS and not dropped:
            notable = False
        if ev.event_type == EventType.DNS_QUERY:
            if notable:
                tags.append(Tag(AttackStage.COMMAND_AND_CONTROL.value, "T1071.004", "heuristic"))
        elif ev.event_type == EventType.NETWORK_CONNECT:
            dport = ev.destination_port
            if _is_global_ip(ev.destination_ip) and notable:
                tags.append(Tag(AttackStage.COMMAND_AND_CONTROL.value, "T1071", "heuristic"))
            if (
                notable
                and ev.destination_ip
                and not _is_global_ip(ev.destination_ip)
                and dport in (22, 445, 3389, 5985)
            ):
                tech = {22: "T1021.004", 445: "T1021.002", 3389: "T1021.001", 5985: "T1021"}[dport]
                tags.append(Tag(AttackStage.LATERAL_MOVEMENT.value, tech, "heuristic"))
            sent = ev.raw_metadata.get("bytes_out")
            if isinstance(sent, (int, float)) and sent >= 5_000_000 and _is_global_ip(ev.destination_ip):
                tags.append(Tag(AttackStage.EXFILTRATION.value, "T1041", "heuristic"))
        if dropped and (ev.destination_ip or ev.domain):
            flags.append("dropped_net")

    def _reg_event(
        self, ev: NormalizedEvent, ts: int, proc: GNode | None, rec: EventRec, tags: list[Tag], host: str
    ) -> None:
        assert ev.registry_key
        key = ev.registry_key
        rnode = self._node(f"reg:{host}:{key.lower()}", "RegistryKey", key, ts)
        etype = "CREATED_REG" if ev.event_type == EventType.REGISTRY_CREATE else "MODIFIED_REG"
        persist = next((t for m, t in _PERSIST_REG_MARKERS if m in key.lower()), None)
        if proc is not None:
            self._edge(etype, proc, rnode, ts, ev.event_id, **({"persistence": True} if persist else {}))
        rec.label = f"{proc.label if proc else 'unknown'} {etype} {key}"
        if persist:
            tags.append(Tag(AttackStage.PERSISTENCE.value, persist, "heuristic"))
            rec.structural = True

    def _persist_event(
        self, ev: NormalizedEvent, host: str, ts: int, proc: GNode | None, rec: EventRec, tags: list[Tag]
    ) -> None:
        name = str(ev.raw_metadata.get("name", ""))[:200]
        tech = {
            EventType.SCHEDULED_TASK: "T1053",
            EventType.SERVICE_CHANGE: "T1543",
        }.get(ev.event_type, "T1547")
        target = ev.file_path or ev.registry_key or name
        rec.label = (
            f"{proc.label if proc else 'unknown'} persistence ({ev.event_type.value}) {target}".strip()
        )
        rec.structural = True
        tags.append(Tag(AttackStage.PERSISTENCE.value, tech, "heuristic"))
        if proc is None:
            return
        if ev.registry_key:
            r = self._node(f"reg:{host}:{ev.registry_key.lower()}", "RegistryKey", ev.registry_key, ts)
            self._edge("CREATED_REG", proc, r, ts, ev.event_id, persistence=True)
        elif ev.file_path or name:
            p = ev.file_path or f"{ev.event_type.value}:{name}"
            f = self._node(f"file:{host}:{p.lower()}", "File", p, ts)
            self._edge("CREATED_FILE", proc, f, ts, ev.event_id, persistence=True)

    def _auth_event(
        self,
        ev: NormalizedEvent,
        host: str,
        ts: int,
        proc: GNode | None,
        host_node: GNode,
        rec: EventRec,
        tags: list[Tag],
    ) -> None:
        if ev.user:
            u = self._node(f"user:{host}:{ev.user}", "User", ev.user, ts)
            self._edge("AUTHENTICATED_AS", proc or host_node, u, ts, ev.event_id)
        ok = ev.raw_metadata.get("success", True)
        logon = str(ev.raw_metadata.get("logon_type", ev.protocol or "")).lower()
        rec.label = f"auth {'success' if ok else 'failure'} user={ev.user}"
        rec.structural = True
        if ok is False:
            tags.append(Tag(AttackStage.CREDENTIAL_ACCESS.value, "T1110", "heuristic"))
        elif logon in _REMOTE_LOGON:
            tags.append(Tag(AttackStage.LATERAL_MOVEMENT.value, "T1021", "heuristic"))

    # -- eviction -----------------------------------------------------------------------
    def _evict(self) -> None:
        while len(self.events) > self.max_events:
            old_id, _ = self.events.popitem(last=False)
            for eid in self.event_edges.pop(old_id, []):
                e = self.edges.pop(eid, None)
                if e is None:
                    continue
                for n in (e.src, e.dst):
                    s = self.adj.get(n)
                    if s is not None:
                        s.discard(eid)
                        if not s:
                            self.adj.pop(n, None)
                            self.nodes.pop(n, None)

    # -- incidents ----------------------------------------------------------------------
    def attach_incident(self, incident: Incident) -> None:
        with self._lock:
            ts = _ms(incident.created_at)
            inode = self._node(
                f"inc:{incident.incident_id}", "Incident", incident.title, ts, {"band": incident.band.value}
            )
            for evid in incident.event_ids:
                if evid not in self.events:
                    continue
                for eid in list(self.event_edges.get(evid, [])):
                    e = self.edges.get(eid)
                    if e is None or e.etype == "PART_OF_INCIDENT":
                        continue
                    for nid in (e.src, e.dst):
                        n = self.nodes.get(nid)
                        if n is None or n.ntype not in ("Process", "File", "IP", "Domain", "RegistryKey"):
                            continue
                        if (nid, inode.node_id) in self._incident_links:
                            continue
                        self._incident_links.add((nid, inode.node_id))
                        self._edge("PART_OF_INCIDENT", n, inode, ts, evid)

    # -- analysis -------------------------------------------------------------------------
    def _is_hub(self, node: GNode, seeds: set[str]) -> bool:
        if node.node_id in seeds:
            return False
        if node.ntype == "Process":
            name = _norm_proc(node.label.split("(", 1)[0])
            if name in _HUB_PROCESSES:
                return True
            kids = sum(
                1
                for x in self.adj.get(node.node_id, ())
                if self.edges[x].etype == "SPAWNED" and self.edges[x].src == node.node_id
            )
            return kids > self.hub_degree
        return len(self.adj.get(node.node_id, ())) > self.hub_degree

    def _component(self, event_id: str) -> tuple[set[str], set[str]]:
        rec = self.events[event_id]
        seeds: set[str] = set()
        for eid in self.event_edges.get(event_id, []):
            e = self.edges[eid]
            for nid in (e.src, e.dst):
                if self.nodes[nid].ntype in ("Process", "File", "IP", "Domain", "RegistryKey"):
                    seeds.add(nid)
        if rec.proc_id and rec.proc_id in self.nodes:
            seeds.add(rec.proc_id)
        exempt = {rec.proc_id} if rec.proc_id else set()
        seen = set(seeds)
        used_events = {event_id}
        q: deque[str] = deque(seeds)
        while q and len(seen) < self.max_chain_nodes:
            nid = q.popleft()
            node = self.nodes[nid]
            if self._is_hub(node, exempt):
                continue
            for eid in list(self.adj.get(nid, ())):
                e = self.edges[eid]
                if e.etype in ("RUNS_ON", "AUTHENTICATED_AS", "PART_OF_INCIDENT"):
                    continue
                if e.etype not in ("SPAWNED", "EXECUTED_FROM") and abs(e.ts - rec.ts) > self.window_ms:
                    continue
                used_events.add(e.event_id)
                other = e.dst if e.src == nid else e.src
                if other not in seen:
                    seen.add(other)
                    q.append(other)
        return seen, used_events

    def analyze(self, event_id: str) -> ChainAnalysis | None:
        with self._lock:
            if event_id not in self.events:
                return None
            nodes, ev_ids = self._component(event_id)
            recs = sorted(
                (self.events[i] for i in ev_ids if i in self.events), key=lambda r: (r.ts, r.event_id)
            )
            score, reasons = score_chain(recs)
            shown = [r for r in recs if r.tags or r.structural or r.event_id == event_id]
            if len(shown) > self.max_chain_events:
                keep = {r.event_id for r in shown if r.tags} | {event_id}
                rest = [r for r in shown if r.event_id not in keep]
                budget = max(0, self.max_chain_events - len(keep))
                keep |= {r.event_id for r in rest[:budget]}
                shown = [r for r in shown if r.event_id in keep][: self.max_chain_events]
            path = self._path(nodes, recs)
            techs = sorted({t.technique for r in recs for t in r.tags if t.technique})
            return ChainAnalysis(score, reasons, shown, path, techs, predict_stage(recs))

    def _path(self, nodes: set[str], recs: list[EventRec]) -> str:
        """Time-ordered first-appearance sequence of node labels (process -> file -> domain -> ip)."""
        first: list[tuple[int, str]] = []  # (first_seen, label)
        for nid in nodes:
            n = self.nodes.get(nid)
            if n is not None:
                first.append((n.first_seen, n.label))
        first.sort()
        labels = [lbl for _, lbl in first][:12]
        return " -> ".join(labels)

    def _signal(self, event_id: str) -> GraphSignal:
        a = self.analyze(event_id)
        if a is None:
            return GraphSignal()
        lines = [f"path: {a.path}"] if a.path else []
        lines += [f"{datetime.fromtimestamp(r.ts / 1000, UTC):%H:%M:%S} {r.label}" for r in a.events]
        pred = a.prediction
        own = self.events[event_id]
        return GraphSignal(
            score=a.score,
            attack_stage=pred.current,
            stage_confidence=pred.current_confidence,
            chain=lines,
            related_event_ids=[r.event_id for r in a.events if r.event_id != event_id][:50],
            mitre_techniques=sorted(set(a.techniques) | {t.technique for t in own.tags if t.technique}),
        )

    def chain_for(self, event_id: str) -> list[str]:
        with self._lock:
            if event_id not in self.events:
                return []
            return self._signal(event_id).chain

    def stage_for(self, event_id: str) -> StagePrediction | None:
        a = self.analyze(event_id)
        return a.prediction if a else None

    # -- adapter surface --------------------------------------------------------------------
    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"nodes": len(self.nodes), "edges": len(self.edges), "events": len(self.events)}

    # -- hydration (used by Kuzu adapter) -----------------------------------------------------
    def load_edge(self, e: GEdge, src: GNode, dst: GNode) -> None:
        with self._lock:
            for n in (src, dst):
                if n.node_id not in self.nodes:
                    self.nodes[n.node_id] = n
            if e.eid not in self.edges:
                self._add_edge(e)

    def load_event(self, rec: EventRec) -> None:
        with self._lock:
            self.events[rec.event_id] = rec


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def tags_to_json(tags: list[Tag]) -> str:
    return json.dumps([t.to_json() for t in tags], separators=(",", ":"))


def tags_from_json(text: str) -> list[Tag]:
    try:
        return [Tag(*t) for t in json.loads(text)]
    except (ValueError, TypeError):
        return []
