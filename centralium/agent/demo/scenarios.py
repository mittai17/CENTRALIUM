"""Safe, synthetic demo/test scenarios (inert strings only; nothing is ever executed).

Indicators use reserved ranges: TEST-NET addresses (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and ``.test`` / ``.invalid`` domains (RFC 2606/6761). The EICAR string is the
standard antivirus test file hash. Each scenario carries its *expectation* so the demo/E2E
runner can compare actual pipeline behaviour with it (ground truth is authored, not learned).
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from centralium.agent.models import EventType, NormalizedEvent

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
DEMO_HOST = "demo-host"
_INERT_PS = base64.b64encode("Write-Host 'centralium-demo'".encode("utf-16-le")).decode()


@dataclass
class DemoScenario:
    name: str
    title: str
    expect: str  # "benign" (no alert) | "detect" (incident expected) | "known" (EPP short-circuit)
    description: str
    events: list[NormalizedEvent] = field(default_factory=list)
    baseline: bool = False  # replayed first, in LEARNING mode, to teach the novelty filter


class _Clock:
    def __init__(self, start: datetime) -> None:
        self.t = start

    def tick(self, ms: int = 400) -> datetime:
        self.t += timedelta(milliseconds=ms)
        return self.t


def _ev(clock: _Clock, event_type: EventType, ms: int = 400, **kw: Any) -> NormalizedEvent:
    kw.setdefault("host_id", DEMO_HOST)
    kw.setdefault("user", "demo")
    kw.setdefault("source", "replay")
    meta = {"synthetic": True, **kw.pop("raw_metadata", {})}
    return NormalizedEvent(event_type=event_type, timestamp=clock.tick(ms), raw_metadata=meta, **kw)


def _proc(
    clock: _Clock,
    pid: int,
    ppid: int,
    name: str,
    path: str,
    cmd: str,
    parent: str,
    signer: str | None,
    ms: int = 400,
    **kw: Any,
) -> NormalizedEvent:
    return _ev(
        clock,
        EventType.PROCESS_START,
        ms,
        pid=pid,
        ppid=ppid,
        process_name=name,
        executable_path=path,
        command_line=cmd,
        parent_process=parent,
        signer=signer,
        **kw,
    )


def normal_browser(clock: _Clock, scope: str = "") -> DemoScenario:
    ev = [
        _proc(
            clock,
            1000,
            1,
            "explorer.exe",
            r"C:\Windows\explorer.exe",
            "explorer.exe",
            "userinit.exe",
            "Microsoft Windows",
        ),
        _proc(
            clock,
            2001,
            1000,
            "chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "chrome.exe",
            "explorer.exe",
            "Google LLC",
        ),
    ]
    for i in range(8):
        ev.append(
            _ev(
                clock,
                EventType.DNS_QUERY,
                700,
                pid=2001,
                ppid=1000,
                process_name="chrome.exe",
                domain=f"cdn{i}.example.test",
            )
        )
        ev.append(
            _ev(
                clock,
                EventType.NETWORK_CONNECT,
                300,
                pid=2001,
                ppid=1000,
                process_name="chrome.exe",
                destination_ip=f"198.51.100.{i + 100}",
                destination_port=443,
                domain=f"cdn{i}.example.test",
                protocol="tcp",
            )
        )
    return DemoScenario(
        "normal_browser",
        "Normal browser activity",
        "benign",
        "Signed browser, common ports, many CDN destinations",
        ev,
        baseline=True,
    )


def developer_workflow(clock: _Clock) -> DemoScenario:
    ev = [
        _proc(clock, 2100, 1, "code", "/usr/share/code/code", "code /home/demo/proj", "systemd", "Microsoft"),
        _proc(clock, 2101, 2100, "bash", "/usr/bin/bash", "bash -lc 'make test'", "code", "Distro"),
        _proc(clock, 2102, 2101, "git", "/usr/bin/git", "git status", "bash", "Distro"),
        _proc(clock, 2103, 2101, "python3", "/usr/bin/python3", "python3 -m pytest -q", "bash", "Distro"),
        _proc(clock, 2104, 2101, "make", "/usr/bin/make", "make test", "bash", "Distro"),
    ]
    for i in range(6):
        ev.append(
            _ev(
                clock,
                EventType.FILE_CREATE,
                250,
                pid=2103,
                ppid=2101,
                process_name="python3",
                file_path=f"/home/demo/proj/.pytest_cache/v/cache{i}",
            )
        )
    return DemoScenario(
        "developer_workflow",
        "Developer workflow",
        "benign",
        "Shells, compilers, git, test runner: LOLBin-like but routine",
        ev,
        baseline=True,
    )


def admin_backup_script(clock: _Clock) -> DemoScenario:
    ev = [
        _proc(
            clock,
            2200,
            1000,
            "taskeng.exe",
            r"C:\Windows\System32\taskeng.exe",
            "taskeng.exe",
            "services.exe",
            "Microsoft Windows",
        ),
        _proc(
            clock,
            2201,
            2200,
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"powershell.exe -ExecutionPolicy Bypass -File C:\Program Files\Admin\backup.ps1",
            "taskeng.exe",
            "Microsoft Windows",
        ),
        _ev(
            clock,
            EventType.FILE_CREATE,
            300,
            pid=2201,
            ppid=2200,
            process_name="powershell.exe",
            file_path=r"D:\Backups\nightly.zip",
        ),
    ]
    return DemoScenario(
        "admin_backup_script",
        "Admin backup script (false-positive check)",
        "benign",
        "Scheduled PowerShell backup: looks like a LOLBin use but is routine; baselined in LEARNING mode",
        ev,
        baseline=True,
    )


def office_powershell_chain(clock: _Clock) -> DemoScenario:
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    stage = r"C:\Users\demo\AppData\Local\Temp\stage2.exe"
    ev = [
        _proc(
            clock,
            3001,
            1000,
            "winword.exe",
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "winword.exe invoice.docm",
            "explorer.exe",
            "Microsoft Corporation",
        ),
        _ev(
            clock,
            EventType.FILE_CREATE,
            500,
            pid=3001,
            ppid=1000,
            process_name="winword.exe",
            file_path=r"C:\Users\demo\Downloads\invoice.docm",
        ),
        _proc(
            clock,
            3002,
            3001,
            "powershell.exe",
            ps,
            f"powershell.exe -NoP -W Hidden -Enc {_INERT_PS}",
            "winword.exe",
            "Microsoft Windows",
            800,
        ),
        _ev(
            clock,
            EventType.NETWORK_CONNECT,
            900,
            pid=3002,
            ppid=3001,
            process_name="powershell.exe",
            destination_ip="203.0.113.50",
            destination_port=8080,
            domain="payload-host.invalid",
            protocol="tcp",
        ),
        _ev(
            clock,
            EventType.FILE_CREATE,
            700,
            pid=3002,
            ppid=3001,
            process_name="powershell.exe",
            file_path=stage,
        ),
        _proc(clock, 3003, 3002, "stage2.exe", stage, "stage2.exe", "powershell.exe", None, 900),
        _ev(
            clock,
            EventType.DNS_QUERY,
            600,
            pid=3003,
            ppid=3002,
            process_name="stage2.exe",
            domain="xq7vkzt9plm2ncd.invalid",
        ),
        _ev(
            clock,
            EventType.NETWORK_CONNECT,
            500,
            pid=3003,
            ppid=3002,
            process_name="stage2.exe",
            destination_ip="203.0.113.50",
            destination_port=443,
            domain="xq7vkzt9plm2ncd.invalid",
            protocol="tcp",
        ),
    ]
    return DemoScenario(
        "office_powershell_chain",
        "Office -> PowerShell -> download -> executable -> DNS -> C2",
        "detect",
        "Word spawns hidden encoded PowerShell, which drops and runs an unsigned exe that beacons out",
        ev,
    )


def ransomware_like(clock: _Clock) -> DemoScenario:
    exe = r"C:\Users\demo\AppData\Local\Temp\locker_sim.exe"
    docs = r"C:\Users\demo\Documents"
    ev = [
        _proc(clock, 4001, 1000, "locker_sim.exe", exe, "locker_sim.exe --simulate", "explorer.exe", None),
        _proc(
            clock,
            4002,
            4001,
            "vssadmin.exe",
            r"C:\Windows\System32\vssadmin.exe",
            "vssadmin.exe delete shadows /all /quiet",
            "locker_sim.exe",
            "Microsoft Windows",
            300,
        ),
    ]
    for i in range(180):
        path = rf"{docs}\report{i:03d}.docx"
        ev.append(
            _ev(
                clock,
                EventType.FILE_MODIFY,
                30,
                pid=4001,
                ppid=1000,
                process_name="locker_sim.exe",
                file_path=path,
                raw_metadata={"entropy_before": 4.3, "entropy_after": 7.9},
            )
        )
        ev.append(
            _ev(
                clock,
                EventType.FILE_RENAME,
                30,
                pid=4001,
                ppid=1000,
                process_name="locker_sim.exe",
                file_path=path + ".locked",
                raw_metadata={"old_path": path},
            )
        )
    ev.append(
        _ev(
            clock,
            EventType.FILE_CREATE,
            200,
            pid=4001,
            ppid=1000,
            process_name="locker_sim.exe",
            file_path=rf"{docs}\README_RESTORE_FILES.txt",
        )
    )
    return DemoScenario(
        "ransomware_like",
        "Ransomware-like file activity (simulated)",
        "detect",
        "Unsigned Temp binary deletes shadow copies then rewrites + renames 180 documents with high entropy",
        ev,
    )


def persistence_creation(clock: _Clock) -> DemoScenario:
    upd = r"C:\Users\demo\AppData\Roaming\upd.exe"
    ev = [
        _proc(clock, 5001, 1000, "upd.exe", upd, "upd.exe", "explorer.exe", None),
        _ev(
            clock,
            EventType.REGISTRY_CREATE,
            500,
            pid=5001,
            ppid=1000,
            process_name="upd.exe",
            registry_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
            raw_metadata={"registry_value": upd},
        ),
        _proc(
            clock,
            5002,
            5001,
            "schtasks.exe",
            r"C:\Windows\System32\schtasks.exe",
            rf"schtasks /create /tn Updater /tr {upd} /sc onlogon",
            "upd.exe",
            "Microsoft Windows",
        ),
        _ev(
            clock,
            EventType.SCHEDULED_TASK,
            300,
            pid=5002,
            ppid=5001,
            process_name="schtasks.exe",
            command_line=rf"schtasks /create /tn Updater /tr {upd} /sc onlogon",
            raw_metadata={"task_name": "Updater", "task_action": upd},
        ),
        _ev(
            clock,
            EventType.PERSISTENCE,
            400,
            pid=5003,
            ppid=1,
            process_name="crontab",
            file_path="/etc/cron.d/updater",
            command_line="* * * * * root /tmp/.updater.sh",
            raw_metadata={"persistence_kind": "cron"},
        ),
        _ev(
            clock,
            EventType.FILE_MODIFY,
            400,
            pid=5004,
            ppid=1,
            process_name="sh",
            file_path="/home/demo/.ssh/authorized_keys",
            raw_metadata={"persistence_kind": "ssh_key"},
        ),
    ]
    return DemoScenario(
        "persistence_creation",
        "Persistence creation (Run key, scheduled task, cron, SSH key)",
        "detect",
        "Run key and scheduled task by an unsigned AppData binary, plus Linux cron/SSH key persistence",
        ev,
    )


def c2_beacon(clock: _Clock) -> DemoScenario:
    exe = r"C:\Users\demo\AppData\Roaming\svc.exe"
    ev = [_proc(clock, 6001, 1000, "svc.exe", exe, "svc.exe", "explorer.exe", None)]
    ev.append(
        _ev(
            clock,
            EventType.DNS_QUERY,
            500,
            pid=6001,
            ppid=1000,
            process_name="svc.exe",
            domain="kqzjxvbmwplrtnyd.invalid",
        )
    )
    for i in range(30):
        ev.append(
            _ev(
                clock,
                EventType.NETWORK_CONNECT,
                1500,
                pid=6001,
                ppid=1000,
                process_name="svc.exe",
                destination_ip="203.0.113.99",
                destination_port=4444 + (i % 4),
                domain="kqzjxvbmwplrtnyd.invalid",
                protocol="tcp",
            )
        )
    return DemoScenario(
        "c2_beacon",
        "C2-like network beaconing",
        "detect",
        "Unsigned AppData binary beacons to a rare TEST-NET IP (low-confidence test IOC) over unusual ports",
        ev,
    )


def known_ioc(clock: _Clock) -> DemoScenario:
    ev = [
        _proc(
            clock,
            7001,
            1000,
            "eicar_test.exe",
            r"C:\Users\demo\Downloads\eicar_test.exe",
            "eicar_test.exe",
            "explorer.exe",
            None,
            hash_sha256=EICAR_SHA256,
        ),
        _ev(
            clock,
            EventType.NETWORK_CONNECT,
            500,
            pid=7002,
            ppid=1000,
            process_name="updater.exe",
            destination_ip="192.0.2.66",
            destination_port=443,
            protocol="tcp",
        ),
    ]
    return DemoScenario(
        "known_ioc",
        "Known test IOC (EICAR hash + test C2 IP)",
        "known",
        "Deterministic EPP detection; short-circuits ML/RAG/LLM",
        ev,
    )


ALL_SCENARIOS = (
    normal_browser,
    developer_workflow,
    admin_backup_script,
    office_powershell_chain,
    ransomware_like,
    persistence_creation,
    c2_beacon,
    known_ioc,
)


def build_scenarios(start: datetime | None = None, names: list[str] | None = None) -> list[DemoScenario]:
    """Build the scenarios on one shared clock (events are strictly time ordered)."""
    t0 = start or (datetime.now(UTC) - timedelta(minutes=30))
    clock = _Clock(t0)
    out: list[DemoScenario] = []
    for fn in ALL_SCENARIOS:
        sc = fn(clock)
        clock.tick(20_000)  # idle gap between scenarios
        if names is None or sc.name in names:
            out.append(sc)
    return out


def scenario_digest(scenarios: list[DemoScenario]) -> str:
    h = hashlib.sha256()
    for s in scenarios:
        h.update(s.name.encode())
        h.update(str(len(s.events)).encode())
    return h.hexdigest()[:12]


def load_replay_scenarios(path: Path | str | None = None) -> list[DemoScenario]:
    """Load safe replay events from a JSONL file (default: ml/datasets/replay/demo_replay.jsonl)
    and group them into DemoScenarios by their scenario tag."""
    from centralium.agent.runtime import PROJECT_ROOT

    p = Path(path) if path is not None else PROJECT_ROOT / "ml" / "datasets" / "replay" / "demo_replay.jsonl"
    if not p.exists():
        raise FileNotFoundError(f"replay file not found: {p}")
    scenarios_map: dict[str, list[NormalizedEvent]] = {}
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = NormalizedEvent.model_validate_json(line)
            sc_name = str(ev.raw_metadata.get("scenario") or "replay")
            scenarios_map.setdefault(sc_name, []).append(ev)
    out: list[DemoScenario] = []
    for sc_name, evs in scenarios_map.items():
        is_mal = any(bool(e.raw_metadata.get("malicious")) for e in evs)
        out.append(
            DemoScenario(
                name=f"replay_{sc_name}",
                title=f"Replay: {sc_name.replace('_', ' ').title()}",
                expect="detect" if is_mal else "benign",
                description=f"Synthetic replay from {p.name} ({len(evs)} events)",
                events=evs,
                baseline=not is_mal,
            )
        )
    return out
