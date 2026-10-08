"""Process-injection and memory detection engine.

Detects:
1. W+X memory mappings (mprotect PROT_READ|PROT_WRITE|PROT_EXEC, VirtualAlloc PAGE_EXECUTE_READWRITE).
2. memfd_create execution (fileless ELF execution via anonymous memory descriptors).
3. ptrace injection (PTRACE_POKETEXT, PTRACE_ATTACH, cross-process memory manipulation).
4. Reflective loader indicators (unbacked memory code execution, ReflectiveLoader exports).
5. CreateRemoteThread and Process Hollowing (Sysmon 8/25, CREATE_SUSPENDED, NtUnmapViewOfSection).

Mapped to MITRE ATT&CK:
- T1055: Process Injection
- T1055.008: Process Injection: Ptrace System Calls
- T1055.012: Process Injection: Process Hollowing
- T1620: Reflective Code Loading
- T1027.010: Command Obfuscation: Fileless Execution
"""

from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import (
    AttackStage,
    EventType,
    Finding,
    FindingSource,
    NormalizedEvent,
    Severity,
    new_id,
)

# --------------------------------------------------------------------------- regex patterns
_MEMFD_PATH_RE = re.compile(r"(/memfd:[^\s]+|/proc/\d+/fd/\d+|\[memfd:[^\]]+\]|\bmemfd_create\b)", re.I)
_PTRACE_CMD_RE = re.compile(
    r"\b(ptrace_attach|ptrace_poketext|ptrace_pokedata|inject_ptrace|linux-injector)\b",
    re.I,
)
_REFLECTIVE_CMD_RE = re.compile(
    r"\b(reflectiveloader|loadremotelibraryr|reflective_dll|memexec|donut(\.exe)?)\b",
    re.I,
)
_HOLLOWING_CMD_RE = re.compile(
    r"\b(hollow(ing)?|processhollowing|unmapviewofsection|runpe)\b",
    re.I,
)

_LEGIT_DEBUGGERS = frozenset({"gdb", "lldb", "strace", "valgrind", "ltrace", "perf", "bpftrace"})


class ProcessInjectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enable_wx_detection: bool = True
    enable_memfd_detection: bool = True
    enable_ptrace_detection: bool = True
    enable_reflective_detection: bool = True
    enable_remote_thread_detection: bool = True
    enable_hollowing_detection: bool = True
    allowed_debuggers: list[str] = Field(default_factory=lambda: list(_LEGIT_DEBUGGERS))


class ProcessInjectionDetector:
    """Evaluates telemetry events and procfs mappings for process-injection indicators."""

    def __init__(self, config: ProcessInjectionConfig | None = None) -> None:
        self.config = config or ProcessInjectionConfig()
        self._allowed_debuggers = {d.lower() for d in self.config.allowed_debuggers}

    def evaluate(self, event: NormalizedEvent) -> list[Finding]:
        findings: list[Finding] = []

        cmd = event.command_line or ""
        pname = (event.process_name or "").lower()
        epath = (event.executable_path or "").lower()
        fpath = (event.file_path or "").lower()
        meta: dict[str, Any] = event.raw_metadata or {}

        # -------------------------------------------------------------------
        # 1. W+X memory mappings
        # -------------------------------------------------------------------
        if self.config.enable_wx_detection:
            prot = str(meta.get("protection") or meta.get("prot") or meta.get("permissions") or "").lower()
            is_wx = (
                "rwx" in prot
                or "execute_readwrite" in prot
                or meta.get("prot") in (7, "7", "0x40", 0x40)
                or meta.get("protection") in ("PAGE_EXECUTE_READWRITE", 0x40)
            )
            is_memory_alloc = event.event_type in (
                EventType.PROCESS_INJECT,
                EventType.MODULE_LOAD,
                EventType.OTHER,
            ) or bool(meta.get("syscall") in ("mprotect", "mmap", "VirtualAlloc", "VirtualProtect"))

            if is_wx and is_memory_alloc:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_INJ_WX_MAPPING",
                        title=f"Writable and Executable (W+X) Memory Mapping Allocated: {pname or cmd[:80]}",
                        severity=Severity.HIGH,
                        score=85.0,
                        confidence=0.90,
                        mitre_techniques=["T1055"],
                        attack_stage=AttackStage.EXECUTION,
                        details={
                            "process_name": pname,
                            "command_line": cmd[:500],
                            "protection": prot or meta.get("protection"),
                            "target_pid": meta.get("target_pid") or event.pid,
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 2. memfd_create fileless execution (T1027.010)
        # -------------------------------------------------------------------
        if self.config.enable_memfd_detection:
            memfd_matched = (
                _MEMFD_PATH_RE.search(cmd)
                or _MEMFD_PATH_RE.search(epath)
                or _MEMFD_PATH_RE.search(fpath)
                or meta.get("syscall") == "memfd_create"
                or meta.get("memfd") is True
            )
            if memfd_matched and event.event_type in (
                EventType.PROCESS_START,
                EventType.FILE_CREATE,
                EventType.MODULE_LOAD,
            ):
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_INJ_MEMFD_EXEC",
                        title=f"Fileless Memfd Execution Detected: {epath or cmd[:80]}",
                        severity=Severity.HIGH,
                        score=90.0,
                        confidence=0.95,
                        mitre_techniques=["T1027.010", "T1055"],
                        attack_stage=AttackStage.EXECUTION,
                        details={
                            "command_line": cmd[:500],
                            "executable_path": epath,
                            "file_path": fpath,
                            "process_name": pname,
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 3. ptrace injection (T1055.008)
        # -------------------------------------------------------------------
        if self.config.enable_ptrace_detection:
            req = str(meta.get("ptrace_request") or meta.get("request") or "").upper()
            ptrace_syscall = meta.get("syscall") == "ptrace"
            ptrace_req_suspicious = any(
                p in req for p in ("PTRACE_POKETEXT", "PTRACE_POKEDATA", "PTRACE_ATTACH", "PTRACE_SEIZE")
            )
            cmd_ptrace = bool(_PTRACE_CMD_RE.search(cmd))

            target_pid = meta.get("target_pid") or meta.get("tracee_pid")
            is_foreign_process = target_pid is not None and target_pid != event.pid

            if (
                (ptrace_syscall and (ptrace_req_suspicious or is_foreign_process)) or cmd_ptrace
            ) and pname not in self._allowed_debuggers:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_INJ_PTRACE",
                        title=f"Suspicious Ptrace Memory Injection or Attach: {pname or cmd[:80]}",
                        severity=Severity.HIGH,
                        score=85.0,
                        confidence=0.90,
                        mitre_techniques=["T1055.008"],
                        attack_stage=AttackStage.PRIVILEGE_ESCALATION,
                        details={
                            "process_name": pname,
                            "command_line": cmd[:500],
                            "target_pid": target_pid,
                            "ptrace_request": req,
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 4. Reflective code loader (T1620, T1055.001)
        # -------------------------------------------------------------------
        if self.config.enable_reflective_detection:
            is_reflective_cmd = bool(_REFLECTIVE_CMD_RE.search(cmd))
            is_unbacked_module = event.event_type == EventType.MODULE_LOAD and (
                meta.get("unbacked") is True or meta.get("is_in_memory") is True
            )
            if is_reflective_cmd or is_unbacked_module:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_INJ_REFLECTIVE_LOAD",
                        title=f"Reflective Code / DLL Loading Indicator: {pname or cmd[:80]}",
                        severity=Severity.HIGH,
                        score=85.0,
                        confidence=0.90,
                        mitre_techniques=["T1620", "T1055.001"],
                        attack_stage=AttackStage.DEFENSE_EVASION,
                        details={
                            "command_line": cmd[:500],
                            "process_name": pname,
                            "unbacked": meta.get("unbacked", False),
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 5. CreateRemoteThread / Cross-process thread injection (T1055)
        # -------------------------------------------------------------------
        if self.config.enable_remote_thread_detection:
            target_pid = meta.get("target_pid") or meta.get("target_process_id")
            is_cross_proc = target_pid is not None and target_pid != event.pid
            is_remote_thread = (
                meta.get("event_id") == 8  # Sysmon Event ID 8: CreateRemoteThread
                or meta.get("action") == "CreateRemoteThread"
                or meta.get("api") in ("CreateRemoteThread", "NtCreateThreadEx")
                or (event.event_type == EventType.PROCESS_INJECT and is_cross_proc)
            )

            if is_remote_thread and is_cross_proc:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_INJ_REMOTE_THREAD",
                        title=f"Cross-Process CreateRemoteThread Injection: {pname} -> PID {target_pid}",
                        severity=Severity.HIGH,
                        score=90.0,
                        confidence=0.95,
                        mitre_techniques=["T1055"],
                        attack_stage=AttackStage.PRIVILEGE_ESCALATION,
                        details={
                            "source_pid": event.pid,
                            "target_pid": target_pid,
                            "process_name": pname,
                            "start_address": meta.get("start_address"),
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 6. Process Hollowing indicators (T1055.012)
        # -------------------------------------------------------------------
        if self.config.enable_hollowing_detection:
            hollowing_cmd = bool(_HOLLOWING_CMD_RE.search(cmd))
            sysmon_tamper = meta.get("event_id") == 25  # Sysmon 25: ProcessTampering
            is_hollow_sequence = (
                meta.get("action") in ("NtUnmapViewOfSection", "ProcessHollowing")
                or meta.get("is_hollowing") is True
                or (meta.get("created_suspended") is True and meta.get("modified_pe") is True)
            )

            if hollowing_cmd or sysmon_tamper or is_hollow_sequence:
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        source=FindingSource.BEHAVIOR,
                        rule_id="BEH_INJ_PROCESS_HOLLOWING",
                        title=f"Process Hollowing / Image Tampering Detected: {pname or cmd[:80]}",
                        severity=Severity.CRITICAL,
                        score=95.0,
                        confidence=0.95,
                        mitre_techniques=["T1055.012"],
                        attack_stage=AttackStage.DEFENSE_EVASION,
                        details={
                            "process_name": pname,
                            "command_line": cmd[:500],
                            "target_pid": meta.get("target_pid"),
                            "action": meta.get("action") or "hollowing",
                        },
                    )
                )

        return findings

    def inspect_proc_maps(self, pid: int, proc_root: Path | str = "/proc") -> list[Finding]:
        """Safely inspects /proc/<pid>/maps for suspicious W+X or anonymous executable mappings."""
        findings: list[Finding] = []
        maps_file = Path(proc_root) / str(pid) / "maps"

        if not maps_file.exists():
            return findings

        with contextlib.suppress(Exception):
            lines = maps_file.read_text(encoding="utf-8", errors="replace").splitlines()[:1000]
            for line in lines:
                parts = line.split()
                if len(parts) < 2:
                    continue
                perms = parts[1]
                path_desc = parts[5] if len(parts) > 5 else "[anon]"

                # W+X permissions: 'rwx' or 'rwxp'
                if "rwx" in perms:
                    findings.append(
                        Finding(
                            finding_id=new_id(),
                            event_id=f"map-scan-{pid}",
                            timestamp=datetime.now(UTC),
                            source=FindingSource.BEHAVIOR,
                            rule_id="BEH_INJ_WX_MAPPING",
                            title=f"W+X Memory Region Found in PID {pid}: {path_desc}",
                            severity=Severity.HIGH,
                            score=85.0,
                            confidence=0.90,
                            mitre_techniques=["T1055"],
                            attack_stage=AttackStage.EXECUTION,
                            details={"pid": pid, "permissions": perms, "mapping": line},
                        )
                    )
                    break  # Avoid flood of findings per process

                # memfd region
                if "memfd" in path_desc and "x" in perms:
                    findings.append(
                        Finding(
                            finding_id=new_id(),
                            event_id=f"map-scan-{pid}",
                            timestamp=datetime.now(UTC),
                            source=FindingSource.BEHAVIOR,
                            rule_id="BEH_INJ_MEMFD_EXEC",
                            title=f"Executable Memfd Region in PID {pid}: {path_desc}",
                            severity=Severity.HIGH,
                            score=90.0,
                            confidence=0.95,
                            mitre_techniques=["T1027.010", "T1055"],
                            attack_stage=AttackStage.EXECUTION,
                            details={"pid": pid, "mapping": line},
                        )
                    )
                    break

        return findings


__all__ = [
    "ProcessInjectionConfig",
    "ProcessInjectionDetector",
]
