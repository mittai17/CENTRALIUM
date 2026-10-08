"""Offline vulnerable package matcher (OSV format) and CIS-style system hardening checks.

Provides:
1. Offline OSV vulnerability matcher: compares installed packages against offline OSV JSON databases.
2. CIS-style hardening checks:
   - SSH server configuration (sshd_config) audit.
   - World-writable /etc files and directories.
   - Sudoers security audit (NOPASSWD: ALL).
   - Local firewall state audit (ufw, iptables, nftables, firewalld).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from centralium.agent.models import (
    AttackStage,
    Finding,
    FindingSource,
    Severity,
    new_id,
)

# ---------------------------------------------------------------------------
# OSV Vulnerable Package Matcher
# ---------------------------------------------------------------------------


class PackageRecord(BaseModel):
    """Installed software package record."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    ecosystem: str = "Debian"


class VulnerabilityMatch(BaseModel):
    """Match result against an OSV vulnerability record."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    package_name: str
    installed_version: str
    summary: str
    fixed_version: str | None = None
    severity: Severity = Severity.HIGH


def _parse_version(v_str: str) -> list[int]:
    """Parse numeric version components for simple semver comparison."""
    clean = re.sub(r"[^0-9.]", "", v_str)
    parts = clean.split(".")
    nums: list[int] = []
    for p in parts:
        if p.isdigit():
            nums.append(int(p))
    return nums or [0]


def _version_lt(v1: str, v2: str) -> bool:
    """Return True if version v1 < v2."""
    p1, p2 = _parse_version(v1), _parse_version(v2)
    max_len = max(len(p1), len(p2))
    p1 += [0] * (max_len - len(p1))
    p2 += [0] * (max_len - len(p2))
    return p1 < p2


def _version_lte(v1: str, v2: str) -> bool:
    """Return True if version v1 <= v2."""
    p1, p2 = _parse_version(v1), _parse_version(v2)
    max_len = max(len(p1), len(p2))
    p1 += [0] * (max_len - len(p1))
    p2 += [0] * (max_len - len(p2))
    return p1 <= p2


class OSVMatcher:
    """Matches package inventories against local OSV format JSON vulnerability databases."""

    def __init__(self, osv_records: list[dict[str, Any]] | None = None) -> None:
        self.records = osv_records or []

    def load_osv_dir(self, osv_dir: Path | str) -> int:
        """Load all OSV JSON files from a local directory."""
        dir_path = Path(osv_dir)
        count = 0
        if not dir_path.exists():
            return 0

        for file_path in dir_path.glob("*.json"):
            with contextlib.suppress(Exception):
                data = json.loads(file_path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "id" in data:
                    self.records.append(data)
                    count += 1
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "id" in item:
                            self.records.append(item)
                            count += 1
        return count

    def match_packages(self, packages: list[PackageRecord]) -> list[VulnerabilityMatch]:
        """Match installed packages against loaded OSV vulnerability records."""
        matches: list[VulnerabilityMatch] = []
        pkg_map = {p.name.lower(): p for p in packages}

        for record in self.records:
            vuln_id = record.get("id", "UNKNOWN")
            summary = record.get("summary", "")
            affected_list = record.get("affected", [])

            for aff in affected_list:
                pkg_info = aff.get("package", {})
                pkg_name = pkg_info.get("name", "").lower()

                if pkg_name not in pkg_map:
                    continue

                installed_pkg = pkg_map[pkg_name]
                inst_ver = installed_pkg.version

                # Check explicit versions list
                if "versions" in aff and inst_ver in aff["versions"]:
                    matches.append(
                        VulnerabilityMatch(
                            vulnerability_id=vuln_id,
                            package_name=installed_pkg.name,
                            installed_version=inst_ver,
                            summary=summary,
                        )
                    )
                    break

                # Check ranges
                ranges = aff.get("ranges", [])
                for r in ranges:
                    events = r.get("events", [])
                    intro = ""
                    fixed = None

                    for ev in events:
                        if "introduced" in ev:
                            intro = str(ev["introduced"])
                        if "fixed" in ev:
                            fixed = str(ev["fixed"])

                    # If installed is >= intro and < fixed
                    is_after_intro = not intro or intro == "0" or _version_lte(intro, inst_ver)
                    is_before_fixed = fixed is None or _version_lt(inst_ver, fixed)

                    if is_after_intro and is_before_fixed:
                        matches.append(
                            VulnerabilityMatch(
                                vulnerability_id=vuln_id,
                                package_name=installed_pkg.name,
                                installed_version=inst_ver,
                                summary=summary,
                                fixed_version=fixed,
                            )
                        )
                        break

        return matches


# ---------------------------------------------------------------------------
# CIS-Style Hardening Checks
# ---------------------------------------------------------------------------


class HardeningCheckResult(BaseModel):
    """Result of an individual posture / hardening check."""

    model_config = ConfigDict(extra="forbid")

    check_id: str
    title: str
    status: str = Field(description="PASS, WARN, or FAIL")
    severity: Severity = Severity.MEDIUM
    details: str
    remediation: str


class CISBenchmarkAuditor:
    """Executes minimal CIS-style hardening checks for Linux systems."""

    def audit_sshd(self, config_path: Path | str = "/etc/ssh/sshd_config") -> list[HardeningCheckResult]:
        """Audit SSH server configuration for CIS guidelines."""
        results: list[HardeningCheckResult] = []
        p = Path(config_path)

        if not p.exists():
            return results

        content = p.read_text(encoding="utf-8", errors="replace")
        lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]

        # 1. PermitRootLogin
        root_login = "yes"  # default on some legacy sshd
        for line in lines:
            if line.lower().startswith("permitrootlogin"):
                parts = line.split()
                if len(parts) >= 2:
                    root_login = parts[1].lower()

        if root_login in ("yes", "without-password"):
            results.append(
                HardeningCheckResult(
                    check_id="CIS_SSH_ROOT_LOGIN",
                    title="SSH Root Login Allowed",
                    status="FAIL" if root_login == "yes" else "WARN",
                    severity=Severity.HIGH if root_login == "yes" else Severity.MEDIUM,
                    details=f"PermitRootLogin is set to '{root_login}' in {config_path}",
                    remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
                )
            )
        else:
            results.append(
                HardeningCheckResult(
                    check_id="CIS_SSH_ROOT_LOGIN",
                    title="SSH Root Login Restricted",
                    status="PASS",
                    severity=Severity.INFO,
                    details="PermitRootLogin is disabled or restricted.",
                    remediation="",
                )
            )

        # 2. PasswordAuthentication
        pw_auth = "yes"
        for line in lines:
            if line.lower().startswith("passwordauthentication"):
                parts = line.split()
                if len(parts) >= 2:
                    pw_auth = parts[1].lower()

        if pw_auth == "yes":
            results.append(
                HardeningCheckResult(
                    check_id="CIS_SSH_PASSWORD_AUTH",
                    title="SSH Password Authentication Enabled",
                    status="WARN",
                    severity=Severity.MEDIUM,
                    details="Password authentication enabled; key-based authentication preferred.",
                    remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config.",
                )
            )
        else:
            results.append(
                HardeningCheckResult(
                    check_id="CIS_SSH_PASSWORD_AUTH",
                    title="SSH Password Authentication Disabled",
                    status="PASS",
                    severity=Severity.INFO,
                    details="Key-based authentication enforced.",
                    remediation="",
                )
            )

        return results

    def audit_world_writable_files(self, scan_dir: Path | str = "/etc") -> list[HardeningCheckResult]:
        """Audit for world-writable configuration files in /etc."""
        results: list[HardeningCheckResult] = []
        p = Path(scan_dir)

        if not p.exists():
            return results

        world_writable: list[str] = []
        for root, _, files in os.walk(p):
            for file_name in files:
                fpath = Path(root) / file_name
                with contextlib.suppress(Exception):
                    st = fpath.stat()
                    # Check other-write bit (0o002)
                    if bool(st.st_mode & 0o002):
                        world_writable.append(str(fpath))

        if world_writable:
            results.append(
                HardeningCheckResult(
                    check_id="CIS_ETC_WORLD_WRITABLE",
                    title="World-Writable Configuration Files Found",
                    status="FAIL",
                    severity=Severity.HIGH,
                    details=(
                        f"Found {len(world_writable)} world-writable file(s): {', '.join(world_writable[:5])}"
                    ),
                    remediation="Run 'chmod o-w <file>' on affected configuration files.",
                )
            )
        else:
            results.append(
                HardeningCheckResult(
                    check_id="CIS_ETC_WORLD_WRITABLE",
                    title="No World-Writable Files in /etc",
                    status="PASS",
                    severity=Severity.INFO,
                    details=f"All scanned files in {scan_dir} have safe permission masks.",
                    remediation="",
                )
            )

        return results

    def audit_sudoers(self, sudoers_path: Path | str = "/etc/sudoers") -> list[HardeningCheckResult]:
        """Audit sudoers file for unrestricted NOPASSWD: ALL entries."""
        results: list[HardeningCheckResult] = []
        p = Path(sudoers_path)

        if not p.exists():
            return results

        content = p.read_text(encoding="utf-8", errors="replace")
        dangerous_lines: list[str] = []

        for line in content.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            if "NOPASSWD" in clean and ("ALL" in clean or "*" in clean):
                dangerous_lines.append(clean)

        if dangerous_lines:
            results.append(
                HardeningCheckResult(
                    check_id="CIS_SUDOERS_NOPASSWD",
                    title="Unrestricted NOPASSWD Sudo Rule Configured",
                    status="FAIL",
                    severity=Severity.HIGH,
                    details=f"Found dangerous sudo rule(s): {'; '.join(dangerous_lines[:3])}",
                    remediation="Require authentication for administrative privilege escalation.",
                )
            )
        else:
            results.append(
                HardeningCheckResult(
                    check_id="CIS_SUDOERS_NOPASSWD",
                    title="Sudo Authentication Enforced",
                    status="PASS",
                    severity=Severity.INFO,
                    details="No unrestricted NOPASSWD wildcard rules detected.",
                    remediation="",
                )
            )

        return results

    def audit_firewall_state(self) -> HardeningCheckResult:
        """Check if any host-level firewall (ufw, iptables, nftables, firewalld) is present."""
        firewalls = ("ufw", "iptables", "nft", "firewall-cmd")
        found = [fw for fw in firewalls if shutil.which(fw)]

        if not found:
            return HardeningCheckResult(
                check_id="CIS_FIREWALL_ACTIVE",
                title="No Host Firewall Tool Detected",
                status="FAIL",
                severity=Severity.HIGH,
                details="None of ufw, iptables, nftables, or firewalld was found in system PATH.",
                remediation="Install and enable an active host firewall (e.g. ufw or nftables).",
            )

        return HardeningCheckResult(
            check_id="CIS_FIREWALL_ACTIVE",
            title="Host Firewall Tool Present",
            status="PASS",
            severity=Severity.INFO,
            details=f"Firewall management tool(s) installed: {', '.join(found)}",
            remediation="",
        )

    def audit_all(
        self,
        etc_dir: Path | str = "/etc",
        sshd_config: Path | str | None = None,
        sudoers_path: Path | str | None = None,
    ) -> list[HardeningCheckResult]:
        """Run all hardening checks and return list of check results."""
        results: list[HardeningCheckResult] = []
        sshd_file = Path(sshd_config or Path(etc_dir) / "ssh" / "sshd_config")
        sudoers_file = Path(sudoers_path or Path(etc_dir) / "sudoers")

        results.extend(self.audit_sshd(sshd_file))
        results.extend(self.audit_world_writable_files(etc_dir))
        results.extend(self.audit_sudoers(sudoers_file))
        results.append(self.audit_firewall_state())
        return results

    def to_findings(self, results: list[HardeningCheckResult]) -> list[Finding]:
        """Convert non-passing hardening check results into standard Findings."""
        findings: list[Finding] = []
        for r in results:
            if r.status in ("WARN", "FAIL"):
                score = 80.0 if r.status == "FAIL" else 50.0
                findings.append(
                    Finding(
                        finding_id=new_id(),
                        event_id=f"posture-{r.check_id.lower()}",
                        timestamp=datetime.now(UTC),
                        source=FindingSource.POSTURE,
                        rule_id=r.check_id,
                        title=f"Posture Defect: {r.title}",
                        severity=r.severity,
                        score=score,
                        confidence=0.95,
                        mitre_techniques=["T1082"],
                        attack_stage=AttackStage.DEFENSE_EVASION,
                        details={
                            "details": r.details,
                            "remediation": r.remediation,
                            "status": r.status,
                        },
                    )
                )
        return findings


__all__ = [
    "CISBenchmarkAuditor",
    "HardeningCheckResult",
    "OSVMatcher",
    "PackageRecord",
    "VulnerabilityMatch",
]
