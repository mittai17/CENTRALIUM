"""Scenario definitions for the SYNTHETIC dataset.

Every value here is an author-chosen prior, not a measurement of real endpoints. Results on
data generated from these priors say nothing about real-world detection performance.
"""

from __future__ import annotations

from dataclasses import dataclass

BENIGN = "benign"


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str  # classifier class
    groups: int  # number of independent groups (sessions/hosts) to generate
    means: dict[str, float]  # overrides of benign feature means
    description: str

    @property
    def malicious(self) -> bool:
        return self.label != BENIGN


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("normal_process", BENIGN, 60, {}, "Routine desktop/server process activity"),
    Scenario(
        "benign_installer",
        BENIGN,
        24,
        {
            "file_create_rate": 220,
            "file_modify_rate": 120,
            "executable_created": 0.8,
            "unsigned_binary": 0.3,
            "privileged_context": 0.9,
            "child_count": 12,
            "net_conn_count": 14,
            "script_interpreter_use": 0.4,
            "write_burst": 0.35,
            "suspicious_dir_write": 0.2,
            "persistence_modification": 0.25,
            "cmdline_length": 160,
            "file_write_entropy": 6.2,
            "powershell_use": 0.15,
            "lolbin_use": 0.2,
        },
        "Package/installer activity: bursts of file creation, privileged, sometimes persistence",
    ),
    Scenario(
        "browser_activity",
        BENIGN,
        24,
        {
            "net_conn_count": 70,
            "net_unique_dest": 35,
            "net_dest_rarity": 0.4,
            "net_domain_rarity": 0.45,
            "net_conn_burst": 0.45,
            "file_create_rate": 25,
            "file_write_entropy": 6.6,
            "child_count": 9,
            "dns_entropy": 3.3,
            "net_port_rarity": 0.05,
        },
        "Browser with many destinations, cache writes, many child processes",
    ),
    Scenario(
        "developer_workflow",
        BENIGN,
        24,
        {
            "script_interpreter_use": 0.9,
            "child_count": 18,
            "file_create_rate": 60,
            "file_modify_rate": 80,
            "file_delete_rate": 12,
            "file_rename_rate": 6,
            "net_conn_count": 20,
            "net_dest_rarity": 0.3,
            "unsigned_binary": 0.5,
            "executable_created": 0.35,
            "powershell_use": 0.12,
            "parent_child_rarity": 0.25,
            "cmdline_length": 130,
            "cmdline_entropy": 3.8,
            "net_port_rarity": 0.25,
            "path_risk": 0.2,
            "unusual_parent_child": 0.15,
            "write_burst": 0.2,
            "lolbin_use": 0.1,
        },
        "Compilers, git, package managers, shells: overlaps heavily with malicious feature ranges",
    ),
    Scenario(
        "suspicious_powershell",
        "powershell_abuse",
        24,
        {
            "powershell_use": 0.97,
            "encoded_command": 0.85,
            "cmdline_length": 480,
            "cmdline_entropy": 5.4,
            "download_execute_sequence": 0.6,
            "unusual_parent_child": 0.55,
            "parent_child_rarity": 0.5,
            "process_rarity": 0.4,
            "net_conn_count": 8,
            "net_dest_rarity": 0.6,
            "script_interpreter_use": 0.9,
            "path_risk": 0.35,
        },
        "Encoded/obfuscated PowerShell with download-and-execute traits (inert strings only)",
    ),
    Scenario(
        "suspicious_shell",
        "suspicious_shell",
        24,
        {
            "script_interpreter_use": 0.97,
            "unusual_parent_child": 0.6,
            "parent_child_rarity": 0.55,
            "download_execute_sequence": 0.55,
            "path_risk": 0.6,
            "suspicious_dir_write": 0.5,
            "executable_created": 0.5,
            "privilege_change": 0.35,
            "net_dest_rarity": 0.5,
            "cmdline_entropy": 4.4,
            "cmdline_length": 220,
            "child_count": 7,
            "process_rarity": 0.35,
        },
        "Shell spawned by an unusual parent, fetching/executing from temp dirs",
    ),
    Scenario(
        "unusual_network",
        "network_anomaly",
        24,
        {
            "net_conn_count": 140,
            "net_unique_dest": 55,
            "net_dest_rarity": 0.8,
            "net_port_rarity": 0.7,
            "net_domain_rarity": 0.85,
            "dns_entropy": 4.1,
            "ip_reputation_risk": 0.5,
            "net_conn_burst": 0.65,
            "process_rarity": 0.3,
            "unsigned_binary": 0.5,
        },
        "Beacon/DGA-like destinations: rare ports/domains, high DNS entropy, bursts",
    ),
    Scenario(
        "mass_file_writes",
        "mass_file_write",
        24,
        {
            "file_create_rate": 350,
            "file_modify_rate": 500,
            "write_burst": 0.75,
            "file_write_entropy": 5.6,
            "suspicious_dir_write": 0.35,
            "file_delete_rate": 40,
            "process_rarity": 0.3,
            "unsigned_binary": 0.4,
        },
        "High-rate file writes without encryption/rename traits (wiper-staging/archiver-like)",
    ),
    Scenario(
        "ransomware_like",
        "ransomware",
        24,
        {
            "file_modify_rate": 700,
            "file_rename_rate": 420,
            "file_create_rate": 200,
            "file_ext_change_rate": 0.8,
            "ext_mutation": 0.85,
            "file_write_entropy": 7.6,
            "entropy_increase": 0.8,
            "write_burst": 0.9,
            "rename_burst": 0.85,
            "shadow_copy_activity": 0.55,
            "process_rarity": 0.5,
            "unsigned_binary": 0.7,
            "file_delete_rate": 60,
        },
        "Rapid rewrite+rename with extension mutation and entropy rise (simulated, no payload)",
    ),
    Scenario(
        "persistence_creation",
        "persistence",
        24,
        {
            "persistence_modification": 0.97,
            "privilege_change": 0.35,
            "path_risk": 0.5,
            "unsigned_binary": 0.55,
            "executable_created": 0.5,
            "process_rarity": 0.35,
            "executable_rarity": 0.45,
            "unusual_parent_child": 0.3,
            "script_interpreter_use": 0.4,
            "suspicious_dir_write": 0.3,
        },
        "Run keys / cron / systemd / scheduled-task creation by an uncommon binary",
    ),
    Scenario(
        "lolbin_abuse",
        "lolbin_abuse",
        24,
        {
            "lolbin_use": 0.97,
            "unusual_parent_child": 0.65,
            "parent_child_rarity": 0.6,
            "download_execute_sequence": 0.45,
            "net_dest_rarity": 0.45,
            "cmdline_length": 260,
            "cmdline_entropy": 4.6,
            "injection_indicator": 0.12,
            "net_conn_count": 6,
            "path_risk": 0.3,
            "script_interpreter_use": 0.4,
        },
        "Signed system utilities used for proxy-exec/download (certutil/mshta/rundll32 style)",
    ),
)

SCENARIO_BY_NAME = {s.name: s for s in SCENARIOS}
CLASSES: tuple[str, ...] = tuple(sorted({s.label for s in SCENARIOS}))
