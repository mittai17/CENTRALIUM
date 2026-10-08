"""Unit tests for offline OSV vulnerability matching and CIS hardening auditor."""

from __future__ import annotations

import json
from pathlib import Path

from centralium.agent.posture.hardening import (
    CISBenchmarkAuditor,
    OSVMatcher,
    PackageRecord,
)


def test_osv_vulnerability_matcher(tmp_path: Path):
    osv_data = {
        "id": "GHSA-1234-5678-9012",
        "summary": "Remote code execution in vulnerable-lib",
        "affected": [
            {
                "package": {"name": "vulnerable-lib", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}],
                    }
                ],
            }
        ],
    }

    osv_file = tmp_path / "osv_test.json"
    osv_file.write_text(json.dumps(osv_data))

    matcher = OSVMatcher()
    count = matcher.load_osv_dir(tmp_path)
    assert count == 1

    # Test vulnerable package version (1.2.0 is >= 1.0.0 and < 1.4.2)
    packages = [
        PackageRecord(name="vulnerable-lib", version="1.2.0", ecosystem="PyPI"),
        PackageRecord(name="safe-lib", version="2.0.0", ecosystem="PyPI"),
    ]
    matches = matcher.match_packages(packages)
    assert len(matches) == 1
    assert matches[0].vulnerability_id == "GHSA-1234-5678-9012"
    assert matches[0].package_name == "vulnerable-lib"
    assert matches[0].fixed_version == "1.4.2"

    # Test patched package version (1.5.0 >= 1.4.2)
    patched_packages = [PackageRecord(name="vulnerable-lib", version="1.5.0", ecosystem="PyPI")]
    assert len(matcher.match_packages(patched_packages)) == 0


def test_cis_sshd_audit(tmp_path: Path):
    auditor = CISBenchmarkAuditor()

    # Insecure sshd config
    insecure_sshd = tmp_path / "sshd_insecure"
    insecure_sshd.write_text("PermitRootLogin yes\nPasswordAuthentication yes\n")
    results = auditor.audit_sshd(insecure_sshd)
    assert any(r.check_id == "CIS_SSH_ROOT_LOGIN" and r.status == "FAIL" for r in results)
    assert any(r.check_id == "CIS_SSH_PASSWORD_AUTH" and r.status == "WARN" for r in results)

    # Secure sshd config
    secure_sshd = tmp_path / "sshd_secure"
    secure_sshd.write_text("PermitRootLogin no\nPasswordAuthentication no\n")
    results_sec = auditor.audit_sshd(secure_sshd)
    assert all(r.status == "PASS" for r in results_sec)


def test_cis_world_writable_and_sudoers_audit(tmp_path: Path):
    auditor = CISBenchmarkAuditor()

    # Mock /etc structure
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    conf_file = etc_dir / "app.conf"
    conf_file.write_text("setting=value")
    conf_file.chmod(0o666)  # World-writable (other write bit set)

    ww_results = auditor.audit_world_writable_files(etc_dir)
    assert any(r.check_id == "CIS_ETC_WORLD_WRITABLE" and r.status == "FAIL" for r in ww_results)

    # Sudoers audit
    sudoers_file = etc_dir / "sudoers"
    sudoers_file.write_text("%admin ALL=(ALL) NOPASSWD: ALL\n")
    sudo_results = auditor.audit_sudoers(sudoers_file)
    assert any(r.check_id == "CIS_SUDOERS_NOPASSWD" and r.status == "FAIL" for r in sudo_results)

    # Convert results to findings
    findings = auditor.to_findings(ww_results + sudo_results)
    assert len(findings) == 2
    assert all(f.source.value == "posture" for f in findings)
