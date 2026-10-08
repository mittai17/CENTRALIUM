"""Unit tests for Phase 2F: Signed policy and rule distribution with atomic rollback."""

from __future__ import annotations

from pathlib import Path

from centralium.agent.self_protection.updates import generate_keypair
from centralium.fleet.distribution import (
    AgentBundleDeployer,
    BundleType,
    DistributionServer,
)


def test_bundle_packaging_and_server_publishing(tmp_path: Path):
    """Test packaging signed bundles with Ed25519 and publishing to distribution server."""
    priv_key, _pub_key = generate_keypair()
    server_dir = tmp_path / "fleet_bundles"

    audit_events: list[tuple[str, str, dict]] = []

    def audit_callback(actor: str, event_type: str, details: dict) -> None:
        audit_events.append((actor, event_type, details))

    server = DistributionServer(storage_dir=server_dir, audit_fn=audit_callback)

    policy_files = {
        "network_policy.json": b'{"block_tor": true, "max_conns_per_sec": 100}',
        "process_policy.json": b'{"block_unsigned_powershell": true}',
    }

    meta = server.publish_bundle(
        bundle_type=BundleType.POLICY,
        version="1.0.0",
        files=policy_files,
        signing_key=priv_key,
        target_groups=["linux-servers"],
    )

    assert meta.bundle_type == BundleType.POLICY
    assert meta.version == "1.0.0"
    assert meta.file_count == 2
    assert "network_policy.json" in meta.file_names
    assert len(audit_events) == 1
    assert audit_events[0][1] == "fleet.bundle_published"

    # Retrieve latest bundle
    found = server.get_latest_bundle(bundle_type=BundleType.POLICY, group="linux-servers")
    assert found is not None
    assert found[0].bundle_id == meta.bundle_id


def test_agent_deploy_success_and_file_application(tmp_path: Path):
    """Test agent successfully verifies Ed25519 signature and applies files."""
    priv_key, pub_key = generate_keypair()
    bundle_path = tmp_path / "bundle_v1.zip"
    target_dir = tmp_path / "agent_rules"
    target_dir.mkdir(parents=True)

    yara_files = {
        "rules/cobalt_strike.yar": b'rule CobaltStrike { strings: $a = "beacon.dll" condition: $a }',
        "rules/mimikatz.yar": b'rule Mimikatz { strings: $a = "sekurlsa" condition: $a }',
    }

    from centralium.fleet.distribution import package_bundle

    package_bundle(
        out_path=bundle_path,
        version="1.0.0",
        bundle_type=BundleType.YARA,
        files=yara_files,
        signing_key=priv_key,
    )

    agent_audits: list[tuple[str, str, dict]] = []

    def agent_audit(actor: str, event_type: str, details: dict) -> None:
        agent_audits.append((actor, event_type, details))

    deployer = AgentBundleDeployer(trusted_public_key=pub_key, audit_fn=agent_audit)
    result = deployer.deploy(
        bundle_path=bundle_path,
        target_dir=target_dir,
        current_version="0.0.0",
    )

    assert result.success is True
    assert result.rolled_back is False
    assert result.version == "1.0.0"

    # Verify target directory has the applied files
    file1 = target_dir / "rules" / "cobalt_strike.yar"
    file2 = target_dir / "rules" / "mimikatz.yar"
    assert file1.exists() and b"beacon.dll" in file1.read_bytes()
    assert file2.exists() and b"sekurlsa" in file2.read_bytes()

    audit_types = [a[1] for a in agent_audits]
    assert "agent.bundle_applied_successfully" in audit_types


def test_agent_deploy_signature_tamper_rejected(tmp_path: Path):
    """Test agent rejects tampered bundle or untrusted signature."""
    priv_key, _pub_key = generate_keypair()
    _other_priv, untrusted_pub = generate_keypair()

    bundle_path = tmp_path / "untrusted_bundle.zip"
    target_dir = tmp_path / "rules"
    target_dir.mkdir(parents=True)

    from centralium.fleet.distribution import package_bundle

    package_bundle(
        out_path=bundle_path,
        version="1.0.0",
        bundle_type=BundleType.SIGMA,
        files={"rules.yml": b"title: Suspicious Execution"},
        signing_key=priv_key,
    )

    deployer = AgentBundleDeployer(trusted_public_key=untrusted_pub)
    res = deployer.deploy(bundle_path=bundle_path, target_dir=target_dir, current_version="0.0.0")

    assert res.success is False
    assert res.rolled_back is False
    assert "verification rejected" in (res.error or "").lower()


def test_agent_deploy_validator_failure_aborts(tmp_path: Path):
    """Test custom content validator can reject invalid rules before they touch target dir."""
    priv_key, pub_key = generate_keypair()
    bundle_path = tmp_path / "invalid_content.zip"
    target_dir = tmp_path / "models"
    target_dir.mkdir(parents=True)
    existing_file = target_dir / "model.onnx"
    existing_file.write_bytes(b"original_model_v0")

    from centralium.fleet.distribution import package_bundle

    package_bundle(
        out_path=bundle_path,
        version="1.1.0",
        bundle_type=BundleType.ML_MODEL,
        files={"model.onnx": b"corrupt_weights_data"},
        signing_key=priv_key,
    )

    def strict_model_validator(staged_dir: Path) -> bool:
        content = (staged_dir / "model.onnx").read_bytes()
        return not content.startswith(b"corrupt")

    deployer = AgentBundleDeployer(trusted_public_key=pub_key)
    res = deployer.deploy(
        bundle_path=bundle_path,
        target_dir=target_dir,
        current_version="1.0.0",
        validator_fn=strict_model_validator,
    )

    assert res.success is False
    assert "validator rejected" in (res.error or "").lower()
    # Target directory remains intact
    assert existing_file.read_bytes() == b"original_model_v0"


def test_agent_deploy_atomic_rollback_on_apply_failure(tmp_path: Path, monkeypatch):
    """Test automatic rollback restores previous state if an error occurs during apply."""
    priv_key, pub_key = generate_keypair()
    bundle_path = tmp_path / "bundle_v2.zip"
    target_dir = tmp_path / "active_policies"
    target_dir.mkdir(parents=True)

    original_file = target_dir / "baseline.json"
    original_file.write_bytes(b"initial_policy_state_v1")

    from centralium.fleet.distribution import package_bundle

    package_bundle(
        out_path=bundle_path,
        version="2.0.0",
        bundle_type=BundleType.POLICY,
        files={"new_rule.json": b"new_policy_v2"},
        signing_key=priv_key,
    )

    import shutil

    original_copy2 = shutil.copy2
    call_count = 0

    def fail_after_first_copy(src, dst):
        nonlocal call_count
        call_count += 1
        if call_count >= 2:
            raise OSError("Simulated disk error during file copy")
        return original_copy2(src, dst)

    monkeypatch.setattr(shutil, "copy2", fail_after_first_copy)

    agent_audits: list[tuple[str, str, dict]] = []

    def audit_cb(actor: str, event_type: str, details: dict) -> None:
        agent_audits.append((actor, event_type, details))

    deployer = AgentBundleDeployer(trusted_public_key=pub_key, audit_fn=audit_cb)
    res = deployer.deploy(bundle_path=bundle_path, target_dir=target_dir, current_version="1.0.0")

    assert res.success is False
    assert res.rolled_back is True

    # Check that original files are restored intact
    assert original_file.exists()
    assert original_file.read_bytes() == b"initial_policy_state_v1"

    # Audit event recorded rollback
    audit_types = [a[1] for a in agent_audits]
    assert "agent.bundle_rollback_executed" in audit_types
