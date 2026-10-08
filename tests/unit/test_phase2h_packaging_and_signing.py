"""Unit tests for Phase 2H: Packaging recipes and Ed25519 release manifest signing."""

import json
from pathlib import Path

from scripts.sign_manifest import (
    build_manifest,
    generate_keypair,
    load_private_key,
    sign_manifest,
    verify_manifest,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_packaging_debian_recipe():
    control = PROJECT_ROOT / "packaging" / "debian" / "control"
    assert control.exists()
    content = control.read_text(encoding="utf-8")
    assert "Package: centralium-agent" in content
    assert "Maintainer:" in content
    assert "Depends:" in content

    postinst = PROJECT_ROOT / "packaging" / "debian" / "postinst"
    assert postinst.exists()
    post_txt = postinst.read_text(encoding="utf-8")
    assert "useradd" in post_txt
    assert "systemctl" in post_txt

    prerm = PROJECT_ROOT / "packaging" / "debian" / "prerm"
    assert prerm.exists()


def test_packaging_rpm_recipe():
    spec = PROJECT_ROOT / "packaging" / "rpm" / "centralium.spec"
    assert spec.exists()
    content = spec.read_text(encoding="utf-8")
    assert "Name:           centralium-agent" in content
    assert "%systemd_post" in content
    assert "%systemd_preun" in content
    assert "%files" in content


def test_hardened_systemd_service_unit():
    service_file = PROJECT_ROOT / "packaging" / "systemd" / "centralium.service"
    assert service_file.exists()
    content = service_file.read_text(encoding="utf-8")

    # Assert required systemd sandboxing directives
    assert "ProtectSystem=strict" in content
    assert "ProtectHome=read-only" in content or "ProtectHome=yes" in content
    assert "NoNewPrivileges=yes" in content
    assert "PrivateTmp=yes" in content
    assert "CapabilityBoundingSet=" in content
    assert "RestrictSUIDSGID=yes" in content
    assert "MemoryDenyWriteExecute=yes" in content
    assert "RestrictAddressFamilies=" in content
    assert "SystemCallArchitectures=native" in content


def test_sign_manifest_lifecycle(tmp_path: Path):
    # 1. Create dummy build artifacts
    pkg1 = tmp_path / "centralium-agent_0.1.0_amd64.deb"
    pkg1.write_bytes(b"Simulated deb package content 12345")
    pkg2 = tmp_path / "centralium-agent-0.1.0-1.x86_64.rpm"
    pkg2.write_bytes(b"Simulated rpm package content 67890")

    # 2. Key generation
    priv, pub = generate_keypair()
    priv_file = tmp_path / "release.key"
    priv_file.write_bytes(priv.private_bytes_raw().hex().encode("ascii"))
    loaded_priv = load_private_key(priv_file)

    # 3. Build & sign manifest
    manifest_raw = build_manifest([pkg1, pkg2], version="0.1.0")
    signed_manifest = sign_manifest(manifest_raw, loaded_priv)

    assert "signature" in signed_manifest
    assert "public_key" in signed_manifest
    assert len(signed_manifest["artifacts"]) == 2

    # 4. Verify valid manifest
    assert verify_manifest(signed_manifest, expected_public_key=pub, verify_files_on_disk=True) is True

    # 5. Tampered artifact hash fails verification
    tampered_manifest = json.loads(json.dumps(signed_manifest))
    tampered_manifest["artifacts"][0]["sha256"] = "0" * 64
    assert verify_manifest(tampered_manifest, expected_public_key=pub) is False

    # 6. Tampered signature fails verification
    tampered_sig = json.loads(json.dumps(signed_manifest))
    tampered_sig["signature"] = "1" * 128
    assert verify_manifest(tampered_sig, expected_public_key=pub) is False

    # 7. Tampered payload on disk fails verification when verify_files_on_disk=True
    pkg1.write_bytes(b"Altered package content after signing")
    assert verify_manifest(signed_manifest, expected_public_key=pub, verify_files_on_disk=True) is False
