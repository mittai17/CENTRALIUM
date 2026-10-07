"""Transparent self-protection: integrity, signed updates, watchdog, tamper events."""

from centralium.agent.self_protection.integrity import (
    IntegrityReport,
    build_manifest,
    check_dir_permissions,
    sha256_file,
    verify_manifest,
)
from centralium.agent.self_protection.monitor import SelfProtectionMonitor, SelfProtectionSettings, sd_notify
from centralium.agent.self_protection.updates import (
    HAVE_CRYPTO,
    UpdateRejected,
    VerifiedBundle,
    create_bundle,
    extract_verified,
    generate_keypair,
    verify_bundle,
)

__all__ = [
    "HAVE_CRYPTO",
    "IntegrityReport",
    "SelfProtectionMonitor",
    "SelfProtectionSettings",
    "UpdateRejected",
    "VerifiedBundle",
    "build_manifest",
    "check_dir_permissions",
    "create_bundle",
    "extract_verified",
    "generate_keypair",
    "sd_notify",
    "sha256_file",
    "verify_bundle",
    "verify_manifest",
]
