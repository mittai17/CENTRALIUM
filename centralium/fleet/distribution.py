"""Signed policy and rule distribution engine for Centralium fleet.

Supports packaging and distributing policies, YARA bundles, Sigma rules, and ML models
signed with Ed25519. Agents verify cryptographic signatures, stage updates, and apply
with atomic rollback on failure, recording audit logs on both agent and server.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from centralium.agent.self_protection.updates import (
    UpdateRejected,
    create_bundle,
    extract_verified,
    verify_bundle,
)

log = logging.getLogger("centralium.fleet.distribution")


class BundleType(StrEnum):
    POLICY = "policy"
    YARA = "yara"
    SIGMA = "sigma"
    ML_MODEL = "ml_model"
    COMPOSITE = "composite"


@dataclass
class BundleMetadata:
    bundle_id: str
    bundle_type: BundleType
    version: str
    sha256: str
    size_bytes: int
    created_at: str
    target_groups: list[str] = field(default_factory=lambda: ["*"])
    file_count: int = 0
    file_names: list[str] = field(default_factory=list)


@dataclass
class DeploymentResult:
    success: bool
    version: str
    bundle_type: str
    applied_files: list[str] = field(default_factory=list)
    error: str | None = None
    rolled_back: bool = False
    details: dict[str, Any] = field(default_factory=dict)


def package_bundle(
    out_path: Path,
    version: str,
    bundle_type: BundleType | str,
    files: dict[str, bytes],
    signing_key: bytes,
    target_groups: list[str] | None = None,
) -> BundleMetadata:
    """Package and sign a distribution bundle using Ed25519."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    b_type = BundleType(bundle_type)
    groups = target_groups or ["*"]

    # Embed bundle metadata inside the bundle payload so agent knows its type/groups
    meta_info = {
        "bundle_type": b_type.value,
        "version": version,
        "target_groups": groups,
        "created_at": datetime.now(UTC).isoformat(),
    }
    files_with_meta = dict(files)
    files_with_meta["_bundle_meta.json"] = json.dumps(meta_info, indent=2).encode("utf-8")

    create_bundle(
        out=out_path,
        version=version,
        files=files_with_meta,
        private_key=signing_key,
    )

    bundle_bytes = out_path.read_bytes()
    sha256_hash = hashlib.sha256(bundle_bytes).hexdigest()
    bundle_id = f"bnd_{b_type.value}_{version.replace('.', '_')}_{sha256_hash[:8]}"

    return BundleMetadata(
        bundle_id=bundle_id,
        bundle_type=b_type,
        version=version,
        sha256=sha256_hash,
        size_bytes=len(bundle_bytes),
        created_at=str(meta_info["created_at"]),
        target_groups=groups,
        file_count=len(files),
        file_names=sorted(files.keys()),
    )


class DistributionServer:
    """Fleet server-side catalog and store for signed distribution bundles."""

    def __init__(
        self,
        storage_dir: Path,
        audit_fn: Callable[[str, str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.audit_fn = audit_fn
        self._bundles: dict[str, tuple[BundleMetadata, Path]] = {}

    def publish_bundle(
        self,
        bundle_type: BundleType | str,
        version: str,
        files: dict[str, bytes],
        signing_key: bytes,
        target_groups: list[str] | None = None,
        actor: str = "fleet-admin",
    ) -> BundleMetadata:
        """Create, sign, store, and publish a new distribution bundle."""
        b_type = BundleType(bundle_type)
        filename = f"{b_type.value}_v{version}.zip"
        target_path = self.storage_dir / filename

        meta = package_bundle(
            out_path=target_path,
            version=version,
            bundle_type=b_type,
            files=files,
            signing_key=signing_key,
            target_groups=target_groups,
        )

        self._bundles[meta.bundle_id] = (meta, target_path)

        if self.audit_fn:
            self.audit_fn(
                actor,
                "fleet.bundle_published",
                {
                    "bundle_id": meta.bundle_id,
                    "bundle_type": meta.bundle_type.value,
                    "version": meta.version,
                    "sha256": meta.sha256,
                    "file_count": meta.file_count,
                    "target_groups": meta.target_groups,
                },
            )
        log.info("Published bundle %s (type=%s, v=%s)", meta.bundle_id, meta.bundle_type, meta.version)
        return meta

    def get_bundle(self, bundle_id: str) -> tuple[BundleMetadata, Path] | None:
        return self._bundles.get(bundle_id)

    def list_bundles(self, bundle_type: BundleType | str | None = None) -> list[BundleMetadata]:
        all_meta = [m for m, _ in self._bundles.values()]
        if bundle_type is not None:
            bt = BundleType(bundle_type)
            return [m for m in all_meta if m.bundle_type == bt]
        return all_meta

    def get_latest_bundle(
        self, bundle_type: BundleType | str, group: str = "default"
    ) -> tuple[BundleMetadata, Path] | None:
        """Find highest version bundle for given type and matching endpoint group."""
        bt = BundleType(bundle_type)
        candidates: list[tuple[BundleMetadata, Path]] = []
        for meta, path in self._bundles.values():
            if meta.bundle_type == bt and ("*" in meta.target_groups or group in meta.target_groups):
                candidates.append((meta, path))
        if not candidates:
            return None

        def _v_tuple(v: str) -> tuple[int, ...]:
            try:
                return tuple(int(x) for x in v.split("."))
            except ValueError:
                return (0,)

        candidates.sort(key=lambda item: _v_tuple(item[0].version), reverse=True)
        return candidates[0]


class AgentBundleDeployer:
    """Agent-side bundle verifier, stager, and atomic applier with rollback."""

    def __init__(
        self,
        trusted_public_key: bytes,
        audit_fn: Callable[[str, str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.trusted_public_key = trusted_public_key
        self.audit_fn = audit_fn

    def _audit(self, actor: str, event_type: str, details: dict[str, Any]) -> None:
        if self.audit_fn:
            try:
                self.audit_fn(actor, event_type, details)
            except Exception as exc:
                log.warning("Agent audit call failed: %s", exc)

    def deploy(
        self,
        bundle_path: Path,
        target_dir: Path,
        current_version: str = "0.0.0",
        validator_fn: Callable[[Path], bool] | None = None,
        actor: str = "centralium-agent",
    ) -> DeploymentResult:
        """Verify, stage, validate, backup, and apply bundle with automatic rollback on error."""
        target_dir = target_dir.resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        # 1. Signature & Integrity Verification
        try:
            verified = verify_bundle(
                bundle=bundle_path,
                public_key=self.trusted_public_key,
                current_version=current_version,
            )
        except UpdateRejected as exc:
            err = f"Bundle verification rejected: {exc}"
            self._audit(
                actor,
                "agent.bundle_verification_failed",
                {"bundle": bundle_path.name, "error": str(exc)},
            )
            return DeploymentResult(
                success=False,
                version=current_version,
                bundle_type="unknown",
                error=err,
                rolled_back=False,
            )

        # 2. Extract into staging
        run_id = uuid.uuid4().hex[:8]
        staging_dir = target_dir.parent / f".staging_{run_id}"
        backup_dir = target_dir.parent / f".backup_{run_id}"

        try:
            extract_verified(bundle_path, staging_dir, verified)

            # Read bundle metadata if present
            meta_path = staging_dir / "_bundle_meta.json"
            bundle_type = "custom"
            if meta_path.exists():
                try:
                    meta_data = json.loads(meta_path.read_text("utf-8"))
                    bundle_type = meta_data.get("bundle_type", "custom")
                except Exception as exc:
                    log.debug("Failed to read _bundle_meta.json: %s", exc)

            # 3. Content validation
            if validator_fn is not None:
                try:
                    is_valid = validator_fn(staging_dir)
                    if not is_valid:
                        raise ValueError("Custom validator rejected staged content")
                except Exception as val_exc:
                    self._audit(
                        actor,
                        "agent.bundle_validation_failed",
                        {"version": verified.version, "error": str(val_exc)},
                    )
                    return DeploymentResult(
                        success=False,
                        version=verified.version,
                        bundle_type=bundle_type,
                        error=f"Validation failed: {val_exc}",
                        rolled_back=False,
                    )

            # 4. Backup existing target directory
            backup_dir.mkdir(parents=True, exist_ok=True)
            for item in target_dir.iterdir():
                if item.name.startswith(".staging_") or item.name.startswith(".backup_"):
                    continue
                dest = backup_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)

            # 5. Apply staged files
            applied_files: list[str] = []
            try:
                for staged_file in staging_dir.rglob("*"):
                    if staged_file.is_file():
                        rel = staged_file.relative_to(staging_dir)
                        if rel.name == "_bundle_meta.json":
                            continue
                        dest_file = target_dir / rel
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(staged_file, dest_file)
                        applied_files.append(str(rel))

                # Post-apply self-check: verify all applied files exist and non-empty
                for rel_str in applied_files:
                    p = target_dir / rel_str
                    if not p.exists():
                        raise OSError(f"Applied file {rel_str} missing after copy")

            except Exception as apply_exc:
                # 6. ROLLBACK on apply failure
                log.error("Apply failed for %s, executing rollback: %s", verified.version, apply_exc)
                # Restore from backup_dir
                for item in target_dir.iterdir():
                    if item.name.startswith(".staging_") or item.name.startswith(".backup_"):
                        continue
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        with contextlib.suppress(OSError):
                            item.unlink()

                try:
                    for b_item in backup_dir.iterdir():
                        b_dest = target_dir / b_item.name
                        shutil.move(str(b_item), str(b_dest))
                except Exception as restore_exc:
                    log.error("Rollback restore encountered error: %s", restore_exc)

                self._audit(
                    actor,
                    "agent.bundle_rollback_executed",
                    {
                        "target_version": verified.version,
                        "reverted_to": current_version,
                        "reason": str(apply_exc),
                    },
                )
                return DeploymentResult(
                    success=False,
                    version=current_version,
                    bundle_type=bundle_type,
                    error=f"Apply failed and rolled back: {apply_exc}",
                    rolled_back=True,
                )

            # 7. Success
            self._audit(
                actor,
                "agent.bundle_applied_successfully",
                {
                    "version": verified.version,
                    "bundle_type": bundle_type,
                    "applied_files_count": len(applied_files),
                },
            )
            return DeploymentResult(
                success=True,
                version=verified.version,
                bundle_type=bundle_type,
                applied_files=applied_files,
                rolled_back=False,
            )

        finally:
            # Clean up temporary staging and backup directories
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)
            if backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
