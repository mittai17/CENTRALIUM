#!/usr/bin/env python3
"""Release manifest generator and Ed25519 signature verifier.

Produces an Ed25519-signed release manifest and SHA-256 checksums of built artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Produce deterministic, sort-keyed, compact JSON bytes for cryptographic signing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def hash_artifact(path: Path | str) -> dict[str, Any]:
    """Compute SHA-256 checksum and size in bytes of an artifact file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Artifact not found: {p}")
    h = hashlib.sha256()
    size = 0
    with p.open("rb") as fh:
        while chunk := fh.read(64 * 1024):
            h.update(chunk)
            size += len(chunk)
    return {
        "name": p.name,
        "path": str(p),
        "sha256": h.hexdigest(),
        "size_bytes": size,
    }


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 signing keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def load_private_key(key_input: str | Path | bytes) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from path, hex string, or raw bytes."""
    if isinstance(key_input, (str, Path)) and Path(key_input).exists():
        raw = Path(key_input).read_bytes().strip()
        if len(raw) == 64:  # hex encoded
            raw = bytes.fromhex(raw.decode("ascii"))
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    if isinstance(key_input, str):
        raw = bytes.fromhex(key_input.strip())
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    if isinstance(key_input, bytes):
        if len(key_input) == 64:
            key_input = bytes.fromhex(key_input.decode("ascii"))
        return ed25519.Ed25519PrivateKey.from_private_bytes(key_input)
    raise ValueError("Invalid private key input")


def load_public_key(pub_input: str | Path | bytes) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from path, hex string, or raw bytes."""
    if isinstance(pub_input, (str, Path)) and Path(pub_input).exists():
        raw = Path(pub_input).read_bytes().strip()
        if len(raw) == 64:
            raw = bytes.fromhex(raw.decode("ascii"))
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    if isinstance(pub_input, str):
        raw = bytes.fromhex(pub_input.strip())
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    if isinstance(pub_input, bytes):
        if len(pub_input) == 64:
            pub_input = bytes.fromhex(pub_input.decode("ascii"))
        return ed25519.Ed25519PublicKey.from_public_bytes(pub_input)
    raise ValueError("Invalid public key input")


def build_manifest(
    artifact_paths: list[Path | str],
    version: str = "0.1.0",
) -> dict[str, Any]:
    """Build unsigned manifest containing SHA-256 hashes of all artifacts."""
    artifacts = [hash_artifact(p) for p in artifact_paths]
    artifacts.sort(key=lambda a: a["name"])
    return {
        "generator": "centralium-release-signer",
        "version": version,
        "created_at": datetime.now(UTC).isoformat(),
        "artifacts": artifacts,
    }


def sign_manifest(
    manifest_data: dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
) -> dict[str, Any]:
    """Sign the canonical manifest payload with Ed25519 private key."""
    # Build payload containing only reproducible metadata and artifacts
    signable_payload = {
        "artifacts": manifest_data["artifacts"],
        "created_at": manifest_data["created_at"],
        "generator": manifest_data["generator"],
        "version": manifest_data["version"],
    }
    canon_bytes = canonical_json_bytes(signable_payload)
    sig_bytes = private_key.sign(canon_bytes)
    pub_bytes = private_key.public_key().public_bytes_raw()

    out = dict(signable_payload)
    out["public_key"] = pub_bytes.hex()
    out["signature"] = sig_bytes.hex()
    return out


def verify_manifest(
    signed_manifest: dict[str, Any],
    expected_public_key: ed25519.Ed25519PublicKey | str | None = None,
    verify_files_on_disk: bool = False,
) -> bool:
    """Verify Ed25519 signature and artifact integrity of a release manifest."""
    try:
        sig_hex = signed_manifest["signature"]
        pub_hex = signed_manifest["public_key"]
        sig_bytes = bytes.fromhex(sig_hex)
        pub_bytes = bytes.fromhex(pub_hex)

        if expected_public_key is not None:
            if isinstance(expected_public_key, str):
                expected_pub = load_public_key(expected_public_key)
            else:
                expected_pub = expected_public_key
            if pub_bytes != expected_pub.public_bytes_raw():
                return False

        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        signable_payload = {
            "artifacts": signed_manifest["artifacts"],
            "created_at": signed_manifest["created_at"],
            "generator": signed_manifest["generator"],
            "version": signed_manifest["version"],
        }
        canon_bytes = canonical_json_bytes(signable_payload)
        pub_key.verify(sig_bytes, canon_bytes)

        if verify_files_on_disk:
            for art in signed_manifest["artifacts"]:
                art_path = Path(art["path"])
                if not art_path.exists():
                    return False
                actual_hash = hash_artifact(art_path)
                if actual_hash["sha256"] != art["sha256"] or actual_hash["size_bytes"] != art["size_bytes"]:
                    return False

        return True
    except (KeyError, ValueError, InvalidSignature, OSError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Centralium release manifest signer & verifier")
    parser.add_argument("--gen-key", action="store_true", help="Generate Ed25519 keypair")
    parser.add_argument("--key-file", type=Path, help="Private key file path")
    parser.add_argument("--pub-file", type=Path, help="Public key file path")
    parser.add_argument("--artifacts", nargs="+", type=Path, help="Artifact files or directories to sign")
    parser.add_argument("--version", default="0.1.0", help="Release version")
    parser.add_argument("--output", "-o", type=Path, help="Output signed manifest JSON path")
    parser.add_argument("--verify", type=Path, help="Verify specified manifest file")
    parser.add_argument("--verify-files", action="store_true", help="Also verify artifact files on disk")

    args = parser.parse_args()

    if args.gen_key:
        priv, pub = generate_keypair()
        priv_path = args.key_file or Path("release.key")
        pub_path = args.pub_file or Path("release.pub")

        priv_fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(priv_fd, "wb") as f:
            f.write(priv.private_bytes_raw().hex().encode("ascii"))
        pub_path.write_bytes(pub.public_bytes_raw().hex().encode("ascii"))
        print(
            f"Generated Ed25519 keypair:\n  Private key: {priv_path} (mode 0600)\n  Public key:  {pub_path}"
        )
        return 0

    if args.verify:
        manifest_data = json.loads(args.verify.read_text(encoding="utf-8"))
        expected_pub = load_public_key(args.pub_file) if args.pub_file else None
        ok = verify_manifest(
            manifest_data,
            expected_public_key=expected_pub,
            verify_files_on_disk=args.verify_files,
        )
        if ok:
            print("OK: Manifest Ed25519 signature is VALID.")
            return 0
        else:
            print("ERROR: Manifest signature or artifact verification FAILED.", file=sys.stderr)
            return 1

    if args.artifacts:
        if not args.key_file:
            print("Error: --key-file required to sign manifest", file=sys.stderr)
            return 1
        priv_key = load_private_key(args.key_file)
        target_files: list[Path] = []
        for p in args.artifacts:
            if p.is_dir():
                target_files.extend(f for f in p.rglob("*") if f.is_file())
            elif p.is_file():
                target_files.append(p)

        manifest = build_manifest(target_files, version=args.version)
        signed = sign_manifest(manifest, priv_key)
        out_json = json.dumps(signed, indent=2)

        if args.output:
            args.output.write_text(out_json, encoding="utf-8")
            print(f"Wrote signed release manifest to {args.output}")
        else:
            print(out_json)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
