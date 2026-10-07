"""Signed update bundle creation/verification.

Bundle = ZIP with ``manifest.json`` (canonical JSON: version, files{name:sha256}), ``manifest.sig``
(raw 64-byte Ed25519 signature over the exact bytes of ``manifest.json``) and ``files/<name>`` entries.

Modes
* ``ed25519`` (needs the ``cryptography`` package): authenticity + integrity against a trusted public key
  pinned in agent config / baked into the install. Unsigned or badly-signed bundles are REJECTED.
* ``hash-pin`` fallback (no ``cryptography``): the caller must supply ``pinned_manifest_sha256``
  obtained out-of-band. This gives integrity only (not publisher authenticity) and the result
  says ``authenticated=False``. Without a pin and without cryptography every bundle is rejected.

Also enforced: no path traversal / absolute / duplicate / undeclared entries, per-file and total size caps
(zip-bomb guard), and rollback protection (``version`` must be greater than ``current_version``).
Verification never executes bundle content. ``extract_verified`` writes only into a fresh staging dir.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

try:  # optional dependency
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised only where cryptography is absent
    HAVE_CRYPTO = False

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_ENTRIES = 20_000
_VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}$")


class UpdateRejected(Exception):
    """Bundle failed verification; message is safe to log."""


@dataclass
class VerifiedBundle:
    version: str
    files: dict[str, str]
    authenticated: bool
    mode: str
    notes: list[str] = field(default_factory=list)


def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def generate_keypair() -> tuple[bytes, bytes]:
    """(private_raw32, public_raw32). Release tooling only; keep the private key offline."""
    if not HAVE_CRYPTO:
        raise RuntimeError("cryptography is not installed")
    sk = Ed25519PrivateKey.generate()
    return (
        sk.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        ),
        sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    )


def create_bundle(out: Path, version: str, files: dict[str, bytes], private_key: bytes | None) -> None:
    """Build a bundle (release tooling / tests). ``private_key=None`` creates an UNSIGNED bundle."""
    if not _VERSION_RE.match(version):
        raise ValueError("bad version")
    manifest = json.dumps(
        {
            "format": 1,
            "version": version,
            "files": {n: hashlib.sha256(d).hexdigest() for n, d in files.items()},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", manifest)
        if private_key is not None:
            if not HAVE_CRYPTO:
                raise RuntimeError("cryptography is not installed")
            z.writestr("manifest.sig", Ed25519PrivateKey.from_private_bytes(private_key).sign(manifest))
        for name, data in files.items():
            z.writestr(f"files/{name}", data)


def _safe_name(name: str) -> bool:
    p = PurePosixPath(name)
    return (
        bool(name) and not p.is_absolute() and ".." not in p.parts and "\\" not in name and "\x00" not in name
    )


def verify_bundle(
    bundle: Path,
    *,
    public_key: bytes | None = None,
    pinned_manifest_sha256: str | None = None,
    current_version: str = "0",
) -> VerifiedBundle:
    """Verify a bundle without extracting it. Raises ``UpdateRejected`` on any problem."""
    try:
        zf = zipfile.ZipFile(bundle)
    except (zipfile.BadZipFile, OSError) as exc:
        raise UpdateRejected(f"unreadable bundle: {type(exc).__name__}") from None
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise UpdateRejected("too many entries")
        names = [i.filename for i in infos]
        if len(set(names)) != len(names):
            raise UpdateRejected("duplicate entries")
        if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES or any(
            i.file_size > MAX_FILE_BYTES for i in infos
        ):
            raise UpdateRejected("bundle exceeds size limits")
        if "manifest.json" not in names:
            raise UpdateRejected("missing manifest.json")
        manifest_bytes = zf.read("manifest.json")

        notes: list[str] = []
        if public_key is not None:
            if not HAVE_CRYPTO:
                raise UpdateRejected("public key supplied but cryptography is unavailable; refusing")
            if "manifest.sig" not in names:
                raise UpdateRejected("unsigned bundle")
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(zf.read("manifest.sig"), manifest_bytes)
            except (InvalidSignature, ValueError):
                raise UpdateRejected("invalid signature") from None
            authenticated, mode = True, "ed25519"
        elif pinned_manifest_sha256 is not None:
            digest = hashlib.sha256(manifest_bytes).hexdigest()
            if not hmac.compare_digest(digest, pinned_manifest_sha256.lower()):
                raise UpdateRejected("manifest hash does not match pinned value")
            authenticated, mode = False, "hash-pin"
            notes.append("integrity only: no publisher authentication (no public key configured)")
        else:
            raise UpdateRejected("no trust anchor: provide a public key or a pinned manifest hash")

        try:
            manifest: dict[str, Any] = json.loads(manifest_bytes)
            version = str(manifest["version"])
            declared: dict[str, str] = dict(manifest["files"])
        except (ValueError, KeyError, TypeError):
            raise UpdateRejected("malformed manifest") from None
        if not _VERSION_RE.match(version) or not _VERSION_RE.match(current_version):
            raise UpdateRejected("malformed version")
        if _vkey(version) <= _vkey(current_version):
            raise UpdateRejected(f"rollback/replay refused: {version} <= {current_version}")

        payload = {n for n in names if n not in ("manifest.json", "manifest.sig")}
        expected_entries = {f"files/{n}" for n in declared}
        if payload != expected_entries:
            raise UpdateRejected("bundle contents do not match manifest (undeclared or missing files)")
        for n, want in declared.items():
            if not _safe_name(n) or not isinstance(want, str):
                raise UpdateRejected("unsafe file name in manifest")
            h = hashlib.sha256()
            with zf.open(f"files/{n}") as fh:
                while block := fh.read(1 << 20):
                    h.update(block)
            if not hmac.compare_digest(h.hexdigest(), want.lower()):
                raise UpdateRejected(f"hash mismatch for {n}")
        return VerifiedBundle(
            version=version, files=declared, authenticated=authenticated, mode=mode, notes=notes
        )


def extract_verified(bundle: Path, staging: Path, verified: VerifiedBundle) -> list[Path]:
    """Extract an already-verified bundle into an EMPTY staging dir (re-checks hashes while writing).

    Installation (swapping staging into place, restarting the service) is deliberately left to the
    operator/service manager so it stays auditable.
    """
    staging.mkdir(parents=True, exist_ok=True)
    if any(staging.iterdir()):
        raise UpdateRejected("staging directory must be empty")
    root = staging.resolve()
    written: list[Path] = []
    with zipfile.ZipFile(bundle) as zf:
        for name, want in verified.files.items():
            dest = (root / name).resolve()
            if root not in dest.parents:
                raise UpdateRejected("path escapes staging dir")
            data = zf.read(f"files/{name}")
            if hashlib.sha256(data).hexdigest() != want.lower():  # TOCTOU re-check
                raise UpdateRejected(f"hash mismatch for {name} at extraction")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with io.BytesIO(data) as src, dest.open("wb") as out:
                out.write(src.read())
            written.append(dest)
    return written
