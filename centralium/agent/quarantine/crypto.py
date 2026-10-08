"""AES-256-GCM encryption at rest for quarantine file blobs and sensitive data.

Uses ``cryptography.hazmat.primitives.ciphers.aead.AESGCM`` with key derivation,
root-protected key files, key rotation, and authenticated envelope packaging.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import stat
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("centralium.quarantine.crypto")

MAGIC_HEADER = b"CQGCM1\x00"  # Centralium Quarantine GCM v1 header (8 bytes)
NONCE_LENGTH = 12  # Standard 96-bit IV for AES-GCM
KEY_LENGTH = 32  # 256-bit AES key


class QuarantineCryptoError(RuntimeError):
    """Base error for quarantine encryption / decryption operations."""


class KeyPermissionError(QuarantineCryptoError):
    """Raised when key directory or key file has insecure permissions."""


class DecryptionError(QuarantineCryptoError):
    """Raised when ciphertext authentication or decryption fails."""


def default_key_path() -> Path:
    """Return default quarantine key file path."""
    env_path = os.environ.get("CENTRALIUM_QUARANTINE_KEY_PATH") or os.environ.get("CENTRALIUM_KEY_FILE")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return Path.home() / ".centralium" / "keys" / "quarantine.key"


class QuarantineCrypto:
    """AES-256-GCM encryption manager supporting key rotation and secure key storage."""

    def __init__(
        self,
        key_path: str | Path | None = None,
        *,
        auto_generate: bool = True,
        strict_permissions: bool = True,
    ) -> None:
        self.key_path = Path(key_path).expanduser().resolve() if key_path else default_key_path()
        self.strict_permissions = strict_permissions
        self.active_key_id: str = "k1"
        self._keys: dict[str, bytes] = {}
        self._load_or_generate_keys(auto_generate=auto_generate)

    # ------------------------------------------------------------------ Key lifecycle
    def _ensure_dir_permissions(self, dir_path: Path) -> None:
        dir_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            st = os.lstat(dir_path)
            if self.strict_permissions and (st.st_mode & 0o077):
                os.chmod(dir_path, 0o700)

    def _verify_file_permissions(self, path: Path) -> None:
        if os.name != "posix" or not self.strict_permissions:
            return
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            raise KeyPermissionError("Key file cannot be a symbolic link")
        # Ensure only owner has read/write permissions
        if st.st_mode & 0o077:
            # Auto-tighten if owned by current user
            if st.st_uid == os.geteuid():
                os.chmod(path, 0o600)
            else:
                msg = (
                    f"Insecure permissions {oct(st.st_mode)} on key file {path} "
                    f"not owned by UID {os.geteuid()}"
                )
                raise KeyPermissionError(msg)

    def _save_keys_file(self) -> None:
        self._ensure_dir_permissions(self.key_path.parent)
        payload = {
            "version": 1,
            "active_key_id": self.active_key_id,
            "keys": {kid: k.hex() for kid, k in self._keys.items()},
        }
        tmp_path = self.key_path.with_suffix(".tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, self.key_path)
        if os.name == "posix":
            os.chmod(self.key_path, 0o600)

    def _load_or_generate_keys(self, auto_generate: bool) -> None:
        if not self.key_path.exists():
            if not auto_generate:
                raise QuarantineCryptoError(f"Key file {self.key_path} does not exist")
            # Generate initial 256-bit key
            init_key = AESGCM.generate_key(bit_length=KEY_LENGTH * 8)
            self.active_key_id = "k1"
            self._keys = {"k1": init_key}
            self._save_keys_file()
            return

        self._verify_file_permissions(self.key_path)
        raw_text = self.key_path.read_text(encoding="utf-8").strip()

        # Handle JSON format or legacy raw hex / string
        try:
            data = json.loads(raw_text)
            if isinstance(data, dict) and "keys" in data:
                self.active_key_id = str(data.get("active_key_id", "k1"))
                self._keys = {kid: bytes.fromhex(h) for kid, h in data["keys"].items()}
                if self.active_key_id not in self._keys:
                    err = f"Active key id '{self.active_key_id}' not found in key store"
                    raise QuarantineCryptoError(err)
                return
        except json.JSONDecodeError:
            pass

        # Check raw hex string (64 chars)
        if len(raw_text) == 64:
            try:
                raw_bytes = bytes.fromhex(raw_text)
                self.active_key_id = "k1"
                self._keys = {"k1": raw_bytes}
                # Upgrade to JSON store
                self._save_keys_file()
                return
            except ValueError:
                pass

        # Check binary bytes if read as binary
        bin_data = self.key_path.read_bytes()
        if len(bin_data) == KEY_LENGTH:
            self.active_key_id = "k1"
            self._keys = {"k1": bin_data}
            self._save_keys_file()
            return

        raise QuarantineCryptoError(f"Unrecognized or corrupted key file format at {self.key_path}")

    def rotate_key(self, new_key_id: str | None = None) -> str:
        """Generate a new AES-256 key, promote it to active, preserving old keys."""
        if not new_key_id:
            new_key_id = f"k_{int(time.time())}_{os.urandom(4).hex()}"
        new_key = AESGCM.generate_key(bit_length=KEY_LENGTH * 8)
        self._keys[new_key_id] = new_key
        self.active_key_id = new_key_id
        self._save_keys_file()
        log.info("Quarantine key rotated to active key ID: %s", new_key_id)
        return new_key_id

    def list_key_ids(self) -> list[str]:
        """Return list of known key IDs."""
        return list(self._keys.keys())

    # ------------------------------------------------------------------ AES-256-GCM Envelope
    def encrypt_bytes(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
        key_id: str | None = None,
    ) -> bytes:
        """Encrypt plaintext bytes with AES-256-GCM authenticated envelope."""
        kid = key_id or self.active_key_id
        if kid not in self._keys:
            raise QuarantineCryptoError(f"Unknown key ID: {kid}")
        key_bytes = self._keys[kid]
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(NONCE_LENGTH)
        kid_bytes = kid.encode("utf-8")
        if len(kid_bytes) > 255:
            raise QuarantineCryptoError("Key ID length cannot exceed 255 bytes")

        aad = associated_data if associated_data is not None else b""
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # Envelope: MAGIC (8) + KID_LEN (1) + KID (N) + NONCE (12) + CIPHERTEXT+TAG
        return MAGIC_HEADER + bytes([len(kid_bytes)]) + kid_bytes + nonce + ciphertext

    def decrypt_bytes(
        self,
        payload: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Authenticate and decrypt an AES-256-GCM envelope."""
        if len(payload) < len(MAGIC_HEADER) + 1 + NONCE_LENGTH + 16:
            raise DecryptionError("Payload too short to be a valid encrypted envelope")
        if not payload.startswith(MAGIC_HEADER):
            raise DecryptionError("Invalid or missing envelope magic header")

        idx = len(MAGIC_HEADER)
        kid_len = payload[idx]
        idx += 1
        kid_bytes = payload[idx : idx + kid_len]
        idx += kid_len
        nonce = payload[idx : idx + NONCE_LENGTH]
        idx += NONCE_LENGTH
        ciphertext = payload[idx:]

        kid = kid_bytes.decode("utf-8", errors="replace")
        if kid not in self._keys:
            raise DecryptionError(f"Key ID '{kid}' is not available in key store")

        key_bytes = self._keys[kid]
        aesgcm = AESGCM(key_bytes)
        aad = associated_data if associated_data is not None else b""
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise DecryptionError(f"AES-GCM authentication/decryption failed: {exc}") from exc

    # ------------------------------------------------------------------ File operations
    def encrypt_file(
        self,
        src_path: Path | str,
        dst_path: Path | str,
        associated_data: bytes | None = None,
        key_id: str | None = None,
    ) -> tuple[int, str]:
        """Encrypt source file into destination file. Returns (plaintext_size, sha256_hexdigest)."""
        src = Path(src_path)
        dst = Path(dst_path)
        data = src.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        enc_blob = self.encrypt_bytes(data, associated_data=associated_data, key_id=key_id)

        tmp_dst = dst.with_suffix(".enc.tmp")
        fd = os.open(tmp_dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(enc_blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_dst, dst)
        return len(data), digest

    def decrypt_file(
        self,
        src_path: Path | str,
        dst_path: Path | str,
        associated_data: bytes | None = None,
    ) -> None:
        """Decrypt encrypted file blob to destination path."""
        src = Path(src_path)
        dst = Path(dst_path)
        enc_blob = src.read_bytes()
        plaintext = self.decrypt_bytes(enc_blob, associated_data=associated_data)

        tmp_dst = dst.with_suffix(".dec.tmp")
        fd = os.open(tmp_dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(plaintext)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_dst, dst)

    # ------------------------------------------------------------------ Sensitive column / field
    def encrypt_field(self, plaintext: str) -> str:
        """Encrypt a string database column into a base64 encoded envelope."""
        if not plaintext:
            return plaintext
        raw = plaintext.encode("utf-8")
        enc = self.encrypt_bytes(raw)
        b64 = base64.b64encode(enc).decode("ascii")
        return f"cqenc:{b64}"

    def decrypt_field(self, value: str) -> str:
        """Decrypt a database field if encrypted with 'cqenc:' prefix; else return value."""
        if not isinstance(value, str) or not value.startswith("cqenc:"):
            return value
        b64 = value[6:]
        try:
            enc = base64.b64decode(b64.encode("ascii"))
            dec = self.decrypt_bytes(enc)
            return dec.decode("utf-8")
        except Exception as exc:
            log.error("Failed to decrypt sensitive field: %s", exc)
            raise DecryptionError(f"Field decryption failed: {exc}") from exc

    def is_encrypted_blob(self, data: bytes) -> bool:
        """Check if bytes match the quarantine encryption envelope header."""
        return data.startswith(MAGIC_HEADER)
