"""Unit tests for Phase 2H: Quarantine AES-256-GCM encryption at rest and key rotation."""

import hashlib
import os
from pathlib import Path

import pytest

from centralium.agent.quarantine.crypto import (
    DecryptionError,
    QuarantineCrypto,
)
from centralium.agent.quarantine.manager import FileQuarantineManager


def test_quarantine_crypto_key_generation(tmp_path: Path):
    key_file = tmp_path / "keys" / "quarantine.key"
    crypto = QuarantineCrypto(key_file)
    assert key_file.exists()
    assert crypto.active_key_id == "k1"
    assert "k1" in crypto.list_key_ids()

    # Verify POSIX permissions 0600 on key file and 0700 on dir
    if os.name == "posix":
        st_file = key_file.stat()
        assert (st_file.st_mode & 0o777) == 0o600
        st_dir = key_file.parent.stat()
        assert (st_dir.st_mode & 0o777) == 0o700


def test_quarantine_crypto_encrypt_decrypt_bytes(tmp_path: Path):
    key_file = tmp_path / "keys" / "quarantine.key"
    crypto = QuarantineCrypto(key_file)

    data = b"Malicious payload evidence string 12345"
    aad = b"incident_meta_data"
    ciphertext = crypto.encrypt_bytes(data, associated_data=aad)

    assert ciphertext != data
    assert crypto.is_encrypted_blob(ciphertext)

    decrypted = crypto.decrypt_bytes(ciphertext, associated_data=aad)
    assert decrypted == data

    # Tampered ciphertext fails authentication
    tampered = bytearray(ciphertext)
    tampered[-5] ^= 0xFF
    with pytest.raises(DecryptionError):
        crypto.decrypt_bytes(bytes(tampered), associated_data=aad)

    # Wrong AAD fails authentication
    with pytest.raises(DecryptionError):
        crypto.decrypt_bytes(ciphertext, associated_data=b"wrong_aad")


def test_quarantine_crypto_key_rotation(tmp_path: Path):
    key_file = tmp_path / "keys" / "quarantine.key"
    crypto = QuarantineCrypto(key_file)

    msg_v1 = b"Secret evidence encrypted with key v1"
    cipher_v1 = crypto.encrypt_bytes(msg_v1)

    # Rotate key to v2
    new_kid = crypto.rotate_key("key_v2")
    assert new_kid == "key_v2"
    assert crypto.active_key_id == "key_v2"
    assert set(crypto.list_key_ids()) == {"k1", "key_v2"}

    # New encryption uses key_v2
    msg_v2 = b"Evidence encrypted with key v2"
    cipher_v2 = crypto.encrypt_bytes(msg_v2)

    # Can decrypt both v1 and v2 ciphertexts
    assert crypto.decrypt_bytes(cipher_v1) == msg_v1
    assert crypto.decrypt_bytes(cipher_v2) == msg_v2

    # Reload from disk into a fresh crypto instance
    reloaded_crypto = QuarantineCrypto(key_file)
    assert reloaded_crypto.active_key_id == "key_v2"
    assert set(reloaded_crypto.list_key_ids()) == {"k1", "key_v2"}
    assert reloaded_crypto.decrypt_bytes(cipher_v1) == msg_v1
    assert reloaded_crypto.decrypt_bytes(cipher_v2) == msg_v2


def test_quarantine_crypto_sensitive_field(tmp_path: Path):
    key_file = tmp_path / "keys" / "quarantine.key"
    crypto = QuarantineCrypto(key_file)

    plain_secret = "Bearer my-super-secret-auth-token-12345"
    encrypted_field = crypto.encrypt_field(plain_secret)
    assert encrypted_field.startswith("cqenc:")
    assert plain_secret not in encrypted_field

    decrypted_field = crypto.decrypt_field(encrypted_field)
    assert decrypted_field == plain_secret

    # Passthrough for unencrypted values
    assert crypto.decrypt_field("plain_unencrypted_value") == "plain_unencrypted_value"


def test_quarantine_manager_with_encryption(tmp_path: Path):
    quarantine_root = tmp_path / "quarantine"
    key_file = tmp_path / "keys" / "quarantine.key"
    crypto = QuarantineCrypto(key_file)

    manager = FileQuarantineManager(
        quarantine_root,
        authorized_users=["analyst_bob"],
        crypto=crypto,
    )

    # Create target file to quarantine
    victim_dir = tmp_path / "victim"
    victim_dir.mkdir(parents=True)
    victim_file = victim_dir / "badware.bin"
    victim_content = b"Simulated trojan executable contents \x90\x90\xcc\xcc"
    victim_file.write_bytes(victim_content)
    orig_sha256 = hashlib.sha256(victim_content).hexdigest()

    # Quarantine it
    record = manager.quarantine(victim_file, reasons=["malicious heuristic"], sources=["test"])
    assert not victim_file.exists()
    assert record.sha256 == orig_sha256
    assert record.metadata.get("encrypted") is True
    assert record.metadata.get("crypto_key_id") == crypto.active_key_id

    # The stored blob on disk is encrypted, not raw plaintext
    blob_path = Path(record.quarantine_path)
    stored_bytes = blob_path.read_bytes()
    assert crypto.is_encrypted_blob(stored_bytes)
    assert stored_bytes != b"Simulated trojan executable contents \x90\x90\xcc\xcc"

    # Integrity verification verifies plaintext matches original sha256
    assert manager.verify(record.quarantine_id) is True

    # Restore decrypts back to original path
    restored_path = manager.restore(
        record.quarantine_id, authorized_by="analyst_bob", reason="False positive review"
    )
    assert restored_path.exists()
    assert restored_path.read_bytes() == b"Simulated trojan executable contents \x90\x90\xcc\xcc"
