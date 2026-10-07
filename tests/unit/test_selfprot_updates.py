from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from centralium.agent.self_protection import (
    HAVE_CRYPTO,
    UpdateRejected,
    create_bundle,
    extract_verified,
    generate_keypair,
    verify_bundle,
)

pytestmark = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")

FILES = {"agent/main.py": b"print('v2')\n", "rules/r.yar": b"rule x { condition: false }\n"}


@pytest.fixture
def keys():
    return generate_keypair()


def make(tmp_path: Path, priv, version="1.1.0", files=None) -> Path:
    out = tmp_path / "b.zip"
    create_bundle(out, version, files or FILES, priv)
    return out


def rewrite(src: Path, dst: Path, mutate) -> Path:
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for i in zin.infolist():
            data = mutate(i.filename, zin.read(i.filename))
            if data is not None:
                zout.writestr(i.filename, data)
        mutate(None, b"")  # allow extra entries hook
    return dst


def test_valid_bundle_accepted_and_extracted(tmp_path, keys):
    priv, pub = keys
    b = make(tmp_path, priv)
    v = verify_bundle(b, public_key=pub, current_version="1.0.0")
    assert v.authenticated and v.mode == "ed25519" and v.version == "1.1.0"
    out = extract_verified(b, tmp_path / "stage", v)
    assert {p.relative_to(tmp_path / "stage").as_posix() for p in out} == set(FILES)
    assert (tmp_path / "stage/agent/main.py").read_bytes() == FILES["agent/main.py"]


def test_unsigned_bundle_rejected(tmp_path, keys):
    _, pub = keys
    b = make(tmp_path, None)
    with pytest.raises(UpdateRejected, match="unsigned"):
        verify_bundle(b, public_key=pub)


def test_wrong_key_rejected(tmp_path, keys):
    priv, _ = keys
    _, other_pub = generate_keypair()
    with pytest.raises(UpdateRejected, match="invalid signature"):
        verify_bundle(make(tmp_path, priv), public_key=other_pub)


def test_tampered_payload_rejected(tmp_path, keys):
    priv, pub = keys
    b = make(tmp_path, priv)
    t = rewrite(b, tmp_path / "t.zip", lambda n, d: b"print('evil')" if n == "files/agent/main.py" else d)
    with pytest.raises(UpdateRejected, match="hash mismatch"):
        verify_bundle(t, public_key=pub)


def test_tampered_manifest_signature_fails(tmp_path, keys):
    priv, pub = keys
    b = make(tmp_path, priv)
    t = rewrite(
        b, tmp_path / "t.zip", lambda n, d: d.replace(b"1.1.0", b"9.9.9") if n == "manifest.json" else d
    )
    with pytest.raises(UpdateRejected, match="invalid signature"):
        verify_bundle(t, public_key=pub)


def test_extra_undeclared_file_rejected(tmp_path, keys):
    priv, pub = keys
    b = make(tmp_path, priv)
    with zipfile.ZipFile(b, "a") as z:
        z.writestr("files/backdoor.sh", b"x")
    with pytest.raises(UpdateRejected, match="do not match manifest"):
        verify_bundle(b, public_key=pub)


def test_rollback_refused(tmp_path, keys):
    priv, pub = keys
    b = make(tmp_path, priv, version="1.0.0")
    with pytest.raises(UpdateRejected, match="rollback"):
        verify_bundle(b, public_key=pub, current_version="1.0.0")


def test_path_traversal_name_rejected(tmp_path, keys):
    priv, pub = keys
    b = make(tmp_path, priv, files={"../evil.py": b"x"})
    with pytest.raises(UpdateRejected, match="unsafe"):
        verify_bundle(b, public_key=pub)


def test_garbage_and_missing_trust_anchor(tmp_path, keys):
    priv, pub = keys
    g = tmp_path / "g.zip"
    g.write_bytes(b"not a zip")
    with pytest.raises(UpdateRejected, match="unreadable"):
        verify_bundle(g, public_key=pub)
    with pytest.raises(UpdateRejected, match="no trust anchor"):
        verify_bundle(make(tmp_path, priv))


def test_hash_pin_fallback_integrity_only(tmp_path, keys):
    import hashlib

    b = make(tmp_path, None)
    digest = hashlib.sha256(zipfile.ZipFile(b).read("manifest.json")).hexdigest()
    v = verify_bundle(b, pinned_manifest_sha256=digest)
    assert v.mode == "hash-pin" and not v.authenticated and v.notes
    with pytest.raises(UpdateRejected, match="pinned"):
        verify_bundle(b, pinned_manifest_sha256="0" * 64)


def test_extract_requires_empty_staging(tmp_path, keys):
    priv, pub = keys
    b = make(tmp_path, priv)
    v = verify_bundle(b, public_key=pub)
    (tmp_path / "stage").mkdir()
    (tmp_path / "stage/old").write_text("x")
    with pytest.raises(UpdateRejected):
        extract_verified(b, tmp_path / "stage", v)
