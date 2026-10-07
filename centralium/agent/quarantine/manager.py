"""Secure file quarantine implementing ``QuarantineManager``.

Guarantees
----------
* Quarantine root is created ``0700`` and verified (owner, no group/other access) on every use.
* The file is opened with ``O_NOFOLLOW`` (symlinks are REFUSED, not followed), must be a
  regular file, is hashed (SHA-256) and copied from that single file descriptor
  (no TOCTOU between hash and copy), stored as ``<id>.quarantine`` with mode ``0400``
  (all execute bits stripped) next to a ``<id>.json`` metadata file, and only then is the
  original unlinked - and only if the path still refers to the same inode.
* Paths are canonicalised (``realpath``); targets inside the quarantine root or under the
  configured protected paths are refused. ``quarantine_id`` is validated (32 hex) so ids can
  never traverse.
* Metadata: sha256, reasons, sources, timestamp, original path/mode/uid/gid/mtime/size.
* Restore needs an authorised actor and a reason, verifies the blob hash (tamper check),
  refuses to overwrite an existing file, restores to the original canonical location
  (parent must still be the same real directory) and **keeps the evidence copy** unless
  ``destroy_evidence_on_restore`` was explicitly enabled.
* Every operation (including denials) is reported to the injected ``audit`` callback
  ``(actor, event_type, details)`` (compatible with ``Database.audit.append``).
* Evidence is never destroyed by default; ``purge`` only works when ``allow_purge=True``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import threading
import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from centralium.agent.interfaces import QuarantineRecord

log = logging.getLogger("centralium.quarantine")

AuditFn = Callable[[str, str, dict[str, Any]], None]
Authorizer = Callable[[str, str, QuarantineRecord], bool]  # (actor, reason, record) -> allowed
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CHUNK = 1024 * 1024


class QuarantineError(RuntimeError):
    pass


class QuarantineAuthError(QuarantineError):
    pass


def _canon(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


class FileQuarantineManager:
    def __init__(
        self,
        root: str | Path,
        *,
        audit: AuditFn | None = None,
        restore_authorizer: Authorizer | None = None,
        authorized_users: Iterable[str] = (),
        protected_paths: Iterable[str] = (),
        max_file_bytes: int = 512 * 1024 * 1024,
        allow_purge: bool = False,
        destroy_evidence_on_restore: bool = False,
    ) -> None:
        self.root = Path(root)
        self._audit = audit
        self._authorizer = restore_authorizer
        self._users = frozenset(authorized_users)
        self._protected = tuple(_canon(p) for p in protected_paths)
        self.max_file_bytes = max_file_bytes
        self.allow_purge = allow_purge
        self.destroy_on_restore = destroy_evidence_on_restore
        self._lock = threading.RLock()
        self._ensure_root()

    # ------------------------------------------------------------------ helpers
    def _ensure_root(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            st = os.lstat(self.root)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise QuarantineError("quarantine root must be a real directory")
            if st.st_uid != os.geteuid():
                raise QuarantineError("quarantine root is not owned by the current user")
            if st.st_mode & 0o077:
                os.chmod(self.root, 0o700)
        self._root_real = _canon(self.root)

    def _emit(self, actor: str, event_type: str, details: dict[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            self._audit(actor, event_type, details)
        except Exception:
            log.exception("audit callback failed for %s", event_type)

    def _paths(self, qid: str) -> tuple[Path, Path]:
        if not _ID_RE.fullmatch(qid):
            raise QuarantineError("invalid quarantine id")
        return self.root / f"{qid}.quarantine", self.root / f"{qid}.json"

    def _in_protected(self, real: str) -> str | None:
        for p in self._protected:
            if real == p or real.startswith(p + os.sep):
                return p
        return None

    # ------------------------------------------------------------------ quarantine
    def quarantine(self, path: Path, reasons: list[str], sources: list[str]) -> QuarantineRecord:
        with self._lock:
            self._ensure_root()
            raw = os.fspath(path)
            if "\x00" in raw or not raw:
                raise QuarantineError("invalid path")
            lst = os.lstat(raw)  # raises FileNotFoundError for missing path
            if stat.S_ISLNK(lst.st_mode):
                self._emit("quarantine", "quarantine_refused", {"path": raw, "why": "symlink"})
                raise QuarantineError("refusing to quarantine a symlink")
            real = _canon(raw)
            if real == self._root_real or real.startswith(self._root_real + os.sep):
                raise QuarantineError("path is inside the quarantine directory")
            prot = self._in_protected(real)
            if prot:
                self._emit(
                    "quarantine", "quarantine_refused", {"path": real, "why": f"protected path {prot}"}
                )
                raise QuarantineError(f"path is under protected location {prot}")
            qid = uuid.uuid4().hex
            blob, meta = self._paths(qid)
            fd = os.open(real, os.O_RDONLY | _NOFOLLOW)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise QuarantineError("only regular files can be quarantined")
                if st.st_size > self.max_file_bytes:
                    raise QuarantineError("file exceeds quarantine size limit")
                if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
                    raise QuarantineError("file changed during quarantine (possible race)")
                digest = hashlib.sha256()
                out_fd = os.open(blob, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
                try:
                    with (
                        os.fdopen(out_fd, "wb", closefd=True) as out,
                        os.fdopen(os.dup(fd), "rb", closefd=True) as src,
                    ):
                        while chunk := src.read(_CHUNK):
                            digest.update(chunk)
                            out.write(chunk)
                        out.flush()
                        os.fsync(out.fileno())
                except BaseException:
                    blob.unlink(missing_ok=True)
                    raise
            finally:
                os.close(fd)
            os.chmod(blob, 0o400)  # no exec bits, read-only, owner only
            rec = QuarantineRecord(
                quarantine_id=qid,
                original_path=real,
                quarantine_path=str(blob),
                sha256=digest.hexdigest(),
                timestamp=datetime.now(UTC).isoformat(),
                reasons=[str(r)[:500] for r in reasons][:50],
                sources=[str(s)[:100] for s in sources][:50],
                metadata={
                    "mode": oct(stat.S_IMODE(st.st_mode)),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "mtime_ns": st.st_mtime_ns,
                    "size": st.st_size,
                },
            )
            try:
                self._write_meta(meta, rec)
                cur = os.lstat(real)
                if (cur.st_dev, cur.st_ino) != (st.st_dev, st.st_ino):
                    raise QuarantineError("original path was replaced during quarantine; not removing it")
                os.unlink(real)
            except BaseException:
                blob.unlink(missing_ok=True)
                meta.unlink(missing_ok=True)
                raise
            self._emit(
                "quarantine",
                "quarantine_file",
                {
                    "quarantine_id": qid,
                    "original_path": real,
                    "sha256": rec.sha256,
                    "reasons": rec.reasons,
                    "sources": rec.sources,
                },
            )
            return rec

    def _write_meta(self, meta: Path, rec: QuarantineRecord) -> None:
        tmp = meta.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(rec.model_dump(mode="json"), fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, meta)

    # ------------------------------------------------------------------ read
    def get(self, quarantine_id: str) -> QuarantineRecord:
        _, meta = self._paths(quarantine_id)
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            rec = QuarantineRecord.model_validate(data)
        except (OSError, ValueError) as exc:
            raise QuarantineError(f"unknown or corrupt quarantine record {quarantine_id}") from exc
        if rec.quarantine_id != quarantine_id:
            raise QuarantineError("quarantine metadata id mismatch")
        return rec

    def list(self) -> list[QuarantineRecord]:
        out: list[QuarantineRecord] = []
        for meta in sorted(self.root.glob("*.json")):
            qid = meta.stem
            if not _ID_RE.fullmatch(qid):
                continue
            try:
                out.append(self.get(qid))
            except QuarantineError:
                log.warning("skipping corrupt quarantine record %s", meta.name)
        return sorted(out, key=lambda r: r.timestamp)

    def verify(self, quarantine_id: str) -> bool:
        """True if the stored blob still matches its recorded SHA-256."""
        rec = self.get(quarantine_id)
        blob, _ = self._paths(quarantine_id)
        h = hashlib.sha256()
        try:
            with blob.open("rb") as fh:
                while chunk := fh.read(_CHUNK):
                    h.update(chunk)
        except OSError:
            return False
        return h.hexdigest() == rec.sha256

    # ------------------------------------------------------------------ restore / purge
    def _authorize(self, actor: str, reason: str, rec: QuarantineRecord) -> None:
        if not actor.strip() or not reason.strip():
            raise QuarantineAuthError("restore requires a non-empty actor and reason")
        if self._authorizer is not None:
            ok = bool(self._authorizer(actor, reason, rec))
        else:
            ok = actor in self._users
        if not ok:
            self._emit(
                actor, "quarantine_restore_denied", {"quarantine_id": rec.quarantine_id, "reason": reason}
            )
            raise QuarantineAuthError(f"'{actor}' is not authorised to restore quarantined files")

    def restore(self, quarantine_id: str, *, authorized_by: str, reason: str) -> Path:
        with self._lock:
            self._ensure_root()
            rec = self.get(quarantine_id)
            self._authorize(authorized_by, reason, rec)
            blob, meta = self._paths(quarantine_id)
            if rec.restored:
                raise QuarantineError("record already restored")
            if not self.verify(quarantine_id):
                self._emit(
                    authorized_by,
                    "quarantine_restore_failed",
                    {"quarantine_id": quarantine_id, "why": "hash mismatch"},
                )
                raise QuarantineError("quarantined blob failed integrity check (tampered or corrupt)")
            dest = rec.original_path
            parent = os.path.dirname(dest)
            if os.path.realpath(parent) != parent:
                raise QuarantineError("original parent directory now resolves elsewhere (symlink); refusing")
            if not os.path.isdir(parent):
                raise QuarantineError("original directory no longer exists")
            if os.path.lexists(dest):
                raise QuarantineError("destination already exists; refusing to overwrite")
            prot = self._in_protected(_canon(dest))
            if prot:
                raise QuarantineError(f"restore target is under protected location {prot}")
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=True) as out, blob.open("rb") as src:
                    while chunk := src.read(_CHUNK):
                        out.write(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                mode = int(str(rec.metadata.get("mode", "0o600")), 8)
                os.chmod(dest, mode & 0o7777)
                mt = rec.metadata.get("mtime_ns")
                if isinstance(mt, int):
                    os.utime(dest, ns=(mt, mt))
            except BaseException:
                Path(dest).unlink(missing_ok=True)
                raise
            rec = rec.model_copy(
                update={
                    "restored": True,
                    "metadata": {
                        **rec.metadata,
                        "restored_by": authorized_by,
                        "restore_reason": reason,
                        "restored_at": datetime.now(UTC).isoformat(),
                    },
                }
            )
            self._write_meta(meta, rec)
            if self.destroy_on_restore:
                os.chmod(blob, 0o600)
                blob.unlink(missing_ok=True)
            self._emit(
                authorized_by,
                "quarantine_restore",
                {
                    "quarantine_id": quarantine_id,
                    "path": dest,
                    "reason": reason,
                    "evidence_kept": not self.destroy_on_restore,
                },
            )
            return Path(dest)

    def purge(self, quarantine_id: str, *, authorized_by: str, reason: str) -> None:
        """Destroy evidence. Disabled unless the manager was built with ``allow_purge=True``."""
        with self._lock:
            if not self.allow_purge:
                self._emit(authorized_by, "quarantine_purge_denied", {"quarantine_id": quarantine_id})
                raise QuarantineAuthError("evidence destruction is disabled by configuration")
            rec = self.get(quarantine_id)
            self._authorize(authorized_by, reason, rec)
            blob, meta = self._paths(quarantine_id)
            if blob.exists():
                os.chmod(blob, 0o600)
                blob.unlink()
            meta.unlink(missing_ok=True)
            self._emit(authorized_by, "quarantine_purge", {"quarantine_id": quarantine_id, "reason": reason})
