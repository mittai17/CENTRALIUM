"""Thread-safe SQLite (WAL) database wrapper. Parameterized SQL only.

* One shared connection guarded by an RLock (sqlite3 objects are not safe to use
  concurrently); autocommit mode with explicit ``BEGIN IMMEDIATE`` transactions.
* Identifiers (table/column names) are never taken from untrusted input: the generic
  helpers validate them against the schema whitelist before interpolation.
* ``:memory:`` is supported for tests.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from centralium.agent.storage.audit import AuditLog
from centralium.agent.storage.schema import LATEST_VERSION, MIGRATIONS, TABLES

log = logging.getLogger("centralium.storage")

Params = Sequence[Any] | dict[str, Any]


class DatabaseError(RuntimeError):
    pass


class Database:
    def __init__(self, path: str | Path = ":memory:", *, auto_migrate: bool = True) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tx_depth = 0
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._columns: dict[str, frozenset[str]] = {}
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
        self.audit = AuditLog(self)
        if auto_migrate:
            self.migrate()

    # ------------------------------------------------------------------ lifecycle
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ migrations
    def schema_version(self) -> int:
        with self._lock:
            return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    def journal_mode(self) -> str:
        with self._lock:
            return str(self._conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    def migrate(self) -> int:
        """Apply pending migrations in order, each atomically. Returns the new version."""
        current = self.schema_version()
        if current > LATEST_VERSION:
            raise DatabaseError(f"database schema v{current} is newer than supported v{LATEST_VERSION}")
        for version, desc, statements in MIGRATIONS:
            if version <= current:
                continue
            log.info("applying migration %d: %s", version, desc)
            with self.transaction() as conn:
                for stmt in statements:
                    conn.execute(stmt)
                # PRAGMA does not accept bound parameters; version is an int constant.
                conn.execute(f"PRAGMA user_version = {int(version)}")
        self._columns.clear()
        return self.schema_version()

    # ------------------------------------------------------------------ execution
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialized write transaction (re-entrant: nested calls join the outer one)."""
        with self._lock:
            outer = self._tx_depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._tx_depth += 1
            try:
                yield self._conn
            except BaseException:
                self._tx_depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._tx_depth -= 1
                if outer:
                    self._conn.execute("COMMIT")

    def execute(self, sql: str, params: Params = ()) -> int:
        """Run one write statement; returns rowcount."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.rowcount

    def executemany(self, sql: str, rows: Sequence[Params]) -> int:
        with self.transaction() as conn:
            return conn.executemany(sql, rows).rowcount

    def query(self, sql: str, params: Params = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Params = ()) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._conn.execute(sql, params).fetchone()
            return row

    def iter_query(self, sql: str, params: Params = (), chunk: int = 1000) -> Iterator[sqlite3.Row]:
        """Chunked iteration; the lock is released between chunks (OFFSET-free: caller's
        SQL must be a stable ordering). Simple implementation: materialize per call."""
        yield from self.query(sql, params)

    def scalar(self, sql: str, params: Params = ()) -> Any:
        row = self.query_one(sql, params)
        return row[0] if row else None

    # ------------------------------------------------------------------ generic helpers
    def table_columns(self, table: str) -> frozenset[str]:
        if table not in TABLES:
            raise DatabaseError(f"unknown table: {table!r}")
        cols = self._columns.get(table)
        if cols is None:
            # table is whitelisted above, safe to interpolate
            rows = self.query(f"PRAGMA table_info({table})")
            cols = frozenset(r["name"] for r in rows)
            self._columns[table] = cols
        return cols

    def insert(self, table: str, row: dict[str, Any], *, on_conflict: str = "ABORT") -> int:
        """Insert ``row`` (column names validated against the schema). Returns lastrowid.
        ``on_conflict``: ABORT | IGNORE | REPLACE."""
        if on_conflict not in {"ABORT", "IGNORE", "REPLACE"}:
            raise DatabaseError("invalid on_conflict")
        cols = self.table_columns(table)
        bad = set(row) - cols
        if bad:
            raise DatabaseError(f"unknown column(s) for {table}: {sorted(bad)}")
        if not row:
            raise DatabaseError("empty row")
        names = list(row)
        sql = (
            f"INSERT OR {on_conflict} INTO {table} ({', '.join(names)}) "  # noqa: S608 (identifiers validated against schema)
            f"VALUES ({', '.join('?' for _ in names)})"
        )
        with self._lock:
            cur = self._conn.execute(sql, [row[n] for n in names])
            return int(cur.lastrowid or 0)

    def count(self, table: str) -> int:
        if table not in TABLES:
            raise DatabaseError(f"unknown table: {table!r}")
        return int(self.scalar(f"SELECT COUNT(*) FROM {table}") or 0)  # noqa: S608

    def integrity_check(self) -> bool:
        return bool(self.scalar("PRAGMA integrity_check") == "ok")

    @staticmethod
    def now() -> str:
        return datetime.now(UTC).isoformat()
