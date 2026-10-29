"""Local HTTP session admission, persistent logout and bounded login attempts.

This is separate from canonical rulings and never upgrades their provisional provenance.
The SQLite write gate serializes HTTP session validation/logout with the guarded operation,
including across app instances sharing the state root. No raw session/credential is stored.
"""

import hashlib
import os
import sqlite3
import stat
from contextlib import contextmanager

from .security import BoundaryError

_TABLE_SQL = {
    "sessions": "CREATE TABLE sessions (token_sha256 TEXT PRIMARY KEY, expires INTEGER NOT NULL)",
    "attempts": "CREATE TABLE attempts (id INTEGER PRIMARY KEY CHECK(id=1), "
    "window INTEGER NOT NULL, count INTEGER NOT NULL)",
}


class WebAuth:
    def __init__(self, root):
        self.path = root / "web-auth.sqlite3"
        with self.transaction(initializing=True) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
                if tables.fetchall():
                    raise BoundaryError("auth_store_unavailable")
                for statement in _TABLE_SQL.values():
                    connection.execute(statement)
                connection.execute("PRAGMA user_version=1")
            elif version != 1:
                raise BoundaryError("auth_store_unavailable")

    @contextmanager
    def transaction(self, *, initializing=False):
        # Owner-controlled root is validated by LocalWorkflow. Reject static replacement of
        # this separate database and SQLite sidecars; hostile concurrent filesystem swaps
        # remain outside the single-owner local-directory contract.
        for parent in (*reversed(self.path.parent.parents), self.path.parent):
            info = parent.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400
            ):
                raise BoundaryError("auth_store_unavailable")
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = self.path.with_name(self.path.name + suffix)
            if os.path.lexists(path):
                info = path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & 0x400
                    or info.st_nlink != 1
                ):
                    raise BoundaryError("auth_store_unavailable")
        connection = sqlite3.connect(self.path, timeout=2, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            # A live instance must not keep using a store changed by another instance or
            # an unsupported upgrade. Check under the same gate as the guarded operation.
            if not initializing:
                self._require_schema(connection)
            yield connection
            if initializing:
                self._require_schema(connection)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _require_schema(connection):
        if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise BoundaryError("auth_store_unavailable")
        actual = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name"
        ).fetchall()
        expected = sorted(("table", name, name, sql) for name, sql in _TABLE_SQL.items())
        if actual != expected:
            raise BoundaryError("auth_store_unavailable")

    @staticmethod
    def token_id(session):
        return hashlib.sha256(session.encode("ascii")).hexdigest()

    def require(self, connection, boundary, session, now):
        boundary.require_session(session, now=now)
        row = connection.execute(
            "SELECT expires FROM sessions WHERE token_sha256=?", (self.token_id(session),)
        ).fetchone()
        if row is None or row[0] <= now:
            raise BoundaryError("operator_session_required")

    def attempt(self, connection, now):
        row = connection.execute("SELECT window,count FROM attempts WHERE id=1").fetchone()
        window, count = (now, 0) if row is None else row
        if now < window or now - window >= 60:
            window, count = now, 0
        if count >= 5:
            return False
        connection.execute("INSERT OR REPLACE INTO attempts VALUES(1,?,?)", (window, count + 1))
        return True

    def admit(self, connection, session, now):
        connection.execute("DELETE FROM sessions WHERE expires<=?", (now,))
        if connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] >= 64:
            raise BoundaryError("session_capacity")
        connection.execute(
            "INSERT INTO sessions VALUES(?,?)", (self.token_id(session.value), session.expires_at)
        )

    def revoke(self, connection, session):
        connection.execute("DELETE FROM sessions WHERE token_sha256=?", (self.token_id(session),))
