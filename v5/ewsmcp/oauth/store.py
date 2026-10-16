"""SQLite persistence for OAuth clients and grants (``<DATA_DIR>/oauth.db``).

Grants survive restarts, so users are not forced to sign in again after a
deploy. Rows hold token hashes and token-sealed ciphertext only (see
``sealing``); losing this file costs re-logins, leaking it opens nothing.
"""

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

MAX_CLIENTS = 10_000  # dynamic registration is anonymous — bound it

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id  TEXT PRIMARY KEY,
    info       TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    id         TEXT PRIMARY KEY,   -- sha256(token)
    kind       TEXT NOT NULL,      -- code | access | refresh
    family     TEXT NOT NULL,      -- one login's lineage of codes/tokens
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL,      -- mailbox SMTP address
    username   TEXT NOT NULL,      -- Exchange logon name
    scopes     TEXT NOT NULL,
    resource   TEXT,
    expires_at REAL NOT NULL,
    sealed     TEXT NOT NULL,      -- password sealed under the token
    extra      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS grants_subject ON grants(subject);
CREATE INDEX IF NOT EXISTS grants_family ON grants(family);
"""


@dataclass
class Grant:
    id: str
    kind: str
    family: str
    client_id: str
    subject: str
    username: str
    scopes: List[str]
    resource: Optional[str]
    expires_at: float
    sealed: str
    extra: Dict[str, Any]


class OAuthStore:
    def __init__(self, data_dir: str):
        path = Path(data_dir) / "oauth.db"
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False,
                                   isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        try:
            path.chmod(0o600)
        except OSError:
            pass

    # ---------------------------------------------------------------- clients

    def put_client(self, client_id: str, info: Dict[str, Any]) -> bool:
        with self._lock:
            (count,) = self._db.execute("SELECT COUNT(*) FROM clients").fetchone()
            if count >= MAX_CLIENTS:
                return False
            self._db.execute(
                "INSERT OR REPLACE INTO clients(client_id, info, created_at) VALUES (?,?,?)",
                (client_id, json.dumps(info), time.time()))
            return True

    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._db.execute(
                "SELECT info FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        return json.loads(row[0]) if row else None

    # ----------------------------------------------------------------- grants

    def put_grant(self, g: Grant) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO grants(id, kind, family, client_id, subject, "
                "username, scopes, resource, expires_at, sealed, extra) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (g.id, g.kind, g.family, g.client_id, g.subject, g.username,
                 json.dumps(g.scopes), g.resource, g.expires_at, g.sealed,
                 json.dumps(g.extra)))

    def get_grant(self, grant_id: str, kind: str) -> Optional[Grant]:
        with self._lock:
            row = self._db.execute(
                "SELECT id, kind, family, client_id, subject, username, scopes, "
                "resource, expires_at, sealed, extra FROM grants "
                "WHERE id = ? AND kind = ?", (grant_id, kind)).fetchone()
        if row is None:
            return None
        g = Grant(*row[:6], json.loads(row[6]), row[7], row[8], row[9], json.loads(row[10]))
        if g.expires_at < time.time():
            self.delete_grant(g.id)
            return None
        return g

    def delete_grant(self, grant_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM grants WHERE id = ?", (grant_id,))

    def delete_family(self, family: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM grants WHERE family = ?", (family,))

    def delete_subject(self, subject: str) -> int:
        with self._lock:
            return self._db.execute(
                "DELETE FROM grants WHERE subject = ?", (subject,)).rowcount

    def purge_expired(self) -> int:
        with self._lock:
            return self._db.execute(
                "DELETE FROM grants WHERE expires_at < ?", (time.time(),)).rowcount
