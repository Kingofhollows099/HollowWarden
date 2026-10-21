"""SQLite persistence.

All database access runs on one dedicated worker thread. sqlite3 connections
must not be shared between threads, and funnelling every query through one
thread also serialises writes, which avoids "database is locked" errors
without needing a connection pool.

Verification tokens and OAuth states are stored as SHA-256 hashes, not in
their raw form. If the database file ever leaked, the attacker couldn't use
anything in it to finish someone else's verification. The raw values are high
entropy (256 bits), so a plain hash is enough here; IP addresses need a keyed
hash instead, which happens in netutil.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import sqlite3
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

ResultType = TypeVar("ResultType")

SCHEMA = """
CREATE TABLE IF NOT EXISTS verify_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS verify_tokens_by_user ON verify_tokens (user_id);

CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    nonce_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_records (
    user_id INTEGER NOT NULL,
    ip_hash TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (user_id, ip_hash)
);
CREATE INDEX IF NOT EXISTS ip_records_by_hash ON ip_records (ip_hash);

CREATE TABLE IF NOT EXISTS pending_reviews (
    user_id INTEGER PRIMARY KEY,
    created_at INTEGER NOT NULL
);
"""


def sha256Hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def newSecretToken() -> str:
    return secrets.token_urlsafe(32)


class Storage:
    def __init__(self, databasePath: str) -> None:
        self._databasePath = databasePath
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="storage")
        self._connection: sqlite3.Connection | None = None

    async def _run(self, function: Callable[..., ResultType], *args: object) -> ResultType:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, function, *args)

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("Storage.open() has not been called")
        return self._connection

    async def open(self) -> None:
        await self._run(self._openSync)

    def _openSync(self) -> None:
        connection = sqlite3.connect(self._databasePath, check_same_thread=False)
        connection.execute("PRAGMA journal_mode=WAL")
        # Overwrite deleted rows with zeros, so purged IP hashes don't linger
        # in free pages of the file where a forensic tool could recover them.
        connection.execute("PRAGMA secure_delete=ON")
        connection.executescript(SCHEMA)
        self._connection = connection

    async def close(self) -> None:
        if self._connection is not None:
            await self._run(self._connection.close)
            self._connection = None
        self._executor.shutdown(wait=True)

    # Verification links

    async def createVerifyToken(self, userId: int, lifetimeSeconds: int, now: float | None = None) -> str:
        token = newSecretToken()
        expiresAt = int((time.time() if now is None else now) + lifetimeSeconds)

        def insert() -> None:
            with self.connection:
                # Only the newest link for a user is valid, so links pasted in
                # old messages stop working once a new one is issued.
                self.connection.execute("DELETE FROM verify_tokens WHERE user_id = ?", (userId,))
                self.connection.execute(
                    "INSERT INTO verify_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    (sha256Hex(token), userId, expiresAt),
                )

        await self._run(insert)
        return token

    async def consumeVerifyToken(self, token: str, now: float | None = None) -> int | None:
        """Return the token's user and delete it, so each link works only once."""
        currentTime = int(time.time() if now is None else now)

        def consume() -> int | None:
            with self.connection:
                row = self.connection.execute(
                    "DELETE FROM verify_tokens WHERE token_hash = ? RETURNING user_id, expires_at",
                    (sha256Hex(token),),
                ).fetchone()
            if row is None or row[1] < currentTime:
                return None
            return int(row[0])

        return await self._run(consume)

    # OAuth state (CSRF protection for the login round trip)

    async def createOauthState(self, userId: int, lifetimeSeconds: int, now: float | None = None) -> tuple[str, str]:
        state = newSecretToken()
        browserNonce = newSecretToken()
        expiresAt = int((time.time() if now is None else now) + lifetimeSeconds)

        def insert() -> None:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO oauth_states (state_hash, user_id, nonce_hash, expires_at) VALUES (?, ?, ?, ?)",
                    (sha256Hex(state), userId, sha256Hex(browserNonce), expiresAt),
                )

        await self._run(insert)
        return state, browserNonce

    async def consumeOauthState(self, state: str, now: float | None = None) -> tuple[int, str] | None:
        currentTime = int(time.time() if now is None else now)

        def consume() -> tuple[int, str] | None:
            with self.connection:
                row = self.connection.execute(
                    "DELETE FROM oauth_states WHERE state_hash = ? RETURNING user_id, nonce_hash, expires_at",
                    (sha256Hex(state),),
                ).fetchone()
            if row is None or row[2] < currentTime:
                return None
            return int(row[0]), str(row[1])

        return await self._run(consume)

    # Alt detection

    async def recordIpAndFindMatches(self, userId: int, ipHash: str, now: float | None = None) -> list[int]:
        """Store this user's IP hash and return other users who share it."""
        currentTime = int(time.time() if now is None else now)

        def recordAndMatch() -> list[int]:
            with self.connection:
                rows = self.connection.execute(
                    "SELECT DISTINCT user_id FROM ip_records WHERE ip_hash = ? AND user_id != ? ORDER BY user_id",
                    (ipHash, userId),
                ).fetchall()
                self.connection.execute(
                    "INSERT INTO ip_records (user_id, ip_hash, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT (user_id, ip_hash) DO UPDATE SET last_seen = excluded.last_seen",
                    (userId, ipHash, currentTime, currentTime),
                )
            return [int(row[0]) for row in rows]

        return await self._run(recordAndMatch)

    # Moderator reviews

    async def addPendingReview(self, userId: int, now: float | None = None) -> None:
        createdAt = int(time.time() if now is None else now)

        def insert() -> None:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO pending_reviews (user_id, created_at) VALUES (?, ?)",
                    (userId, createdAt),
                )

        await self._run(insert)

    async def hasPendingReview(self, userId: int) -> bool:
        def check() -> bool:
            row = self.connection.execute("SELECT 1 FROM pending_reviews WHERE user_id = ?", (userId,)).fetchone()
            return row is not None

        return await self._run(check)

    async def popPendingReview(self, userId: int) -> bool:
        """Remove a pending review. Returns False if there wasn't one, which
        stops two moderators clicking at once from both acting on it."""

        def pop() -> bool:
            with self.connection:
                cursor = self.connection.execute("DELETE FROM pending_reviews WHERE user_id = ?", (userId,))
            return cursor.rowcount > 0

        return await self._run(pop)

    # Housekeeping

    async def purgeExpired(self, ipRetentionSeconds: int | None, now: float | None = None) -> None:
        currentTime = int(time.time() if now is None else now)

        def purge() -> None:
            with self.connection:
                self.connection.execute("DELETE FROM verify_tokens WHERE expires_at < ?", (currentTime,))
                self.connection.execute("DELETE FROM oauth_states WHERE expires_at < ?", (currentTime,))
                if ipRetentionSeconds is not None:
                    self.connection.execute(
                        "DELETE FROM ip_records WHERE last_seen < ?", (currentTime - ipRetentionSeconds,)
                    )

        await self._run(purge)
