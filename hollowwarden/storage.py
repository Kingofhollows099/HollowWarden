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
import logging
import os
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TypeVar

ResultType = TypeVar("ResultType")

log = logging.getLogger(__name__)


class MigrationError(Exception):
    """Old data can't be moved safely without the operator's help."""

# Every table is keyed by guild_id, so each server's data stays separate:
# a member is only ever matched against others in the same server.
SCHEMA_VERSION = 2
SCHEMA_TABLES = {
    "verify_tokens": """CREATE TABLE IF NOT EXISTS verify_tokens (
        token_hash TEXT PRIMARY KEY,
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )""",
    "oauth_states": """CREATE TABLE IF NOT EXISTS oauth_states (
        state_hash TEXT PRIMARY KEY,
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        nonce_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    )""",
    "ip_records": """CREATE TABLE IF NOT EXISTS ip_records (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        ip_hash TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        PRIMARY KEY (guild_id, user_id, ip_hash)
    )""",
    "pending_reviews": """CREATE TABLE IF NOT EXISTS pending_reviews (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (guild_id, user_id)
    )""",
}
SCHEMA_INDEXES = (
    "CREATE INDEX IF NOT EXISTS verify_tokens_by_member ON verify_tokens (guild_id, user_id)",
    "CREATE INDEX IF NOT EXISTS ip_records_by_guild_hash ON ip_records (guild_id, ip_hash)",
)


def sha256Hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def newSecretToken() -> str:
    return secrets.token_urlsafe(32)


class Storage:
    def __init__(self, databasePath: str, legacyGuildId: int | None = None) -> None:
        """legacyGuildId is the server that data from before multi-server
        support belongs to: the one server the bot used to run in."""
        self._databasePath = databasePath
        self._legacyGuildId = legacyGuildId
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
        try:
            connection.execute("PRAGMA secure_delete=ON")
            self._migrate(connection)
            with connection:
                for statement in (*SCHEMA_TABLES.values(), *SCHEMA_INDEXES):
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except BaseException:
            # Don't leave the file open if setting it up failed.
            connection.close()
            raise
        self._connection = connection

    def _migrate(self, connection: sqlite3.Connection) -> None:
        """Bring a database from before multi-server support up to date.

        Those tables have no guild_id. IP records and pending reviews are
        kept and assigned to the server the bot ran in, so alt detection
        keeps its history. Verification links and login states only last
        ten minutes, so they're simply dropped; anyone mid-verification
        clicks Verify again.
        """
        tableColumns = {
            table: {row[1] for row in connection.execute(f"PRAGMA table_info({table})")} for table in SCHEMA_TABLES
        }
        if not any(columns and "guild_id" not in columns for columns in tableColumns.values()):
            return
        hasOldData = any(
            tableColumns[table] and connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
            for table in ("ip_records", "pending_reviews")
        )
        if hasOldData and self._legacyGuildId is None:
            raise RuntimeError("the database has data from before multi-server support, but no server to assign it to")

        movedCounts = {}
        # One transaction: either everything moves across or nothing changes.
        # The explicit BEGIN matters. Python's sqlite3 only opens a
        # transaction by itself before INSERT/UPDATE/DELETE, so without it the
        # DROP and ALTER statements below would each commit on their own.
        with connection:
            connection.execute("BEGIN")
            connection.execute("DROP TABLE IF EXISTS verify_tokens")
            connection.execute("DROP TABLE IF EXISTS oauth_states")
            # The old indexes' names would otherwise linger until their
            # tables are dropped; remove them up front.
            connection.execute("DROP INDEX IF EXISTS ip_records_by_hash")
            connection.execute("DROP INDEX IF EXISTS verify_tokens_by_user")
            for table, columns in (
                ("ip_records", "user_id, ip_hash, first_seen, last_seen"),
                ("pending_reviews", "user_id, created_at"),
            ):
                if not tableColumns[table]:
                    continue
                connection.execute(f"ALTER TABLE {table} RENAME TO {table}_before_guilds")
                connection.execute(SCHEMA_TABLES[table])
                movedCounts[table] = connection.execute(
                    f"INSERT INTO {table} (guild_id, {columns}) SELECT ?, {columns} FROM {table}_before_guilds",
                    (self._legacyGuildId,),
                ).rowcount
                connection.execute(f"DROP TABLE {table}_before_guilds")
        log.info(
            "database upgraded for multiple servers: %s IP records and %s pending reviews assigned to GUILD_ID %s",
            movedCounts.get("ip_records", 0),
            movedCounts.get("pending_reviews", 0),
            self._legacyGuildId,
        )

    async def close(self) -> None:
        if self._connection is not None:
            await self._run(self._connection.close)
            self._connection = None
        self._executor.shutdown(wait=True)

    # Verification links

    async def createVerifyToken(self, guildId: int, userId: int, lifetimeSeconds: int, now: float | None = None) -> str:
        token = newSecretToken()
        expiresAt = int((time.time() if now is None else now) + lifetimeSeconds)

        def insert() -> None:
            with self.connection:
                # Only the newest link for a member is valid, so links pasted
                # in old messages stop working once a new one is issued.
                self.connection.execute(
                    "DELETE FROM verify_tokens WHERE guild_id = ? AND user_id = ?", (guildId, userId)
                )
                self.connection.execute(
                    "INSERT INTO verify_tokens (token_hash, guild_id, user_id, expires_at) VALUES (?, ?, ?, ?)",
                    (sha256Hex(token), guildId, userId, expiresAt),
                )

        await self._run(insert)
        return token

    async def consumeVerifyToken(self, token: str, now: float | None = None) -> tuple[int, int] | None:
        """Return the token's (guild, user) and delete it, so each link works only once."""
        currentTime = int(time.time() if now is None else now)

        def consume() -> tuple[int, int] | None:
            with self.connection:
                row = self.connection.execute(
                    "DELETE FROM verify_tokens WHERE token_hash = ? RETURNING guild_id, user_id, expires_at",
                    (sha256Hex(token),),
                ).fetchone()
            if row is None or row[2] < currentTime:
                return None
            return int(row[0]), int(row[1])

        return await self._run(consume)

    # OAuth state (CSRF protection for the login round trip)

    async def createOauthState(
        self, guildId: int, userId: int, lifetimeSeconds: int, now: float | None = None
    ) -> tuple[str, str]:
        state = newSecretToken()
        browserNonce = newSecretToken()
        expiresAt = int((time.time() if now is None else now) + lifetimeSeconds)

        def insert() -> None:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO oauth_states (state_hash, guild_id, user_id, nonce_hash, expires_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (sha256Hex(state), guildId, userId, sha256Hex(browserNonce), expiresAt),
                )

        await self._run(insert)
        return state, browserNonce

    async def consumeOauthState(self, state: str, now: float | None = None) -> tuple[int, int, str] | None:
        """Return the state's (guild, user, nonce hash) and delete it."""
        currentTime = int(time.time() if now is None else now)

        def consume() -> tuple[int, int, str] | None:
            with self.connection:
                row = self.connection.execute(
                    "DELETE FROM oauth_states WHERE state_hash = ? RETURNING guild_id, user_id, nonce_hash, expires_at",
                    (sha256Hex(state),),
                ).fetchone()
            if row is None or row[3] < currentTime:
                return None
            return int(row[0]), int(row[1]), str(row[2])

        return await self._run(consume)

    # Alt detection

    async def recordIpAndFindMatches(
        self, guildId: int, userId: int, ipHash: str, now: float | None = None
    ) -> list[int]:
        """Store this member's IP hash and return other members of the same
        server who share it. Other servers' records are never consulted."""
        currentTime = int(time.time() if now is None else now)

        def recordAndMatch() -> list[int]:
            with self.connection:
                rows = self.connection.execute(
                    "SELECT DISTINCT user_id FROM ip_records "
                    "WHERE guild_id = ? AND ip_hash = ? AND user_id != ? ORDER BY user_id",
                    (guildId, ipHash, userId),
                ).fetchall()
                self.connection.execute(
                    "INSERT INTO ip_records (guild_id, user_id, ip_hash, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT (guild_id, user_id, ip_hash) DO UPDATE SET last_seen = excluded.last_seen",
                    (guildId, userId, ipHash, currentTime, currentTime),
                )
            return [int(row[0]) for row in rows]

        return await self._run(recordAndMatch)

    # Moderator reviews

    async def addPendingReview(self, guildId: int, userId: int, now: float | None = None) -> None:
        createdAt = int(time.time() if now is None else now)

        def insert() -> None:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO pending_reviews (guild_id, user_id, created_at) VALUES (?, ?, ?)",
                    (guildId, userId, createdAt),
                )

        await self._run(insert)

    async def hasPendingReview(self, guildId: int, userId: int) -> bool:
        def check() -> bool:
            row = self.connection.execute(
                "SELECT 1 FROM pending_reviews WHERE guild_id = ? AND user_id = ?", (guildId, userId)
            ).fetchone()
            return row is not None

        return await self._run(check)

    async def popPendingReview(self, guildId: int, userId: int) -> bool:
        """Remove a pending review. Returns False if there wasn't one, which
        stops two moderators clicking at once from both acting on it."""

        def pop() -> bool:
            with self.connection:
                cursor = self.connection.execute(
                    "DELETE FROM pending_reviews WHERE guild_id = ? AND user_id = ?", (guildId, userId)
                )
            return cursor.rowcount > 0

        return await self._run(pop)

    # Housekeeping

    async def purgeExpired(
        self,
        ipRetentionSecondsByGuild: Mapping[int, int] | None = None,
        otherGuildsRetentionSeconds: int | None = None,
        now: float | None = None,
    ) -> None:
        """Delete expired links and login states, and IP records older than
        each server's retention period. Records from servers no longer in
        the config use otherGuildsRetentionSeconds, so removing a server
        from the config doesn't keep its data forever."""
        currentTime = int(time.time() if now is None else now)
        retentionByGuild = dict(ipRetentionSecondsByGuild or {})

        def purge() -> None:
            with self.connection:
                self.connection.execute("DELETE FROM verify_tokens WHERE expires_at < ?", (currentTime,))
                self.connection.execute("DELETE FROM oauth_states WHERE expires_at < ?", (currentTime,))
                for guildId, retentionSeconds in retentionByGuild.items():
                    self.connection.execute(
                        "DELETE FROM ip_records WHERE guild_id = ? AND last_seen < ?",
                        (guildId, currentTime - retentionSeconds),
                    )
                if otherGuildsRetentionSeconds is not None:
                    cutoff = currentTime - otherGuildsRetentionSeconds
                    if retentionByGuild:
                        placeholders = ", ".join("?" for _ in retentionByGuild)
                        self.connection.execute(
                            f"DELETE FROM ip_records WHERE guild_id NOT IN ({placeholders}) AND last_seen < ?",
                            (*retentionByGuild, cutoff),
                        )
                    else:
                        # Not "NOT IN (NULL)": in SQL that's never true, so it
                        # would silently delete nothing.
                        self.connection.execute("DELETE FROM ip_records WHERE last_seen < ?", (cutoff,))

        await self._run(purge)


class ServerStorage:
    """One database per server, each in its own directory:
    <data directory>/servers/<guild id>/hollowwarden.db.

    Keeping servers in separate files means one server's records can't turn
    up in another's queries even by mistake, and removing a server's data is
    a matter of deleting its directory.

    Verification links and OAuth states start with the server's guild ID
    ("<guild id>.<secret>"), so a request can be routed to the right
    database. Tampering with that prefix just sends the lookup to a database
    where the secret doesn't exist.
    """

    def __init__(
        self,
        dataDirectory: Path,
        guildIds: list[int],
        legacyDatabasePath: Path | None = None,
        legacyGuildId: int | None = None,
    ) -> None:
        self.dataDirectory = dataDirectory
        self.guildIds = list(guildIds)
        self.legacyDatabasePath = legacyDatabasePath
        self.legacyGuildId = legacyGuildId
        self._stores: dict[int, Storage] = {}

    def databasePathFor(self, guildId: int) -> Path:
        return self.dataDirectory / "servers" / str(guildId) / "hollowwarden.db"

    async def open(self) -> None:
        await self._moveLegacyDatabase()
        for guildId in self.guildIds:
            databasePath = self.databasePathFor(guildId)
            databasePath.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            store = Storage(str(databasePath))
            await store.open()
            self._stores[guildId] = store
        for orphanDirectory in self.unconfiguredDirectories():
            log.warning(
                "%s holds data for a server that's no longer configured. Its old IP records are still "
                "deleted on schedule; delete the directory if you don't need the rest",
                orphanDirectory,
            )

    async def _moveLegacyDatabase(self) -> None:
        """Move the single database from before multi-server support into
        its server's directory, upgrading it on the way."""
        legacyPath = self.legacyDatabasePath
        if legacyPath is None or not legacyPath.exists():
            return
        if self.legacyGuildId is None or self.legacyGuildId not in self.guildIds:
            raise MigrationError(
                f"{legacyPath} holds data from before multi-server support, and with several servers configured "
                "the bot can't tell which one it belongs to. Set LEGACY_DATA_GUILD_ID in .env to that server's "
                "guild_id (the server the bot used to run in)"
            )
        targetPath = self.databasePathFor(self.legacyGuildId)
        if targetPath.exists():
            # Never merge or overwrite: leave both for the operator to sort out.
            log.error("not moving %s: %s already exists. Neither file was changed", legacyPath, targetPath)
            return
        targetPath.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        legacyStore = Storage(str(legacyPath), legacyGuildId=self.legacyGuildId)
        await legacyStore.open()
        await legacyStore.close()
        # Closing checkpoints the write-ahead log, but move its files too in
        # case any are left, so nothing is separated from its database.
        for suffix in ("", "-wal", "-shm"):
            sourcePath = Path(f"{legacyPath}{suffix}")
            if sourcePath.exists():
                os.replace(sourcePath, f"{targetPath}{suffix}")
                # Owner-only, whatever permissions the old file had.
                os.chmod(f"{targetPath}{suffix}", 0o600)
        log.info("moved %s to %s", legacyPath, targetPath)

    def unconfiguredDirectories(self) -> list[Path]:
        serversDirectory = self.dataDirectory / "servers"
        if not serversDirectory.is_dir():
            return []
        configured = {str(guildId) for guildId in self.guildIds}
        return sorted(path for path in serversDirectory.iterdir() if path.is_dir() and path.name not in configured)

    async def close(self) -> None:
        for store in self._stores.values():
            await store.close()
        self._stores.clear()

    def forGuild(self, guildId: int) -> Storage:
        try:
            return self._stores[guildId]
        except KeyError:
            raise KeyError(f"server {guildId} isn't configured") from None

    def _routeSecret(self, routedValue: str) -> tuple[Storage, str] | None:
        guildText, separator, secret = routedValue.partition(".")
        if not separator or not guildText.isdigit():
            return None
        store = self._stores.get(int(guildText))
        return (store, secret) if store is not None else None

    # The same operations as Storage, routed to each server's own database.

    async def createVerifyToken(self, guildId: int, userId: int, lifetimeSeconds: int, now: float | None = None) -> str:
        secret = await self.forGuild(guildId).createVerifyToken(guildId, userId, lifetimeSeconds, now=now)
        return f"{guildId}.{secret}"

    async def consumeVerifyToken(self, token: str, now: float | None = None) -> tuple[int, int] | None:
        routed = self._routeSecret(token)
        return await routed[0].consumeVerifyToken(routed[1], now=now) if routed else None

    async def createOauthState(
        self, guildId: int, userId: int, lifetimeSeconds: int, now: float | None = None
    ) -> tuple[str, str]:
        secret, browserNonce = await self.forGuild(guildId).createOauthState(guildId, userId, lifetimeSeconds, now=now)
        return f"{guildId}.{secret}", browserNonce

    async def consumeOauthState(self, state: str, now: float | None = None) -> tuple[int, int, str] | None:
        routed = self._routeSecret(state)
        return await routed[0].consumeOauthState(routed[1], now=now) if routed else None

    async def recordIpAndFindMatches(self, guildId: int, userId: int, ipHash: str, now: float | None = None) -> list[int]:
        return await self.forGuild(guildId).recordIpAndFindMatches(guildId, userId, ipHash, now=now)

    async def addPendingReview(self, guildId: int, userId: int, now: float | None = None) -> None:
        await self.forGuild(guildId).addPendingReview(guildId, userId, now=now)

    async def hasPendingReview(self, guildId: int, userId: int) -> bool:
        return await self.forGuild(guildId).hasPendingReview(guildId, userId)

    async def popPendingReview(self, guildId: int, userId: int) -> bool:
        return await self.forGuild(guildId).popPendingReview(guildId, userId)

    async def purgeExpired(
        self, ipRetentionSecondsByGuild: Mapping[int, int], otherServersRetentionSeconds: int, now: float | None = None
    ) -> None:
        for guildId, store in self._stores.items():
            retentionSeconds = ipRetentionSecondsByGuild[guildId]
            await store.purgeExpired({guildId: retentionSeconds}, otherGuildsRetentionSeconds=retentionSeconds, now=now)
        # Servers removed from the config still get their old IP records
        # deleted, so taking a server out doesn't keep its data forever.
        for orphanDirectory in self.unconfiguredDirectories():
            databasePath = orphanDirectory / "hollowwarden.db"
            if not databasePath.exists():
                continue
            orphanStore = Storage(str(databasePath))
            try:
                await orphanStore.open()
                await orphanStore.purgeExpired(otherGuildsRetentionSeconds=otherServersRetentionSeconds, now=now)
            finally:
                await orphanStore.close()
