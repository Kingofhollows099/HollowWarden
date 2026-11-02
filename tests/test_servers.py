"""Multiple servers: one settings file per server, separate data, and
isolation (nothing from one server ever affects or shows up in another)."""

import logging
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest

from hollowwarden.bot import HollowWardenBot, StartupError
from hollowwarden.config import ConfigError, loadSettings
from hollowwarden.storage import MigrationError, ServerStorage
from hollowwarden.verification import Outcome, Verifier
from hollowwarden.web import VerificationSite

from .test_admin import makeInteraction
from .test_core import baseEnviron, webEnviron
from .test_flow import NEW_USER, OLD_USER, OTHER_OLD_USER, FakeGateway, FakeOAuth, finishFlow

FRIENDS = 111111111111111111
GAMING = 777777777777777771
FRIENDS_ADMIN_ROLE = 555555555555555555
GAMING_ADMIN_ROLE = 777777777777777772


def friendsSettings(**changes):
    values = {
        "guild_id": str(FRIENDS),
        "verified_role_id": "222222222222222222",
        "mod_channel_id": "333333333333333333",
        "admin_role_ids": [str(FRIENDS_ADMIN_ROLE)],
        "verify_method": "web",
    }
    values.update(changes)
    return values


def gamingSettings(**changes):
    values = {
        "name": "Gaming",
        "guild_id": str(GAMING),
        "verified_role_id": "777777777777777773",
        "mod_channel_id": "777777777777777774",
        "admin_role_ids": [str(GAMING_ADMIN_ROLE)],
        "verify_method": "captcha",
        "min_account_age_days": 0,
        "flagged_action": "allow",
    }
    values.update(changes)
    return values


def toToml(values):
    lines = []
    for key, value in values.items():
        if isinstance(value, bool):
            lines.append(f"{key} = {str(value).lower()}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        elif isinstance(value, list):
            lines.append(f"{key} = [{', '.join(repr(item).replace(chr(39), chr(34)) for item in value)}]")
        else:
            lines.append(f'{key} = "{value}"')
    return "\n".join(lines) + "\n"


def writeServers(tmp_path, servers):
    """servers: {file name without .toml: settings dict or raw text}."""
    serversDirectory = tmp_path / "config" / "servers"
    serversDirectory.mkdir(parents=True, exist_ok=True)
    (serversDirectory / "README.md").write_text("Files that don't end in .toml are ignored.")
    for name, values in servers.items():
        text = values if isinstance(values, str) else toToml(values)
        (serversDirectory / f"{name}.toml").write_text(text)
    return serversDirectory


def environWithServers(tmp_path, servers, **overrides):
    environ = webEnviron(tmp_path, SERVERS_DIR=str(writeServers(tmp_path, servers)), TRUSTED_PROXIES="127.0.0.1/32")
    # Per-server settings live in each server's .toml file, not .env.
    for name in ("GUILD_ID", "VERIFIED_ROLE_ID", "MOD_CHANNEL_ID", "ADMIN_ROLE_IDS", "VERIFY_METHOD"):
        environ.pop(name, None)
    environ.update(overrides)
    return environ


@pytest.fixture
def twoServers(tmp_path):
    return loadSettings(environWithServers(tmp_path, {"friends": friendsSettings(), "gaming": gamingSettings()}))


@pytest.fixture
async def twoStores(tmp_path):
    stores = ServerStorage(tmp_path / "data", [FRIENDS, GAMING])
    await stores.open()
    yield stores
    await stores.close()


class TestServerFiles:
    def test_eachServerLoadsItsOwnSettings(self, twoServers):
        friends, gaming = twoServers.servers[FRIENDS], twoServers.servers[GAMING]
        assert friends.name == "friends"  # defaults to the file name
        assert gaming.name == "Gaming"
        assert (friends.verifyMethod, gaming.verifyMethod) == ("web", "captcha")
        assert (friends.flaggedAction, gaming.flaggedAction) == ("review", "allow")
        assert (friends.minAccountAgeDays, gaming.minAccountAgeDays) == (7, 0)
        assert friends.adminRoleIds == {FRIENDS_ADMIN_ROLE} and gaming.adminRoleIds == {GAMING_ADMIN_ROLE}
        assert twoServers.web is not None  # one server uses web, so it's loaded

    def test_noServerDirectoriesFallsBackToEnv(self, tmp_path):
        emptyDirectory = tmp_path / "config" / "servers"
        emptyDirectory.mkdir(parents=True)
        (emptyDirectory / "README.md").write_text("only a readme")
        settings = loadSettings(baseEnviron(tmp_path, SERVERS_DIR=str(emptyDirectory)))
        assert list(settings.servers) == [FRIENDS]
        assert settings.legacyDataGuildId == FRIENDS

    def test_webSecretsNotNeededWhenNoServerUsesWeb(self, tmp_path):
        environ = environWithServers(tmp_path, {"gaming": gamingSettings()})
        for name in ("PUBLIC_BASE_URL", "DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET_FILE", "IP_HASH_KEY_FILE"):
            environ.pop(name)
        assert loadSettings(environ).web is None

    @pytest.mark.parametrize(
        "servers, expected",
        [
            ({"friends": friendsSettings(admin_roles=["1"])}, "unknown setting"),  # typo of admin_role_ids
            ({"friends": "guild_id = "}, "isn't valid TOML"),
            ({"bad name!": friendsSettings()}, "use only letters"),
            ({"friends": friendsSettings(verify_method="sms")}, "verify_method must be one of"),
            ({"friends": friendsSettings(flag_vpn="yes")}, "flag_vpn must be true or false"),
            ({"friends": friendsSettings(min_account_age_days=True)}, "whole number"),
            ({"friends": friendsSettings(admin_role_ids=[str(FRIENDS)])}, "@everyone"),
            ({"friends": friendsSettings(admin_role_ids="555555555555555555")}, "must be a list"),
            ({"a": friendsSettings(), "b": gamingSettings(guild_id=str(FRIENDS))}, "same guild_id"),
            # A shared mod channel would show one server's reviews to the other's moderators.
            ({"a": friendsSettings(), "b": gamingSettings(mod_channel_id="333333333333333333")}, "same mod_channel_id"),
        ],
    )
    def test_mistakesAreRejectedClearly(self, tmp_path, servers, expected):
        with pytest.raises(ConfigError, match=expected):
            loadSettings(environWithServers(tmp_path, servers))

    def test_folderFromTheFirstLayoutGivesTheMoveCommand(self, tmp_path):
        serversDirectory = writeServers(tmp_path, {"gaming": gamingSettings()})
        (serversDirectory / "friends").mkdir()
        (serversDirectory / "friends" / "settings.toml").write_text(toToml(friendsSettings()))
        environ = environWithServers(tmp_path, {})
        with pytest.raises(ConfigError, match=r"servers/friends/ is a folder\. Move it with: mv .*friends/settings\.toml .*friends\.toml"):
            loadSettings(environ)

    def test_otherFilesAreIgnored(self, tmp_path):
        serversDirectory = writeServers(tmp_path, {"friends": friendsSettings()})
        (serversDirectory / "notes.txt").write_text("not a server")
        (serversDirectory / "friends.toml.bak").write_text("an old copy")
        (serversDirectory / ".hidden.toml").write_text("an editor's temporary file")
        assert list(loadSettings(environWithServers(tmp_path, {})).servers) == [FRIENDS]

    def test_perServerSettingsLeftInEnvAreRejected(self, tmp_path):
        environ = environWithServers(tmp_path, {"friends": friendsSettings()}, GUILD_ID=str(FRIENDS))
        with pytest.raises(ConfigError, match="GUILD_ID are set in .env"):
            loadSettings(environ)

    def test_legacyDataServer(self, tmp_path):
        servers = {"friends": friendsSettings(), "gaming": gamingSettings()}
        assert loadSettings(environWithServers(tmp_path, servers)).legacyDataGuildId is None
        named = loadSettings(environWithServers(tmp_path / "2", servers, LEGACY_DATA_GUILD_ID=str(GAMING)))
        assert named.legacyDataGuildId == GAMING
        with pytest.raises(ConfigError, match="LEGACY_DATA_GUILD_ID"):
            loadSettings(environWithServers(tmp_path / "3", servers, LEGACY_DATA_GUILD_ID="999999999999999999"))


def createLegacyDatabase(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE verify_tokens (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE oauth_states (state_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, nonce_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL);
        CREATE TABLE ip_records (user_id INTEGER NOT NULL, ip_hash TEXT NOT NULL, first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL, PRIMARY KEY (user_id, ip_hash));
        CREATE INDEX ip_records_by_hash ON ip_records (ip_hash);
        CREATE TABLE pending_reviews (user_id INTEGER PRIMARY KEY, created_at INTEGER NOT NULL);
        INSERT INTO verify_tokens VALUES ('old', 1, 9999999999);
        """
    )
    connection.execute("INSERT INTO ip_records VALUES (?, 'hashA', 1, 9999999999)", (OLD_USER,))
    connection.execute("INSERT INTO pending_reviews VALUES (?, 5)", (NEW_USER,))
    connection.commit()
    connection.close()


class TestSeparateData:
    async def test_eachServerHasItsOwnDatabaseDirectory(self, tmp_path, twoStores):
        for guildId in (FRIENDS, GAMING):
            databasePath = tmp_path / "data" / "servers" / str(guildId) / "hollowwarden.db"
            assert databasePath.exists()
            assert databasePath.parent.stat().st_mode & 0o077 == 0  # owner-only directory

    async def test_altsAreOnlyMatchedWithinOneServer(self, twoStores):
        await twoStores.recordIpAndFindMatches(FRIENDS, OLD_USER, "hashA")
        assert await twoStores.recordIpAndFindMatches(GAMING, OTHER_OLD_USER, "hashA") == []
        assert await twoStores.recordIpAndFindMatches(FRIENDS, OTHER_OLD_USER, "hashA") == [OLD_USER]

    async def test_reviewsAndLinksAreSeparate(self, twoStores):
        await twoStores.addPendingReview(FRIENDS, NEW_USER)
        assert not await twoStores.hasPendingReview(GAMING, NEW_USER)
        assert not await twoStores.popPendingReview(GAMING, NEW_USER)
        assert await twoStores.hasPendingReview(FRIENDS, NEW_USER)

        token = await twoStores.createVerifyToken(GAMING, OLD_USER, 60)
        secret = token.split(".", 1)[1]
        # Swapping the server prefix doesn't find the link in another server.
        assert await twoStores.consumeVerifyToken(f"{FRIENDS}.{secret}") is None
        assert await twoStores.consumeVerifyToken(token) == (GAMING, OLD_USER)
        assert await twoStores.consumeVerifyToken("not-a-token") is None
        assert await twoStores.consumeVerifyToken(f"123456789012345678.{secret}") is None  # unknown server

    async def test_eachServerKeepsIpRecordsForItsOwnPeriod(self, twoStores):
        await twoStores.recordIpAndFindMatches(FRIENDS, OLD_USER, "hashA", now=1000)
        await twoStores.recordIpAndFindMatches(GAMING, OLD_USER, "hashA", now=1000)
        await twoStores.purgeExpired({FRIENDS: 100, GAMING: 10_000}, otherServersRetentionSeconds=100, now=2000)
        assert await twoStores.recordIpAndFindMatches(FRIENDS, OTHER_OLD_USER, "hashA", now=2000) == []
        assert await twoStores.recordIpAndFindMatches(GAMING, OTHER_OLD_USER, "hashA", now=2000) == [OLD_USER]

    async def test_removedServersDataStillExpires(self, tmp_path):
        stores = ServerStorage(tmp_path / "data", [FRIENDS, GAMING])
        await stores.open()
        await stores.recordIpAndFindMatches(GAMING, OLD_USER, "hashA", now=1000)
        await stores.close()

        # Gaming is taken out of the config: its directory stays, its old IP records don't.
        remaining = ServerStorage(tmp_path / "data", [FRIENDS])
        await remaining.open()
        assert remaining.unconfiguredDirectories() == [tmp_path / "data" / "servers" / str(GAMING)]
        await remaining.purgeExpired({FRIENDS: 100}, otherServersRetentionSeconds=100, now=2000)
        await remaining.close()
        orphan = sqlite3.connect(tmp_path / "data" / "servers" / str(GAMING) / "hollowwarden.db")
        try:
            assert orphan.execute("SELECT COUNT(*) FROM ip_records").fetchone()[0] == 0
        finally:
            orphan.close()


class TestMigratingOldData:
    async def test_oldDatabaseMovesIntoItsServersDirectory(self, tmp_path):
        dataDirectory = tmp_path / "data"
        dataDirectory.mkdir()
        createLegacyDatabase(dataDirectory / "hollowwarden.db")

        stores = ServerStorage(dataDirectory, [FRIENDS, GAMING], dataDirectory / "hollowwarden.db", legacyGuildId=FRIENDS)
        await stores.open()
        assert not (dataDirectory / "hollowwarden.db").exists()
        assert stores.databasePathFor(FRIENDS).stat().st_mode & 0o077 == 0  # moved file is owner-only
        # Alt history and pending reviews survive, in the right server only.
        assert await stores.recordIpAndFindMatches(FRIENDS, OTHER_OLD_USER, "hashA") == [OLD_USER]
        assert await stores.recordIpAndFindMatches(GAMING, OTHER_OLD_USER, "hashA") == []
        assert await stores.hasPendingReview(FRIENDS, NEW_USER)
        assert not await stores.hasPendingReview(GAMING, NEW_USER)
        await stores.close()

    async def test_severalServersWithoutLegacyGuildIdStopsSafely(self, tmp_path):
        dataDirectory = tmp_path / "data"
        dataDirectory.mkdir()
        createLegacyDatabase(dataDirectory / "hollowwarden.db")
        stores = ServerStorage(dataDirectory, [FRIENDS, GAMING], dataDirectory / "hollowwarden.db", legacyGuildId=None)
        with pytest.raises(MigrationError, match="LEGACY_DATA_GUILD_ID"):
            await stores.open()
        assert (dataDirectory / "hollowwarden.db").exists()  # untouched

    async def test_neverOverwritesAnExistingServerDatabase(self, tmp_path, caplog):
        dataDirectory = tmp_path / "data"
        first = ServerStorage(dataDirectory, [FRIENDS])
        await first.open()
        await first.recordIpAndFindMatches(FRIENDS, OTHER_OLD_USER, "newer")
        await first.close()
        createLegacyDatabase(dataDirectory / "hollowwarden.db")

        stores = ServerStorage(dataDirectory, [FRIENDS], dataDirectory / "hollowwarden.db", legacyGuildId=FRIENDS)
        with caplog.at_level(logging.ERROR):
            await stores.open()
        assert (dataDirectory / "hollowwarden.db").exists()
        assert any("not moving" in record.getMessage() for record in caplog.records)
        assert await stores.recordIpAndFindMatches(FRIENDS, OLD_USER, "newer") == [OTHER_OLD_USER]
        await stores.close()


class TestDecisionsUseEachServersRules:
    async def test_sameMemberDifferentRules(self, twoServers, twoStores):
        gateway = FakeGateway({NEW_USER: False})
        verifier = Verifier(twoServers, twoStores, gateway)
        # Friends requires a 7-day-old account and holds for review...
        assert await verifier.completeCaptcha(FRIENDS, NEW_USER) is Outcome.PENDING_REVIEW
        # ...Gaming has no minimum, so the same account is verified there.
        gateway.members[NEW_USER] = False
        assert await verifier.completeCaptcha(GAMING, NEW_USER) is Outcome.VERIFIED

    async def test_decisionsGoToTheRightServer(self, twoServers, twoStores):
        gateway = FakeGateway({NEW_USER: False})
        calls = []
        originalPost = gateway.postReview

        async def recordingPost(guildId, *args, **kwargs):
            calls.append(guildId)
            return await originalPost(guildId, *args, **kwargs)

        gateway.postReview = recordingPost
        verifier = Verifier(twoServers, twoStores, gateway)
        await verifier.completeCaptcha(FRIENDS, NEW_USER)
        assert calls == [FRIENDS]
        # A Friends review can't be resolved from Gaming.
        assert not await verifier.resolveReview(GAMING, NEW_USER, approve=True)
        assert await verifier.resolveReview(FRIENDS, NEW_USER, approve=True)

    async def test_unconfiguredServerIsRefused(self, twoServers, twoStores):
        verifier = Verifier(twoServers, twoStores, FakeGateway({OLD_USER: False}))
        with pytest.raises(ValueError, match="isn't configured"):
            await verifier.completeCaptcha(123456789012345678, OLD_USER)


class TestWebFlowAcrossServers:
    async def test_linkFromOneServerVerifiesInThatServer(self, aiohttp_client, twoServers, twoStores):
        gateway = FakeGateway({OLD_USER: False})
        oauth = FakeOAuth()
        site = VerificationSite(twoServers.web, twoStores, Verifier(twoServers, twoStores, gateway), oauth, lambda: True)
        client = await aiohttp_client(site.createApp())
        client.storage = twoStores

        token = await twoStores.createVerifyToken(GAMING, OLD_USER, 600)
        response = await client.get(f"/verify?t={token}", headers={"X-Real-IP": "1.1.1.1"}, allow_redirects=False)
        assert response.status == 303
        from urllib.parse import parse_qs, urlsplit

        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        assert state.startswith(f"{GAMING}.")
        oauth.userIdForCode["code"] = OLD_USER
        nonce = response.cookies["__Host-hw_nonce"].value
        await finishFlow(client, state, nonce, "code", clientIp="1.1.1.1")
        # Recorded in Gaming only.
        assert await twoStores.recordIpAndFindMatches(GAMING, OTHER_OLD_USER, "x") == []
        assert gateway.granted == [OLD_USER]


@pytest.fixture
def bot(twoServers, twoStores):
    return HollowWardenBot(twoServers, twoStores)


class TestBotAcrossServers:
    def test_adminInOneServerIsNotAdminInAnother(self, bot):
        friendsAdmin = makeInteraction([FRIENDS_ADMIN_ROLE], guildId=FRIENDS)
        assert bot.isBotAdmin(friendsAdmin)
        # The same role ID means nothing in Gaming; Gaming has its own admin roles.
        assert not bot.isBotAdmin(makeInteraction([FRIENDS_ADMIN_ROLE], guildId=GAMING))
        assert bot.isBotAdmin(makeInteraction([GAMING_ADMIN_ROLE], guildId=GAMING))
        assert not bot.isBotAdmin(makeInteraction([FRIENDS_ADMIN_ROLE], guildId=123456789012345678))

    async def test_unconfiguredServersAreLeft(self, bot):
        stranger = SimpleNamespace(id=123456789012345678, name="Stranger", leave=AsyncMock())
        bot.tree.sync = AsyncMock()
        await bot.on_guild_join(stranger)
        stranger.leave.assert_awaited_once()
        bot.tree.sync.assert_not_awaited()

    async def test_commandsSyncedInEveryServer(self, bot):
        bot.tree.sync = AsyncMock()
        await bot.setup_hook()
        assert {call.kwargs["guild"].id for call in bot.tree.sync.await_args_list} == {FRIENDS, GAMING}

    async def test_oneServerDenyingSyncDoesntStopTheOthers(self, bot, caplog):
        async def sync(guild):
            if guild.id == GAMING:
                raise discord.Forbidden(SimpleNamespace(status=403, reason="Forbidden"), "Missing Access")

        bot.tree.sync = sync
        with caplog.at_level(logging.ERROR):
            await bot.setup_hook()  # no StartupError: Friends still works
        assert any("Gaming" in record.getMessage() for record in caplog.records)

    async def test_everyServerDenyingSyncIsAStartupError(self, bot):
        bot.tree.sync = AsyncMock(side_effect=discord.Forbidden(SimpleNamespace(status=403, reason="x"), "x"))
        with pytest.raises(StartupError):
            await bot.setup_hook()

    async def test_modChannelFromAnotherServerIsRefused(self, bot):
        # Gaming's mod channel ID, but the channel is actually in Friends.
        wrongChannel = MagicMock(spec=discord.TextChannel)
        wrongChannel.guild = SimpleNamespace(id=FRIENDS)
        bot.get_channel = lambda channelId: wrongChannel
        assert await bot.getModChannel(bot.settings.servers[GAMING]) is None
        wrongChannel.send.assert_not_called()

    async def test_verifyClickUsesThatServersMethod(self, bot):
        bot.sendWebLink = AsyncMock()
        bot.sendCaptcha = AsyncMock()
        for guildId in (FRIENDS, GAMING):
            interaction = makeInteraction([], guildId=guildId)
            interaction.user.get_role = lambda roleId: None
            await bot.handleVerifyClick(interaction)
        assert bot.sendWebLink.await_args.args[1].guildId == FRIENDS
        assert bot.sendCaptcha.await_args.args[1].guildId == GAMING

    async def test_verifyClickInUnconfiguredServerIsIgnored(self, bot):
        bot.sendWebLink = AsyncMock()
        bot.sendCaptcha = AsyncMock()
        await bot.handleVerifyClick(makeInteraction([], guildId=123456789012345678))
        bot.sendWebLink.assert_not_awaited()
        bot.sendCaptcha.assert_not_awaited()

    def test_reportOnlyDescribesItsOwnServer(self, bot):
        summary = bot.describeSettings(bot.settings.servers[GAMING])
        assert "Gaming" in summary and "friends" not in summary
