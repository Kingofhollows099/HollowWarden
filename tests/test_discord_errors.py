"""Discord permission errors (Forbidden 50001 / 50013) must produce clear
messages and never leave verification half-done."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest

import hollowwarden.__main__ as entryPoint
from hollowwarden.bot import HollowWardenBot, StartupError
from hollowwarden.verification import MemberState, Outcome, Verifier

from .test_admin import OWNER_ID, makeInteraction
from .test_flow import (  # noqa: F401 (storage and settings are pytest fixtures)
    NEW_USER,
    OLD_USER,
    FakeGateway,
    FakeOAuth,
    finishFlow,
    settings,
    startFlow,
    storage,
)

MOD_CHANNEL_ID = 333333333333333333


def forbidden(code=50001, message="Missing Access"):
    return discord.Forbidden(SimpleNamespace(status=403, reason="Forbidden"), {"code": code, "message": message})


def serverError():
    return discord.HTTPException(SimpleNamespace(status=500, reason="Server Error"), "boom")


def modChannelRaising(error):
    channel = MagicMock()
    channel.send = AsyncMock(side_effect=error)
    return channel


@pytest.fixture
def bot(settings, storage):
    return HollowWardenBot(settings, storage)


def errorMessages(caplog):
    return [record.getMessage() for record in caplog.records if record.levelno >= logging.ERROR]


class TestCommandSyncDenied:
    async def test_syncForbiddenBecomesStartupError(self, bot):
        bot.tree.sync = AsyncMock(side_effect=forbidden())
        with pytest.raises(StartupError) as raised:
            await bot.setup_hook()
        message = str(raised.value)
        assert "GUILD_ID 111111111111111111" in message
        assert "applications.commands" in message
        # Raised "from None": no chained Discord traceback to wade through.
        assert raised.value.__cause__ is None and raised.value.__suppress_context__

    def test_startupErrorExitsCleanlyWithoutTraceback(self, monkeypatch, caplog):
        async def failingMain():
            raise StartupError("Discord denied access to GUILD_ID 1")

        monkeypatch.setattr(entryPoint, "main", failingMain)
        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exited:
            entryPoint.cli()
        assert exited.value.code != 0
        assert "Discord denied access to GUILD_ID 1" in errorMessages(caplog)
        assert all(record.exc_info is None for record in caplog.records)


class TestPanelCommand:
    async def test_cantPostInChannelRepliesPrivately(self, bot, caplog):
        interaction = makeInteraction([], userId=OWNER_ID)
        interaction.channel = modChannelRaising(forbidden(50013, "Missing Permissions"))
        interaction.channel_id = 444
        interaction.response = SimpleNamespace(send_message=AsyncMock())

        with caplog.at_level(logging.WARNING):
            await bot.handlePanelCommand(interaction)

        reply = interaction.response.send_message.await_args
        assert reply.kwargs["ephemeral"] is True
        assert reply.args[0].startswith("⚠  I can't post here.")
        assert "Attach Files" in reply.args[0]
        assert any("verification panel" in record.getMessage() for record in caplog.records)


class TestModChannelPosts:
    async def test_modLogForbiddenIsLoggedNotRaised(self, bot, caplog):
        bot.getModChannel = AsyncMock(return_value=modChannelRaising(forbidden()))
        with caplog.at_level(logging.ERROR):
            await bot.postModLog("✓  someone verified")
        assert any(
            f"can't post in MOD_CHANNEL_ID {MOD_CHANNEL_ID}" in message and "Embed Links" in message
            for message in errorMessages(caplog)
        )

    @pytest.mark.parametrize("needsDecision", [True, False])
    async def test_reviewForbiddenReturnsFalse(self, bot, needsDecision):
        bot.getModChannel = AsyncMock(return_value=modChannelRaising(forbidden()))
        assert await bot.postReview(OLD_USER, ["reason"], needsDecision=needsDecision) is False

    async def test_otherDiscordErrorsAlsoReturnFalse(self, bot, caplog):
        bot.getModChannel = AsyncMock(return_value=modChannelRaising(serverError()))
        with caplog.at_level(logging.ERROR):
            assert await bot.postReview(OLD_USER, ["reason"], needsDecision=True) is False
        assert any("HTTP 500" in message for message in errorMessages(caplog))

    async def test_unreachableChannelReturnsFalse(self, bot):
        bot.getModChannel = AsyncMock(return_value=None)
        assert await bot.postReview(OLD_USER, ["reason"], needsDecision=True) is False

    async def test_successfulPostReturnsTrue(self, bot):
        channel = MagicMock()
        channel.send = AsyncMock()
        bot.getModChannel = AsyncMock(return_value=channel)
        assert await bot.postReview(OLD_USER, ["reason"], needsDecision=True) is True
        assert channel.send.await_args.kwargs["view"] is not None


class TestVerifierWhenModChannelFails:
    async def test_reviewNotPostedMeansNotPending(self, settings, storage):
        gateway = FakeGateway({NEW_USER: False})
        gateway.modChannelWorks = False
        verifier = Verifier(settings, storage, gateway)

        assert await verifier.completeCaptcha(NEW_USER) is Outcome.UNAVAILABLE
        assert not await storage.hasPendingReview(NEW_USER)
        assert gateway.granted == []

        # Once the permission is fixed, a retry works normally instead of
        # being stuck answering "pending".
        gateway.modChannelWorks = True
        assert await verifier.completeCaptcha(NEW_USER) is Outcome.PENDING_REVIEW
        assert await storage.hasPendingReview(NEW_USER)
        assert len(gateway.reviews) == 1

    async def test_allowModeStillVerifiesIfAlertFails(self, settings, storage):
        from dataclasses import replace

        gateway = FakeGateway({NEW_USER: False})
        gateway.modChannelWorks = False
        verifier = Verifier(replace(settings, flaggedAction="allow"), storage, gateway)
        assert await verifier.completeCaptcha(NEW_USER) is Outcome.VERIFIED
        assert gateway.granted == [NEW_USER]


@pytest.fixture
async def realBotSite(aiohttp_client, settings, storage):
    """The web flow wired to the real bot, faking only Discord's API: role
    grants succeed, but the mod channel refuses every post. This recreates
    the reported incident."""
    from hollowwarden.web import VerificationSite

    bot = HollowWardenBot(settings, storage)
    members = {OLD_USER: False, NEW_USER: False}

    async def getMemberState(userId):
        if userId not in members:
            return MemberState(isMember=False, hasVerifiedRole=False)
        return MemberState(isMember=True, hasVerifiedRole=members[userId])

    async def grantVerifiedRole(userId, auditReason=None):
        members[userId] = True

    bot.getMemberState = getMemberState
    bot.grantVerifiedRole = grantVerifiedRole
    bot.getModChannel = AsyncMock(return_value=modChannelRaising(forbidden()))

    oauth = FakeOAuth()
    site = VerificationSite(settings.web, storage, bot.verifier, oauth, lambda: True)
    client = await aiohttp_client(site.createApp())
    client.storage = storage
    client.oauth = oauth
    client.members = members
    return client


class TestWebFlowWhenModChannelFails:
    async def test_verifiedMemberSeesSuccessNotAnError(self, realBotSite):
        state, nonce = await startFlow(realBotSite, OLD_USER)
        realBotSite.oauth.userIdForCode["code1"] = OLD_USER
        response = await finishFlow(realBotSite, state, nonce, "code1")
        assert response.status == 200
        assert "✓  Verified." in await response.text()
        assert realBotSite.members[OLD_USER] is True

    async def test_heldMemberIsToldAndNotLeftPending(self, realBotSite):
        state, nonce = await startFlow(realBotSite, NEW_USER)
        realBotSite.oauth.userIdForCode["code1"] = NEW_USER
        response = await finishFlow(realBotSite, state, nonce, "code1")
        assert response.status == 503
        assert "Please tell a moderator" in await response.text()
        assert not await realBotSite.storage.hasPendingReview(NEW_USER)
        assert realBotSite.members[NEW_USER] is False


class TestCheckSetup:
    def runCheck(self, bot, caplog, botModPermissions):
        from .test_test_config import makeFakeGuild

        guild, verifiedRole = makeFakeGuild(botModPermissions=botModPermissions)
        bot.get_guild = lambda guildId: guild
        bot.getVerifiedRole = lambda: verifiedRole
        with caplog.at_level(logging.ERROR):
            bot.checkSetup()
        return errorMessages(caplog)

    def test_missingChannelPermissionsAreNamed(self, bot, caplog):
        messages = self.runCheck(bot, caplog, discord.Permissions(view_channel=True))
        assert any(
            "Send Messages, Embed Links" in message and str(MOD_CHANNEL_ID) in message and "View Channel" not in message
            for message in messages
        )

    def test_noErrorWhenPermissionsAreRight(self, bot, caplog):
        permissions = discord.Permissions(view_channel=True, send_messages=True, embed_links=True)
        assert self.runCheck(bot, caplog, permissions) == []


class TestWrongAccountPage:
    async def test_explainsHowToFixIt(self, aiohttp_client, settings, storage):
        from hollowwarden.web import VerificationSite

        oauth = FakeOAuth()
        gateway = FakeGateway({OLD_USER: False, NEW_USER: False})
        site = VerificationSite(settings.web, storage, Verifier(settings, storage, gateway), oauth, lambda: True)
        client = await aiohttp_client(site.createApp())
        client.storage = storage

        state, nonce = await startFlow(client, OLD_USER)
        oauth.userIdForCode["code1"] = NEW_USER
        response = await finishFlow(client, state, nonce, "code1")
        text = await response.text()
        assert response.status == 403
        for hint in ("private window", "Not you?", "Click Verify in Discord again", "works only once"):
            assert hint in text


class TestRejoiningServer:
    """Kicking the bot deletes its slash commands; rejoining must restore them."""

    def homeGuild(self):
        return SimpleNamespace(id=111111111111111111, name="Home", leave=AsyncMock())

    async def test_rejoinRegistersCommandsAndRechecksSetup(self, bot):
        bot.tree.sync = AsyncMock()
        bot.checkSetup = MagicMock()
        await bot.on_guild_join(self.homeGuild())
        assert bot.tree.sync.await_args.kwargs["guild"].id == 111111111111111111
        bot.checkSetup.assert_called_once()

    async def test_rejoinWithoutCommandsScopeLogsInsteadOfCrashing(self, bot, caplog):
        bot.tree.sync = AsyncMock(side_effect=forbidden())
        bot.checkSetup = MagicMock()
        with caplog.at_level(logging.ERROR):
            await bot.on_guild_join(self.homeGuild())
        assert any("applications.commands" in message for message in errorMessages(caplog))
        bot.checkSetup.assert_called_once()

    async def test_otherServerIsLeftWithoutRegistering(self, bot):
        bot.tree.sync = AsyncMock()
        otherGuild = SimpleNamespace(id=999999999999999999, name="Other", leave=AsyncMock())
        await bot.on_guild_join(otherGuild)
        otherGuild.leave.assert_awaited_once()
        bot.tree.sync.assert_not_awaited()
