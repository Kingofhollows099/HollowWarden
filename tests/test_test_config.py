"""Tests for /test-config: each check, the report, and the command itself."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import discord
import pytest
from aiohttp import web as aiohttpWeb

from hollowwarden.bot import HollowWardenBot
from hollowwarden.config import loadSettings
from hollowwarden.diagnostics import (
    ERROR,
    MAX_REPORT_LENGTH,
    OK,
    WARNING,
    Finding,
    checkApplication,
    checkDatabase,
    checkOauthCredentials,
    checkWebsite,
    formatReport,
    interpretSelfTest,
)
from hollowwarden.oauth import OAuthError
from hollowwarden.storage import Storage
from hollowwarden.verification import Verifier
from hollowwarden.web import VerificationSite

from .test_admin import OWNER_ID, makeInteraction
from .test_core import webEnviron
from .test_flow import FakeGateway, FakeOAuth, settings, storage  # noqa: F401 (pytest fixtures)

MOD_CHANNEL_ID = 333333333333333333
ALL_MOD_PERMISSIONS = discord.Permissions(view_channel=True, send_messages=True, embed_links=True)


def makeFakeGuild(
    botModPermissions=ALL_MOD_PERMISSIONS,
    everyoneSeesMod=False,
    verifiedSeesMod=False,
    everyoneVisibleChannels=("verify",),
):
    """A guild with a mod channel and some text channels, where each role can
    be given different permissions in the mod channel."""
    me = SimpleNamespace(guild_permissions=discord.Permissions(manage_roles=True))
    everyoneRole = SimpleNamespace(name="@everyone")
    verifiedRole = SimpleNamespace(name="Verified", mention="<@&222222222222222222>")

    def modPermissionsFor(target):
        if target is me:
            return botModPermissions
        if target is everyoneRole:
            return discord.Permissions(view_channel=everyoneSeesMod)
        return discord.Permissions(view_channel=verifiedSeesMod)

    modChannel = SimpleNamespace(id=MOD_CHANNEL_ID, name="mod-log", permissions_for=modPermissionsFor)

    def makeChannel(index, name):
        isVisible = name in everyoneVisibleChannels
        return SimpleNamespace(
            id=1000 + index,
            name=name,
            permissions_for=lambda target: discord.Permissions(view_channel=isVisible and target is everyoneRole),
        )

    channelNames = ["verify", "rules", "general", "memes", "gaming", "music", "art"]
    textChannels = [makeChannel(index, name) for index, name in enumerate(channelNames)] + [modChannel]
    guild = SimpleNamespace(
        me=me,
        default_role=everyoneRole,
        text_channels=textChannels,
        get_role=lambda roleId: object(),
        get_channel=lambda channelId: modChannel if channelId == MOD_CHANNEL_ID else None,
    )
    return guild, verifiedRole


@pytest.fixture
def bot(settings, storage):
    return HollowWardenBot(settings, storage)


def findingsFor(bot, **guildOptions):
    guild, verifiedRole = makeFakeGuild(**guildOptions)
    bot.get_guild = lambda guildId: guild
    bot.getVerifiedRole = lambda: verifiedRole
    return bot.collectSetupFindings()


def levelsContaining(findings, text):
    return [finding.level for finding in findings if text in finding.text]


class TestServerChecks:
    def test_goodSetupHasNoProblems(self, bot):
        findings = findingsFor(bot)
        assert [finding for finding in findings if finding.level != OK] == []
        assert levelsContaining(findings, "can only see: #verify") == [OK]

    def test_modChannelVisibleToEveryoneIsAnError(self, bot):
        findings = findingsFor(bot, everyoneSeesMod=True)
        assert levelsContaining(findings, "Everyone in the server can see the mod channel") == [ERROR]

    def test_modChannelVisibleToVerifiedIsAnError(self, bot):
        findings = findingsFor(bot, verifiedSeesMod=True)
        assert levelsContaining(findings, "Every verified member can see the mod channel") == [ERROR]

    def test_noVisibleChannelIsAnError(self, bot):
        findings = findingsFor(bot, everyoneVisibleChannels=())
        assert levelsContaining(findings, "can't reach the Verify button") == [ERROR]

    def test_manyVisibleChannelsIsAWarning(self, bot):
        findings = findingsFor(bot, everyoneVisibleChannels=("verify", "rules", "general", "memes", "gaming", "art"))
        [finding] = [finding for finding in findings if "Unverified members can see 6 channels" in finding.text]
        assert finding.level == WARNING
        assert "#verify" in finding.text and "and 1 more" in finding.text

    def test_administratorIsAWarning(self, bot):
        guild, verifiedRole = makeFakeGuild()
        guild.me.guild_permissions = discord.Permissions(administrator=True)
        bot.get_guild = lambda guildId: guild
        bot.getVerifiedRole = lambda: verifiedRole
        assert levelsContaining(bot.collectSetupFindings(), "has Administrator") == [WARNING]

    def test_startupLogsTheSameFindings(self, bot, caplog):
        guild, verifiedRole = makeFakeGuild(everyoneSeesMod=True)
        bot.get_guild = lambda guildId: guild
        bot.getVerifiedRole = lambda: verifiedRole
        with caplog.at_level(logging.INFO):
            bot.checkSetup()
        logged = [(record.levelno, record.getMessage()) for record in caplog.records]
        assert any(level == logging.ERROR and "can see the mod channel" in message for level, message in logged)
        # Passed checks aren't logged at startup, only problems.
        assert not any("can only see" in message for _, message in logged)


class TestApplicationCheck:
    def test_publicBotIsAWarning(self, settings):
        findings = checkApplication(SimpleNamespace(bot_public=True, redirect_uris=[settings.web.redirectUri]), settings)
        assert levelsContaining(findings, "Public Bot is on") == [WARNING]

    def test_registeredRedirectPasses(self, settings):
        appInfo = SimpleNamespace(bot_public=False, redirect_uris=[settings.web.redirectUri])
        assert all(finding.level == OK for finding in checkApplication(appInfo, settings))

    def test_wrongRedirectIsAnError(self, settings):
        appInfo = SimpleNamespace(bot_public=False, redirect_uris=["https://other.example.com/callback"])
        assert levelsContaining(checkApplication(appInfo, settings), "isn't listed") == [ERROR]

    def test_unknownRedirectsIsOnlyAWarning(self, settings):
        appInfo = SimpleNamespace(bot_public=False, redirect_uris=[])
        assert levelsContaining(checkApplication(appInfo, settings), "Couldn't confirm") == [WARNING]


class TestSelfTestInterpretation:
    @pytest.fixture
    def webSettings(self, settings):
        return settings.web

    def test_headerMissingIsAnError(self, webSettings):
        [finding] = interpretSelfTest(webSettings, 400, "<p>Connection problem</p>", behindCloudflare=False)
        assert finding.level == ERROR and "X-Real-IP" in finding.text

    def test_cloudflareHeaderWithoutCloudflareIsExplained(self, tmp_path):
        webSettings = loadSettings(webEnviron(tmp_path, CLIENT_IP_HEADER="CF-Connecting-IP")).web
        [finding] = interpretSelfTest(webSettings, 400, "Connection problem", behindCloudflare=False)
        assert finding.level == ERROR and "isn't behind Cloudflare" in finding.text

    def test_proxyCantReachBotIsAnError(self, webSettings):
        [finding] = interpretSelfTest(webSettings, 502, "Bad Gateway", behindCloudflare=False)
        assert finding.level == ERROR and "NPM_NETWORK" in finding.text

    def test_someOtherServerIsAnError(self, webSettings):
        [finding] = interpretSelfTest(webSettings, 404, "<html>nginx</html>", behindCloudflare=False)
        assert finding.level == ERROR and "not from HollowWarden" in finding.text

    def test_allGood(self, webSettings):
        findings = interpretSelfTest(webSettings, 200, "ok", behindCloudflare=False)
        assert [finding.level for finding in findings] == [OK, OK]

    def test_privateIpIsAWarning(self, webSettings):
        findings = interpretSelfTest(webSettings, 200, "private", behindCloudflare=False)
        assert [finding.level for finding in findings] == [OK, WARNING]

    def test_cloudflareWithRealIpHeaderIsAWarning(self, webSettings):
        findings = interpretSelfTest(webSettings, 200, "ok", behindCloudflare=True)
        assert findings[1].level == WARNING and "flagged as alts" in findings[1].text


class TestWebsiteCheckEndToEnd:
    """Runs the real website locally and lets checkWebsite call it over HTTP."""

    async def runAgainstLocalSite(self, aiohttp_server, unused_tcp_port_factory, tmp_path, storage, **overrides):
        port = unused_tcp_port_factory()
        settings = loadSettings(
            webEnviron(
                tmp_path,
                PUBLIC_BASE_URL=f"http://127.0.0.1:{port}",
                ALLOW_INSECURE_HTTP="1",
                **overrides,
            )
        )
        site = VerificationSite(settings.web, storage, Verifier(settings, storage, FakeGateway()), FakeOAuth(), lambda: True)
        await aiohttp_server(site.createApp(), port=port)
        return await checkWebsite(settings.web)

    async def test_headerNotSentByProxyIsCaught(self, aiohttp_server, unused_tcp_port_factory, tmp_path, storage):
        # The check connects from 127.0.0.1, which is "the proxy" here, and
        # sends no X-Real-IP: exactly a proxy that doesn't set the header.
        findings = await self.runAgainstLocalSite(
            aiohttp_server, unused_tcp_port_factory, tmp_path, storage, TRUSTED_PROXIES="127.0.0.1/32"
        )
        assert [finding.level for finding in findings] == [ERROR]
        assert "didn't send the X-Real-IP header" in findings[0].text

    async def test_wrongTrustedProxiesShowsPrivateIp(self, aiohttp_server, unused_tcp_port_factory, tmp_path, storage):
        findings = await self.runAgainstLocalSite(
            aiohttp_server, unused_tcp_port_factory, tmp_path, storage, TRUSTED_PROXIES="10.0.0.0/8"
        )
        assert [finding.level for finding in findings] == [OK, WARNING]
        assert "private address" in findings[1].text

    async def test_unreachableSiteIsAWarning(self, unused_tcp_port_factory, tmp_path):
        port = unused_tcp_port_factory()
        settings = loadSettings(
            webEnviron(tmp_path, PUBLIC_BASE_URL=f"http://127.0.0.1:{port}", ALLOW_INSECURE_HTTP="1")
        )
        [finding] = await checkWebsite(settings.web)
        assert finding.level == WARNING and "NAT loopback" in finding.text


class TestSelfTestPage:
    async def test_saysOnlyWhetherIpIsPublic(self, aiohttp_client, settings, storage):
        site = VerificationSite(settings.web, storage, Verifier(settings, storage, FakeGateway()), FakeOAuth(), lambda: True)
        client = await aiohttp_client(site.createApp())
        # A real public address. Documentation ranges like 203.0.113.0/24
        # are correctly treated as not public.
        publicResponse = await client.get("/selftest", headers={"X-Real-IP": "1.1.1.1"})
        privateResponse = await client.get("/selftest", headers={"X-Real-IP": "10.1.2.3"})
        assert await publicResponse.text() == "ok"
        assert await privateResponse.text() == "private"


class TestOtherChecks:
    async def test_databaseOk(self, storage):
        assert (await checkDatabase(storage)).level == OK

    async def test_databaseFailureIsAnError(self, tmp_path):
        closedStorage = Storage(str(tmp_path / "closed.db"))
        finding = await checkDatabase(closedStorage)
        assert finding.level == ERROR

    async def test_rejectedOauthSecretIsAnError(self):
        oauth = SimpleNamespace(credentialsAreValid=AsyncMock(return_value=False))
        assert (await checkOauthCredentials(oauth)).level == ERROR

    async def test_oauthCheckThatCantRunIsAWarning(self):
        oauth = SimpleNamespace(credentialsAreValid=AsyncMock(side_effect=OAuthError("Discord answered HTTP 400")))
        finding = await checkOauthCredentials(oauth)
        assert finding.level == WARNING and "HTTP 400" in finding.text


class TestReport:
    def test_titles(self):
        assert formatReport([Finding(OK, "a")], "s")[0] == "✓  Everything looks good"
        assert formatReport([Finding(WARNING, "a")], "s")[0] == "⚠  No problems, 1 warning"
        assert formatReport([Finding(ERROR, "a"), Finding(ERROR, "b")], "s")[0] == "⚠  2 problems found"

    def test_problemsListedFirst(self):
        _, description = formatReport([Finding(OK, "fine"), Finding(ERROR, "broken")], "summary")
        assert description.index("broken") < description.index("fine")

    def test_longReportsFitInAnEmbed(self):
        findings = [Finding(OK, "x" * 300) for _ in range(40)] + [Finding(ERROR, "the real problem")]
        _, description = formatReport(findings, "summary")
        assert len(description) <= 4096 and len(description) <= MAX_REPORT_LENGTH + 50
        assert "the real problem" in description and "not shown" in description


class TestCommand:
    async def test_nonAdminIsRefused(self, bot):
        interaction = makeInteraction([])
        interaction.response = SimpleNamespace(send_message=AsyncMock(), defer=AsyncMock())
        await bot.handleTestConfig(interaction)
        assert "Only bot admins" in interaction.response.send_message.await_args.args[0]
        interaction.response.defer.assert_not_awaited()

    async def test_adminGetsPrivateReport(self, bot):
        interaction = makeInteraction([], userId=OWNER_ID)
        interaction.response = SimpleNamespace(defer=AsyncMock())
        interaction.followup = SimpleNamespace(send=AsyncMock())
        bot.collectSetupFindings = lambda: [Finding(ERROR, "role problem")]
        bot.collectLiveFindings = AsyncMock(return_value=[Finding(OK, "database fine")])

        await bot.handleTestConfig(interaction)

        assert interaction.response.defer.await_args.kwargs["ephemeral"] is True
        sent = interaction.followup.send.await_args
        assert sent.kwargs["ephemeral"] is True
        embed = sent.kwargs["embed"]
        assert embed.title == "⚠  1 problem found"
        assert "role problem" in embed.description and "database fine" in embed.description

    async def test_crashingCheckStillProducesReport(self, bot):
        interaction = makeInteraction([], userId=OWNER_ID)
        interaction.response = SimpleNamespace(defer=AsyncMock())
        interaction.followup = SimpleNamespace(send=AsyncMock())
        bot.collectSetupFindings = lambda: []
        bot.collectLiveFindings = AsyncMock(side_effect=RuntimeError("boom"))
        await bot.handleTestConfig(interaction)
        assert "couldn't run" in interaction.followup.send.await_args.kwargs["embed"].description
