"""Raid protection: detection, holding, the single alert, and Approve/Deny all."""

import asyncio
import sqlite3
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord
import pytest

import hollowwarden.bot as botModule
from hollowwarden.bot import MAX_RAID_LIST_LENGTH, HollowWardenBot, buildRaidAlert
from hollowwarden.config import ConfigError, loadSettings
from hollowwarden.raids import RaidDetector, RaidSummary
from hollowwarden.storage import RAID_RETENTION_SECONDS, ServerStorage
from hollowwarden.verification import Outcome, Verifier

from .test_admin import OWNER_ID, makeInteraction
from .test_core import baseEnviron
from .test_flow import (  # noqa: F401 (settings and storage are pytest fixtures)
    GUILD_ID,
    NEW_USER,
    FakeGateway,
    settings,
    storage,
    userIdCreatedDaysAgo,
    withServerSettings,
)

OTHER_GUILD = 777777777777777771
WINDOW_MINUTES = 5
# Attempt times are relative to now: account ages are worked out from the
# same clock, and a 1970 timestamp would make every account look brand new.
BASE = int(time.time())
# Old accounts, so nobody is flagged for account age: what's tested is the raid.
MEMBERS = [userIdCreatedDaysAgo(400) + index for index in range(12)]


@pytest.fixture
def raidSettings(settings):
    return withServerSettings(settings, raidThreshold=3, raidWindowMinutes=WINDOW_MINUTES)


def makeVerifier(raidSettings, storage, members=MEMBERS):
    gateway = FakeGateway({userId: False for userId in members})
    return Verifier(raidSettings, storage, gateway), gateway


async def attempt(verifier, userId, now, guildId=GUILD_ID):
    return await verifier._complete(guildId, userId, method="captcha", ipHash=None, now=now)


class TestDetector:
    def test_slidingWindowCountsDistinctUsers(self):
        detector = RaidDetector()
        assert detector.record(GUILD_ID, 1, now=0, windowSeconds=60) == [1]
        assert detector.record(GUILD_ID, 1, now=10, windowSeconds=60) == [1]  # same person twice
        assert detector.record(GUILD_ID, 2, now=20, windowSeconds=60) == [1, 2]
        # By 75s, user 1's attempts at 0s and 10s are outside the 60s window.
        assert detector.record(GUILD_ID, 3, now=75, windowSeconds=60) == [2, 3]
        assert detector.record(GUILD_ID, 4, now=200, windowSeconds=60) == [4]

    def test_serversAreCountedSeparately(self):
        detector = RaidDetector()
        detector.record(GUILD_ID, 1, now=0, windowSeconds=60)
        assert detector.record(OTHER_GUILD, 2, now=1, windowSeconds=60) == [2]


class TestDetection:
    async def test_belowThresholdIsNormalVerification(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        assert await attempt(verifier, MEMBERS[0], now=BASE + 0) is Outcome.VERIFIED
        assert await attempt(verifier, MEMBERS[1], now=BASE + 10) is Outcome.VERIFIED
        assert gateway.raidAlerts == []

    async def test_thresholdStartsOneAlertAndHoldsEveryone(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        await attempt(verifier, MEMBERS[0], now=BASE + 0)
        await attempt(verifier, MEMBERS[1], now=BASE + 10)
        # The third attempt within 5 minutes is a raid.
        assert await attempt(verifier, MEMBERS[2], now=BASE + 20) is Outcome.PENDING_REVIEW
        [alert] = gateway.raidAlerts
        assert (alert.memberCount, alert.heldCount, alert.verifiedBeforeCount) == (3, 1, 2)

        # Everyone after that is held too, with no further alerts or per-member reviews.
        for offset, userId in enumerate(MEMBERS[3:6]):
            assert await attempt(verifier, userId, now=BASE + 30 + offset) is Outcome.PENDING_REVIEW
        assert len(gateway.raidAlerts) == 1 and gateway.reviews == []
        lastUpdate = gateway.raidAlertUpdates[-1][1]
        assert (lastUpdate.memberCount, lastUpdate.heldCount) == (6, 4)
        assert gateway.granted == MEMBERS[:2]

    async def test_flaggedMembersAreFoldedIntoTheRaid(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage, members=MEMBERS[:2] + [NEW_USER])
        await attempt(verifier, MEMBERS[0], now=BASE + 0)
        await attempt(verifier, MEMBERS[1], now=BASE + 10)
        assert await attempt(verifier, NEW_USER, now=BASE + 20) is Outcome.PENDING_REVIEW
        # Too young, but it's in the raid alert, not a separate review.
        assert gateway.reviews == []
        assert gateway.raidAlerts[0].flaggedCount == 1

    async def test_spreadOutAttemptsAreNotARaid(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        for index, userId in enumerate(MEMBERS[:6]):
            assert await attempt(verifier, userId, now=BASE + 0 + index * WINDOW_MINUTES * 60) is Outcome.VERIFIED
        assert gateway.raidAlerts == []

    async def test_raidEndsAfterAQuietWindow(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        for index, userId in enumerate(MEMBERS[:3]):
            await attempt(verifier, userId, now=BASE + 0 + index)
        quietLater = BASE + 2 + WINDOW_MINUTES * 60 + 1
        assert await attempt(verifier, MEMBERS[3], now=quietLater) is Outcome.VERIFIED
        assert len(gateway.raidAlerts) == 1

    async def test_offWhenThresholdIsZero(self, settings, storage):
        verifier, gateway = makeVerifier(withServerSettings(settings, raidThreshold=0), storage)
        for index, userId in enumerate(MEMBERS):
            assert await attempt(verifier, userId, now=BASE + 0 + index) is Outcome.VERIFIED
        assert gateway.raidAlerts == []

    async def test_simultaneousAttemptsOpenOnlyOneRaid(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        outcomes = await asyncio.gather(*(attempt(verifier, userId, now=BASE + 0) for userId in MEMBERS))
        assert len(gateway.raidAlerts) == 1
        assert outcomes.count(Outcome.VERIFIED) == 2  # only the two before detection
        assert outcomes.count(Outcome.PENDING_REVIEW) == len(MEMBERS) - 2

    async def test_alertThatCantBePostedHoldsNobody(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        await attempt(verifier, MEMBERS[0], now=BASE + 0)
        await attempt(verifier, MEMBERS[1], now=BASE + 1)
        gateway.modChannelWorks = False
        assert await attempt(verifier, MEMBERS[2], now=BASE + 2) is Outcome.UNAVAILABLE
        assert not await storage.hasPendingReview(GUILD_ID, MEMBERS[2])
        # Once posting works again, the raid carries on normally.
        gateway.modChannelWorks = True
        assert await attempt(verifier, MEMBERS[3], now=BASE + 3) is Outcome.PENDING_REVIEW
        assert len(gateway.raidAlerts) == 1


async def startRaid(verifier, heldUserIds=MEMBERS[2:6]):
    """Two let in, then a raid holding heldUserIds. Returns the raid ID."""
    await attempt(verifier, MEMBERS[0], now=BASE + 0)
    await attempt(verifier, MEMBERS[1], now=BASE + 1)
    for offset, userId in enumerate(heldUserIds):
        await attempt(verifier, userId, now=BASE + 2 + offset)
    return verifier.gateway.raidAlerts[0].raidId


class TestResolving:
    async def test_approveAllVerifiesEveryoneHeld(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        raidId = await startRaid(verifier)
        resolution = await verifier.resolveRaid(GUILD_ID, raidId, approve=True, adminId=OWNER_ID)
        assert resolution.approved == 4 and resolution.failed == 0
        assert set(gateway.granted) == set(MEMBERS[:6])
        assert gateway.removed == []
        for userId in MEMBERS[2:6]:
            assert not await storage.hasPendingReview(GUILD_ID, userId)

    async def test_denyAllKeepsThemOutAndRevokesEarlyArrivals(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        raidId = await startRaid(verifier)
        resolution = await verifier.resolveRaid(GUILD_ID, raidId, approve=False, adminId=OWNER_ID)
        assert (resolution.denied, resolution.rolesRemoved) == (4, 2)
        assert set(gateway.removed) == set(MEMBERS[:2])
        assert gateway.granted == MEMBERS[:2]  # from before detection only
        assert "Verified role removed from 2" in resolution.describe(approve=False)

    async def test_decidingTwiceDoesNothing(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        raidId = await startRaid(verifier)
        assert await verifier.resolveRaid(GUILD_ID, raidId, approve=True, adminId=OWNER_ID)
        assert await verifier.resolveRaid(GUILD_ID, raidId, approve=False, adminId=OWNER_ID) is None
        assert gateway.removed == []

    async def test_membersHandledOneByOneAreLeftAlone(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        raidId = await startRaid(verifier)
        await verifier.manualVerify(GUILD_ID, MEMBERS[2], adminId=OWNER_ID)
        resolution = await verifier.resolveRaid(GUILD_ID, raidId, approve=False, adminId=OWNER_ID)
        assert resolution.skipped == 1 and resolution.denied == 3
        assert MEMBERS[2] not in gateway.removed  # manually vouched for, so not revoked

    async def test_afterADecisionANewBurstStartsANewRaid(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        raidId = await startRaid(verifier)
        await verifier.resolveRaid(GUILD_ID, raidId, approve=False, adminId=OWNER_ID)
        assert await attempt(verifier, MEMBERS[6], now=BASE + 10) is Outcome.PENDING_REVIEW
        assert len(gateway.raidAlerts) == 2 and gateway.raidAlerts[1].raidId != raidId

    async def test_aFailedGrantStaysHeld(self, raidSettings, storage):
        verifier, gateway = makeVerifier(raidSettings, storage)
        raidId = await startRaid(verifier)

        async def failingGrant(guildId, userId, auditReason=None):
            raise RuntimeError("role hierarchy")

        gateway.grantVerifiedRole = failingGrant
        resolution = await verifier.resolveRaid(GUILD_ID, raidId, approve=True, adminId=OWNER_ID)
        assert resolution.failed == 4
        assert await storage.hasPendingReview(GUILD_ID, MEMBERS[2])


class TestServersAreSeparate:
    async def test_raidInOneServerDoesntAffectAnother(self, tmp_path, raidSettings):
        stores = ServerStorage(tmp_path / "data", [GUILD_ID, OTHER_GUILD])
        await stores.open()
        try:
            servers = {
                GUILD_ID: raidSettings.servers[GUILD_ID],
                OTHER_GUILD: replace(raidSettings.servers[GUILD_ID], guildId=OTHER_GUILD, name="Other"),
            }
            verifier, gateway = makeVerifier(replace(raidSettings, servers=servers), stores)
            raidId = await startRaid(verifier)
            # The other server's attempts are counted on their own.
            assert await attempt(verifier, MEMBERS[8], now=BASE + 10, guildId=OTHER_GUILD) is Outcome.VERIFIED
            # A raid ID from one server means nothing in another.
            assert await verifier.resolveRaid(OTHER_GUILD, raidId, approve=False, adminId=OWNER_ID) is None
            assert await stores.hasPendingReview(GUILD_ID, MEMBERS[2])
        finally:
            await stores.close()


class TestStorage:
    async def test_oldRaidsArePurged(self, storage):
        store = storage.forGuild(GUILD_ID)
        raidId = await store.createRaid(now=BASE + 0)
        await store.addRaidMember(raidId, MEMBERS[0], verifiedBefore=False, reasons=["x"], now=BASE + 0)
        await storage.purgeExpired({GUILD_ID: 10**9}, otherServersRetentionSeconds=10**9, now=BASE + RAID_RETENTION_SECONDS + 1)
        assert await store.getRaid(raidId) is None
        assert await store.listRaidMembers(raidId) == []

    async def test_databaseFromThePreviousVersionGainsRaidTables(self, tmp_path):
        # A database as the multi-server version (schema 2) left it: guild_id
        # everywhere, no raid tables. Opening it must not be mistaken for the
        # older single-server format.
        databasePath = tmp_path / "data" / "servers" / str(GUILD_ID) / "hollowwarden.db"
        databasePath.parent.mkdir(parents=True)
        connection = sqlite3.connect(databasePath)
        connection.executescript(
            """
            CREATE TABLE verify_tokens (token_hash TEXT PRIMARY KEY, guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL);
            CREATE TABLE oauth_states (state_hash TEXT PRIMARY KEY, guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, nonce_hash TEXT NOT NULL, expires_at INTEGER NOT NULL);
            CREATE TABLE ip_records (guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, ip_hash TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY (guild_id, user_id, ip_hash));
            CREATE TABLE pending_reviews (guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (guild_id, user_id));
            PRAGMA user_version = 2;
            """
        )
        connection.execute("INSERT INTO pending_reviews VALUES (?, ?, 5)", (GUILD_ID, MEMBERS[0]))
        connection.commit()
        connection.close()

        for _ in range(2):  # and again, now that it has the raid tables
            stores = ServerStorage(tmp_path / "data", [GUILD_ID])
            await stores.open()
            assert await stores.hasPendingReview(GUILD_ID, MEMBERS[0])
            assert await stores.forGuild(GUILD_ID).createRaid() > 0
            await stores.close()


class TestConfig:
    def test_defaultsAndOverrides(self, tmp_path):
        server = loadSettings(baseEnviron(tmp_path)).servers[GUILD_ID]
        assert (server.raidThreshold, server.raidWindowMinutes) == (10, 5)
        server = loadSettings(baseEnviron(tmp_path, RAID_THRESHOLD="0", RAID_WINDOW_MINUTES="30")).servers[GUILD_ID]
        assert (server.raidThreshold, server.raidWindowMinutes) == (0, 30)

    @pytest.mark.parametrize("overrides", [{"RAID_THRESHOLD": "1"}, {"RAID_THRESHOLD": "-3"}, {"RAID_WINDOW_MINUTES": "0"}])
    def test_badValuesRejected(self, tmp_path, overrides):
        with pytest.raises(ConfigError, match="RAID_"):
            loadSettings(baseEnviron(tmp_path, **overrides))


def sampleSummary(**changes):
    values = dict(raidId=7, startedAt=1000, memberCount=6, heldCount=4, verifiedBeforeCount=2, flaggedCount=1,
                  threshold=3, windowMinutes=5)
    values.update(changes)
    return RaidSummary(**values)


class TestAlertMessage:
    def test_undecidedAlertHasAllThreeButtonsWithoutEmoji(self):
        view = buildRaidAlert(sampleSummary())["view"]
        labels = [item.item.label for item in view.children]
        assert labels == ["✓ Approve all", "⚠ Deny all", "List members"]
        # Discord rejects invalid button emoji; the symbols live in the labels.
        assert all(item.item.emoji is None for item in view.children)

    def test_decidedAlertKeepsOnlyTheList(self):
        message = buildRaidAlert(sampleSummary(decision="denied", decidedBy=OWNER_ID, resultText="4 denied."))
        assert [item.item.label for item in message["view"].children] == ["List members"]
        assert "Denied all" in message["embed"].fields[-1].value

    def test_disabledSampleForTestConfig(self):
        view = buildRaidAlert(sampleSummary(), disabled=True)["view"]
        assert all(item.item.disabled for item in view.children)


@pytest.fixture
def bot(raidSettings, storage):
    return HollowWardenBot(raidSettings, storage)


def adminInteraction():
    interaction = makeInteraction([], userId=OWNER_ID)
    interaction.response = SimpleNamespace(send_message=AsyncMock(), defer=AsyncMock(), edit_message=AsyncMock())
    interaction.followup = SimpleNamespace(send=AsyncMock())
    interaction.edit_original_response = AsyncMock()
    interaction.message = SimpleNamespace(id=555)
    return interaction


class TestButtons:
    async def test_nonAdminIsRefused(self, bot):
        interaction = makeInteraction([])
        interaction.response = SimpleNamespace(send_message=AsyncMock())
        await bot.handleRaidButton(interaction, 1, "deny")
        assert "Only bot admins" in interaction.response.send_message.await_args.args[0]

    async def test_denyAsksForConfirmationFirst(self, bot):
        bot.verifier.gateway = FakeGateway({userId: False for userId in MEMBERS})
        raidId = await startRaid(bot.verifier)
        interaction = adminInteraction()
        await bot.handleRaidButton(interaction, raidId, "deny")
        call = interaction.response.send_message.await_args
        assert "removes the Verified role from the **2**" in call.args[0]
        assert call.kwargs["ephemeral"] is True
        # Nothing has happened yet.
        assert bot.verifier.gateway.removed == []

    async def test_confirmingAppliesAndUpdatesTheAlert(self, bot):
        bot.verifier.gateway = FakeGateway({userId: False for userId in MEMBERS})
        raidId = await startRaid(bot.verifier)
        bot.editRaidAlert = AsyncMock()
        bot.postModLog = AsyncMock()
        interaction = adminInteraction()
        await bot.applyRaidDecision(interaction, raidId, approve=False, alertMessage=interaction.message)
        assert set(bot.verifier.gateway.removed) == set(MEMBERS[:2])
        editedSummary = bot.editRaidAlert.await_args.args[2]
        assert editedSummary.decision == "denied" and "4 denied" in editedSummary.resultText
        assert "Raid denied" in bot.postModLog.await_args.args[1]
        # A second confirmation (another moderator) changes nothing.
        await bot.applyRaidDecision(adminInteraction(), raidId, approve=True, alertMessage=None)
        assert bot.verifier.gateway.granted == MEMBERS[:2]

    async def test_listShowsEachMemberAndWhy(self, bot):
        bot.verifier.gateway = FakeGateway({userId: False for userId in MEMBERS[:3] + [NEW_USER]})
        raidId = await startRaid(bot.verifier, heldUserIds=[MEMBERS[2], NEW_USER])
        interaction = adminInteraction()
        await bot.handleRaidButton(interaction, raidId, "list")
        call = interaction.followup.send.await_args
        assert call.kwargs["ephemeral"] is True
        text = call.kwargs["embed"].description
        assert f"<@{MEMBERS[0]}>" in text and "let in before detection" in text
        assert f"<@{NEW_USER}>" in text and "held" in text and "old (minimum is 7 days)" in text

    async def test_longListComesAsAFile(self, bot, monkeypatch):
        monkeypatch.setattr(botModule, "MAX_RAID_LIST_LENGTH", 50)
        bot.verifier.gateway = FakeGateway({userId: False for userId in MEMBERS})
        raidId = await startRaid(bot.verifier)
        interaction = adminInteraction()
        await bot.handleRaidButton(interaction, raidId, "list")
        attachedFile = interaction.followup.send.await_args.kwargs["file"]
        assert attachedFile.filename == f"raid-{raidId}-members.txt"
        assert MAX_RAID_LIST_LENGTH > 50  # the real limit is unchanged

    async def test_raidIdFromAnotherServerFindsNothing(self, bot):
        interaction = adminInteraction()
        await bot.handleRaidButton(interaction, 999, "deny")
        assert "Already handled" in interaction.response.send_message.await_args.args[0]

    async def test_alertEditsAreBatched(self, bot, monkeypatch):
        monkeypatch.setattr(botModule, "RAID_ALERT_EDIT_INTERVAL_SECONDS", 0.05)
        bot.editRaidAlert = AsyncMock()
        for count in range(20):
            await bot.updateRaidAlert(GUILD_ID, 555, sampleSummary(memberCount=count))
        await asyncio.sleep(0.15)
        # Twenty updates, one edit, showing the newest numbers.
        bot.editRaidAlert.assert_awaited_once()
        assert bot.editRaidAlert.await_args.args[2].memberCount == 19

    async def test_removeVerifiedRoleSkipsPeopleWhoLeft(self, bot):
        role = SimpleNamespace(id=222, guild=SimpleNamespace(fetch_member=AsyncMock(side_effect=discord.NotFound(
            SimpleNamespace(status=404, reason="Not Found"), "Unknown Member"))))
        bot.getVerifiedRole = lambda server: role
        assert await bot.removeVerifiedRole(GUILD_ID, MEMBERS[0], auditReason="test") is False

    async def test_testConfigPostsASampleAlert(self, bot):
        sent = SimpleNamespace(delete=AsyncMock())
        channel = MagicMock()
        channel.send = AsyncMock(return_value=sent)
        bot.getModChannel = AsyncMock(return_value=channel)
        finding = await bot.checkRaidAlertPost(bot.settings.servers[GUILD_ID])
        assert finding.level == "ok"
        sent.delete.assert_awaited_once()
        assert all(item.item.disabled for item in channel.send.await_args.kwargs["view"].children)
