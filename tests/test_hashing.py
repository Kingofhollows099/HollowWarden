"""The slow (scrypt) hash for stored IPs, and the transition from the old one."""

import asyncio
import time

import pytest

import hollowwarden.netutil as netutil
from hollowwarden.netutil import SLOW_HASH_PREFIX, SlowIpHasher, hashIp, hashIpSlow

from hollowwarden.verification import Outcome, Verifier

from .test_flow import (  # noqa: F401 (settings, storage and webClient are pytest fixtures)
    GUILD_ID,
    OLD_USER,
    OTHER_OLD_USER,
    FakeGateway,
    finishFlow,
    settings,
    startFlow,
    storage,
    webClient,
    withServerSettings,
)

KEY = b"k" * 48


class TestSlowHash:
    def test_sameIpSameValueOnlyWithTheSameKey(self):
        assert hashIpSlow(KEY, "203.0.113.5") == hashIpSlow(KEY, "203.0.113.5")
        assert hashIpSlow(KEY, "203.0.113.5") != hashIpSlow(KEY, "203.0.113.6")
        assert hashIpSlow(KEY, "203.0.113.5") != hashIpSlow(b"x" * 48, "203.0.113.5")

    def test_normalisedLikeTheFastHash(self):
        assert hashIpSlow(KEY, "::ffff:203.0.113.5") == hashIpSlow(KEY, "203.0.113.5")
        assert hashIpSlow(KEY, "2001:db8:1:2::1") == hashIpSlow(KEY, "2001:db8:1:2:ffff::9")

    def test_markedAndDistinctFromTheOldFormat(self):
        slowHash = hashIpSlow(KEY, "203.0.113.5")
        assert slowHash.startswith(SLOW_HASH_PREFIX)
        assert slowHash != hashIp(KEY, "203.0.113.5")
        assert "203.0.113.5" not in slowHash

    def test_costSettingsNeed32MbPerGuess(self):
        # scrypt needs 128 x r x N bytes. Lowering these would quietly make
        # stolen hashes far cheaper to reverse (and stop old records matching).
        assert 128 * netutil.SCRYPT_BLOCK_SIZE * netutil.SCRYPT_COST == 32 * 1024 * 1024
        start = time.perf_counter()
        hashIpSlow(KEY, "203.0.113.5")
        assert time.perf_counter() - start > 0.02  # genuinely slow, not accidentally fast


class TestSlowIpHasher:
    async def test_onlyTwoRunAtOnce(self, monkeypatch):
        running = 0
        mostAtOnce = 0

        def fakeSlowHash(ipHashKey, rawIp):
            nonlocal running, mostAtOnce
            running += 1
            mostAtOnce = max(mostAtOnce, running)
            time.sleep(0.05)
            running -= 1
            return SLOW_HASH_PREFIX + rawIp

        monkeypatch.setattr(netutil, "hashIpSlow", fakeSlowHash)
        hasher = SlowIpHasher(KEY)
        results = await asyncio.gather(*(hasher.hash(f"203.0.113.{index}") for index in range(8)))
        assert len(results) == 8
        assert mostAtOnce == 2  # each needs 32 MB: never more than 64 MB at once

    async def test_botKeepsRunningWhileHashing(self):
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.005)

        tickerTask = asyncio.create_task(ticker())
        await SlowIpHasher(KEY).hash("203.0.113.5")
        tickerTask.cancel()
        # The hash runs in a thread, so other work carried on meanwhile.
        assert ticks > 5


@pytest.fixture
def countSlowHashes(monkeypatch):
    calls = []
    realSlowHash = netutil.hashIpSlow

    def countingSlowHash(ipHashKey, rawIp):
        calls.append(rawIp)
        return realSlowHash(ipHashKey, rawIp)

    monkeypatch.setattr(netutil, "hashIpSlow", countingSlowHash)
    return calls


class TestWebsite:
    async def test_onlyACompletedLoginPaysForTheSlowHash(self, webClient, countSlowHashes):
        for _ in range(5):
            await webClient.get("/verify?t=x", headers={"X-Real-IP": "203.0.113.10"})
            await webClient.get("/selftest", headers={"X-Real-IP": "203.0.113.10"})
        state, nonce = await startFlow(webClient, OLD_USER)
        assert countSlowHashes == []  # page loads and starting a login cost nothing extra
        webClient.oauth.userIdForCode["code1"] = OLD_USER
        await finishFlow(webClient, state, nonce, "code1")
        assert countSlowHashes == ["203.0.113.10"]

    async def test_onlyTheSlowHashIsStored(self, webClient, settings):
        state, nonce = await startFlow(webClient, OLD_USER)
        webClient.oauth.userIdForCode["code1"] = OLD_USER
        await finishFlow(webClient, state, nonce, "code1")
        rows = webClient.storage.forGuild(GUILD_ID).connection.execute("SELECT ip_hash FROM ip_records").fetchall()
        assert rows == [(hashIpSlow(settings.web.ipHashKey, "203.0.113.10"),)]

    async def test_recordsFromBeforeTheChangeStillCatchAlts(self, webClient, settings):
        # OLD_USER verified before the update, so their record is in the old format.
        oldFormatHash = hashIp(settings.web.ipHashKey, "203.0.113.10")
        await webClient.storage.recordIpAndFindMatches(GUILD_ID, OLD_USER, oldFormatHash)

        state, nonce = await startFlow(webClient, OTHER_OLD_USER)
        webClient.oauth.userIdForCode["code2"] = OTHER_OLD_USER
        response = await finishFlow(webClient, state, nonce, "code2")
        assert "moderator" in await response.text()
        [review] = webClient.gateway.reviews
        assert str(OLD_USER) in review[1][0]


def ipRecords(storage):
    return sorted(
        storage.forGuild(GUILD_ID)
        .connection.execute("SELECT user_id, ip_hash, first_seen, last_seen FROM ip_records")
        .fetchall()
    )


THIRD_USER = OTHER_OLD_USER + 1
HOME_IP = "203.0.113.10"
OTHER_IP = "198.51.100.7"


class TestUpgradingOldRecords:
    """Old-format records are rewritten in the slow format when their IP
    verifies again, since the IP is known at that moment."""

    async def test_matchIsHeldAndTheOldRecordIsUpgraded(self, settings, storage):
        key = settings.web.ipHashKey
        await storage.recordIpAndFindMatches(GUILD_ID, OLD_USER, hashIp(key, HOME_IP), now=1000)
        gateway = FakeGateway({OLD_USER: False, OTHER_OLD_USER: False})
        verifier = Verifier(settings, storage, gateway)

        outcome = await verifier.completeWeb(
            GUILD_ID, OTHER_OLD_USER, hashIpSlow(key, HOME_IP), legacyIpHash=hashIp(key, HOME_IP)
        )

        # The old record still caught the alt, exactly as a new one would.
        assert outcome is Outcome.PENDING_REVIEW
        assert gateway.granted == []
        assert str(OLD_USER) in gateway.reviews[0][1][0]
        # ...and no longer exists in the old format. Its dates are kept, so
        # the upgrade doesn't make it live any longer.
        records = ipRecords(storage)
        assert (OLD_USER, hashIpSlow(key, HOME_IP), 1000, 1000) in records
        assert all(ipHash.startswith(SLOW_HASH_PREFIX) for _, ipHash, _, _ in records)

    async def test_allowSettingLetsThemInWithAnAlertAndStillUpgrades(self, settings, storage):
        key = settings.web.ipHashKey
        await storage.recordIpAndFindMatches(GUILD_ID, OLD_USER, hashIp(key, HOME_IP), now=1000)
        gateway = FakeGateway({OLD_USER: False, OTHER_OLD_USER: False})
        verifier = Verifier(withServerSettings(settings, flaggedAction="allow"), storage, gateway)

        outcome = await verifier.completeWeb(
            GUILD_ID, OTHER_OLD_USER, hashIpSlow(key, HOME_IP), legacyIpHash=hashIp(key, HOME_IP)
        )

        assert outcome is Outcome.VERIFIED
        assert gateway.reviews and gateway.reviews[0][2] is False  # an alert, not a decision
        assert all(ipHash.startswith(SLOW_HASH_PREFIX) for _, ipHash, _, _ in ipRecords(storage))

    async def test_aMatchedNewRecordIsLeftAlone(self, settings, storage):
        key = settings.web.ipHashKey
        await storage.recordIpAndFindMatches(GUILD_ID, OLD_USER, hashIpSlow(key, HOME_IP), now=1000)
        matches = await storage.recordIpAndFindMatches(
            GUILD_ID, OTHER_OLD_USER, hashIpSlow(key, HOME_IP), now=2000, legacyIpHash=hashIp(key, HOME_IP)
        )
        assert matches == [OLD_USER]
        assert (OLD_USER, hashIpSlow(key, HOME_IP), 1000, 1000) in ipRecords(storage)

    async def test_recordsInBothFormatsAreMerged(self, settings, storage):
        key = settings.web.ipHashKey
        # OLD_USER verified from this IP before and after the update.
        await storage.recordIpAndFindMatches(GUILD_ID, OLD_USER, hashIp(key, HOME_IP), now=1000)
        await storage.recordIpAndFindMatches(GUILD_ID, OLD_USER, hashIpSlow(key, HOME_IP), now=3000)
        await storage.recordIpAndFindMatches(
            GUILD_ID, OTHER_OLD_USER, hashIpSlow(key, HOME_IP), now=5000, legacyIpHash=hashIp(key, HOME_IP)
        )
        # One record, spanning both: the earliest first_seen and latest last_seen.
        assert [record for record in ipRecords(storage) if record[0] == OLD_USER] == [
            (OLD_USER, hashIpSlow(key, HOME_IP), 1000, 3000)
        ]

    async def test_theVerifyingMembersOwnOldRecordIsUpgraded(self, settings, storage):
        key = settings.web.ipHashKey
        await storage.recordIpAndFindMatches(GUILD_ID, OLD_USER, hashIp(key, HOME_IP), now=1000)
        matches = await storage.recordIpAndFindMatches(
            GUILD_ID, OLD_USER, hashIpSlow(key, HOME_IP), now=2000, legacyIpHash=hashIp(key, HOME_IP)
        )
        assert matches == []  # re-verifying from your own network isn't an alt
        assert ipRecords(storage) == [(OLD_USER, hashIpSlow(key, HOME_IP), 1000, 2000)]

    async def test_otherNetworksOldRecordsAreUntouched(self, settings, storage):
        key = settings.web.ipHashKey
        await storage.recordIpAndFindMatches(GUILD_ID, THIRD_USER, hashIp(key, OTHER_IP), now=1000)
        await storage.recordIpAndFindMatches(
            GUILD_ID, OLD_USER, hashIpSlow(key, HOME_IP), now=2000, legacyIpHash=hashIp(key, HOME_IP)
        )
        # Its IP hasn't been seen since the update, so it stays as it is and
        # expires on its normal schedule.
        assert (THIRD_USER, hashIp(key, OTHER_IP), 1000, 1000) in ipRecords(storage)

    async def test_upgradedRecordsKeepMatching(self, settings, storage):
        key = settings.web.ipHashKey
        await storage.recordIpAndFindMatches(GUILD_ID, OLD_USER, hashIp(key, HOME_IP), now=1000)
        await storage.recordIpAndFindMatches(
            GUILD_ID, OTHER_OLD_USER, hashIpSlow(key, HOME_IP), now=2000, legacyIpHash=hashIp(key, HOME_IP)
        )
        # A third account from the same network is matched against both.
        matches = await storage.recordIpAndFindMatches(
            GUILD_ID, THIRD_USER, hashIpSlow(key, HOME_IP), now=3000, legacyIpHash=hashIp(key, HOME_IP)
        )
        assert matches == [OLD_USER, OTHER_OLD_USER]
