"""The slow (scrypt) hash for stored IPs, and the transition from the old one."""

import asyncio
import time

import pytest

import hollowwarden.netutil as netutil
from hollowwarden.netutil import SLOW_HASH_PREFIX, SlowIpHasher, hashIp, hashIpSlow

from .test_flow import (  # noqa: F401 (settings, storage and webClient are pytest fixtures)
    GUILD_ID,
    OLD_USER,
    OTHER_OLD_USER,
    finishFlow,
    settings,
    startFlow,
    storage,
    webClient,
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
