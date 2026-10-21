import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest

from hollowwarden.config import loadSettings
from hollowwarden.oauth import DiscordOAuth, OAuthError
from hollowwarden.storage import Storage
from hollowwarden.verification import DISCORD_EPOCH_MS, MemberState, Outcome, Verifier
from hollowwarden.web import NONCE_COOKIE_NAME, VerificationSite

from .test_core import webEnviron

PROXY_IP = "127.0.0.1"


def userIdCreatedDaysAgo(days: float) -> int:
    createdMs = int((time.time() - days * 86400) * 1000)
    return (createdMs - DISCORD_EPOCH_MS) << 22


OLD_USER = userIdCreatedDaysAgo(400)
OTHER_OLD_USER = userIdCreatedDaysAgo(300) + 1
NEW_USER = userIdCreatedDaysAgo(1)


class FakeGateway:
    def __init__(self, members=None):
        self.members = members if members is not None else {}
        self.granted = []
        self.auditReasons = []
        self.logs = []
        self.reviews = []

    async def getMemberState(self, userId):
        if userId not in self.members:
            return MemberState(isMember=False, hasVerifiedRole=False)
        return MemberState(isMember=True, hasVerifiedRole=self.members[userId])

    async def grantVerifiedRole(self, userId, auditReason=None):
        self.granted.append(userId)
        self.auditReasons.append(auditReason)
        self.members[userId] = True

    async def postModLog(self, message):
        self.logs.append(message)

    async def postReview(self, userId, reasons, needsDecision):
        self.reviews.append((userId, reasons, needsDecision))


class FakeOAuth(DiscordOAuth):
    def __init__(self):
        super().__init__("444444444444444444", "secret", "https://verify.example.com/callback")
        self.userIdForCode = {}

    async def fetchUserId(self, code):
        if code not in self.userIdForCode:
            raise OAuthError("bad code")
        return self.userIdForCode[code]


@pytest.fixture
async def storage(tmp_path):
    storageInstance = Storage(str(tmp_path / "test.db"))
    await storageInstance.open()
    yield storageInstance
    await storageInstance.close()


@pytest.fixture
def settings(tmp_path):
    return loadSettings(webEnviron(tmp_path, TRUSTED_PROXIES="127.0.0.1/32"))


class TestStorage:
    async def test_verifyTokenIsSingleUse(self, storage):
        token = await storage.createVerifyToken(OLD_USER, 60)
        assert await storage.consumeVerifyToken(token) == OLD_USER
        assert await storage.consumeVerifyToken(token) is None

    async def test_verifyTokenExpires(self, storage):
        token = await storage.createVerifyToken(OLD_USER, 60, now=1000)
        assert await storage.consumeVerifyToken(token, now=1061) is None

    async def test_newTokenInvalidatesOld(self, storage):
        oldToken = await storage.createVerifyToken(OLD_USER, 60)
        newToken = await storage.createVerifyToken(OLD_USER, 60)
        assert await storage.consumeVerifyToken(oldToken) is None
        assert await storage.consumeVerifyToken(newToken) == OLD_USER

    async def test_rawTokensNotStored(self, storage):
        token = await storage.createVerifyToken(OLD_USER, 60)
        rows = storage.connection.execute("SELECT token_hash FROM verify_tokens").fetchall()
        assert token not in str(rows)

    async def test_ipMatching(self, storage):
        assert await storage.recordIpAndFindMatches(OLD_USER, "hashA") == []
        assert await storage.recordIpAndFindMatches(OLD_USER, "hashA") == []
        assert await storage.recordIpAndFindMatches(OTHER_OLD_USER, "hashA") == [OLD_USER]

    async def test_ipRetention(self, storage):
        await storage.recordIpAndFindMatches(OLD_USER, "hashA", now=1000)
        await storage.purgeExpired(ipRetentionSeconds=100, now=2000)
        assert await storage.recordIpAndFindMatches(OTHER_OLD_USER, "hashA", now=2000) == []

    async def test_pendingReviewPopsOnce(self, storage):
        await storage.addPendingReview(OLD_USER)
        assert await storage.popPendingReview(OLD_USER)
        assert not await storage.popPendingReview(OLD_USER)


class TestVerifier:
    async def test_cleanUserVerified(self, settings, storage):
        gateway = FakeGateway({OLD_USER: False})
        outcome = await Verifier(settings, storage, gateway).completeWeb(OLD_USER, "hashA")
        assert outcome is Outcome.VERIFIED
        assert gateway.granted == [OLD_USER]

    async def test_youngAccountHeld(self, settings, storage):
        gateway = FakeGateway({NEW_USER: False})
        outcome = await Verifier(settings, storage, gateway).completeCaptcha(NEW_USER)
        assert outcome is Outcome.PENDING_REVIEW
        assert gateway.granted == []
        assert "old" in gateway.reviews[0][1][0]

    async def test_altHeldForReview(self, settings, storage):
        gateway = FakeGateway({OLD_USER: True, OTHER_OLD_USER: False})
        await storage.recordIpAndFindMatches(OLD_USER, "hashA")
        verifier = Verifier(settings, storage, gateway)
        assert await verifier.completeWeb(OTHER_OLD_USER, "hashA") is Outcome.PENDING_REVIEW
        assert gateway.granted == []
        assert str(OLD_USER) in gateway.reviews[0][1][0]
        # Retrying while pending doesn't spam the moderators.
        assert await verifier.completeWeb(OTHER_OLD_USER, "hashA") is Outcome.PENDING_REVIEW
        assert len(gateway.reviews) == 1

        assert await verifier.resolveReview(OTHER_OLD_USER, approve=True)
        assert gateway.granted == [OTHER_OLD_USER]
        assert not await verifier.resolveReview(OTHER_OLD_USER, approve=True)

    async def test_allowPolicyGrantsButFlags(self, settings, storage):
        gateway = FakeGateway({NEW_USER: False})
        verifier = Verifier(replace(settings, flaggedAction="allow"), storage, gateway)
        assert await verifier.completeCaptcha(NEW_USER) is Outcome.VERIFIED
        assert gateway.granted == [NEW_USER]
        assert gateway.reviews[0][2] is False

    async def test_manualVerifyBypassesChecks(self, settings, storage):
        # A brand-new account would normally be held; an admin can let it in.
        gateway = FakeGateway({NEW_USER: False})
        outcome = await Verifier(settings, storage, gateway).manualVerify(NEW_USER, OLD_USER, "my cousin")
        assert outcome is Outcome.VERIFIED
        assert gateway.granted == [NEW_USER]
        assert gateway.reviews == []
        assert str(OLD_USER) in gateway.auditReasons[0]
        assert str(OLD_USER) in gateway.logs[0] and "my cousin" in gateway.logs[0]

    async def test_manualVerifyClosesPendingReview(self, settings, storage):
        gateway = FakeGateway({NEW_USER: False})
        verifier = Verifier(settings, storage, gateway)
        assert await verifier.completeCaptcha(NEW_USER) is Outcome.PENDING_REVIEW
        assert await verifier.manualVerify(NEW_USER, OLD_USER) is Outcome.VERIFIED
        # The old review's Approve button now reports "already handled".
        assert not await verifier.resolveReview(NEW_USER, approve=True)

    async def test_manualVerifyKeepsReviewIfGrantFails(self, settings, storage):
        gateway = FakeGateway({NEW_USER: False})
        verifier = Verifier(settings, storage, gateway)
        await verifier.completeCaptcha(NEW_USER)

        async def failingGrant(userId, auditReason=None):
            raise RuntimeError("role hierarchy")

        gateway.grantVerifiedRole = failingGrant
        with pytest.raises(RuntimeError):
            await verifier.manualVerify(NEW_USER, OLD_USER)
        assert await storage.hasPendingReview(NEW_USER)

    async def test_manualVerifyEdgeCases(self, settings, storage):
        gateway = FakeGateway({OLD_USER: True})
        verifier = Verifier(settings, storage, gateway)
        assert await verifier.manualVerify(OLD_USER, OTHER_OLD_USER) is Outcome.ALREADY_VERIFIED
        assert await verifier.manualVerify(NEW_USER, OTHER_OLD_USER) is Outcome.NOT_MEMBER
        assert gateway.granted == [] and gateway.logs == []

    async def test_nonMemberRejected(self, settings, storage):
        gateway = FakeGateway({})
        assert await Verifier(settings, storage, gateway).completeWeb(OLD_USER, "hashA") is Outcome.NOT_MEMBER
        # IPs of people who aren't in the server are never recorded.
        assert await storage.recordIpAndFindMatches(OTHER_OLD_USER, "hashA") == []


@pytest.fixture
async def webClient(aiohttp_client, settings, storage):
    gateway = FakeGateway({OLD_USER: False, OTHER_OLD_USER: False})
    oauth = FakeOAuth()
    site = VerificationSite(settings.web, storage, Verifier(settings, storage, gateway), oauth, lambda: True)
    client = await aiohttp_client(site.createApp())
    client.gateway = gateway
    client.oauth = oauth
    client.storage = storage
    return client


async def startFlow(client, userId, clientIp="203.0.113.10"):
    token = await client.storage.createVerifyToken(userId, 600)
    response = await client.get(f"/verify?t={token}", headers={"X-Real-IP": clientIp}, allow_redirects=False)
    assert response.status == 303
    state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
    nonce = response.cookies[NONCE_COOKIE_NAME].value
    return state, nonce


async def finishFlow(client, state, nonce, code, clientIp="203.0.113.10"):
    return await client.get(
        f"/callback?state={state}&code={code}",
        headers={"X-Real-IP": clientIp, "Cookie": f"{NONCE_COOKIE_NAME}={nonce}"},
    )


class TestWebFlow:
    async def test_happyPath(self, webClient):
        state, nonce = await startFlow(webClient, OLD_USER)
        webClient.oauth.userIdForCode["code1"] = OLD_USER
        response = await finishFlow(webClient, state, nonce, "code1")
        assert response.status == 200
        assert "verified" in await response.text()
        assert webClient.gateway.granted == [OLD_USER]

    async def test_redirectAndCookieAreHardened(self, webClient):
        token = await webClient.storage.createVerifyToken(OLD_USER, 600)
        response = await webClient.get(f"/verify?t={token}", headers={"X-Real-IP": "203.0.113.10"}, allow_redirects=False)
        location = urlsplit(response.headers["Location"])
        assert location.netloc == "discord.com"
        assert parse_qs(location.query)["scope"] == ["identify"]
        setCookie = response.headers["Set-Cookie"]
        for attribute in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
            assert attribute in setCookie
        assert response.headers["Referrer-Policy"] == "no-referrer"

    async def test_securityHeadersOnEveryPage(self, webClient):
        response = await webClient.get("/nope", headers={"X-Real-IP": "203.0.113.10"})
        assert response.status == 404
        assert "default-src 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["Server"] == "hollowwarden"

    async def test_tokenReuseRejected(self, webClient):
        token = await webClient.storage.createVerifyToken(OLD_USER, 600)
        first = await webClient.get(f"/verify?t={token}", headers={"X-Real-IP": "203.0.113.10"}, allow_redirects=False)
        second = await webClient.get(f"/verify?t={token}", headers={"X-Real-IP": "203.0.113.10"}, allow_redirects=False)
        assert first.status == 303
        assert second.status == 410

    async def test_missingNonceCookieRejected(self, webClient):
        state, _ = await startFlow(webClient, OLD_USER)
        webClient.oauth.userIdForCode["code1"] = OLD_USER
        response = await finishFlow(webClient, state, "attacker-nonce", "code1")
        assert response.status == 400
        assert webClient.gateway.granted == []

    async def test_stateCannotBeReplayed(self, webClient):
        state, nonce = await startFlow(webClient, OLD_USER)
        webClient.oauth.userIdForCode["code1"] = OLD_USER
        assert (await finishFlow(webClient, state, nonce, "code1")).status == 200
        assert (await finishFlow(webClient, state, nonce, "code1")).status == 400

    async def test_wrongAccountRejected(self, webClient):
        state, nonce = await startFlow(webClient, OLD_USER)
        webClient.oauth.userIdForCode["code1"] = OTHER_OLD_USER
        response = await finishFlow(webClient, state, nonce, "code1")
        assert response.status == 403
        assert webClient.gateway.granted == []

    async def test_altDetectedAcrossAccounts(self, webClient):
        state, nonce = await startFlow(webClient, OLD_USER)
        webClient.oauth.userIdForCode["code1"] = OLD_USER
        await finishFlow(webClient, state, nonce, "code1")

        state, nonce = await startFlow(webClient, OTHER_OLD_USER)
        webClient.oauth.userIdForCode["code2"] = OTHER_OLD_USER
        response = await finishFlow(webClient, state, nonce, "code2")
        assert "moderator" in await response.text()
        assert webClient.gateway.granted == [OLD_USER]

    async def test_htmlInjectionEscaped(self, webClient):
        response = await webClient.get("/verify?t=<script>alert(1)</script>", headers={"X-Real-IP": "203.0.113.10"})
        assert "<script>" not in await response.text()

    async def test_rateLimited(self, webClient):
        statuses = [
            (await webClient.get("/verify?t=x", headers={"X-Real-IP": "203.0.113.99"})).status for _ in range(25)
        ]
        assert statuses[-1] == 429

    async def test_missingProxyHeaderFailsClosed(self, webClient):
        response = await webClient.get("/verify?t=x")
        assert response.status == 400
