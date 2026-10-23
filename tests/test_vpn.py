"""VPN detection: the list, its safety checks, downloads, and the decision."""

import os
import time

import pytest
from aiohttp import web

from hollowwarden.config import ConfigError, loadSettings
from hollowwarden.diagnostics import OK, WARNING, checkVpnList
from hollowwarden.verification import Outcome, Verifier
from hollowwarden.vpnlist import DEFAULT_VPN_LIST_URLS, STALE_AFTER_SECONDS, ListRejected, NetworkList, VpnChecker
from hollowwarden.vpnlist import validate
from hollowwarden.web import VerificationSite

from .test_core import webEnviron
from .test_flow import OLD_USER, FakeGateway, FakeOAuth, finishFlow, settings, startFlow, storage  # noqa: F401

# 150 ranges in 185.x.0.0/24, enough to pass the minimum-size check.
GOOD_LIST = "# known VPN ranges\n" + "\n".join(f"185.{index}.0.0/24" for index in range(150)) + "\n"


class TestNetworkList:
    def test_lookupsAndBoundaries(self):
        networkList = NetworkList.parse(GOOD_LIST + "2001:db8::/32\n")
        assert networkList.contains("185.3.0.0") and networkList.contains("185.3.0.255")
        assert not networkList.contains("185.3.1.0")
        assert not networkList.contains("73.0.0.1")
        assert networkList.contains("2001:db8:1::1")
        assert networkList.contains("::ffff:185.3.0.7")  # IPv4 written as IPv6

    def test_skipsJunkAndOverlyBroadEntries(self):
        networkList = NetworkList.parse("185.1.0.0/24\nnot-an-ip\n<html>\n0.0.0.0/1\n10.0.0.0/8  # far too broad\n")
        assert networkList.rangeCount == 1
        assert not networkList.contains("1.2.3.4")

    def test_overlapsAreMerged(self):
        networkList = NetworkList.parse("185.1.0.0/24\n185.1.0.0/25\n185.1.1.0/24\n")
        assert len(networkList.starts[4]) == 1  # merged into 185.1.0.0/23 for lookups
        assert networkList.rangeCount == 3  # but counted as published
        assert networkList.contains("185.1.1.200")


class TestValidation:
    def test_tooSmallIsRejected(self):
        # What an error page or a truncated download looks like.
        with pytest.raises(ListRejected, match="only 2 ranges"):
            validate(NetworkList.parse("185.1.0.0/24\n185.2.0.0/24\n"))

    def test_implausibleCoverageIsRejected(self):
        # 700 /12 ranges covers about 17% of the internet.
        hugeList = "\n".join(f"{16 + index // 16}.{(index % 16) * 16}.0.0/12" for index in range(700))
        with pytest.raises(ListRejected, match="isn't plausible"):
            validate(NetworkList.parse(hugeList))

    def test_goodListPasses(self):
        validate(NetworkList.parse(GOOD_LIST))


@pytest.fixture
async def listServer(aiohttp_server):
    """Serves whatever `served["body"]` holds, with `served["status"]`."""
    served = {"body": GOOD_LIST, "status": 200}

    async def handler(request):
        return web.Response(text=served["body"], status=served["status"])

    app = web.Application()
    app.router.add_get("/list.txt", handler)
    server = await aiohttp_server(app)
    served["url"] = str(server.make_url("/list.txt"))
    return served


class TestRefresh:
    async def test_downloadsCachesAndReloads(self, listServer, tmp_path):
        cachePath = tmp_path / "vpn-ranges.txt"
        checker = VpnChecker((listServer["url"],), cachePath)
        assert checker.isVpn("185.5.0.1") is None  # no list yet: check skipped
        assert await checker.refresh()
        assert checker.isVpn("185.5.0.1") is True and checker.isVpn("73.0.0.1") is False
        assert cachePath.exists() and not cachePath.with_suffix(".tmp").exists()

        # After a restart, the cached list works before any download.
        restarted = VpnChecker((listServer["url"],), cachePath)
        restarted.loadCache()
        assert restarted.isVpn("185.5.0.1") is True

    @pytest.mark.parametrize(
        "body, status",
        [
            ("<html>rate limited</html>", 200),  # error page served as 200
            ("185.1.0.0/24\n", 200),  # truncated
            ("", 500),  # server error
        ],
    )
    async def test_badDownloadKeepsCurrentList(self, listServer, tmp_path, body, status):
        checker = VpnChecker((listServer["url"],), tmp_path / "vpn-ranges.txt")
        await checker.refresh()
        listServer["body"], listServer["status"] = body, status
        assert await checker.refresh() is False
        assert checker.lastError
        assert checker.isVpn("185.5.0.1") is True  # previous list still in use

    async def test_oversizedDownloadIsRefused(self, listServer, tmp_path, monkeypatch):
        import hollowwarden.vpnlist as vpnlistModule

        monkeypatch.setattr(vpnlistModule, "MAX_DOWNLOAD_BYTES", 1000)
        checker = VpnChecker((listServer["url"],), tmp_path / "vpn-ranges.txt")
        assert await checker.refresh() is False
        assert "larger than" in checker.lastError

    def test_corruptCacheIsIgnored(self, tmp_path):
        cachePath = tmp_path / "vpn-ranges.txt"
        cachePath.write_text("garbage")
        checker = VpnChecker(("https://example.invalid/list.txt",), cachePath)
        checker.loadCache()
        assert checker.networkList is None

    def test_staleness(self, tmp_path):
        cachePath = tmp_path / "vpn-ranges.txt"
        cachePath.write_text(GOOD_LIST)
        oldTime = time.time() - STALE_AFTER_SECONDS - 60
        os.utime(cachePath, (oldTime, oldTime))
        checker = VpnChecker(("https://example.invalid/list.txt",), cachePath)
        checker.loadCache()
        assert checker.isStale()


class TestConfig:
    def test_onByDefaultWithDefaultList(self, tmp_path):
        assert loadSettings(webEnviron(tmp_path)).web.vpnListUrls == DEFAULT_VPN_LIST_URLS

    def test_canBeTurnedOff(self, tmp_path):
        assert loadSettings(webEnviron(tmp_path, FLAG_VPN="false")).web.vpnListUrls == ()

    def test_customUrls(self, tmp_path):
        urls = "https://a.example/one.txt, https://b.example/two.txt"
        settings = loadSettings(webEnviron(tmp_path, VPN_LIST_URLS=urls))
        assert settings.web.vpnListUrls == ("https://a.example/one.txt", "https://b.example/two.txt")

    @pytest.mark.parametrize(
        "overrides",
        [{"VPN_LIST_URLS": "http://insecure.example/list.txt"}, {"VPN_LIST_URLS": "list.txt"}, {"FLAG_VPN": "maybe"}],
    )
    def test_unsafeValuesRejected(self, tmp_path, overrides):
        with pytest.raises(ConfigError):
            loadSettings(webEnviron(tmp_path, **overrides))


class TestDecision:
    async def test_vpnUserIsHeldForReview(self, settings, storage):
        gateway = FakeGateway({OLD_USER: False})
        outcome = await Verifier(settings, storage, gateway).completeWeb(OLD_USER, "hashA", isVpn=True)
        assert outcome is Outcome.PENDING_REVIEW
        assert gateway.granted == []
        assert any("VPN" in reason for reason in gateway.reviews[0][1])

    @pytest.mark.parametrize("isVpn", [False, None])
    async def test_nonVpnOrUncheckedIsVerified(self, settings, storage, isVpn):
        gateway = FakeGateway({OLD_USER: False})
        assert await Verifier(settings, storage, gateway).completeWeb(OLD_USER, "hashA", isVpn=isVpn) is Outcome.VERIFIED


class TestWebFlow:
    async def test_vpnVisitorIsHeldThroughTheRealSite(self, aiohttp_client, settings, storage, tmp_path):
        cachePath = tmp_path / "vpn-ranges.txt"
        cachePath.write_text(GOOD_LIST)
        checker = VpnChecker(("https://example.invalid/list.txt",), cachePath)
        checker.loadCache()
        gateway = FakeGateway({OLD_USER: False})
        oauth = FakeOAuth()
        site = VerificationSite(settings.web, storage, Verifier(settings, storage, gateway), oauth, lambda: True, checker)
        client = await aiohttp_client(site.createApp())
        client.storage = storage

        state, nonce = await startFlow(client, OLD_USER, clientIp="185.7.0.9")
        oauth.userIdForCode["code1"] = OLD_USER
        response = await finishFlow(client, state, nonce, "code1", clientIp="185.7.0.9")
        assert "moderator" in await response.text()
        assert gateway.granted == []
        assert any("VPN" in reason for reason in gateway.reviews[0][1])


class TestDiagnostics:
    def test_off(self):
        assert checkVpnList(None).level == OK

    def test_notLoadedYet(self):
        checker = VpnChecker(("https://example.invalid/list.txt",), None)
        checker.lastError = "ClientConnectorError"
        finding = checkVpnList(checker)
        assert finding.level == WARNING and "ClientConnectorError" in finding.text

    def test_freshAndStale(self, tmp_path):
        cachePath = tmp_path / "vpn-ranges.txt"
        cachePath.write_text(GOOD_LIST)
        checker = VpnChecker(("https://example.invalid/list.txt",), cachePath)
        checker.loadCache()
        assert checkVpnList(checker).level == OK and "150 ranges" in checkVpnList(checker).text
        assert checkVpnList(checker, now=time.time() + STALE_AFTER_SECONDS + 60).level == WARNING
