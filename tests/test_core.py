import ipaddress

import pytest

from hollowwarden.captcha import CAPTCHA_ALPHABET, CAPTCHA_LENGTH, codesMatch, generateCode, renderCaptcha
from hollowwarden.config import ConfigError, loadSettings
from hollowwarden.netutil import hashIp, normalizeIp, resolveClientIp
from hollowwarden.ratelimit import RateLimiter

TRUSTED = (ipaddress.ip_network("172.20.0.0/16"),)


def baseEnviron(tmp_path, **overrides):
    tokenFile = tmp_path / "token"
    tokenFile.write_text("bot-token\n")
    environ = {
        "DISCORD_BOT_TOKEN_FILE": str(tokenFile),
        "GUILD_ID": "111111111111111111",
        "VERIFIED_ROLE_ID": "222222222222222222",
        "MOD_CHANNEL_ID": "333333333333333333",
        "ADMIN_ROLE_IDS": "555555555555555555, 666666666666666666",
    }
    environ.update(overrides)
    return environ


def webEnviron(tmp_path, **overrides):
    secretFile = tmp_path / "client_secret"
    secretFile.write_text("client-secret")
    keyFile = tmp_path / "ip_key"
    keyFile.write_text("k" * 48)
    webValues = {
        "VERIFY_METHOD": "web",
        "PUBLIC_BASE_URL": "https://verify.example.com/",
        "DISCORD_CLIENT_ID": "444444444444444444",
        "DISCORD_CLIENT_SECRET_FILE": str(secretFile),
        "IP_HASH_KEY_FILE": str(keyFile),
        "TRUSTED_PROXIES": "172.20.0.0/16",
        "CLIENT_IP_HEADER": "X-Real-IP",
    }
    webValues.update(overrides)
    return baseEnviron(tmp_path, **webValues)


class TestConfig:
    def test_captchaModeNeedsNoWebSecrets(self, tmp_path):
        settings = loadSettings(baseEnviron(tmp_path))
        assert settings.verifyMethod == "captcha"
        assert settings.web is None
        assert settings.botToken == "bot-token"

    def test_secretsHiddenFromRepr(self, tmp_path):
        settings = loadSettings(webEnviron(tmp_path))
        assert "bot-token" not in repr(settings)
        assert "client-secret" not in repr(settings)
        assert "kkkk" not in repr(settings)

    def test_webModeLoads(self, tmp_path):
        settings = loadSettings(webEnviron(tmp_path))
        assert settings.web.redirectUri == "https://verify.example.com/callback"

    @pytest.mark.parametrize(
        "overrides",
        [
            {"PUBLIC_BASE_URL": "http://verify.example.com"},
            {"PUBLIC_BASE_URL": "https://verify.example.com/?x=1"},
            {"TRUSTED_PROXIES": ""},
            {"CLIENT_IP_HEADER": ""},
            {"TRUSTED_PROXIES": "not-an-ip"},
            {"CLIENT_IP_HEADER": "X-Real-IP\r\nEvil: 1"},
            {"DISCORD_CLIENT_ID": "abc"},
        ],
    )
    def test_webModeRejectsUnsafeValues(self, tmp_path, overrides):
        with pytest.raises(ConfigError):
            loadSettings(webEnviron(tmp_path, **overrides))

    def test_shortIpKeyRejected(self, tmp_path):
        environ = webEnviron(tmp_path)
        (tmp_path / "ip_key").write_text("short")
        with pytest.raises(ConfigError, match="IP_HASH_KEY"):
            loadSettings(environ)

    def test_missingSecretFile(self, tmp_path):
        with pytest.raises(ConfigError, match="DISCORD_BOT_TOKEN"):
            loadSettings(baseEnviron(tmp_path, DISCORD_BOT_TOKEN_FILE=str(tmp_path / "missing")))

    def test_adminRolesParsed(self, tmp_path):
        settings = loadSettings(baseEnviron(tmp_path))
        assert settings.adminRoleIds == {555555555555555555, 666666666666666666}

    @pytest.mark.parametrize(
        "adminRoleIds",
        [
            "",
            "admins",
            "555555555555555555,not-a-role",
            "111111111111111111",  # @everyone: every member would be a bot admin
            "555555555555555555,222222222222222222",  # the Verified role
        ],
    )
    def test_unsafeAdminRolesRejected(self, tmp_path, adminRoleIds):
        with pytest.raises(ConfigError, match="ADMIN_ROLE_IDS"):
            loadSettings(baseEnviron(tmp_path, ADMIN_ROLE_IDS=adminRoleIds))

    def test_invalidSnowflake(self, tmp_path):
        with pytest.raises(ConfigError, match="GUILD_ID"):
            loadSettings(baseEnviron(tmp_path, GUILD_ID="my-server"))


class TestNetUtil:
    def test_ipv6CollapsedToSlash64(self):
        assert normalizeIp("2001:db8:1:2:aaaa::1") == normalizeIp("2001:db8:1:2:bbbb::2")
        assert normalizeIp("2001:db8:1:2::1") != normalizeIp("2001:db8:1:3::1")

    def test_ipv4MappedTreatedAsIpv4(self):
        assert normalizeIp("::ffff:203.0.113.5") == "203.0.113.5"

    def test_hashIsKeyed(self):
        assert hashIp(b"a" * 32, "203.0.113.5") == hashIp(b"a" * 32, "203.0.113.5")
        assert hashIp(b"a" * 32, "203.0.113.5") != hashIp(b"b" * 32, "203.0.113.5")
        assert "203.0.113.5" not in hashIp(b"a" * 32, "203.0.113.5")

    def test_headerIgnoredFromUntrustedPeer(self):
        # A visitor connecting directly can't choose their IP with a header.
        clientIp = resolveClientIp("198.51.100.7", {"X-Real-IP": "1.2.3.4"}, TRUSTED, "X-Real-IP")
        assert clientIp == "198.51.100.7"

    def test_headerUsedFromTrustedProxy(self):
        assert resolveClientIp("172.20.0.5", {"X-Real-IP": "203.0.113.9"}, TRUSTED, "X-Real-IP") == "203.0.113.9"

    @pytest.mark.parametrize("headerValue", [None, "", "1.2.3.4, 5.6.7.8", "not-an-ip"])
    def test_trustedProxyWithBadHeaderFailsClosed(self, headerValue):
        headers = {} if headerValue is None else {"X-Real-IP": headerValue}
        assert resolveClientIp("172.20.0.5", headers, TRUSTED, "X-Real-IP") is None


class TestRateLimiter:
    def test_limitsWithinWindow(self):
        limiter = RateLimiter(maxEvents=2, windowSeconds=10)
        assert limiter.allow("a", now=0)
        assert limiter.allow("a", now=1)
        assert not limiter.allow("a", now=2)
        assert limiter.allow("b", now=2)
        assert limiter.allow("a", now=11)

    def test_keyCountIsBounded(self):
        limiter = RateLimiter(maxEvents=1, windowSeconds=10, maxKeys=3)
        for key in range(100):
            limiter.allow(key, now=0)
        assert len(limiter._events) <= 3


class TestCaptcha:
    def test_codeShapeAndRandomness(self):
        codes = {generateCode() for _ in range(50)}
        assert len(codes) == 50
        for code in codes:
            assert len(code) == CAPTCHA_LENGTH
            assert set(code) <= set(CAPTCHA_ALPHABET)

    def test_matchingIsForgivingButExact(self):
        assert codesMatch("AB3CDE", " ab3 cde ")
        assert not codesMatch("AB3CDE", "AB3CD")
        assert not codesMatch("AB3CDE", "")

    def test_rendersPng(self):
        assert renderCaptcha("AB3CDE").startswith(b"\x89PNG")
