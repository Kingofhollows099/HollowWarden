"""Configuration loading and validation.

Secrets (bot token, OAuth client secret, IP hashing key) are read from files
rather than environment variables. Environment variables leak easily: they show
up in `docker inspect`, in /proc/<pid>/environ, in crash reports and in every
child process. A file mounted as a Docker secret has none of those problems.

Everything is validated once at startup so a misconfiguration stops the bot
immediately with a clear message, instead of failing halfway through
verifying someone.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

VERIFY_METHODS = ("captcha", "web")
FLAGGED_ACTIONS = ("review", "allow")
CLIENT_IP_HEADER_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")
SNOWFLAKE_PATTERN = re.compile(r"^[0-9]{15,21}$")
MIN_IP_HASH_KEY_LENGTH = 32


class ConfigError(Exception):
    """Raised when the configuration is missing or invalid."""


@dataclass(frozen=True)
class WebSettings:
    publicBaseUrl: str
    clientId: str
    clientSecret: str = field(repr=False)
    ipHashKey: bytes = field(repr=False)
    trustedProxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    clientIpHeader: str | None
    ipRetentionDays: int
    listenHost: str
    listenPort: int

    @property
    def redirectUri(self) -> str:
        return f"{self.publicBaseUrl}/callback"


@dataclass(frozen=True)
class Settings:
    botToken: str = field(repr=False)
    guildId: int
    verifiedRoleId: int
    modChannelId: int
    verifyMethod: str
    flaggedAction: str
    minAccountAgeDays: int
    databasePath: str
    logLevel: str
    web: WebSettings | None


def readSecret(name: str, environ: dict[str, str]) -> str:
    filePath = environ.get(f"{name}_FILE")
    if not filePath:
        raise ConfigError(f"{name}_FILE must be set to the path of a secret file")
    try:
        value = Path(filePath).read_text(encoding="utf-8").strip()
    except OSError as error:
        # Only the reason is reported, never any of the file's contents.
        raise ConfigError(f"could not read {name}_FILE: {error.strerror}") from None
    if not value:
        raise ConfigError(f"secret file for {name} is empty")
    return value


def readRequired(name: str, environ: dict[str, str]) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} must be set")
    return value


def readSnowflake(name: str, environ: dict[str, str]) -> int:
    value = readRequired(name, environ)
    if not SNOWFLAKE_PATTERN.match(value):
        raise ConfigError(f"{name} must be a Discord ID (enable Developer Mode and use Copy ID)")
    return int(value)


def readInt(name: str, environ: dict[str, str], default: int, minimum: int, maximum: int) -> int:
    rawValue = environ.get(name, "").strip()
    if not rawValue:
        return default
    try:
        value = int(rawValue)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number") from None
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def readChoice(name: str, environ: dict[str, str], choices: tuple[str, ...], default: str) -> str:
    value = environ.get(name, "").strip().lower() or default
    if value not in choices:
        raise ConfigError(f"{name} must be one of: {', '.join(choices)}")
    return value


def parsePublicBaseUrl(rawUrl: str, allowInsecure: bool) -> str:
    parts = urlsplit(rawUrl)
    if parts.scheme != "https" and not (allowInsecure and parts.scheme == "http"):
        # OAuth codes and verification links travel through this URL, so it
        # must be encrypted end to end.
        raise ConfigError("PUBLIC_BASE_URL must start with https://")
    if not parts.hostname or parts.query or parts.fragment or parts.username or parts.password:
        raise ConfigError("PUBLIC_BASE_URL must be a plain URL like https://verify.example.com")
    return rawUrl.rstrip("/")


def parseTrustedProxies(rawValue: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for entry in filter(None, (part.strip() for part in rawValue.split(","))):
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise ConfigError(f"TRUSTED_PROXIES entry {entry!r} is not an IP address or CIDR range") from None
    return tuple(networks)


def loadWebSettings(environ: dict[str, str]) -> WebSettings:
    allowInsecure = environ.get("ALLOW_INSECURE_HTTP", "").strip() == "1"
    publicBaseUrl = parsePublicBaseUrl(readRequired("PUBLIC_BASE_URL", environ), allowInsecure)

    clientId = readRequired("DISCORD_CLIENT_ID", environ)
    if not SNOWFLAKE_PATTERN.match(clientId):
        raise ConfigError("DISCORD_CLIENT_ID must be your application's ID")

    ipHashKey = readSecret("IP_HASH_KEY", environ)
    if len(ipHashKey) < MIN_IP_HASH_KEY_LENGTH:
        raise ConfigError(
            f"IP_HASH_KEY must be at least {MIN_IP_HASH_KEY_LENGTH} characters; "
            "generate one with: openssl rand -base64 48"
        )

    trustedProxies = parseTrustedProxies(environ.get("TRUSTED_PROXIES", ""))
    clientIpHeader = environ.get("CLIENT_IP_HEADER", "").strip() or None
    if clientIpHeader and not CLIENT_IP_HEADER_PATTERN.match(clientIpHeader):
        raise ConfigError("CLIENT_IP_HEADER must be a header name such as X-Real-IP")
    if trustedProxies and not clientIpHeader:
        raise ConfigError("CLIENT_IP_HEADER must be set when TRUSTED_PROXIES is set")
    if clientIpHeader and not trustedProxies:
        # Without a trusted proxy list, anyone could send the header and pick
        # their own "IP address".
        raise ConfigError("TRUSTED_PROXIES must be set when CLIENT_IP_HEADER is set")

    return WebSettings(
        publicBaseUrl=publicBaseUrl,
        clientId=clientId,
        clientSecret=readSecret("DISCORD_CLIENT_SECRET", environ),
        ipHashKey=ipHashKey.encode("utf-8"),
        trustedProxies=trustedProxies,
        clientIpHeader=clientIpHeader,
        ipRetentionDays=readInt("IP_RETENTION_DAYS", environ, default=180, minimum=1, maximum=3650),
        listenHost=environ.get("WEB_LISTEN_HOST", "").strip() or "0.0.0.0",
        listenPort=readInt("WEB_LISTEN_PORT", environ, default=8080, minimum=1, maximum=65535),
    )


def loadSettings(environ: dict[str, str] | None = None) -> Settings:
    environ = dict(os.environ if environ is None else environ)
    verifyMethod = readChoice("VERIFY_METHOD", environ, VERIFY_METHODS, default="captcha")
    return Settings(
        botToken=readSecret("DISCORD_BOT_TOKEN", environ),
        guildId=readSnowflake("GUILD_ID", environ),
        verifiedRoleId=readSnowflake("VERIFIED_ROLE_ID", environ),
        modChannelId=readSnowflake("MOD_CHANNEL_ID", environ),
        verifyMethod=verifyMethod,
        flaggedAction=readChoice("FLAGGED_ACTION", environ, FLAGGED_ACTIONS, default="review"),
        minAccountAgeDays=readInt("MIN_ACCOUNT_AGE_DAYS", environ, default=7, minimum=0, maximum=3650),
        databasePath=environ.get("DATABASE_PATH", "").strip() or "/data/hollowwarden.db",
        logLevel=readChoice("LOG_LEVEL", environ, ("debug", "info", "warning", "error"), default="info"),
        # The web settings (and their secrets) are only needed, and only
        # loaded, when the web method is in use.
        web=loadWebSettings(environ) if verifyMethod == "web" else None,
    )
