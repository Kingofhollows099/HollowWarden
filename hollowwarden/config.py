"""Configuration loading and validation.

Secrets (bot token, OAuth client secret, IP hashing key) are read from files
rather than environment variables. Environment variables leak easily: they show
up in `docker inspect`, in /proc/<pid>/environ, in crash reports and in every
child process. A file mounted as a Docker secret has none of those problems.

Everything is validated once at startup so a misconfiguration stops the bot
immediately with a clear message, instead of failing halfway through
verifying someone.

Each server has its own settings file, SERVERS_DIR/<name>.toml (default
/config/servers). That location is mounted read-only and only the operator
can edit it. It's deliberately not configurable from Discord: whoever took
over a Discord admin account could otherwise change how their server
verifies people, or add a server. With no server files, the single server
described in .env is used, as before.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .vpnlist import DEFAULT_VPN_LIST_URLS

VERIFY_METHODS = ("captcha", "web")
FLAGGED_ACTIONS = ("review", "allow")
CLIENT_IP_HEADER_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")
SNOWFLAKE_PATTERN = re.compile(r"^[0-9]{15,21}$")
MIN_IP_HASH_KEY_LENGTH = 32
DEFAULT_SERVERS_DIR = "/config/servers"
SERVER_FILE_SUFFIX = ".toml"
SERVER_FILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
DEFAULT_IP_RETENTION_DAYS = 180
# Settings that belong to one server. With server files they go in each
# <name>.toml, so finding any of them in .env as well is ambiguous.
PER_SERVER_ENV_SETTINGS = (
    "GUILD_ID",
    "VERIFIED_ROLE_ID",
    "MOD_CHANNEL_ID",
    "ADMIN_ROLE_IDS",
    "VERIFY_METHOD",
    "FLAGGED_ACTION",
    "MIN_ACCOUNT_AGE_DAYS",
    "FLAG_VPN",
    "IP_RETENTION_DAYS",
)
SERVER_FILE_KEYS = {
    "name",
    "guild_id",
    "verified_role_id",
    "mod_channel_id",
    "admin_role_ids",
    "verify_method",
    "flagged_action",
    "min_account_age_days",
    "flag_vpn",
    "ip_retention_days",
}


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
    # Where to download VPN ranges from. Shared by every server; each server
    # decides whether to act on a match (ServerSettings.flagVpn).
    vpnListUrls: tuple[str, ...]
    listenHost: str
    listenPort: int

    @property
    def redirectUri(self) -> str:
        return f"{self.publicBaseUrl}/callback"


@dataclass(frozen=True)
class ServerSettings:
    """Everything that can differ between the Discord servers the bot runs in."""

    name: str
    guildId: int
    verifiedRoleId: int
    modChannelId: int
    adminRoleIds: frozenset[int]
    verifyMethod: str
    flaggedAction: str
    minAccountAgeDays: int
    flagVpn: bool
    ipRetentionDays: int


@dataclass(frozen=True)
class Settings:
    botToken: str = field(repr=False)
    servers: dict[int, ServerSettings]
    # Where the database lived before multi-server support. Each server now
    # has its own under the same directory, in servers/<guild id>/.
    databasePath: str
    logLevel: str
    web: WebSettings | None
    # The server that data from before multi-server support belongs to, if
    # it can be worked out (see loadSettings).
    legacyDataGuildId: int | None = None

    @property
    def dataDirectory(self) -> Path:
        return Path(self.databasePath).parent

    def server(self, guildId: int | None) -> ServerSettings | None:
        return self.servers.get(guildId) if guildId is not None else None

    @property
    def usesWeb(self) -> bool:
        return any(server.verifyMethod == "web" for server in self.servers.values())


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


def missingSettingHint(name: str, environ: dict[str, str]) -> str:
    """Point at .env.example when a setting is absent rather than blank.

    A blank value means the line is in .env but wasn't filled in. A missing
    line usually means the setting was added by an update after .env was
    created, which the person can't guess from "must be set" alone.
    """
    if name in environ:
        return ""
    return (
        f". {name} isn't in your .env at all; if you set up HollowWarden before this setting existed, "
        "copy it from .env.example"
    )


def readRequired(name: str, environ: dict[str, str]) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} must be set{missingSettingHint(name, environ)}")
    return value


def parseSnowflake(value: object, label: str) -> int:
    # bool is an int in Python; never accept true/false as an ID.
    text = str(value).strip() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    if not SNOWFLAKE_PATTERN.match(text):
        raise ConfigError(f"{label} must be a Discord ID (enable Developer Mode and use Copy ID)")
    return int(text)


def readSnowflake(name: str, environ: dict[str, str]) -> int:
    return parseSnowflake(readRequired(name, environ), name)


def parseAdminRoleIds(entries: list[object], guildId: int, verifiedRoleId: int, label: str, hint: str = "") -> frozenset[int]:
    if not entries:
        raise ConfigError(f"{label} must list at least one role ID{hint}")
    roleIds = {parseSnowflake(entry, f"{label} entry {entry!r}") for entry in entries}
    # Either of these would quietly make large numbers of people bot admins:
    # @everyone (whose ID is the server's ID) is held by all members, and the
    # Verified role by everyone who passes verification.
    if guildId in roleIds:
        raise ConfigError(f"{label} must not include @everyone (the server's own ID)")
    if verifiedRoleId in roleIds:
        raise ConfigError(f"{label} must not include the verified role")
    return frozenset(roleIds)


def parseInt(value: object, label: str, minimum: int, maximum: int) -> int:
    # bool is an int in Python, so true/false would otherwise count as 1/0.
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ConfigError(f"{label} must be a whole number")
    try:
        number = int(str(value).strip())
    except ValueError:
        raise ConfigError(f"{label} must be a whole number") from None
    if not minimum <= number <= maximum:
        raise ConfigError(f"{label} must be between {minimum} and {maximum}")
    return number


def parseChoice(value: object, label: str, choices: tuple[str, ...]) -> str:
    text = str(value).strip().lower() if isinstance(value, str) else ""
    if text not in choices:
        raise ConfigError(f"{label} must be one of: {', '.join(choices)}")
    return text


def parseBool(value: object, label: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower() if isinstance(value, str) else ""
    if text not in ("true", "false"):
        raise ConfigError(f"{label} must be true or false")
    return text == "true"


def readInt(name: str, environ: dict[str, str], default: int, minimum: int, maximum: int) -> int:
    rawValue = environ.get(name, "").strip()
    return parseInt(rawValue, name, minimum, maximum) if rawValue else default


def readChoice(name: str, environ: dict[str, str], choices: tuple[str, ...], default: str) -> str:
    return parseChoice(environ.get(name, "").strip() or default, name, choices)


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


def readVpnListUrls(environ: dict[str, str]) -> tuple[str, ...]:
    rawUrls = environ.get("VPN_LIST_URLS", "").strip()
    urls = tuple(url.strip() for url in rawUrls.split(",") if url.strip()) if rawUrls else DEFAULT_VPN_LIST_URLS
    for url in urls:
        parts = urlsplit(url)
        # HTTPS only: over plain HTTP, anyone on the network path could swap
        # in their own list and choose who gets flagged.
        if parts.scheme != "https" or not parts.hostname:
            raise ConfigError(f"VPN_LIST_URLS entry {url!r} must be an https:// URL")
    return urls


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
        vpnListUrls=readVpnListUrls(environ),
        listenHost=environ.get("WEB_LISTEN_HOST", "").strip() or "0.0.0.0",
        listenPort=readInt("WEB_LISTEN_PORT", environ, default=8080, minimum=1, maximum=65535),
    )


def loadServerFromEnv(environ: dict[str, str]) -> ServerSettings:
    """The original single-server setup, configured entirely in .env."""
    guildId = readSnowflake("GUILD_ID", environ)
    verifiedRoleId = readSnowflake("VERIFIED_ROLE_ID", environ)
    adminEntries = [entry.strip() for entry in environ.get("ADMIN_ROLE_IDS", "").split(",") if entry.strip()]
    return ServerSettings(
        name="this server",
        guildId=guildId,
        verifiedRoleId=verifiedRoleId,
        modChannelId=readSnowflake("MOD_CHANNEL_ID", environ),
        adminRoleIds=parseAdminRoleIds(
            adminEntries,
            guildId,
            verifiedRoleId,
            "ADMIN_ROLE_IDS",
            " (comma-separated)" + missingSettingHint("ADMIN_ROLE_IDS", environ),
        ),
        verifyMethod=readChoice("VERIFY_METHOD", environ, VERIFY_METHODS, default="captcha"),
        flaggedAction=readChoice("FLAGGED_ACTION", environ, FLAGGED_ACTIONS, default="review"),
        minAccountAgeDays=readInt("MIN_ACCOUNT_AGE_DAYS", environ, default=7, minimum=0, maximum=3650),
        flagVpn=parseBool(environ.get("FLAG_VPN", "").strip() or "true", "FLAG_VPN"),
        ipRetentionDays=readInt(
            "IP_RETENTION_DAYS", environ, default=DEFAULT_IP_RETENTION_DAYS, minimum=1, maximum=3650
        ),
    )


def parseServerEntry(entry: dict[str, object], label: str, defaultName: str) -> ServerSettings:
    # Reject unknown keys: a misspelt setting would otherwise be ignored
    # silently and its default used instead.
    unknownKeys = sorted(set(entry) - SERVER_FILE_KEYS)
    if unknownKeys:
        raise ConfigError(f"{label}: unknown setting(s) {', '.join(unknownKeys)}")
    for requiredKey in ("guild_id", "verified_role_id", "mod_channel_id", "admin_role_ids"):
        if requiredKey not in entry:
            raise ConfigError(f"{label}: {requiredKey} must be set")

    guildId = parseSnowflake(entry["guild_id"], f"{label}: guild_id")
    verifiedRoleId = parseSnowflake(entry["verified_role_id"], f"{label}: verified_role_id")
    adminRoleIds = entry["admin_role_ids"]
    if not isinstance(adminRoleIds, list):
        raise ConfigError(f'{label}: admin_role_ids must be a list, like ["123…", "456…"]')
    name = entry.get("name", defaultName)
    if not isinstance(name, str) or not name.strip() or len(name) > 100:
        raise ConfigError(f"{label}: name must be a short piece of text")
    return ServerSettings(
        name=name.strip(),
        guildId=guildId,
        verifiedRoleId=verifiedRoleId,
        modChannelId=parseSnowflake(entry["mod_channel_id"], f"{label}: mod_channel_id"),
        adminRoleIds=parseAdminRoleIds(adminRoleIds, guildId, verifiedRoleId, f"{label}: admin_role_ids"),
        verifyMethod=parseChoice(entry.get("verify_method", "captcha"), f"{label}: verify_method", VERIFY_METHODS),
        flaggedAction=parseChoice(entry.get("flagged_action", "review"), f"{label}: flagged_action", FLAGGED_ACTIONS),
        minAccountAgeDays=parseInt(entry.get("min_account_age_days", 7), f"{label}: min_account_age_days", 0, 3650),
        flagVpn=parseBool(entry.get("flag_vpn", True), f"{label}: flag_vpn"),
        ipRetentionDays=parseInt(
            entry.get("ip_retention_days", DEFAULT_IP_RETENTION_DAYS), f"{label}: ip_retention_days", 1, 3650
        ),
    )


def loadServerFiles(serversDirectory: Path) -> list[ServerSettings]:
    """Read every <name>.toml directly inside serversDirectory, one per server.

    Other files (such as the README) are ignored. A subdirectory isn't: the
    first version of multi-server support used <name>/settings.toml, so one
    of those is pointed out rather than quietly skipped, which would leave
    that server unconfigured without any warning.
    """
    servers = []
    for path in sorted(serversDirectory.iterdir()):
        if path.name.startswith("."):
            continue
        if path.is_dir():
            oldSettings = path / "settings.toml"
            hint = (
                f" Move it with: mv {oldSettings} {serversDirectory / path.name}{SERVER_FILE_SUFFIX} "
                f"&& rmdir {path}"
                if oldSettings.exists()
                else " Server settings go in files like servers/friends.toml, not in folders."
            )
            raise ConfigError(f"servers/{path.name}/ is a folder.{hint}")
        if path.suffix != SERVER_FILE_SUFFIX:
            continue
        if not SERVER_FILE_NAME_PATTERN.match(path.stem):
            raise ConfigError(f"server file {path.name!r}: use only letters, numbers, - and _ in its name")
        label = f"servers/{path.name}"
        try:
            with path.open("rb") as settingsFile:
                entry = tomllib.load(settingsFile)
        except OSError as error:
            raise ConfigError(f"could not read {label}: {error.strerror}") from None
        except tomllib.TOMLDecodeError as error:
            raise ConfigError(f"{label} isn't valid TOML: {error}") from None
        servers.append(parseServerEntry(entry, label, defaultName=path.stem))
    return servers


def checkServersAreDistinct(servers: list[ServerSettings]) -> None:
    """Catch copy-paste slips that would mix servers up. A mod channel shared
    between two servers would show one server's reviews (including who
    shares a network with whom) to the other server's moderators."""
    for attribute, description in (("guildId", "guild_id"), ("modChannelId", "mod_channel_id"), ("verifiedRoleId", "verified_role_id")):
        seen: dict[int, str] = {}
        for server in servers:
            value = getattr(server, attribute)
            if value in seen:
                raise ConfigError(f"servers {seen[value]!r} and {server.name!r} have the same {description}")
            seen[value] = server.name


def loadSettings(environ: dict[str, str] | None = None) -> Settings:
    environ = dict(os.environ if environ is None else environ)
    serversDirectory = Path(environ.get("SERVERS_DIR", "").strip() or DEFAULT_SERVERS_DIR)
    servers = loadServerFiles(serversDirectory) if serversDirectory.is_dir() else []
    if servers:
        conflicting = [name for name in PER_SERVER_ENV_SETTINGS if environ.get(name, "").strip()]
        if conflicting:
            raise ConfigError(
                f"{', '.join(conflicting)} are set in .env, but servers are configured in {serversDirectory}. "
                "Move them into each server's .toml file and delete them from .env, so there's only one source"
            )
        checkServersAreDistinct(servers)
    else:
        servers = [loadServerFromEnv(environ)]
    serverMap = {server.guildId: server for server in servers}

    # Data from before multi-server support has no server attached. With one
    # server it's obviously that one; with several, the operator has to say.
    rawLegacyGuildId = environ.get("LEGACY_DATA_GUILD_ID", "").strip()
    if rawLegacyGuildId:
        legacyDataGuildId = parseSnowflake(rawLegacyGuildId, "LEGACY_DATA_GUILD_ID")
        if legacyDataGuildId not in serverMap:
            raise ConfigError("LEGACY_DATA_GUILD_ID must be one of the configured servers' guild_id")
    else:
        legacyDataGuildId = servers[0].guildId if len(servers) == 1 else None

    usesWeb = any(server.verifyMethod == "web" for server in servers)
    return Settings(
        botToken=readSecret("DISCORD_BOT_TOKEN", environ),
        servers=serverMap,
        databasePath=environ.get("DATABASE_PATH", "").strip() or "/data/hollowwarden.db",
        logLevel=readChoice("LOG_LEVEL", environ, ("debug", "info", "warning", "error"), default="info"),
        # The web settings (and their secrets) are only needed, and only
        # loaded, when at least one server uses the web method.
        web=loadWebSettings(environ) if usesWeb else None,
        legacyDataGuildId=legacyDataGuildId,
    )
