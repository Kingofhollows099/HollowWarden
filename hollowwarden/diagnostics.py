"""Setup checks for /test-config.

Each check returns Findings instead of raising or logging, so the same
results can go to the startup log or to an admin in Discord. Checks that
reach outside the process (Discord's API, the public website) live here;
checks on the server's roles and channels live on the bot, which owns that
state.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import aiohttp

from .config import Settings, WebSettings
from .oauth import DiscordOAuth, OAuthError
from .storage import Storage
from .vpnlist import VpnChecker

OK = "ok"
WARNING = "warning"
ERROR = "error"

WEBSITE_TIMEOUT = aiohttp.ClientTimeout(total=10)
MAX_REPORT_LENGTH = 4000  # Discord allows 4096 characters in an embed description


@dataclass(frozen=True)
class Finding:
    """One result. ERROR means verification is broken or unsafe; WARNING
    means it works, but something should probably change."""

    level: str
    text: str


def checkApplication(appInfo: object, settings: Settings) -> list[Finding]:
    findings = []
    if getattr(appInfo, "bot_public", False):
        findings.append(
            Finding(
                WARNING,
                "Public Bot is on, so anyone can add this bot to their own server (it leaves, but it shouldn't "
                "be possible). Turn it off under Developer Portal → Bot.",
            )
        )
    else:
        findings.append(Finding(OK, "Public Bot is off."))

    if settings.web is not None:
        redirectUris = getattr(appInfo, "redirect_uris", None) or []
        redirectUri = settings.web.redirectUri
        if redirectUri in redirectUris:
            findings.append(Finding(OK, f"OAuth redirect `{redirectUri}` is registered."))
        elif not redirectUris:
            # Discord didn't report any redirects. That could mean none are
            # set, or just that the API didn't include them, so don't call it
            # an error.
            findings.append(
                Finding(
                    WARNING,
                    f"Couldn't confirm the OAuth redirect. Make sure `{redirectUri}` is listed under "
                    "Developer Portal → OAuth2 → Redirects.",
                )
            )
        else:
            findings.append(
                Finding(
                    ERROR,
                    f"`{redirectUri}` isn't listed under Developer Portal → OAuth2 → Redirects, so Discord "
                    "will refuse every web login. Add it exactly as shown.",
                )
            )
    return findings


async def checkDatabase(storage: Storage) -> Finding:
    try:
        # A real write, but a harmless one: it only deletes verification
        # links and login states that have already expired.
        await storage.purgeExpired(ipRetentionSeconds=None)
    except Exception as error:
        return Finding(ERROR, f"The database couldn't be written to ({type(error).__name__}). Check the data volume.")
    return Finding(OK, "Database is readable and writable.")


async def checkOauthCredentials(oauth: DiscordOAuth) -> Finding:
    try:
        isValid = await oauth.credentialsAreValid()
    except (OAuthError, aiohttp.ClientError, TimeoutError) as error:
        return Finding(WARNING, f"Couldn't check the OAuth client secret ({error or type(error).__name__}).")
    if not isValid:
        return Finding(
            ERROR,
            "Discord rejected DISCORD_CLIENT_ID or the client secret, so every web login will fail. Reset the "
            "secret under Developer Portal → OAuth2 and update secrets/discord_client_secret.",
        )
    return Finding(OK, "OAuth client ID and secret are valid.")


async def checkWebsite(webSettings: WebSettings) -> list[Finding]:
    """Request the bot's own /selftest page through the public URL, the same
    path a member's browser takes: DNS, Cloudflare (if used), TLS, Nginx
    Proxy Manager, and the client-IP settings."""
    selfTestUrl = f"{webSettings.publicBaseUrl}/selftest"
    try:
        async with aiohttp.ClientSession(timeout=WEBSITE_TIMEOUT) as session:
            async with session.get(selfTestUrl, allow_redirects=False) as response:
                status = response.status
                body = (await response.text())[:2000]
                behindCloudflare = "CF-Ray" in response.headers
    except aiohttp.ClientConnectorCertificateError:
        return [
            Finding(ERROR, f"{webSettings.publicBaseUrl} has an invalid HTTPS certificate. Check the SSL tab in NPM.")
        ]
    except (aiohttp.ClientError, TimeoutError) as error:
        return [
            Finding(
                WARNING,
                f"Couldn't reach {webSettings.publicBaseUrl} from the bot's server ({type(error).__name__}). If "
                "it opens fine on your phone over mobile data, your router probably doesn't support NAT "
                "loopback, and you can ignore this.",
            )
        ]
    return interpretSelfTest(webSettings, status, body, behindCloudflare)


def interpretSelfTest(webSettings: WebSettings, status: int, body: str, behindCloudflare: bool) -> list[Finding]:
    usesCloudflareHeader = (webSettings.clientIpHeader or "").lower() == "cf-connecting-ip"

    if status == 400 and "Connection problem" in body:
        if usesCloudflareHeader and not behindCloudflare:
            return [
                Finding(
                    ERROR,
                    "CLIENT_IP_HEADER is CF-Connecting-IP, but the site isn't behind Cloudflare's proxy (orange "
                    "cloud), so nothing sets that header. Use X-Real-IP, or turn on the Cloudflare proxy.",
                )
            ]
        return [
            Finding(
                ERROR,
                f"The website is reachable, but the proxy didn't send the {webSettings.clientIpHeader} header, "
                "so no one can verify. Check CLIENT_IP_HEADER matches your setup (see README → Getting the "
                "real IP).",
            )
        ]
    if status in (502, 503, 504):
        return [
            Finding(
                ERROR,
                f"The proxy couldn't reach HollowWarden (HTTP {status}). Check the NPM proxy host forwards to "
                "`hollowwarden` port 8080 and that both containers share NPM_NETWORK.",
            )
        ]
    if status == 429:
        return [Finding(WARNING, "The website check was rate-limited. Wait a few minutes and run it again.")]
    if status != 200 or body not in ("ok", "private", "untrusted-proxy", "cloudflare-ip"):
        return [
            Finding(
                ERROR,
                f"{webSettings.publicBaseUrl} answered with HTTP {status}, but not from HollowWarden. Check "
                "PUBLIC_BASE_URL and the NPM proxy host.",
            )
        ]

    findings = [Finding(OK, f"Website is reachable at {webSettings.publicBaseUrl} over HTTPS.")]
    if body == "untrusted-proxy":
        findings.append(
            Finding(
                ERROR,
                "Nginx Proxy Manager's address isn't in TRUSTED_PROXIES, so the bot ignores "
                f"{webSettings.clientIpHeader} and sees NPM's own address for every visitor. Every member "
                "would be flagged as an alt of every other. Set TRUSTED_PROXIES to the subnet from "
                "`docker network inspect <NPM_NETWORK> --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'`.",
            )
        )
    elif body == "private":
        findings.append(
            Finding(
                WARNING,
                "This test request reached the site from inside your own network (router NAT loopback, or "
                "local DNS such as Pi-hole, AdGuard or /etc/hosts), so the proxy reported a private address. "
                "Real visitors aren't affected by that. To confirm, open "
                f"{webSettings.publicBaseUrl}/selftest on a phone with Wi-Fi off: it should say ok.",
            )
        )
    elif body == "cloudflare-ip":
        findings.append(
            Finding(
                ERROR,
                "The site is behind Cloudflare, but the bot sees Cloudflare's servers instead of visitors, so "
                "every member would be flagged as an alt of every other. In Nginx Proxy Manager, edit this "
                "proxy host, open the Advanced tab, add `real_ip_header CF-Connecting-IP;` and save. Keep "
                "CLIENT_IP_HEADER=X-Real-IP (see README → Getting the real IP).",
            )
        )
    elif behindCloudflare and usesCloudflareHeader:
        findings.append(
            Finding(
                OK,
                "Visitor IPs are read from Cloudflare. Make sure your firewall only lets Cloudflare connect "
                "to ports 80/443, or the header could be faked. This check can't verify that.",
            )
        )
    elif behindCloudflare:
        findings.append(Finding(OK, "Real visitor IPs are being restored from Cloudflare correctly."))
    else:
        findings.append(Finding(OK, "Visitor IPs are being read correctly."))
    return findings


def checkVpnList(vpnChecker: VpnChecker | None, now: float | None = None) -> Finding:
    if vpnChecker is None:
        return Finding(OK, "VPN detection is turned off (FLAG_VPN=false).")
    if vpnChecker.networkList is None:
        reason = f" Last error: {vpnChecker.lastError}." if vpnChecker.lastError else ""
        return Finding(
            WARNING,
            "VPN detection is on, but the VPN list hasn't downloaded yet, so VPN users aren't being flagged."
            f"{reason} Check the server can reach VPN_LIST_URLS.",
        )
    ageDays = int(((time.time() if now is None else now) - (vpnChecker.updatedAt or 0)) // 86400)
    summary = f"{vpnChecker.networkList.rangeCount:,} ranges, updated {ageDays} day{'s' if ageDays != 1 else ''} ago"
    if vpnChecker.isStale(now=now):
        reason = f" Last error: {vpnChecker.lastError}." if vpnChecker.lastError else ""
        return Finding(WARNING, f"The VPN list hasn't updated in a while ({summary}).{reason}")
    return Finding(OK, f"VPN list loaded ({summary}).")


def formatReport(findings: list[Finding], summary: str) -> tuple[str, str]:
    errors = [finding for finding in findings if finding.level == ERROR]
    warnings = [finding for finding in findings if finding.level == WARNING]
    passed = [finding for finding in findings if finding.level == OK]

    if errors:
        title = f"⚠  {len(errors)} problem{'s' if len(errors) != 1 else ''} found"
    elif warnings:
        title = f"⚠  No problems, {len(warnings)} warning{'s' if len(warnings) != 1 else ''}"
    else:
        title = "✓  Everything looks good"

    lines = [summary]
    for heading, group, symbol in (("Problems", errors, "⚠"), ("Warnings", warnings, "⚠"), ("Passed", passed, "✓")):
        if group:
            lines.append(f"\n**{heading}**")
            lines.extend(f"{symbol}  {finding.text}" for finding in group)

    description = ""
    for index, line in enumerate(lines):
        if len(description) + len(line) + 1 > MAX_REPORT_LENGTH:
            # Problems come first, so anything cut off is the least important.
            description += f"\n…{len(lines) - index} more lines not shown."
            break
        description += ("\n" if description else "") + line
    return title, description
