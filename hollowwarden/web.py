"""The public verification website (used only when VERIFY_METHOD=web).

This is the only part of HollowWarden reachable from the internet, so it's
kept as small as possible: two pages, GET only, no JavaScript, no forms, no
user-supplied HTML. The flow:

1. In Discord, the member clicks Verify and gets a private, single-use link
   that expires after a few minutes: /verify?t=<token>.
2. /verify spends that token, stores a random OAuth `state`, puts a random
   nonce in a cookie, and redirects to Discord's login page.
3. Discord redirects back to /callback with a code and the `state`. We check
   the state exists, hasn't expired, and was issued to *this browser* (the
   cookie nonce). That blocks login CSRF, where an attacker tricks someone
   into finishing the attacker's login.
4. We swap the code for the user's ID and confirm it's the same account that
   clicked Verify. That stops someone from passing their link to a friend
   (or an alt) on a different network.
5. Only then is the visitor's IP hashed and checked for alts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import logging
import re
from collections.abc import Awaitable, Callable

from aiohttp import web

from .config import WebSettings
from .netutil import hashIp, resolveClientIp
from .oauth import DiscordOAuth, OAuthError
from .ratelimit import RateLimiter
from .storage import Storage, sha256Hex
from .verification import Outcome, Verifier

log = logging.getLogger(__name__)

TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
OAUTH_CODE_PATTERN = re.compile(r"^[A-Za-z0-9]{1,128}$")
# The __Host- prefix makes browsers refuse the cookie unless it's Secure,
# has Path=/ and has no Domain, so a sibling subdomain can't overwrite it.
NONCE_COOKIE_NAME = "__Host-hw_nonce"
OAUTH_STATE_LIFETIME_SECONDS = 600
IP_HASH_KEY = "hollowwarden.ipHash"

# The Clipboard Cleaner theme: dark navy, flat, a 4px radius, one raspberry
# accent kept for status. Custom property names match the design system's
# tokens so values can be traced back to it. Its type sizes were made for a
# compact desktop toolbar, so body and status text are scaled up here to stay
# readable on phones. Only system fonts are used: loading web fonts would
# mean a third-party request (and a looser CSP) on every visit.
PAGE_STYLE = (
    ":root{color-scheme:dark;--backgroundCLR:#181825;--statusBG:#11111b;--dividerCLR:#2a2a3e;"
    "--statusTextCLR:#e94560;--tooltip-fg:#dddddd;--radius-sm:4px;"
    '--mono:Consolas,monospace;--sans:"Segoe UI",sans-serif}'
    "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;"
    "padding:16px;box-sizing:border-box;background:var(--statusBG);color:var(--tooltip-fg);"
    "font:15px/1.5 var(--sans)}"
    "main{box-sizing:border-box;width:100%;max-width:28rem;background:var(--backgroundCLR);border:1px solid var(--dividerCLR);"
    "border-radius:var(--radius-sm);overflow:hidden}"
    "header{padding:6px 8px;border-bottom:1px solid var(--dividerCLR);font:700 14.67px/1.5 var(--mono)}"
    "section{padding:16px 8px 20px}"
    "h1{margin:0 0 8px;font:700 18.67px/1.3 var(--mono)}p{margin:0}"
    "footer{padding:3px 8px;background:var(--statusBG);color:var(--statusTextCLR);"
    "font:13px/1.5 var(--mono);white-space:pre-wrap}"
)
# Hashing the one stylesheet into the CSP lets the policy forbid every other
# style and all scripts, so even an HTML injection bug couldn't run code.
PAGE_STYLE_HASH = base64.b64encode(hashlib.sha256(PAGE_STYLE.encode()).digest()).decode()
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        f"default-src 'none'; style-src 'sha256-{PAGE_STYLE_HASH}'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    # Stops the browser sending the /verify?t=... URL (with its token) to
    # Discord in the Referer header when it follows our redirect.
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=31536000",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    # Don't advertise the aiohttp and Python versions to scanners.
    "Server": "hollowwarden",
}

# (title, message, status line). Following the theme's copy rules, an
# outcome's status line starts with ✓ or ⚠ and two spaces; success and
# failure are told apart by that symbol, never by colour.
OUTCOME_PAGES = {
    Outcome.VERIFIED: ("You're verified", "You now have access to the server. You can close this tab.", "✓  Verified."),
    Outcome.PENDING_REVIEW: (
        "Waiting for a moderator",
        "Your verification needs a quick manual check. A moderator will review it soon.",
        "Pending review.",
    ),
    Outcome.ALREADY_VERIFIED: (
        "Already verified",
        "This account is already verified. You can close this tab.",
        "✓  Already verified.",
    ),
    Outcome.NOT_MEMBER: (
        "Join the server first",
        "This Discord account isn't a member of the server.",
        "⚠  Not a member.",
    ),
}


def renderPage(status: int, title: str, message: str, statusLine: str | None = None) -> web.Response:
    if statusLine is None:
        statusLine = f"⚠  {title}." if status >= 400 else "Ready."
    body = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)} · HollowWarden</title><style>{PAGE_STYLE}</style></head>"
        "<body><main><header>HollowWarden</header>"
        f"<section><h1>{html.escape(title)}</h1><p>{html.escape(message)}</p></section>"
        f'<footer role="status">{html.escape(statusLine)}</footer></main></body></html>'
    )
    return web.Response(status=status, text=body, content_type="text/html", charset="utf-8")


class VerificationSite:
    def __init__(
        self,
        settings: WebSettings,
        storage: Storage,
        verifier: Verifier,
        oauth: DiscordOAuth,
        isBotReady: Callable[[], bool],
    ) -> None:
        self.settings = settings
        self.storage = storage
        self.verifier = verifier
        self.oauth = oauth
        self.isBotReady = isBotReady
        self.rateLimiter = RateLimiter(maxEvents=20, windowSeconds=600)

    def createApp(self) -> web.Application:
        # Only small GET requests are expected, so refuse large bodies.
        app = web.Application(middlewares=[self.errorMiddleware, self.clientMiddleware], client_max_size=16 * 1024)
        app.router.add_get("/verify", self.handleVerify)
        app.router.add_get("/callback", self.handleCallback)
        app.router.add_get("/healthz", self.handleHealth)
        app.on_response_prepare.append(self.addSecurityHeaders)
        return app

    @staticmethod
    async def addSecurityHeaders(request: web.Request, response: web.StreamResponse) -> None:
        response.headers.update(SECURITY_HEADERS)

    @web.middleware
    async def errorMiddleware(
        self, request: web.Request, handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
    ) -> web.StreamResponse:
        try:
            return await handler(request)
        except web.HTTPException as error:
            if error.status == 404:
                return renderPage(404, "Not found", "There's nothing here.")
            return renderPage(error.status, "Request refused", "That request couldn't be handled.")
        except Exception:
            # Full details go to the server log; the visitor gets nothing an
            # attacker could learn from.
            log.exception("unhandled error while serving %s", request.path)
            return renderPage(500, "Something went wrong", "Please try again, or ask a moderator for help.")

    @web.middleware
    async def clientMiddleware(
        self, request: web.Request, handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
    ) -> web.StreamResponse:
        if request.path == "/healthz":
            return await handler(request)
        clientIp = resolveClientIp(
            request.remote, request.headers, self.settings.trustedProxies, self.settings.clientIpHeader
        )
        if clientIp is None:
            log.warning(
                "could not determine the client IP; check TRUSTED_PROXIES and CLIENT_IP_HEADER "
                "match your Nginx Proxy Manager setup"
            )
            return renderPage(400, "Connection problem", "Your connection couldn't be checked. Please tell a moderator.")
        # From here on only the hash is used, rate limiting included, so the
        # raw IP never outlives this request, not even in memory.
        ipHash = hashIp(self.settings.ipHashKey, clientIp)
        if not self.rateLimiter.allow(ipHash):
            return renderPage(429, "Slow down", "Too many attempts. Please wait a few minutes and try again.")
        request[IP_HASH_KEY] = ipHash
        return await handler(request)

    async def handleHealth(self, request: web.Request) -> web.Response:
        return web.Response(text="ok")

    async def handleVerify(self, request: web.Request) -> web.Response:
        token = request.query.get("t", "")
        if not TOKEN_PATTERN.match(token):
            return renderPage(400, "Invalid link", "This verification link isn't valid. Click Verify in Discord again.")
        if not self.isBotReady():
            return renderPage(503, "Starting up", "The bot is starting up. Please try again in a minute.")

        userId = await self.storage.consumeVerifyToken(token)
        if userId is None:
            return renderPage(
                410, "Link expired", "This link has expired or was already used. Click Verify in Discord again."
            )

        state, browserNonce = await self.storage.createOauthState(userId, OAUTH_STATE_LIFETIME_SECONDS)
        response = web.Response(status=303, headers={"Location": self.oauth.authorizeUrl(state)})
        response.set_cookie(
            NONCE_COOKIE_NAME,
            browserNonce,
            max_age=OAUTH_STATE_LIFETIME_SECONDS,
            path="/",
            secure=True,
            httponly=True,
            # Lax (not Strict) because the cookie has to come back on the
            # top-level redirect from discord.com to /callback.
            samesite="Lax",
        )
        return response

    async def handleCallback(self, request: web.Request) -> web.Response:
        if "error" in request.query:
            return self.finish(renderPage(400, "Login cancelled", "Click Verify in Discord to try again."))

        state = request.query.get("state", "")
        code = request.query.get("code", "")
        if not TOKEN_PATTERN.match(state) or not OAUTH_CODE_PATTERN.match(code):
            return self.finish(renderPage(400, "Invalid request", "Click Verify in Discord to start again."))

        stateRecord = await self.storage.consumeOauthState(state)
        if stateRecord is None:
            return self.finish(
                renderPage(400, "Link expired", "This login took too long. Click Verify in Discord again.")
            )
        expectedUserId, nonceHash = stateRecord

        cookieNonce = request.cookies.get(NONCE_COOKIE_NAME, "")
        if not hmac.compare_digest(sha256Hex(cookieNonce), nonceHash):
            return self.finish(
                renderPage(
                    400,
                    "Different browser",
                    "Please finish verifying in the same browser you opened the link in. Click Verify again.",
                )
            )

        try:
            loggedInUserId = await self.oauth.fetchUserId(code)
        except OAuthError as error:
            log.warning("OAuth exchange failed: %s", error)
            return self.finish(renderPage(502, "Discord login failed", "Please click Verify in Discord again."))

        if loggedInUserId != expectedUserId:
            log.info("user %s's link was completed by a different account", expectedUserId)
            return self.finish(
                renderPage(
                    403,
                    "Wrong account",
                    "You logged in with a different Discord account than the one that clicked Verify. "
                    "Log in as that account and try again.",
                )
            )

        ipHash = request[IP_HASH_KEY]
        outcome = await self.verifier.completeWeb(expectedUserId, ipHash)
        title, message, statusLine = OUTCOME_PAGES[outcome]
        return self.finish(renderPage(200, title, message, statusLine))

    @staticmethod
    def finish(response: web.Response) -> web.Response:
        response.del_cookie(NONCE_COOKIE_NAME, path="/", secure=True, httponly=True, samesite="Lax")
        return response
