"""The minimal Discord OAuth2 client used by the web verification flow.

Only the `identify` scope is requested: just enough to learn which Discord
account is using the browser. No email, no server list, no ability to act
as the user. The access token is revoked as soon as the ID has been read, so
there's never a stored token that could be stolen.
"""

from __future__ import annotations

import logging
from urllib.parse import urlencode

import aiohttp

log = logging.getLogger(__name__)

AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
API_BASE_URL = "https://discord.com/api/v10"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10)


class OAuthError(Exception):
    """The OAuth exchange with Discord failed."""


class DiscordOAuth:
    def __init__(self, clientId: str, clientSecret: str, redirectUri: str) -> None:
        self.clientId = clientId
        self._clientSecret = clientSecret
        self.redirectUri = redirectUri
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        self._session = aiohttp.ClientSession(timeout=REQUEST_TIMEOUT)

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()

    def authorizeUrl(self, state: str) -> str:
        query = urlencode(
            {
                "client_id": self.clientId,
                "response_type": "code",
                "redirect_uri": self.redirectUri,
                "scope": "identify",
                "state": state,
                "prompt": "consent",
            }
        )
        return f"{AUTHORIZE_URL}?{query}"

    async def fetchUserId(self, code: str) -> int:
        if self._session is None:
            raise RuntimeError("DiscordOAuth.start() has not been called")
        clientAuthHeaders = {"Authorization": aiohttp.encode_basic_auth(self.clientId, self._clientSecret)}

        async with self._session.post(
            f"{API_BASE_URL}/oauth2/token",
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirectUri},
            headers=clientAuthHeaders,
        ) as tokenResponse:
            if tokenResponse.status != 200:
                # The response body is deliberately not logged, in case it
                # echoes anything sensitive back.
                raise OAuthError(f"token exchange failed with HTTP {tokenResponse.status}")
            tokenPayload = await tokenResponse.json()

        accessToken = tokenPayload.get("access_token")
        if not isinstance(accessToken, str) or tokenPayload.get("token_type") != "Bearer":
            raise OAuthError("token exchange returned an unexpected payload")

        try:
            async with self._session.get(
                f"{API_BASE_URL}/users/@me", headers={"Authorization": f"Bearer {accessToken}"}
            ) as userResponse:
                if userResponse.status != 200:
                    raise OAuthError(f"user lookup failed with HTTP {userResponse.status}")
                userPayload = await userResponse.json()
        finally:
            await self._revoke(accessToken, clientAuthHeaders)

        userId = userPayload.get("id")
        if not isinstance(userId, str) or not userId.isdigit():
            raise OAuthError("user lookup returned an unexpected payload")
        return int(userId)

    async def credentialsAreValid(self) -> bool:
        """Check the client ID and secret without needing a user to log in.

        A client-credentials request only succeeds when both are right. The
        token it returns belongs to the app's owner, isn't needed, and is
        revoked straight away.
        """
        if self._session is None:
            raise RuntimeError("DiscordOAuth.start() has not been called")
        clientAuthHeaders = {"Authorization": aiohttp.encode_basic_auth(self.clientId, self._clientSecret)}
        async with self._session.post(
            f"{API_BASE_URL}/oauth2/token",
            data={"grant_type": "client_credentials", "scope": "identify"},
            headers=clientAuthHeaders,
        ) as tokenResponse:
            if tokenResponse.status in (400, 401):
                # A wrong ID or secret is "invalid_client". Anything else is
                # some other problem, and shouldn't be reported as a bad secret.
                errorPayload = await tokenResponse.json(content_type=None)
                if isinstance(errorPayload, dict) and errorPayload.get("error") == "invalid_client":
                    return False
            if tokenResponse.status != 200:
                raise OAuthError(f"Discord answered HTTP {tokenResponse.status}")
            tokenPayload = await tokenResponse.json()
        accessToken = tokenPayload.get("access_token")
        if isinstance(accessToken, str):
            await self._revoke(accessToken, clientAuthHeaders)
        return True

    async def _revoke(self, accessToken: str, clientAuthHeaders: dict[str, str]) -> None:
        assert self._session is not None
        try:
            async with self._session.post(
                f"{API_BASE_URL}/oauth2/token/revoke",
                data={"token": accessToken, "token_type_hint": "access_token"},
                headers=clientAuthHeaders,
            ) as revokeResponse:
                if revokeResponse.status != 200:
                    log.warning("could not revoke OAuth token (HTTP %s)", revokeResponse.status)
        except aiohttp.ClientError as error:
            log.warning("could not revoke OAuth token: %s", type(error).__name__)
