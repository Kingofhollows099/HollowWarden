"""The real OAuth client against a local stand-in for Discord's endpoints.

Every other web test swaps DiscordOAuth for a fake, so before these tests
nothing ran the real token exchange or revoke code. That gap let a broken
merge (a NameError in _revoke) reach production.
"""

import base64
import warnings

import pytest
from aiohttp import web

import hollowwarden.oauth as oauthModule
from hollowwarden.oauth import DiscordOAuth, OAuthError

CLIENT_ID = "444444444444444444"
CLIENT_SECRET = "right-secret"
EXPECTED_AUTH = "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
USER_ID = "123456789012345678"


@pytest.fixture
async def fakeDiscord(aiohttp_server, monkeypatch):
    """Records each request, and answers like Discord's OAuth endpoints."""
    calls = []

    async def token(request):
        form = await request.post()
        calls.append(("token", form.get("grant_type"), request.headers.get("Authorization")))
        if request.headers.get("Authorization") != EXPECTED_AUTH:
            return web.json_response({"error": "invalid_client"}, status=401)
        if form.get("grant_type") == "authorization_code" and form.get("code") != "good-code":
            return web.json_response({"error": "invalid_grant"}, status=400)
        return web.json_response({"access_token": "user-token", "token_type": "Bearer"})

    async def me(request):
        calls.append(("me", None, request.headers.get("Authorization")))
        return web.json_response({"id": USER_ID})

    async def revoke(request):
        form = await request.post()
        calls.append(("revoke", form.get("token"), request.headers.get("Authorization")))
        return web.json_response({})

    app = web.Application()
    app.router.add_post("/oauth2/token", token)
    app.router.add_get("/users/@me", me)
    app.router.add_post("/oauth2/token/revoke", revoke)
    server = await aiohttp_server(app)
    monkeypatch.setattr(oauthModule, "API_BASE_URL", str(server.make_url("")).rstrip("/"))
    return calls


@pytest.fixture
async def oauth():
    client = DiscordOAuth(CLIENT_ID, CLIENT_SECRET, "https://verify.example.com/callback")
    await client.start()
    yield client
    await client.close()


def revokeCalls(calls):
    return [call for call in calls if call[0] == "revoke"]


class TestLogin:
    async def test_returnsUserAndRevokesToken(self, fakeDiscord, oauth):
        assert await oauth.fetchUserId("good-code") == int(USER_ID)
        # The token is revoked, using the app's credentials.
        assert revokeCalls(fakeDiscord) == [("revoke", "user-token", EXPECTED_AUTH)]
        assert ("me", None, "Bearer user-token") in fakeDiscord

    async def test_badCodeRaisesOAuthError(self, fakeDiscord, oauth):
        with pytest.raises(OAuthError):
            await oauth.fetchUserId("bad-code")


class TestCredentialCheck:
    async def test_rightSecretIsValidAndTokenRevoked(self, fakeDiscord, oauth):
        assert await oauth.credentialsAreValid() is True
        assert revokeCalls(fakeDiscord) == [("revoke", "user-token", EXPECTED_AUTH)]

    async def test_wrongSecretIsInvalid(self, fakeDiscord):
        wrongClient = DiscordOAuth(CLIENT_ID, "wrong-secret", "https://verify.example.com/callback")
        await wrongClient.start()
        try:
            assert await wrongClient.credentialsAreValid() is False
        finally:
            await wrongClient.close()
        assert revokeCalls(fakeDiscord) == []


async def test_noDeprecatedAiohttpApis(fakeDiscord, oauth):
    # aiohttp.BasicAuth is deprecated and goes away in aiohttp 4, so make sure
    # nothing here still uses it.
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        await oauth.fetchUserId("good-code")
        await oauth.credentialsAreValid()
