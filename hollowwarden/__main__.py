"""Entry point: `python -m hollowwarden`."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
from pathlib import Path

from aiohttp import web

from .bot import HollowWardenBot, StartupError
from .config import ConfigError, Settings, loadSettings
from .oauth import DiscordOAuth
from .storage import Storage
from .vpnlist import VpnChecker
from .web import VerificationSite

log = logging.getLogger("hollowwarden")

PURGE_INTERVAL_SECONDS = 3600


async def purgeLoop(storage: Storage, settings: Settings) -> None:
    ipRetentionSeconds = settings.web.ipRetentionDays * 86400 if settings.web else None
    while True:
        try:
            await storage.purgeExpired(ipRetentionSeconds)
        except Exception:
            log.exception("purge failed")
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)


async def run(settings: Settings) -> None:
    storage = Storage(settings.databasePath)
    await storage.open()
    bot = HollowWardenBot(settings, storage)
    oauth: DiscordOAuth | None = None
    webRunner: web.AppRunner | None = None
    vpnRefreshTask: asyncio.Task | None = None
    purgeTask = asyncio.create_task(purgeLoop(storage, settings))

    try:
        if settings.web is not None:
            oauth = DiscordOAuth(settings.web.clientId, settings.web.clientSecret, settings.web.redirectUri)
            await oauth.start()
            bot.oauth = oauth
            vpnChecker = None
            if settings.web.vpnListUrls:
                # Cached next to the database, on the only writable volume.
                vpnChecker = VpnChecker(settings.web.vpnListUrls, Path(settings.databasePath).parent / "vpn-ranges.txt")
                vpnChecker.loadCache()
                vpnRefreshTask = asyncio.create_task(vpnChecker.refreshForever())
                bot.vpnChecker = vpnChecker
            site = VerificationSite(settings.web, storage, bot.verifier, oauth, bot.is_ready, vpnChecker)
            # access_log=None: access logs would record visitors' IPs and the
            # one-time tokens and OAuth codes in the URLs.
            webRunner = web.AppRunner(site.createApp(), access_log=None)
            await webRunner.setup()
            await web.TCPSite(webRunner, settings.web.listenHost, settings.web.listenPort).start()
            log.info("verification site listening on port %s", settings.web.listenPort)
        else:
            log.info("CAPTCHA mode: no web server started")

        await bot.start(settings.botToken)
    finally:
        for backgroundTask in (purgeTask, vpnRefreshTask):
            if backgroundTask is not None:
                backgroundTask.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await backgroundTask
        if not bot.is_closed():
            await bot.close()
        if webRunner is not None:
            await webRunner.cleanup()
        if oauth is not None:
            await oauth.close()
        await storage.close()


async def main() -> None:
    settings = loadSettings()
    logging.getLogger().setLevel(settings.logLevel.upper())

    mainTask = asyncio.current_task()
    loop = asyncio.get_running_loop()
    # Docker stops containers with SIGTERM. Turning it into a cancellation
    # lets the bot disconnect cleanly and SQLite close properly.
    for stopSignal in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(stopSignal, mainTask.cancel)

    with contextlib.suppress(asyncio.CancelledError):
        await run(settings)
    log.info("stopped")


def cli() -> None:
    # New files (the database) are readable by this user only.
    os.umask(0o077)
    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
    try:
        asyncio.run(main())
    except ConfigError as error:
        log.error("configuration error: %s", error)
        sys.exit(2)
    except StartupError as error:
        log.error("%s", error)
        sys.exit(3)


if __name__ == "__main__":
    cli()
