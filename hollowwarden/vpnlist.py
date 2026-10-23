"""VPN detection against a public list of VPN address ranges.

The check runs entirely on this server. The list is downloaded and cached,
then each visitor's IP is looked up locally before it's hashed. Raw IPs are
never sent anywhere, unlike paid lookup services, which would mean handing
every member's real IP to a third party.

A list is data, not code, so a bad or tampered download can't run anything.
The worst it could do is flag the wrong people, and the checks below are
there to stop that: a list that's too small (an error page or a truncated
file) or that covers an implausible share of the internet (for example one
containing 0.0.0.0/1) is rejected, and the last good list stays in use.
"""

from __future__ import annotations

import asyncio
import bisect
import ipaddress
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

import aiohttp

log = logging.getLogger(__name__)

DEFAULT_VPN_LIST_URLS = ("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",)
REFRESH_INTERVAL_SECONDS = 24 * 3600
STALE_AFTER_SECONDS = 3 * 24 * 3600
DOWNLOAD_TIMEOUT = aiohttp.ClientTimeout(total=60)
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024
MIN_RANGES = 100
# The broadest single range accepted. Real VPN providers announce small
# blocks (the default list's broadest is a /17); anything wider than this is
# far more likely a mistake that would sweep in home internet customers.
MIN_PREFIX_LENGTH = {4: 12, 6: 24}
# The default VPN list covers about 0.07% of IPv4, and even the much broader
# datacenter list is about 9%. A list claiming more than this is rejected.
MAX_IPV4_COVERAGE = 0.15


class ListRejected(Exception):
    """A downloaded list failed the sanity checks."""


@dataclass(frozen=True)
class NetworkList:
    """IP ranges merged and sorted per IP version, for fast lookups."""

    starts: dict[int, list[int]]
    ends: dict[int, list[int]]
    # Entries accepted from the list as published, before overlapping or
    # adjacent ones are merged. Used for the size check and for display.
    rangeCount: int

    @classmethod
    def parse(cls, text: str) -> NetworkList:
        networks = []
        skippedCount = 0
        for line in text.splitlines():
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                skippedCount += 1
                continue
            if network.prefixlen < MIN_PREFIX_LENGTH[network.version]:
                skippedCount += 1
                continue
            networks.append(network)
        if skippedCount:
            log.warning("VPN list: skipped %s entries that weren't valid, narrow-enough IP ranges", skippedCount)

        starts: dict[int, list[int]] = {4: [], 6: []}
        ends: dict[int, list[int]] = {4: [], 6: []}
        for version in (4, 6):
            for network in ipaddress.collapse_addresses(n for n in networks if n.version == version):
                starts[version].append(int(network.network_address))
                ends[version].append(int(network.broadcast_address))
        return cls(starts=starts, ends=ends, rangeCount=len(networks))

    def ipv4Coverage(self) -> float:
        return sum(end - start + 1 for start, end in zip(self.starts[4], self.ends[4])) / 2**32

    def contains(self, rawIp: str) -> bool:
        address = ipaddress.ip_address(rawIp)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        value = int(address)
        starts = self.starts[address.version]
        index = bisect.bisect_right(starts, value) - 1
        return index >= 0 and value <= self.ends[address.version][index]


def validate(networkList: NetworkList) -> None:
    coverage = networkList.ipv4Coverage()
    if coverage > MAX_IPV4_COVERAGE:
        raise ListRejected(f"it covers {coverage:.1%} of all IPv4 addresses, which isn't plausible")
    if networkList.rangeCount < MIN_RANGES:
        raise ListRejected(f"only {networkList.rangeCount} ranges, expected at least {MIN_RANGES}")


class VpnChecker:
    def __init__(self, urls: tuple[str, ...], cachePath: Path) -> None:
        self.urls = urls
        self.cachePath = cachePath
        self.networkList: NetworkList | None = None
        self.updatedAt: float | None = None
        self.lastError: str | None = None

    def loadCache(self) -> None:
        """Use the list saved by an earlier run, so the check works straight
        away after a restart, even if the download source is down."""
        try:
            text = self.cachePath.read_text(encoding="utf-8")
            networkList = NetworkList.parse(text)
            validate(networkList)
        except FileNotFoundError:
            return
        except (OSError, ListRejected) as error:
            log.warning("ignoring the cached VPN list: %s", error)
            return
        self.networkList = networkList
        self.updatedAt = self.cachePath.stat().st_mtime
        log.info("loaded cached VPN list: %s ranges", networkList.rangeCount)

    def isVpn(self, rawIp: str) -> bool | None:
        """True or False, or None when no list is loaded yet (check skipped)."""
        if self.networkList is None:
            return None
        return self.networkList.contains(rawIp)

    def isStale(self, now: float | None = None) -> bool:
        currentTime = time.time() if now is None else now
        return self.updatedAt is None or currentTime - self.updatedAt > STALE_AFTER_SECONDS

    async def refresh(self) -> bool:
        """Download, check and swap in a new list. On any failure the current
        list stays in use, and the reason is kept for /test-config."""
        try:
            parts = []
            async with aiohttp.ClientSession(timeout=DOWNLOAD_TIMEOUT) as session:
                for url in self.urls:
                    parts.append(await self._download(session, url))
            text = "\n".join(parts)
            networkList = await asyncio.to_thread(NetworkList.parse, text)
            validate(networkList)
            await asyncio.to_thread(self._writeCache, text)
        except (aiohttp.ClientError, TimeoutError, OSError, ListRejected, UnicodeDecodeError) as error:
            self.lastError = f"{type(error).__name__}: {error}" if str(error) else type(error).__name__
            log.warning("couldn't update the VPN list (%s); keeping the current one", self.lastError)
            return False
        self.networkList = networkList
        self.updatedAt = time.time()
        self.lastError = None
        log.info("VPN list updated: %s ranges", networkList.rangeCount)
        return True

    async def _download(self, session: aiohttp.ClientSession, url: str) -> str:
        async with session.get(url) as response:
            if response.status != 200:
                raise ListRejected(f"{url} answered HTTP {response.status}")
            body = bytearray()
            async for chunk in response.content.iter_chunked(64 * 1024):
                body.extend(chunk)
                # Stop early rather than letting a huge response fill memory.
                if len(body) > MAX_DOWNLOAD_BYTES:
                    raise ListRejected(f"{url} is larger than {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB")
        return body.decode("utf-8")

    def _writeCache(self, text: str) -> None:
        # Write to a temporary file and rename it, so a crash halfway through
        # never leaves a truncated list behind.
        temporaryPath = self.cachePath.with_suffix(".tmp")
        temporaryPath.write_text(text, encoding="utf-8")
        os.replace(temporaryPath, self.cachePath)

    async def refreshForever(self) -> None:
        # Download now if there's no cached list or it's over a day old;
        # otherwise the cache is fresh enough until the next scheduled update.
        if self.updatedAt is None or time.time() - self.updatedAt >= REFRESH_INTERVAL_SECONDS:
            await self.refresh()
        while True:
            await asyncio.sleep(REFRESH_INTERVAL_SECONDS)
            await self.refresh()
