"""Client IP handling: finding the real address and hashing it.

Raw IP addresses are never stored. There are only about 4 billion IPv4
addresses, so any hash of one can be reversed by hashing every possible
address and comparing. Two things stand in the way:

- A secret key. Without it, a stored value reveals nothing, so a leaked
  database or backup on its own is useless.
- A deliberately slow hash (scrypt) for everything that's stored. With a
  fast hash, someone who stole the key as well could try every IPv4 address
  in about two hours on one CPU core. With scrypt, each guess costs about
  0.1 seconds and 32 MB of memory, which turns that into about 11 years per
  core, and the memory requirement blunts graphics cards. Nothing can stop
  someone with the key from checking a single guess ("was this person on
  this IP?"); this protects against reversing everything at once.

A fast keyed hash (HMAC) is still used for the website's rate limiter, which
runs on every request and is only ever held in memory. Making that slow
would let anyone burn the server's CPU and memory just by loading pages.
Equal IPs still give equal values with either hash, which is all alt
detection needs.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
from collections.abc import Iterable, Mapping

IPV6_PREFIX_LENGTH = 64

# Stored hashes start with this, which tells them apart from the HMAC values
# stored before the slow hash was introduced.
SLOW_HASH_PREFIX = "scrypt1:"
# scrypt's cost settings: 2^15 rounds with block size 8 needs 32 MB of memory
# per hash (128 x 8 x 2^15 bytes) and takes about 0.1 seconds. Changing them
# changes every hash, so existing records would stop matching.
SCRYPT_COST = 2**15
SCRYPT_BLOCK_SIZE = 8
SCRYPT_PARALLELISM = 1
SCRYPT_MAX_MEMORY = 64 * 1024 * 1024
# How many slow hashes may run at once. Each needs 32 MB, and the container
# is limited to 256 MB, so a burst of logins must queue rather than pile up.
MAX_CONCURRENT_SLOW_HASHES = 2


def normalizeIp(rawIp: str) -> str:
    """Reduce an address to the form we compare on.

    ISPs normally hand each home a whole IPv6 /64 and devices rotate through
    it constantly, so comparing full IPv6 addresses would almost never match.
    Comparing the /64 is the IPv6 equivalent of comparing a home's IPv4
    address.
    """
    address = ipaddress.ip_address(rawIp.strip())
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        network = ipaddress.ip_network(f"{address}/{IPV6_PREFIX_LENGTH}", strict=False)
        return str(network)
    return str(address)


def hashIp(ipHashKey: bytes, rawIp: str) -> str:
    """The fast keyed hash: for in-memory use (rate limiting), and for
    matching records stored before the slow hash existed."""
    return hmac.new(ipHashKey, normalizeIp(rawIp).encode("ascii"), hashlib.sha256).hexdigest()


def hashIpSlow(ipHashKey: bytes, rawIp: str) -> str:
    """The slow keyed hash used for everything stored. The secret key is the
    salt, so the same IP always gives the same value (as alt detection needs)
    but only with this key."""
    digest = hashlib.scrypt(
        normalizeIp(rawIp).encode("ascii"),
        salt=ipHashKey,
        n=SCRYPT_COST,
        r=SCRYPT_BLOCK_SIZE,
        p=SCRYPT_PARALLELISM,
        maxmem=SCRYPT_MAX_MEMORY,
        dklen=32,
    )
    return SLOW_HASH_PREFIX + digest.hex()


class SlowIpHasher:
    """Runs hashIpSlow off the event loop, a limited number at a time, so a
    hash never stalls the bot and a burst of logins can't exhaust memory."""

    def __init__(self, ipHashKey: bytes, maxConcurrent: int = MAX_CONCURRENT_SLOW_HASHES) -> None:
        self._ipHashKey = ipHashKey
        self._semaphore = asyncio.Semaphore(maxConcurrent)

    async def hash(self, rawIp: str) -> str:
        async with self._semaphore:
            return await asyncio.to_thread(hashIpSlow, self._ipHashKey, rawIp)


def isTrustedProxy(
    peerIp: str | None, trustedProxies: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]
) -> bool:
    """True if the connection itself comes from one of TRUSTED_PROXIES."""
    if not peerIp:
        return False
    try:
        peerAddress = ipaddress.ip_address(peerIp)
    except ValueError:
        return False
    return any(peerAddress in network for network in trustedProxies)


def resolveClientIp(
    peerIp: str | None,
    headers: Mapping[str, str],
    trustedProxies: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
    clientIpHeader: str | None,
) -> str | None:
    """Work out the visitor's IP, or return None if it can't be trusted.

    A header like X-Real-IP is only believed when the connection itself comes
    from a proxy we trust (Nginx Proxy Manager). Otherwise anyone could send
    that header and choose their own IP, which would defeat alt detection.
    """
    if not peerIp:
        return None
    try:
        peerAddress = ipaddress.ip_address(peerIp)
    except ValueError:
        return None

    if not isTrustedProxy(peerIp, trustedProxies):
        return str(peerAddress)

    headerValue = headers.get(clientIpHeader or "", "").strip()
    # Only a single address is accepted. Multi-hop lists like X-Forwarded-For
    # are easy to parse wrongly in a way that lets the client pick the
    # answer, so they're rejected rather than guessed at.
    if not headerValue or "," in headerValue:
        return None
    try:
        return str(ipaddress.ip_address(headerValue))
    except ValueError:
        return None
