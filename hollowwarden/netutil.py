"""Client IP handling: finding the real address and hashing it.

Raw IP addresses are never stored. Each one is passed through HMAC-SHA256
with a secret key, and only that result is kept. The key matters because there
are only about 4 billion IPv4 addresses: a plain SHA-256 of an IP can be
reversed in minutes by hashing every possible address. Without the key, the
HMAC values reveal nothing, yet two equal IPs still produce equal values,
which is all alt detection needs.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections.abc import Iterable, Mapping

IPV6_PREFIX_LENGTH = 64


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
    return hmac.new(ipHashKey, normalizeIp(rawIp).encode("ascii"), hashlib.sha256).hexdigest()


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
