"""Raid detection: spotting a burst of verification attempts in one server.

What's counted is attempts that reach the verification decision (someone
passing the CAPTCHA or finishing the web login), not raw joins. Seeing every
join would need Discord's privileged Server Members intent, which the bot
deliberately doesn't have, and accounts that join but never verify can't see
anything anyway. The burst that matters is accounts trying to get *in*.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

# Recent attempts kept per server. Far above any useful threshold, so it only
# matters if something floods the bot, and then it caps memory use.
MAX_TRACKED_ATTEMPTS = 2000


@dataclass(frozen=True)
class RaidSummary:
    """What the raid alert message shows."""

    raidId: int
    startedAt: int
    memberCount: int
    heldCount: int
    verifiedBeforeCount: int
    flaggedCount: int
    threshold: int
    windowMinutes: int
    decision: str | None = None
    decidedBy: int | None = None
    resultText: str | None = None


class RaidDetector:
    """A sliding window of recent verification attempts for each server."""

    def __init__(self) -> None:
        self._attempts: dict[int, deque[tuple[float, int]]] = {}

    def record(self, guildId: int, userId: int, now: float, windowSeconds: float) -> list[int]:
        """Add an attempt and return the distinct users who attempted within
        the window, oldest first, this one included."""
        attempts = self._attempts.setdefault(guildId, deque(maxlen=MAX_TRACKED_ATTEMPTS))
        attempts.append((now, userId))
        cutoff = now - windowSeconds
        while attempts and attempts[0][0] < cutoff:
            attempts.popleft()
        recentUserIds: dict[int, None] = {}
        for _, attemptUserId in attempts:
            recentUserIds[attemptUserId] = None
        return list(recentUserIds)
