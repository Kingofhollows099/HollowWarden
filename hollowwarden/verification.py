"""The verification decision, kept separate from Discord and the web server.

Both verification methods end up here, so the rules (account age, alt
matches, review or allow) live in exactly one place. Discord access goes
through the small `DiscordGateway` interface, which lets the tests check the
decision logic with a fake gateway instead of a real bot.
"""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass
from typing import Protocol

from .config import Settings
from .storage import Storage

log = logging.getLogger(__name__)

DISCORD_EPOCH_MS = 1420070400000
MAX_MATCHES_LISTED = 10


class Outcome(enum.Enum):
    VERIFIED = "verified"
    PENDING_REVIEW = "pending_review"
    ALREADY_VERIFIED = "already_verified"
    NOT_MEMBER = "not_member"


@dataclass(frozen=True)
class MemberState:
    isMember: bool
    hasVerifiedRole: bool


class DiscordGateway(Protocol):
    async def getMemberState(self, userId: int) -> MemberState: ...

    async def grantVerifiedRole(self, userId: int) -> None: ...

    async def postModLog(self, message: str) -> None: ...

    async def postReview(self, userId: int, reasons: list[str], needsDecision: bool) -> None: ...


def accountCreatedAt(userId: int) -> float:
    """Discord IDs encode their creation time, so no API call is needed."""
    return ((userId >> 22) + DISCORD_EPOCH_MS) / 1000


def describeAge(seconds: float) -> str:
    days = int(seconds // 86400)
    if days >= 1:
        return f"{days} day{'s' if days != 1 else ''}"
    hours = int(seconds // 3600)
    return f"{hours} hour{'s' if hours != 1 else ''}"


class Verifier:
    def __init__(self, settings: Settings, storage: Storage, gateway: DiscordGateway) -> None:
        self.settings = settings
        self.storage = storage
        self.gateway = gateway

    async def completeCaptcha(self, userId: int) -> Outcome:
        return await self._complete(userId, method="captcha", ipHash=None)

    async def completeWeb(self, userId: int, ipHash: str) -> Outcome:
        return await self._complete(userId, method="web login", ipHash=ipHash)

    async def _complete(self, userId: int, method: str, ipHash: str | None, now: float | None = None) -> Outcome:
        currentTime = time.time() if now is None else now

        memberState = await self.gateway.getMemberState(userId)
        if not memberState.isMember:
            return Outcome.NOT_MEMBER
        if memberState.hasVerifiedRole:
            return Outcome.ALREADY_VERIFIED
        if await self.storage.hasPendingReview(userId):
            return Outcome.PENDING_REVIEW

        reasons = []

        accountAge = currentTime - accountCreatedAt(userId)
        minimumAge = self.settings.minAccountAgeDays * 86400
        if accountAge < minimumAge:
            reasons.append(
                f"Account is only {describeAge(accountAge)} old (minimum is {self.settings.minAccountAgeDays} days)."
            )

        if ipHash is not None:
            matchedUserIds = await self.storage.recordIpAndFindMatches(userId, ipHash, now=currentTime)
            if matchedUserIds:
                reasons.append(await self._describeMatches(matchedUserIds))

        if not reasons:
            await self.gateway.grantVerifiedRole(userId)
            await self.gateway.postModLog(f"✓  <@{userId}> (`{userId}`) verified by {method}.")
            log.info("user %s verified by %s", userId, method)
            return Outcome.VERIFIED

        if self.settings.flaggedAction == "allow":
            await self.gateway.grantVerifiedRole(userId)
            await self.gateway.postReview(userId, reasons, needsDecision=False)
            log.info("user %s verified by %s with flags", userId, method)
            return Outcome.VERIFIED

        await self.storage.addPendingReview(userId, now=currentTime)
        await self.gateway.postReview(userId, reasons, needsDecision=True)
        log.info("user %s held for moderator review", userId)
        return Outcome.PENDING_REVIEW

    async def _describeMatches(self, matchedUserIds: list[int]) -> str:
        descriptions = []
        for matchedUserId in matchedUserIds[:MAX_MATCHES_LISTED]:
            matchedState = await self.gateway.getMemberState(matchedUserId)
            # "Not in server" covers both "left" and "banned". Checking for a
            # ban would need the Ban Members permission, which is far too
            # powerful to give this bot just for a label.
            status = "in server" if matchedState.isMember else "not in server (left or banned)"
            descriptions.append(f"<@{matchedUserId}> (`{matchedUserId}`, {status})")
        extraCount = len(matchedUserIds) - MAX_MATCHES_LISTED
        if extraCount > 0:
            descriptions.append(f"and {extraCount} more")
        return "Verified from the same network as: " + ", ".join(descriptions) + "."

    async def resolveReview(self, userId: int, approve: bool) -> bool:
        """Apply a moderator decision. Returns False if it was already handled."""
        if not await self.storage.popPendingReview(userId):
            return False
        if approve:
            try:
                await self.gateway.grantVerifiedRole(userId)
            except Exception:
                # Put the review back so the decision can be retried rather
                # than silently lost.
                await self.storage.addPendingReview(userId)
                raise
        return True
