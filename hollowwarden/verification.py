"""The verification decision, kept separate from Discord and the web server.

Both verification methods end up here, so the rules (account age, alt
matches, review or allow) live in exactly one place. Every call names the
server it's for, and that server's own settings and data are used. Discord access goes
through the small `DiscordGateway` interface, which lets the tests check the
decision logic with a fake gateway instead of a real bot.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import time
from dataclasses import dataclass
from typing import Protocol

from .config import ServerSettings, Settings
from .raids import RaidDetector, RaidSummary
from .storage import ServerStorage

log = logging.getLogger(__name__)

DISCORD_EPOCH_MS = 1420070400000
MAX_MATCHES_LISTED = 10


class Outcome(enum.Enum):
    VERIFIED = "verified"
    PENDING_REVIEW = "pending_review"
    ALREADY_VERIFIED = "already_verified"
    NOT_MEMBER = "not_member"
    # Verification couldn't finish because Discord refused something the bot
    # needed (usually a missing permission). Nothing was left half-done.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class MemberState:
    isMember: bool
    hasVerifiedRole: bool


class DiscordGateway(Protocol):
    """Discord access for the Verifier.

    postModLog and postReview never raise for Discord errors. A mod-channel
    message is a side effect, and a missing permission there must not turn a
    finished verification into an error. They log the cause instead, and
    postReview reports whether the message was actually posted.
    """

    async def getMemberState(self, guildId: int, userId: int) -> MemberState: ...

    async def grantVerifiedRole(self, guildId: int, userId: int, auditReason: str | None = None) -> None: ...

    async def postModLog(self, guildId: int, message: str) -> None: ...

    async def postReview(self, guildId: int, userId: int, reasons: list[str], needsDecision: bool) -> bool: ...

    async def postRaidAlert(self, guildId: int, summary: RaidSummary) -> int | None:
        """Post the raid alert. Returns its message ID, or None if it couldn't be posted."""
        ...

    async def updateRaidAlert(self, guildId: int, messageId: int, summary: RaidSummary) -> None: ...

    async def removeVerifiedRole(self, guildId: int, userId: int, auditReason: str) -> bool:
        """True if the role was removed; False if they'd left or didn't have it."""
        ...


@dataclass(frozen=True)
class RaidResolution:
    approved: int = 0
    denied: int = 0
    rolesRemoved: int = 0
    skipped: int = 0
    failed: int = 0

    def describe(self, approve: bool) -> str:
        parts = [f"{self.approved} verified" if approve else f"{self.denied} denied"]
        if self.rolesRemoved:
            parts.append(f"Verified role removed from {self.rolesRemoved} let in before detection")
        if self.skipped:
            parts.append(f"{self.skipped} already handled or gone")
        if self.failed:
            parts.append(f"{self.failed} failed (see the bot's logs)")
        return ", ".join(parts) + "."


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
    def __init__(self, settings: Settings, storage: ServerStorage, gateway: DiscordGateway) -> None:
        self.settings = settings
        self.storage = storage
        self.gateway = gateway
        self.raidDetector = RaidDetector()
        # One lock per server around raid bookkeeping, so concurrent attempts
        # can't open two raids at once, and a moderator's "Approve all" or
        # "Deny all" can't miss someone being added at the same moment.
        self._raidLocks: dict[int, asyncio.Lock] = {}

    def serverSettings(self, guildId: int) -> ServerSettings:
        server = self.settings.server(guildId)
        if server is None:
            # Callers only pass configured servers; this is a safety net.
            raise ValueError(f"server {guildId} isn't configured")
        return server

    async def completeCaptcha(self, guildId: int, userId: int) -> Outcome:
        return await self._complete(guildId, userId, method="captcha", ipHash=None)

    async def completeWeb(
        self, guildId: int, userId: int, ipHash: str, isVpn: bool | None = None, legacyIpHash: str | None = None
    ) -> Outcome:
        """isVpn is None when no VPN list is loaded yet. legacyIpHash matches
        records stored before the slow hash (see storage)."""
        return await self._complete(
            guildId, userId, method="web login", ipHash=ipHash, isVpn=isVpn, legacyIpHash=legacyIpHash
        )

    async def _complete(
        self,
        guildId: int,
        userId: int,
        method: str,
        ipHash: str | None,
        isVpn: bool | None = None,
        now: float | None = None,
        legacyIpHash: str | None = None,
    ) -> Outcome:
        server = self.serverSettings(guildId)
        currentTime = time.time() if now is None else now

        memberState = await self.gateway.getMemberState(guildId, userId)
        if not memberState.isMember:
            return Outcome.NOT_MEMBER
        if memberState.hasVerifiedRole:
            return Outcome.ALREADY_VERIFIED
        if await self.storage.hasPendingReview(guildId, userId):
            return Outcome.PENDING_REVIEW

        reasons = []

        accountAge = currentTime - accountCreatedAt(userId)
        minimumAge = server.minAccountAgeDays * 86400
        if accountAge < minimumAge:
            reasons.append(
                f"Account is only {describeAge(accountAge)} old (minimum is {server.minAccountAgeDays} days)."
            )

        if isVpn and server.flagVpn:
            # A VPN hides the network someone really connects from, which is
            # what alt detection relies on, so a moderator should take a look.
            reasons.append("Connected through a known VPN network, so the alt check can't see their real network.")

        if ipHash is not None:
            matchedUserIds = await self.storage.recordIpAndFindMatches(
                guildId, userId, ipHash, now=currentTime, legacyIpHash=legacyIpHash
            )
            if matchedUserIds:
                reasons.append(await self._describeMatches(guildId, matchedUserIds))

        if server.raidThreshold:
            raidOutcome = await self._holdIfRaid(server, userId, reasons, currentTime)
            if raidOutcome is not None:
                return raidOutcome

        if not reasons:
            await self.gateway.grantVerifiedRole(guildId, userId)
            await self.gateway.postModLog(guildId, f"✓  <@{userId}> (`{userId}`) verified by {method}.")
            log.info("user %s verified in server %s by %s", userId, guildId, method)
            return Outcome.VERIFIED

        if server.flaggedAction == "allow":
            await self.gateway.grantVerifiedRole(guildId, userId)
            # The role is already granted, so a failed alert is only logged
            # (by the gateway). It doesn't change the outcome.
            await self.gateway.postReview(guildId, userId, reasons, needsDecision=False)
            log.info("user %s verified in server %s by %s with flags", userId, guildId, method)
            return Outcome.VERIFIED

        # Post first, record second. The review message is the only way a
        # moderator can act on a review, so if it can't be posted the member
        # must not be marked pending: they'd be stuck in a review nobody can
        # see, and every retry would answer "pending". (A moderator clicking
        # in the moment between the two steps would just see "Already
        # handled" and could click again.)
        if not await self.gateway.postReview(guildId, userId, reasons, needsDecision=True):
            log.warning(
                "user %s in server %s could not be held for review: the review message couldn't be posted",
                userId,
                guildId,
            )
            return Outcome.UNAVAILABLE
        await self.storage.addPendingReview(guildId, userId, now=currentTime)
        log.info("user %s in server %s held for moderator review", userId, guildId)
        return Outcome.PENDING_REVIEW

    def _raidLock(self, guildId: int) -> asyncio.Lock:
        return self._raidLocks.setdefault(guildId, asyncio.Lock())

    async def _holdIfRaid(self, server: ServerSettings, userId: int, reasons: list[str], now: float) -> Outcome | None:
        """Count this attempt, and if the server is in a raid, hold the member
        as part of it. Returns None when there's no raid, so normal
        verification carries on.

        During a raid every attempt is held, flagged or not, and added to one
        raid alert instead of getting its own review message: a flood of
        review messages is exactly what a raid would otherwise cause.
        """
        guildId = server.guildId
        windowSeconds = server.raidWindowMinutes * 60
        store = self.storage.forGuild(guildId)
        async with self._raidLock(guildId):
            recentUserIds = self.raidDetector.record(guildId, userId, now, windowSeconds)
            raid = await store.findActiveRaid(activeSince=now - windowSeconds)
            if raid is None:
                if len(recentUserIds) < server.raidThreshold:
                    return None
                raidId = await store.createRaid(now=now)
                log.warning(
                    "possible raid in %s: %s verification attempts within %s minutes",
                    server.name,
                    len(recentUserIds),
                    server.raidWindowMinutes,
                )
                await self._addEarlierAttempts(server, raidId, [uid for uid in recentUserIds if uid != userId], now)
                raid = await store.getRaid(raidId)
                assert raid is not None

            await store.addRaidMember(raid.raidId, userId, verifiedBefore=False, reasons=reasons, now=now)
            summary = await self.raidSummary(server, raid.raidId)
            if raid.messageId is None:
                # Post first, mark pending second, as with single reviews: if
                # the alert can't be posted, nobody can act on this member.
                messageId = await self.gateway.postRaidAlert(guildId, summary)
                if messageId is None:
                    await store.removeRaidMember(raid.raidId, userId)
                    log.warning("user %s in %s couldn't be held: the raid alert couldn't be posted", userId, server.name)
                    return Outcome.UNAVAILABLE
                await store.setRaidMessage(raid.raidId, server.modChannelId, messageId)
            else:
                await self.gateway.updateRaidAlert(guildId, raid.messageId, summary)
            await self.storage.addPendingReview(guildId, userId, now=now)
        log.info("user %s in %s held as part of raid %s", userId, server.name, raid.raidId)
        return Outcome.PENDING_REVIEW

    async def _addEarlierAttempts(self, server: ServerSettings, raidId: int, earlierUserIds: list[int], now: float) -> None:
        """When a raid is detected, the attempts that triggered it happened
        before anyone knew. Include those who got in (so "Deny all" can take
        their role back) and those already waiting for review."""
        store = self.storage.forGuild(server.guildId)
        for earlierUserId in earlierUserIds:
            state = await self.gateway.getMemberState(server.guildId, earlierUserId)
            if state.hasVerifiedRole:
                await store.addRaidMember(raidId, earlierUserId, verifiedBefore=True, reasons=[], now=now)
            elif state.isMember and await self.storage.hasPendingReview(server.guildId, earlierUserId):
                await store.addRaidMember(
                    raidId,
                    earlierUserId,
                    verifiedBefore=False,
                    reasons=["Was already waiting for review when the raid was detected."],
                    now=now,
                )

    async def raidSummary(self, server: ServerSettings, raidId: int, resultText: str | None = None) -> RaidSummary:
        store = self.storage.forGuild(server.guildId)
        raid = await store.getRaid(raidId)
        if raid is None:
            raise ValueError(f"raid {raidId} doesn't exist in {server.name}")
        members = await store.listRaidMembers(raidId)
        held = [member for member in members if not member.verifiedBefore]
        return RaidSummary(
            raidId=raidId,
            startedAt=raid.startedAt,
            memberCount=len(members),
            heldCount=len(held),
            verifiedBeforeCount=len(members) - len(held),
            flaggedCount=sum(1 for member in held if member.reasons),
            threshold=server.raidThreshold,
            windowMinutes=server.raidWindowMinutes,
            decision=raid.decision,
            decidedBy=raid.decidedBy,
            resultText=resultText,
        )

    async def resolveRaid(self, guildId: int, raidId: int, approve: bool, adminId: int) -> RaidResolution | None:
        """Approve or deny everyone in a raid. Returns None if it was already
        decided (or doesn't exist in this server).

        Approve verifies everyone still held. Deny keeps everyone held out and
        also removes the Verified role from anyone let in before the raid was
        detected. People handled one by one in the meantime (by /verify-member,
        say) are left as they are.
        """
        server = self.serverSettings(guildId)
        store = self.storage.forGuild(guildId)
        async with self._raidLock(guildId):
            if await store.getRaid(raidId) is None:
                return None
            if not await store.claimRaidDecision(raidId, "approved" if approve else "denied", adminId):
                return None
            counts = {"approved": 0, "denied": 0, "rolesRemoved": 0, "skipped": 0, "failed": 0}
            for member in await store.listRaidMembers(raidId):
                if member.verifiedBefore:
                    if approve:
                        continue
                    try:
                        removed = await self.gateway.removeVerifiedRole(
                            guildId, member.userId, auditReason=f"Raid denied by admin {adminId}"
                        )
                    except Exception:
                        log.exception("couldn't remove the Verified role from %s in %s", member.userId, server.name)
                        counts["failed"] += 1
                        continue
                    counts["rolesRemoved" if removed else "skipped"] += 1
                    continue
                if not await self.storage.popPendingReview(guildId, member.userId):
                    counts["skipped"] += 1
                    continue
                if not approve:
                    counts["denied"] += 1
                    continue
                try:
                    await self.gateway.grantVerifiedRole(
                        guildId, member.userId, auditReason=f"Raid approved by admin {adminId}"
                    )
                except Exception:
                    log.exception("couldn't verify %s in %s while approving a raid", member.userId, server.name)
                    # Keep them held so they can still be handled one by one.
                    await self.storage.addPendingReview(guildId, member.userId)
                    counts["failed"] += 1
                    continue
                counts["approved"] += 1
        resolution = RaidResolution(**counts)
        log.info(
            "raid %s in %s %s by %s: %s",
            raidId,
            server.name,
            "approved" if approve else "denied",
            adminId,
            resolution.describe(approve),
        )
        return resolution

    async def _describeMatches(self, guildId: int, matchedUserIds: list[int]) -> str:
        descriptions = []
        for matchedUserId in matchedUserIds[:MAX_MATCHES_LISTED]:
            matchedState = await self.gateway.getMemberState(guildId, matchedUserId)
            # "Not in server" covers both "left" and "banned". Checking for a
            # ban would need the Ban Members permission, which is far too
            # powerful to give this bot just for a label.
            status = "in server" if matchedState.isMember else "not in server (left or banned)"
            descriptions.append(f"<@{matchedUserId}> (`{matchedUserId}`, {status})")
        extraCount = len(matchedUserIds) - MAX_MATCHES_LISTED
        if extraCount > 0:
            descriptions.append(f"and {extraCount} more")
        return "Verified from the same network as: " + ", ".join(descriptions) + "."

    async def manualVerify(self, guildId: int, userId: int, adminId: int, note: str | None = None) -> Outcome:
        """An admin vouches for someone directly, so none of the checks run.

        Every manual verification is posted to the mod log with the admin's
        name, and is always written to the bot's own log too, so a record
        survives even if the mod-channel post fails. A bypass is exactly what
        a compromised or careless admin account would use, so it should never
        happen silently.
        """
        self.serverSettings(guildId)
        memberState = await self.gateway.getMemberState(guildId, userId)
        if not memberState.isMember:
            return Outcome.NOT_MEMBER
        if memberState.hasVerifiedRole:
            return Outcome.ALREADY_VERIFIED

        # Discord's audit log names the bot as the one who added the role, so
        # the admin is recorded in the reason.
        await self.gateway.grantVerifiedRole(guildId, userId, auditReason=f"Manually verified by admin {adminId}")
        # Cleared only after the role is granted, so a failure leaves any
        # pending review in place. Once cleared, that review's buttons answer
        # "Already handled".
        await self.storage.popPendingReview(guildId, userId)
        noteText = f" Note: {note}" if note else ""
        await self.gateway.postModLog(
            guildId, f"✓  <@{userId}> (`{userId}`) manually verified by <@{adminId}>.{noteText}"
        )
        log.info("user %s manually verified in server %s by %s", userId, guildId, adminId)
        return Outcome.VERIFIED

    async def resolveReview(self, guildId: int, userId: int, approve: bool) -> bool:
        """Apply a moderator decision. Returns False if it was already handled."""
        self.serverSettings(guildId)
        if not await self.storage.popPendingReview(guildId, userId):
            return False
        if approve:
            try:
                await self.gateway.grantVerifiedRole(guildId, userId)
            except Exception:
                # Put the review back so the decision can be retried rather
                # than silently lost.
                await self.storage.addPendingReview(guildId, userId)
                raise
        return True
