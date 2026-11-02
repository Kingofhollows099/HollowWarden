"""The Discord side: verify panel, CAPTCHA flow, and moderator review buttons.

Least privilege throughout:
- No privileged intents. Button clicks carry the member's details, and roles
  are added through the REST API, so the bot never needs to watch every
  member join or read message content.
- Server permissions needed: Manage Roles, plus View Channel / Send Messages /
  Embed Links / Attach Files where it posts. Nothing else, and never
  Administrator.
- It leaves any server that isn't in its configuration, so a leaked invite
  link can't put it to work elsewhere.
- Every server has its own settings, roles and data. Each interaction is
  handled using the settings of the server it came from, and nothing from
  one server is ever shown in another.

Method names that discord.py calls by convention (setup_hook, on_ready,
callback, on_submit, from_custom_id) must keep its snake_case names.
"""

from __future__ import annotations

import io
import logging
import time
from dataclasses import dataclass

import discord
from discord import app_commands

from .captcha import codesMatch, generateCode, renderCaptcha
from .config import ServerSettings, Settings
from .diagnostics import ERROR, OK, WARNING, Finding, checkApplication, checkDatabase, checkOauthCredentials
from .diagnostics import checkVpnList, checkWebsite, formatReport
from .ratelimit import RateLimiter
from .storage import ServerStorage
from .oauth import DiscordOAuth
from .vpnlist import VpnChecker
from .verification import MemberState, Outcome, Verifier

log = logging.getLogger(__name__)

VERIFY_BUTTON_ID = "hollowwarden:verify"
CAPTCHA_LIFETIME_SECONDS = 300
CAPTCHA_ATTEMPTS = 3
MAX_ACTIVE_CAPTCHAS = 1000
WEB_LINK_LIFETIME_SECONDS = 600

# A verified role carrying any of these would let anyone who passes
# verification take over the server, so the bot refuses to hand it out.
DANGEROUS_PERMISSIONS = discord.Permissions(
    administrator=True,
    manage_guild=True,
    manage_roles=True,
    manage_channels=True,
    manage_webhooks=True,
    manage_messages=True,
    manage_nicknames=True,
    manage_expressions=True,
    manage_events=True,
    manage_threads=True,
    kick_members=True,
    ban_members=True,
    moderate_members=True,
    mention_everyone=True,
    view_audit_log=True,
)

# Styling follows the Clipboard Cleaner theme: one raspberry accent on every
# embed, and outcome messages that start with ✓ or ⚠ plus two spaces, so
# success and failure are told apart by symbol rather than colour.
ACCENT_COLOUR = discord.Colour(0xE94560)

OUTCOME_MESSAGES = {
    Outcome.VERIFIED: "✓  Verified. Welcome to the server.",
    Outcome.PENDING_REVIEW: "Pending review. A moderator will take a quick look before you get access.",
    Outcome.ALREADY_VERIFIED: "✓  Already verified.",
    Outcome.NOT_MEMBER: "⚠  You need to be in the server to verify.",
    Outcome.UNAVAILABLE: "⚠  Verification couldn't be completed right now. Please tell a moderator.",
}

# What the bot needs in the mod channel, as (permission attribute, name shown
# in Discord's settings).
MOD_CHANNEL_PERMISSIONS = (
    ("view_channel", "View Channel"),
    ("send_messages", "Send Messages"),
    ("embed_links", "Embed Links"),
)


class UnsafeRoleError(Exception):
    """The verified role is misconfigured in a way that would be dangerous."""


class StartupError(Exception):
    """Discord refused something the bot needs before it can run at all."""


@dataclass
class CaptchaChallenge:
    code: str
    expiresAt: float
    attemptsLeft: int


class VerifyPanelView(discord.ui.View):
    """The permanent "Verify" button. A fixed custom_id plus timeout=None
    keeps it working across bot restarts."""

    def __init__(self) -> None:
        super().__init__(timeout=None)

    # Discord only offers fixed button colours. Its red is the closest to the
    # theme's raspberry accent, which marks the "go" action.
    @discord.ui.button(label="Verify", emoji="▶", style=discord.ButtonStyle.danger, custom_id=VERIFY_BUTTON_ID)
    async def verifyButton(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.client.handleVerifyClick(interaction)


class CaptchaAnswerModal(discord.ui.Modal, title="Verification"):
    answer = discord.ui.TextInput(label="Type the code from the image", min_length=1, max_length=12)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        await interaction.client.handleCaptchaAnswer(interaction, str(self.answer.value))


class CaptchaView(discord.ui.View):
    def __init__(self) -> None:
        super().__init__(timeout=CAPTCHA_LIFETIME_SECONDS)

    @discord.ui.button(label="Enter code", emoji="▶", style=discord.ButtonStyle.danger)
    async def enterCodeButton(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.send_modal(CaptchaAnswerModal())


class ReviewButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"hollowwarden:review:(?P<action>approve|deny):(?P<userId>[0-9]{15,21})",
):
    """Approve or deny buttons on a review alert. The user ID lives in the
    custom_id, so the buttons keep working after a restart."""

    def __init__(self, action: str, userId: int, disabled: bool = False) -> None:
        isApprove = action == "approve"
        super().__init__(
            # Both neutral grey, told apart by symbol and label, so a red
            # "go" button can't be mistaken for Deny at a glance. The symbol
            # goes in the label, not the emoji field: Discord accepts only
            # real emoji there, and ✓ (U+2713) isn't one. Using it made Discord
            # reject every review message.
            discord.ui.Button(
                label="✓ Approve" if isApprove else "⚠ Deny",
                style=discord.ButtonStyle.secondary,
                custom_id=f"hollowwarden:review:{action}:{userId}",
                disabled=disabled,
            )
        )
        self.action = action
        self.userId = userId

    @classmethod
    async def from_custom_id(
        cls, interaction: discord.Interaction, item: discord.ui.Button, match
    ) -> "ReviewButton":
        return cls(match["action"], int(match["userId"]))

    async def callback(self, interaction: discord.Interaction) -> None:
        await interaction.client.handleReviewDecision(interaction, self.userId, self.action == "approve")


def buildReviewMessage(
    userId: int, reasons: list[str], needsDecision: bool, disabled: bool = False
) -> dict[str, object]:
    heading = "⚠  Held for review" if needsDecision else "⚠  Verified with flags"
    embed = discord.Embed(title=heading, description=f"<@{userId}> (`{userId}`)", colour=ACCENT_COLOUR)
    embed.add_field(name="Why", value="\n".join(f"• {reason}" for reason in reasons)[:1024], inline=False)
    view = None
    if needsDecision:
        view = discord.ui.View(timeout=None)
        view.add_item(ReviewButton("approve", userId, disabled=disabled))
        view.add_item(ReviewButton("deny", userId, disabled=disabled))
    return {"embed": embed, "view": view}


class HollowWardenBot(discord.Client):
    def __init__(self, settings: Settings, storage: ServerStorage) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(
            intents=intents,
            # Never ping anyone, whatever ends up in a message. Mod alerts
            # mention users only so they render as clickable names.
            allowed_mentions=discord.AllowedMentions.none(),
        )
        self.settings = settings
        self.storage = storage
        self.verifier = Verifier(settings, storage, self)
        self.tree = app_commands.CommandTree(self)
        self.clickLimiter = RateLimiter(maxEvents=5, windowSeconds=600)
        # Keyed by (guild ID, user ID): someone in two servers gets a
        # separate challenge in each.
        self.captchaChallenges: dict[tuple[int, int], CaptchaChallenge] = {}
        # Set by the entry point in web mode, so /test-config can check the
        # OAuth credentials.
        self.oauth: DiscordOAuth | None = None
        self.lastModChannelError: str | None = None
        # Set by the entry point when VPN detection is on.
        self.vpnChecker: VpnChecker | None = None

    async def setup_hook(self) -> None:
        self.add_view(VerifyPanelView())
        self.add_dynamic_items(ReviewButton)

        # Who may use these is decided by each server's admin_role_ids,
        # checked in code on every use (see isBotAdmin). They're deliberately
        # not hidden with Discord's default_permissions: that would key
        # visibility to a Discord permission rather than your chosen roles,
        # and the two would drift apart. To hide them from regular members
        # anyway, use Server Settings → Integrations; that only affects
        # visibility, not access.
        @app_commands.command(name="verification-panel", description="Post the verification button in this channel")
        @app_commands.guild_only()
        async def verificationPanelCommand(interaction: discord.Interaction) -> None:
            await self.handlePanelCommand(interaction)

        @app_commands.command(name="verify-member", description="Verify a member without making them pass a check")
        @app_commands.describe(member="Who to verify", note="Why, shown in the mod log")
        @app_commands.guild_only()
        async def verifyMemberCommand(
            interaction: discord.Interaction,
            member: discord.Member,
            note: app_commands.Range[str, 1, 200] | None = None,
        ) -> None:
            await self.handleManualVerify(interaction, member, note)

        # The same action from a member's right-click menu (Apps → Verify member).
        @app_commands.context_menu(name="Verify member")
        @app_commands.guild_only()
        async def verifyMemberMenu(interaction: discord.Interaction, member: discord.Member) -> None:
            await self.handleManualVerify(interaction, member, None)

        @app_commands.command(name="test-config", description="Check that HollowWarden is set up correctly")
        @app_commands.guild_only()
        async def testConfigCommand(interaction: discord.Interaction) -> None:
            await self.handleTestConfig(interaction)

        # Registered only in your configured servers, never globally.
        configuredGuilds = [discord.Object(id=guildId) for guildId in self.settings.servers]
        for command in (verificationPanelCommand, verifyMemberCommand, verifyMemberMenu, testConfigCommand):
            self.tree.add_command(command, guilds=configuredGuilds)

        deniedGuildIds = []
        for guildId in self.settings.servers:
            try:
                await self.syncCommands(guildId)
            except discord.Forbidden:
                deniedGuildIds.append(guildId)
        if len(deniedGuildIds) == len(self.settings.servers):
            # Nothing would work anywhere. Stop with one readable error rather
            # than a traceback, so each pass of Docker's restart loop shows it.
            raise StartupError(self.describeSyncDenied(deniedGuildIds[0]))
        for guildId in deniedGuildIds:
            # Other servers still work, so keep running and say what's wrong.
            log.error("%s", self.describeSyncDenied(guildId))

    async def syncCommands(self, guildId: int) -> None:
        await self.tree.sync(guild=discord.Object(id=guildId))
        log.info("slash commands registered in %s (%s)", self.settings.servers[guildId].name, guildId)

    def describeSyncDenied(self, guildId: int) -> str:
        server = self.settings.servers[guildId]
        return (
            f"Discord denied access to {server.name} (guild_id {guildId}): the bot isn't in that server, "
            "or was invited without the applications.commands scope. Re-invite it using "
            "OAuth2 → URL Generator with the bot and applications.commands scopes."
        )

    async def on_ready(self) -> None:
        log.info("logged in as %s (%s)", self.user, self.user.id if self.user else "?")
        for guild in list(self.guilds):
            if self.settings.server(guild.id) is None:
                log.warning("leaving unconfigured server %s (%s)", guild.name, guild.id)
                await guild.leave()
        for server in self.settings.servers.values():
            self.checkSetup(server)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        server = self.settings.server(guild.id)
        if server is None:
            log.warning("added to unconfigured server %s (%s); leaving", guild.name, guild.id)
            await guild.leave()
            return
        # Removing the bot from a server deletes its slash commands there, and
        # re-adding it doesn't bring them back. They're normally registered
        # only at startup, so register them again now instead of requiring a
        # restart. The bot also gets a brand-new role on rejoin, which loses
        # its old position and channel permissions, so re-check the setup too.
        log.info("re-added to %s (%s); registering commands again", server.name, guild.id)
        try:
            await self.syncCommands(guild.id)
        except discord.Forbidden:
            # Unlike at startup, don't stop a running bot over this: its
            # buttons and the web flow still work without slash commands.
            log.error("%s", self.describeSyncDenied(guild.id))
        self.checkSetup(server)

    def checkSetup(self, server: ServerSettings) -> None:
        """Log clear warnings for common setup mistakes at startup, rather
        than having the first person to verify discover them. /test-config
        runs the same checks and more."""
        for finding in self.collectSetupFindings(server):
            if finding.level == ERROR:
                log.error("%s: %s", server.name, finding.text)
            elif finding.level == WARNING:
                log.warning("%s: %s", server.name, finding.text)

    def collectSetupFindings(self, server: ServerSettings) -> list[Finding]:
        """Check a server's roles and channels, using only what's cached
        locally (no API calls), so it's safe to run at startup."""
        guild = self.get_guild(server.guildId)
        if guild is None:
            return [Finding(ERROR, f"The bot is not in guild_id {server.guildId}; invite it first.")]
        findings = []

        if guild.me.guild_permissions.administrator:
            findings.append(
                Finding(WARNING, "The bot has Administrator. Remove it; Manage Roles is all it needs.")
            )
        else:
            findings.append(Finding(OK, "The bot doesn't have Administrator."))

        try:
            verifiedRole = self.getVerifiedRole(server)
        except UnsafeRoleError as error:
            verifiedRole = None
            findings.append(Finding(ERROR, f"Verified role: {error}."))
        else:
            findings.append(Finding(OK, f"The bot can safely give out {verifiedRole.mention}."))

        missingRoleIds = [roleId for roleId in server.adminRoleIds if guild.get_role(roleId) is None]
        if missingRoleIds:
            findings.append(
                Finding(ERROR, f"admin_role_ids contains roles that don't exist: {', '.join(map(str, missingRoleIds))}.")
            )
        else:
            adminMentions = ", ".join(f"<@&{roleId}>" for roleId in sorted(server.adminRoleIds))
            findings.append(Finding(OK, f"Bot admin roles: {adminMentions}."))

        findings.extend(self.collectModChannelFindings(server, guild, verifiedRole))
        findings.extend(self.collectVisibilityFindings(server, guild))
        return findings

    def collectModChannelFindings(
        self, server: ServerSettings, guild: discord.Guild, verifiedRole: discord.Role | None
    ) -> list[Finding]:
        modChannel = guild.get_channel(server.modChannelId)
        if modChannel is None:
            # Also catches a mod channel ID that belongs to a different
            # server: guild.get_channel only finds this server's channels.
            return [Finding(ERROR, f"mod_channel_id {server.modChannelId} is not a channel in this server.")]
        findings = []

        # Discord tells bots about every channel, including ones they can't
        # open, so the channel existing proves nothing. Check what the bot
        # is actually allowed to do there.
        channelPermissions = modChannel.permissions_for(guild.me)
        missingPermissions = [label for name, label in MOD_CHANNEL_PERMISSIONS if not getattr(channelPermissions, name)]
        if missingPermissions:
            findings.append(
                Finding(
                    ERROR,
                    f"HollowWarden is missing {', '.join(missingPermissions)} in mod_channel_id "
                    f"{server.modChannelId}; allow them for its role in that channel's permissions, or "
                    "verification messages and reviews can't be posted.",
                )
            )
        else:
            findings.append(Finding(OK, f"The bot can post in the mod channel <#{modChannel.id}>."))

        # Reviews say which accounts share an internet connection, so the mod
        # channel must stay private.
        if modChannel.permissions_for(guild.default_role).view_channel:
            findings.append(
                Finding(
                    ERROR,
                    f"Everyone in the server can see the mod channel (#{modChannel.name}), including who shares "
                    "a network with whom. Deny View Channel for @everyone there.",
                )
            )
        elif verifiedRole is not None and modChannel.permissions_for(verifiedRole).view_channel:
            findings.append(
                Finding(
                    ERROR,
                    f"Every verified member can see the mod channel (#{modChannel.name}), including who shares "
                    f"a network with whom. Deny View Channel for {verifiedRole.name} there.",
                )
            )
        else:
            findings.append(Finding(OK, "The mod channel is hidden from regular members."))
        return findings

    def collectVisibilityFindings(self, server: ServerSettings, guild: discord.Guild) -> list[Finding]:
        """Verification only protects channels that unverified members can't see."""
        visibleChannels = [
            channel
            for channel in guild.text_channels
            if channel.id != server.modChannelId and channel.permissions_for(guild.default_role).view_channel
        ]
        if not visibleChannels:
            return [
                Finding(
                    ERROR,
                    "Unverified members can't see any channel, so they can't reach the Verify button. Let "
                    "@everyone view your #verify channel.",
                )
            ]
        names = ", ".join(f"#{channel.name}" for channel in visibleChannels[:5])
        if len(visibleChannels) > 5:
            names += f" and {len(visibleChannels) - 5} more"
        if len(visibleChannels) > 3:
            return [
                Finding(
                    WARNING,
                    f"Unverified members can see {len(visibleChannels)} channels ({names}). Verification only "
                    "keeps people out of channels hidden from @everyone.",
                )
            ]
        return [Finding(OK, f"Unverified members can only see: {names}.")]

    async def collectLiveFindings(self, server: ServerSettings) -> list[Finding]:
        """Checks that call out to Discord or the website. Only run on
        request, since they make network calls."""
        findings = []
        try:
            findings.extend(checkApplication(await self.application_info(), self.settings))
        except discord.HTTPException as error:
            findings.append(Finding(WARNING, f"Couldn't read the app's settings from Discord (HTTP {error.status})."))
        findings.append(await checkDatabase(self.storage.forGuild(server.guildId)))
        findings.append(await self.checkReviewPost(server))
        if server.verifyMethod == "web" and self.settings.web is not None:
            if self.oauth is not None:
                findings.append(await checkOauthCredentials(self.oauth))
            findings.extend(await checkWebsite(self.settings.web))
            findings.append(checkVpnList(self.vpnChecker if server.flagVpn else None))
        return findings

    async def checkReviewPost(self, server: ServerSettings) -> Finding:
        """Post a sample review and delete it straight away.

        Checking permissions alone isn't enough: Discord can still reject a
        message for its content (as an invalid button emoji once did). Members
        who need review get "Verification unavailable" when that happens, so
        try the real thing. The sample's buttons are disabled, so nothing
        happens if it can't be deleted.
        """
        # Any real Discord ID fits the button format. The bot's own is used
        # when logged in (always, in practice), the server's otherwise.
        sampleUserId = self.user.id if self.user is not None else server.guildId
        sampleMessage = buildReviewMessage(
            sampleUserId,
            ["This is a test from /test-config. It will be deleted straight away."],
            needsDecision=True,
            disabled=True,
        )
        message = await self.sendToModChannel(server.guildId, **sampleMessage)
        if message is None:
            return Finding(
                ERROR,
                f"Review messages can't be posted ({self.lastModChannelError}). Members who need a "
                "moderator's review will see \"Verification unavailable\" until this is fixed.",
            )
        try:
            await message.delete()
        except discord.HTTPException:
            return Finding(WARNING, "A test review posted fine, but couldn't be deleted. Delete it from the mod channel.")
        return Finding(OK, "A test review message posted to the mod channel and was deleted.")

    def describeSettings(self, server: ServerSettings) -> str:
        parts = [f"Server: **{discord.utils.escape_markdown(server.name)}**"]
        parts.append(f"Method: **{server.verifyMethod}**")
        parts.append(f"Flagged members: **{server.flaggedAction}**")
        parts.append(f"Minimum account age: **{server.minAccountAgeDays} days**")
        if server.verifyMethod == "web":
            parts.append(f"VPN flagging: **{'on' if server.flagVpn else 'off'}**")
            parts.append(f"IP hashes kept: **{server.ipRetentionDays} days**")
        return " · ".join(parts)

    def getVerifiedRole(self, server: ServerSettings) -> discord.Role:
        guild = self.get_guild(server.guildId)
        if guild is None:
            raise UnsafeRoleError("the bot is not in this server")
        role = guild.get_role(server.verifiedRoleId)
        if role is None:
            raise UnsafeRoleError(f"verified_role_id {server.verifiedRoleId} does not exist in this server")
        if role.permissions.value & DANGEROUS_PERMISSIONS.value:
            raise UnsafeRoleError(
                f"refusing to grant role '{role.name}': it has moderator/admin permissions. "
                "The verified role should only unlock channels."
            )
        if role.managed or role.is_default():
            raise UnsafeRoleError(f"role '{role.name}' can't be assigned by bots")
        if role >= guild.me.top_role:
            raise UnsafeRoleError(f"move the bot's role above '{role.name}' in Server Settings → Roles")
        if not guild.me.guild_permissions.manage_roles:
            raise UnsafeRoleError("the bot needs the Manage Roles permission")
        return role

    def serverFor(self, interaction: discord.Interaction) -> ServerSettings | None:
        """The settings of the server an interaction came from, or None if
        that server isn't configured (or it's a DM)."""
        return self.settings.server(interaction.guild_id)

    def isBotAdmin(self, interaction: discord.Interaction) -> bool:
        """True if this person holds one of this server's admin roles.

        Discord's own permissions (even Administrator) don't count: only the
        roles you chose do. The server owner is the one exception, since they
        can give themselves any role anyway, and leaving them out would only
        risk locking you out of your own bot. Being an admin in one server
        grants nothing in another.
        """
        server = self.serverFor(interaction)
        if server is None or not isinstance(interaction.user, discord.Member):
            return False
        if interaction.guild is not None and interaction.user.id == interaction.guild.owner_id:
            return True
        return any(role.id in server.adminRoleIds for role in interaction.user.roles)

    # DiscordGateway implementation (used by Verifier)

    async def getMemberState(self, guildId: int, userId: int) -> MemberState:
        server = self.settings.servers[guildId]
        guild = self.get_guild(guildId)
        if guild is None:
            raise RuntimeError(f"the bot is not in {server.name}")
        try:
            member = await guild.fetch_member(userId)
        except discord.NotFound:
            return MemberState(isMember=False, hasVerifiedRole=False)
        hasRole = any(role.id == server.verifiedRoleId for role in member.roles)
        return MemberState(isMember=True, hasVerifiedRole=hasRole)

    async def grantVerifiedRole(self, guildId: int, userId: int, auditReason: str | None = None) -> None:
        role = self.getVerifiedRole(self.settings.servers[guildId])
        member = await role.guild.fetch_member(userId)
        await member.add_roles(role, reason=auditReason or "Passed HollowWarden verification")

    async def postModLog(self, guildId: int, message: str) -> None:
        await self.sendToModChannel(guildId, content=message)

    async def postReview(self, guildId: int, userId: int, reasons: list[str], needsDecision: bool) -> bool:
        return await self.sendToModChannel(guildId, **buildReviewMessage(userId, reasons, needsDecision)) is not None

    async def sendToModChannel(self, guildId: int, **messageFields) -> discord.Message | None:
        """Post to a server's mod channel. Returns None and logs the cause
        instead of raising, so callers decide whether a failed post matters.
        The cause is also kept in lastModChannelError for /test-config."""
        server = self.settings.servers[guildId]
        self.lastModChannelError = None
        channel = await self.getModChannel(server)
        if channel is None:
            self.lastModChannelError = (
                f"mod_channel_id {server.modChannelId} isn't a text channel in {server.name} that HollowWarden can reach"
            )
            log.error("%s", self.lastModChannelError)
            return None
        try:
            return await channel.send(**messageFields)
        except discord.Forbidden:
            self.lastModChannelError = (
                f"can't post in mod_channel_id {server.modChannelId} ({server.name}): give HollowWarden "
                "View Channel, Send Messages and Embed Links there"
            )
        except discord.HTTPException as error:
            # Discord's own explanation (such as "Invalid emoji") is the part
            # that says what to fix. It describes our message, not a member.
            detail = " ".join(str(error.text).split())[:300] or "no details given"
            self.lastModChannelError = (
                f"Discord rejected a post to mod_channel_id {server.modChannelId} ({server.name}) "
                f"(HTTP {error.status}, code {error.code}: {detail})"
            )
        log.error("%s", self.lastModChannelError)
        return None

    async def getModChannel(self, server: ServerSettings) -> discord.abc.Messageable | None:
        channel = self.get_channel(server.modChannelId)
        if channel is None:
            try:
                channel = await self.fetch_channel(server.modChannelId)
            except discord.HTTPException:
                return None
        if not isinstance(channel, discord.abc.Messageable):
            return None
        # A channel belonging to another server would show this server's
        # reviews (including who shares a network) to strangers. Refuse it.
        if getattr(getattr(channel, "guild", None), "id", None) != server.guildId:
            log.error("mod_channel_id %s isn't in %s; refusing to post there", server.modChannelId, server.name)
            return None
        return channel

    # Interaction handlers

    async def handlePanelCommand(self, interaction: discord.Interaction) -> None:
        if not self.isBotAdmin(interaction):
            await interaction.response.send_message("⚠  Only bot admins can do that.", ephemeral=True)
            return
        embed = discord.Embed(
            title="Verification",
            description="Press **Verify** to get access to the server.",
            colour=ACCENT_COLOUR,
        )
        try:
            await interaction.channel.send(embed=embed, view=VerifyPanelView())
        except discord.Forbidden:
            # Answer the interaction either way. Otherwise Discord only shows
            # "The application did not respond", which says nothing useful.
            log.warning("can't post the verification panel in channel %s: missing permissions", interaction.channel_id)
            await interaction.response.send_message(
                "⚠  I can't post here. Give my role View Channel, Send Messages, Embed Links and Attach Files "
                "in this channel.",
                ephemeral=True,
            )
            return
        await interaction.response.send_message("✓  Verification panel posted.", ephemeral=True)

    async def handleVerifyClick(self, interaction: discord.Interaction) -> None:
        server = self.serverFor(interaction)
        if server is None:
            return
        userId = interaction.user.id
        member = interaction.user
        if isinstance(member, discord.Member) and member.get_role(server.verifiedRoleId) is not None:
            await interaction.response.send_message(OUTCOME_MESSAGES[Outcome.ALREADY_VERIFIED], ephemeral=True)
            return
        if not self.clickLimiter.allow((server.guildId, userId)):
            await interaction.response.send_message(
                "⚠  Too many attempts. Wait a few minutes and try again.", ephemeral=True
            )
            return
        if await self.storage.hasPendingReview(server.guildId, userId):
            await interaction.response.send_message(OUTCOME_MESSAGES[Outcome.PENDING_REVIEW], ephemeral=True)
            return

        if server.verifyMethod == "web":
            await self.sendWebLink(interaction, server)
        else:
            await self.sendCaptcha(interaction, server)

    async def sendWebLink(self, interaction: discord.Interaction, server: ServerSettings) -> None:
        assert self.settings.web is not None
        token = await self.storage.createVerifyToken(server.guildId, interaction.user.id, WEB_LINK_LIFETIME_SECONDS)
        view = discord.ui.View()
        view.add_item(
            discord.ui.Button(label="Open verification page", url=f"{self.settings.web.publicBaseUrl}/verify?t={token}")
        )
        # Ephemeral, so only this person ever sees their link.
        await interaction.response.send_message(
            "Log in with Discord to verify. This link is yours only, works once, "
            f"and expires in {WEB_LINK_LIFETIME_SECONDS // 60} minutes. **Don't share it.**",
            view=view,
            ephemeral=True,
        )

    async def sendCaptcha(self, interaction: discord.Interaction, server: ServerSettings) -> None:
        now = time.monotonic()
        self.pruneCaptchas(now)
        if len(self.captchaChallenges) >= MAX_ACTIVE_CAPTCHAS:
            await interaction.response.send_message("⚠  Verification is busy. Try again shortly.", ephemeral=True)
            return

        code = generateCode()
        self.captchaChallenges[(server.guildId, interaction.user.id)] = CaptchaChallenge(
            code=code, expiresAt=now + CAPTCHA_LIFETIME_SECONDS, attemptsLeft=CAPTCHA_ATTEMPTS
        )
        imageFile = discord.File(io.BytesIO(renderCaptcha(code)), filename="captcha.png")
        embed = discord.Embed(
            title="Verification",
            description=f"Type the code in the image. {CAPTCHA_ATTEMPTS} attempts, "
            f"{CAPTCHA_LIFETIME_SECONDS // 60} minutes. Not case sensitive.",
            colour=ACCENT_COLOUR,
        )
        embed.set_image(url="attachment://captcha.png")
        await interaction.response.send_message(embed=embed, file=imageFile, view=CaptchaView(), ephemeral=True)

    def pruneCaptchas(self, now: float) -> None:
        expiredKeys = [key for key, challenge in self.captchaChallenges.items() if challenge.expiresAt <= now]
        for key in expiredKeys:
            del self.captchaChallenges[key]

    async def handleCaptchaAnswer(self, interaction: discord.Interaction, submittedCode: str) -> None:
        server = self.serverFor(interaction)
        if server is None:
            return
        userId = interaction.user.id
        challengeKey = (server.guildId, userId)
        challenge = self.captchaChallenges.get(challengeKey)
        if challenge is None or challenge.expiresAt <= time.monotonic():
            self.captchaChallenges.pop(challengeKey, None)
            await interaction.response.send_message(
                "⚠  Code expired. Press **Verify** for a new one.", ephemeral=True
            )
            return

        if not codesMatch(challenge.code, submittedCode):
            challenge.attemptsLeft -= 1
            if challenge.attemptsLeft <= 0:
                del self.captchaChallenges[challengeKey]
                await interaction.response.send_message(
                    "⚠  Incorrect, no attempts left. Press **Verify** for a new code.", ephemeral=True
                )
            else:
                await interaction.response.send_message(
                    f"⚠  Incorrect. {challenge.attemptsLeft} attempt(s) left.", ephemeral=True
                )
            return

        # Delete before doing anything else so the same code can't be used twice.
        del self.captchaChallenges[challengeKey]
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            outcome = await self.verifier.completeCaptcha(server.guildId, userId)
        except Exception:
            log.exception("verification failed for %s in %s", userId, server.name)
            await interaction.followup.send("⚠  Something went wrong. Tell a moderator.", ephemeral=True)
            return
        await interaction.followup.send(OUTCOME_MESSAGES[outcome], ephemeral=True)

    async def handleTestConfig(self, interaction: discord.Interaction) -> None:
        # Admin-only: the report describes the server's security setup.
        if not self.isBotAdmin(interaction):
            await interaction.response.send_message("⚠  Only bot admins can do that.", ephemeral=True)
            return
        server = self.serverFor(interaction)
        assert server is not None  # isBotAdmin is False for unconfigured servers
        await interaction.response.defer(ephemeral=True, thinking=True)
        log.info("configuration test run in %s by %s", server.name, interaction.user.id)

        # Only this server's checks: the report never mentions other servers.
        findings = self.collectSetupFindings(server)
        try:
            findings.extend(await self.collectLiveFindings(server))
        except Exception:
            log.exception("a configuration check failed unexpectedly")
            findings.append(Finding(WARNING, "Some checks couldn't run. Check the bot's logs."))

        title, description = formatReport(findings, self.describeSettings(server))
        embed = discord.Embed(title=title, description=description, colour=ACCENT_COLOUR)
        await interaction.followup.send(embed=embed, ephemeral=True)

    async def handleManualVerify(
        self, interaction: discord.Interaction, member: discord.Member, note: str | None
    ) -> None:
        if not self.isBotAdmin(interaction):
            await interaction.response.send_message("⚠  Only bot admins can do that.", ephemeral=True)
            return
        server = self.serverFor(interaction)
        assert server is not None
        await interaction.response.defer(ephemeral=True, thinking=True)

        # One line, no Markdown tricks, so a note can't disguise itself as
        # extra log entries in the mod channel.
        cleanNote = discord.utils.escape_markdown(" ".join(note.split())) if note else None
        try:
            outcome = await self.verifier.manualVerify(server.guildId, member.id, interaction.user.id, cleanNote)
        except UnsafeRoleError as error:
            await interaction.followup.send(f"⚠  {error}", ephemeral=True)
            return
        except Exception:
            log.exception("manual verification of %s in %s failed", member.id, server.name)
            await interaction.followup.send("⚠  Couldn't verify them. Check the bot's logs.", ephemeral=True)
            return

        if outcome is Outcome.VERIFIED:
            # Any CAPTCHA they had open is now pointless.
            self.captchaChallenges.pop((server.guildId, member.id), None)
            await interaction.followup.send(f"✓  Verified {member.mention}.", ephemeral=True)
        elif outcome is Outcome.ALREADY_VERIFIED:
            await interaction.followup.send(f"✓  {member.mention} is already verified.", ephemeral=True)
        else:
            await interaction.followup.send("⚠  That person isn't in the server.", ephemeral=True)

    async def handleReviewDecision(self, interaction: discord.Interaction, userId: int, approve: bool) -> None:
        # Checked on every click, not just by channel visibility: if the mod
        # channel's permissions are ever loosened, the buttons stay locked.
        if not self.isBotAdmin(interaction):
            await interaction.response.send_message("⚠  Only bot admins can do that.", ephemeral=True)
            return
        server = self.serverFor(interaction)
        assert server is not None
        await interaction.response.defer()
        try:
            handled = await self.verifier.resolveReview(server.guildId, userId, approve)
        except Exception:
            log.exception("could not apply review decision for %s in %s", userId, server.name)
            await interaction.followup.send("⚠  Couldn't apply that. Check the bot's logs.", ephemeral=True)
            return
        if not handled:
            await interaction.followup.send("⚠  Already handled.", ephemeral=True)
            return

        decision = "✓  Approved" if approve else "⚠  Denied"
        log.info(
            "review for %s in %s %s by %s", userId, server.name, "approved" if approve else "denied", interaction.user.id
        )
        message = interaction.message
        if message is not None:
            embed = message.embeds[0] if message.embeds else discord.Embed()
            embed.add_field(name="Decision", value=f"{decision} by {interaction.user.mention}", inline=False)
            await message.edit(embed=embed, view=None)
