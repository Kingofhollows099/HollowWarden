from types import SimpleNamespace
from unittest.mock import MagicMock

import discord
import pytest

from hollowwarden.bot import HollowWardenBot
from hollowwarden.config import loadSettings
from hollowwarden.storage import Storage

from .test_core import baseEnviron

GUILD_ID = 111111111111111111
ADMIN_ROLE = 555555555555555555
OTHER_ROLE = 777777777777777777
OWNER_ID = 900000000000000000
MEMBER_ID = 900000000000000001


@pytest.fixture
def bot(tmp_path):
    return HollowWardenBot(loadSettings(baseEnviron(tmp_path)), Storage(str(tmp_path / "test.db")))


def makeInteraction(roleIds, userId=MEMBER_ID, guildId=GUILD_ID, administrator=False):
    member = MagicMock(spec=discord.Member)
    member.id = userId
    member.roles = [SimpleNamespace(id=roleId) for roleId in roleIds]
    member.guild_permissions = discord.Permissions(administrator=administrator)
    return SimpleNamespace(
        guild_id=guildId,
        guild=SimpleNamespace(owner_id=OWNER_ID),
        user=member,
        permissions=discord.Permissions(administrator=administrator),
    )


class TestBotAdmin:
    def test_configuredRoleIsAdmin(self, bot):
        assert bot.isBotAdmin(makeInteraction([OTHER_ROLE, ADMIN_ROLE]))

    def test_otherRolesAreNot(self, bot):
        assert not bot.isBotAdmin(makeInteraction([OTHER_ROLE]))

    def test_discordAdministratorPermissionAloneIsNot(self, bot):
        # Only the chosen roles count, not Discord's own permissions.
        assert not bot.isBotAdmin(makeInteraction([OTHER_ROLE], administrator=True))

    def test_serverOwnerAlwaysIs(self, bot):
        assert bot.isBotAdmin(makeInteraction([], userId=OWNER_ID))

    def test_otherServerNeverIs(self, bot):
        assert not bot.isBotAdmin(makeInteraction([ADMIN_ROLE], guildId=222222222222222223))

    def test_nonMemberUserIsNot(self, bot):
        interaction = makeInteraction([ADMIN_ROLE])
        interaction.user = SimpleNamespace(id=MEMBER_ID, roles=[SimpleNamespace(id=ADMIN_ROLE)])
        assert not bot.isBotAdmin(interaction)
