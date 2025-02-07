#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from logging import getLogger

from yunohost.tools import Migration

logger = getLogger("yunohost.migration")

###################################################
# Tools used also for restoration
###################################################


class MyMigration(Migration):
    """
    Delete legacy XMPP permission
    """

    introduced_in_version = "12.0"
    dependencies = []

    ldap_migration_started = False

    @Migration.ldap_migration
    def run(self, *args):
        #from yunohost.permission import permission_delete, user_permission_list

        self.ldap_migration_started = True

        # FIXME : xmpp will be implicitly deleted after perm refactor ?
        #if "xmpp.main" in user_permission_list()["permissions"]:
        #    permission_delete("xmpp.main", force=True)

    def run_after_system_restore(self):
        self.run()
