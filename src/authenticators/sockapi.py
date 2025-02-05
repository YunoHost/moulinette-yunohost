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

from moulinette.authentication import BaseAuthenticator


class Authenticator(BaseAuthenticator):
    name = "sockapi"

    def __init__(self, *args, **kwargs):
        pass

    def _authenticate_credentials(self, credentials=None):
        return {"user": 0}

    def set_session_cookie(self, infos):
        pass

    def get_session_cookie(self, raise_if_no_session_exists=True):
        return {"id": "pouetpouet"}

    def delete_session_cookie(self):
        pass

    @staticmethod
    def invalidate_all_sessions_for_user(user):
        pass
