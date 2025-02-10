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

import base64
import hashlib
import logging
import os
import time
from pathlib import Path

import jwt
import ldap
import ldap.filter
import ldap.sasl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from moulinette import m18n
from moulinette.authentication import BaseAuthenticator
from moulinette.utils.filesystem import read_json
from moulinette.utils.text import random_ascii

from yunohost.utils.error import YunohostAuthenticationError, YunohostError
from yunohost.utils.ldap import _get_ldap_interface

logger = logging.getLogger("yunohostportal.authenticators.ldap_ynhuser")


def SESSION_SECRET():
    # Only load this once actually requested to avoid boring issues like
    # "secret doesnt exists yet" (before postinstall) and therefore service
    # miserably fail to start
    if not SESSION_SECRET.value:
        SESSION_SECRET.value = (
            open("/etc/yunohost/.ssowat_cookie_secret").read().strip()
        )
    assert SESSION_SECRET.value
    return SESSION_SECRET.value


SESSION_SECRET.value = None  # type: ignore
SESSION_FOLDER = "/var/cache/yunohost-portal/sessions"
SESSION_VALIDITY = 3 * 24 * 3600  # 3 days

URI = "ldap://localhost:389"
USERDN = "uid={username},ou=users,dc=yunohost,dc=org"

# Cache on-disk settings to RAM for faster access
DOMAIN_USER_ACL_DICT: dict[str, dict] = {}
PORTAL_SETTINGS_DIR = "/etc/yunohost/portal"


# Should a user have *minimal* access to a domain?
# - if the user has permission for an application with a URI on the domain, yes
# - if the user is an admin, yes
# - if the user has an email on the domain, yes
# - otherwise, no
def user_is_allowed_on_domain(user: str, domain: str) -> bool:

    assert "/" not in domain

    portal_settings_path = Path(PORTAL_SETTINGS_DIR) / f"{domain}.json"

    if not portal_settings_path.exists():
        if "." not in domain:
            return False
        parent_domain = domain.split(".", 1)[-1]
        return user_is_allowed_on_domain(user, parent_domain)

    # Check that the domain permissions haven't changed on-disk since we read them
    # by comparing file mtime. If we haven't read the file yet, read it for the first time.
    # We compare mtime by equality not superiority because maybe the system clock has changed.
    mtime = portal_settings_path.stat().st_mtime
    if (
        domain not in DOMAIN_USER_ACL_DICT
        or DOMAIN_USER_ACL_DICT[domain]["mtime"] != mtime
    ):
        users: set[str] = set()
        for infos in read_json(str(portal_settings_path))["apps"].values():
            users = users.union(infos["users"])
        DOMAIN_USER_ACL_DICT[domain] = {}
        DOMAIN_USER_ACL_DICT[domain]["mtime"] = mtime
        DOMAIN_USER_ACL_DICT[domain]["users"] = users

    if user in DOMAIN_USER_ACL_DICT[domain]["users"]:
        # A user with explicit permission to an application is certainly welcome
        return True

    ADMIN_GROUP = "cn=admins,ou=groups"
    try:
        admins = (
            _get_ldap_interface()
            .search(ADMIN_GROUP, attrs=["memberUid"])[0]
            .get("memberUid", [])
        )
    except Exception as e:
        logger.error(f"Failed to list admin users: {e}")
        return False
    if user in admins:
        # Admins can access everything
        return True

    try:
        user_result = _get_ldap_interface().search("ou=users", f"uid={user}", ["mail"])
        if len(user_result) != 1:
            logger.error(
                f"User not found or many users found for {user}. How is this possible after so much validation?"
            )
            return False

        user_mail = user_result[0]["mail"]
        if len(user_mail) != 1:
            logger.error(
                f"User {user} found, but has the wrong number of email addresses: {user_mail}"
            )
            return False

        user_mail = user_mail[0]
        if "@" not in user_mail:
            logger.error(f"Invalid email address for {user}: {user_mail}")
            return False

        if user_mail.split("@")[1] == domain:
            # A user from that domain is welcome
            return True

        # Users from other domains don't belong here
        return False
    except Exception as e:
        logger.error(f"Failed to get email info for {user}: {e}")
        return False


# We want to save the password in the cookie, but we should do so in an encrypted fashion
# This is needed because the SSO later needs to possibly inject the Basic Auth header
# which includes the user's password
# It's also needed because we need to be able to open LDAP sessions, authenticated as the user,
# which requires the user's password
#
# To do so, we use AES-256-CBC. As it's a block encryption algorithm, it requires an IV,
# which we need to keep around for decryption on SSOwat'side.
#
# SESSION_SECRET is used as the encryption key, which implies it must be exactly 32-char long (256/8)
#
# The result is a string formatted as <password_enc_b64>|<iv_b64>
# For example: ctl8kk5GevYdaA5VZ2S88Q==|yTAzCx0Gd1+MCit4EQl9lA==
def encrypt(data):
    alg = algorithms.AES(SESSION_SECRET().encode())
    iv = os.urandom(int(alg.block_size / 8))

    E = Cipher(alg, modes.CBC(iv), default_backend()).encryptor()
    p = padding.PKCS7(alg.block_size).padder()
    data_padded = p.update(data.encode()) + p.finalize()
    data_enc = E.update(data_padded) + E.finalize()
    data_enc_b64 = base64.b64encode(data_enc).decode()
    iv_b64 = base64.b64encode(iv).decode()
    return data_enc_b64 + "|" + iv_b64


def decrypt(data_enc_and_iv_b64):
    data_enc_b64, iv_b64 = data_enc_and_iv_b64.split("|")
    data_enc = base64.b64decode(data_enc_b64)
    iv = base64.b64decode(iv_b64)

    alg = algorithms.AES(SESSION_SECRET().encode())
    D = Cipher(alg, modes.CBC(iv), default_backend()).decryptor()
    p = padding.PKCS7(alg.block_size).unpadder()
    data_padded = D.update(data_enc)
    data = p.update(data_padded) + p.finalize()
    return data.decode()


def short_hash(data):
    return hashlib.shake_256(data.encode()).hexdigest(20)


class Authenticator(BaseAuthenticator):
    name = "ldap_ynhuser"

    def _authenticate_credentials(self, credentials=None):
        from bottle import request

        try:
            username, password = credentials.split(":", 1)
        except ValueError:
            raise YunohostError("invalid_credentials")

        username = ldap.filter.escape_filter_chars(username)
        # Search username, if user give a mail instead
        if "@" in username:
            user = _get_ldap_interface().search("ou=users", f"mail={username}", ["uid"])
            if len(user) != 0:
                username = user[0]['uid'][0]

        def _reconnect():
            con = ldap.ldapobject.ReconnectLDAPObject(URI, retry_max=2, retry_delay=0.5)
            con.simple_bind_s(USERDN.format(username=username), password)
            return con

        try:
            con = _reconnect()
        except ldap.INVALID_CREDENTIALS:
            # FIXME FIXME FIXME : this should be properly logged and caught by Fail2ban ! !  ! ! ! ! !
            raise YunohostError("invalid_password")
        except ldap.SERVER_DOWN:
            logger.warning(m18n.n("ldap_server_down"))

        # Check that we are indeed logged in with the expected identity
        try:
            # whoami_s return dn:..., then delete these 3 characters
            who = con.whoami_s()[3:]
        except Exception as e:
            logger.warning("Error during ldap authentication process: %s", e)
            raise
        else:
            if who != USERDN.format(username=username):
                raise YunohostError(
                    "Not logged with the appropriate identity ?!",
                    raw_msg=True,
                )
        finally:
            # Free the connection, we don't really need it to keep it open as the point is only to check authentication...
            if con:
                con.unbind_s()

            ldap_user_infos = _get_ldap_interface().search(
                "ou=users", f"uid={username}", attrs=["cn", "mail"]
            )[0]

        if not user_is_allowed_on_domain(username, request.get_header("host")):
            raise YunohostAuthenticationError("unable_authenticate")

        return {
            "user": username,
            "pwd": encrypt(password),
            "email": ldap_user_infos["mail"][0],
            "fullname": ldap_user_infos["cn"][0],
        }

    def set_session_cookie(self, infos):
        from bottle import request, response

        assert isinstance(infos, dict)
        assert "user" in infos
        assert "pwd" in infos
        assert "email" in infos
        assert "fullname" in infos

        # Create a session id, built as <user_hash> + some random ascii
        # Prefixing with the user hash is meant to provide the ability to invalidate all this user's session
        # (eg because the user gets deleted, or password gets changed)
        # User hashing not really meant for security, just to sort of anonymize/pseudonymize the session file name
        infos["id"] = short_hash(infos["user"]) + random_ascii(20)
        infos["host"] = request.get_header("host")

        is_dev = Path("/etc/yunohost/.portal-api-allowed-cors-origins").exists()

        response.set_cookie(
            "yunohost.portal",
            jwt.encode(infos, SESSION_SECRET(), algorithm="HS256"),
            secure=True,
            httponly=True,
            path="/",
            samesite="strict" if not is_dev else None,
            domain=f".{request.get_header('host')}",
            max_age=SESSION_VALIDITY
            - 600,  # remove 1 minute such that cookie expires on the browser slightly sooner on browser side, just to help desimbuigate edge case near the expiration limit
        )

        # Create the session file (expiration mechanism)
        session_file = f'{SESSION_FOLDER}/{infos["id"]}'
        os.system(f'touch "{session_file}"')

    def get_session_cookie(self, decrypt_pwd=False):
        from bottle import request, response

        try:
            token = request.get_cookie("yunohost.portal", default="").encode()
            infos = jwt.decode(
                token,
                SESSION_SECRET(),
                algorithms="HS256",
                options={"require": ["id", "host", "user", "pwd"]},
            )
        except Exception:
            raise YunohostAuthenticationError("unable_authenticate")

        if not infos:
            raise YunohostAuthenticationError("unable_authenticate")

        if infos["host"] != request.get_header("host"):
            raise YunohostAuthenticationError("unable_authenticate")

        if not user_is_allowed_on_domain(infos["user"], infos["host"]):
            raise YunohostAuthenticationError("unable_authenticate")

        self.purge_expired_session_files()
        session_file = Path(SESSION_FOLDER) / infos["id"]
        if not session_file.exists():
            response.delete_cookie("yunohost.portal", path="/")
            raise YunohostAuthenticationError("session_expired")

        # Otherwise, we 'touch' the file to extend the validity
        session_file.touch()

        is_dev = Path("/etc/yunohost/.portal-api-allowed-cors-origins").exists()

        # We also re-set the cookie such that validity is also extended on browser side
        response.set_cookie(
            "yunohost.portal",
            request.get_cookie(
                "yunohost.portal"
            ),  # Reuse the same token to avoid recomputing stuff (saves a bit of CPU / delay I suppose?)
            secure=True,
            httponly=True,
            path="/",
            samesite="strict" if not is_dev else None,
            domain=f".{request.get_header('host')}",
            max_age=SESSION_VALIDITY
            - 600,  # remove 1 minute such that cookie expires on the browser slightly sooner on browser side, just to help desimbuigate edge case near the expiration limit
        )

        if decrypt_pwd:
            infos["pwd"] = decrypt(infos["pwd"])

        return infos

    def delete_session_cookie(self):
        from bottle import response

        try:
            infos = self.get_session_cookie()
            session_file = Path(SESSION_FOLDER) / infos["id"]
            session_file.unlink()
        except Exception as e:
            logger.debug(
                f"User logged out, but failed to properly invalidate the session : {e}"
            )

        response.delete_cookie("yunohost.portal", path="/")

    def purge_expired_session_files(self):

        for session_file in Path(SESSION_FOLDER).iterdir():
            print(session_file.stat().st_mtime - time.time())
            if abs(session_file.stat().st_mtime - time.time()) > SESSION_VALIDITY:
                try:
                    session_file.unlink()
                except Exception as e:
                    logger.debug(f"Failed to delete session file {session_file} ? {e}")

    @staticmethod
    def invalidate_all_sessions_for_user(user):

        for file in Path(SESSION_FOLDER).glob(f"{short_hash(user)}*"):
            try:
                file.unlink()
            except Exception as e:
                logger.debug(f"Failed to delete session file {file} ? {e}")
