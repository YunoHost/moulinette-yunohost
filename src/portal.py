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

import logging
from pathlib import Path
from typing import Any, Union

import ldap
from moulinette.utils.filesystem import read_json

from yunohost.authenticators.ldap_ynhuser import Authenticator as Auth
from yunohost.authenticators.ldap_ynhuser import user_is_allowed_on_domain
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.ldap import LDAPInterface, _get_ldap_interface, _ldap_path_extract
from yunohost.utils.password import (
    _hash_user_password,
    assert_password_is_compatible,
    assert_password_is_strong_enough,
)

logger = logging.getLogger("portal")

PORTAL_SETTINGS_DIR = "/etc/yunohost/portal"
ADMIN_ALIASES = ["root", "admin", "admins", "webmaster", "postmaster", "abuse"]


def _get_user_infos(
    user_attrs: list[str],
) -> tuple[str, str, dict[str, Any]]:
    auth = Auth().get_session_cookie()
    username = auth["user"]
    result = _get_ldap_interface().search("ou=users", f"uid={username}", user_attrs)
    if not result:
        raise YunohostValidationError("user_unknown", user=username)

    return username, auth["host"], result[0]


def _get_portal_settings(
    domain: Union[str, None] = None, username: Union[str, None] = None
) -> dict[str, Any]:
    """
    Returns domain's portal settings which are a combo of domain's portal config panel options
    and the list of apps availables on this domain computed by `app.app_ssowatconf()`.
    """

    if not domain:
        from bottle import request

        domain = request.get_header("host")

    assert domain and "/" not in domain

    settings: dict[str, Any] = {
        "apps": {},
        "public": False,
        "portal_logo": "",
        "portal_theme": "system",
        "portal_tile_theme": "simple",
        "portal_title": "YunoHost",
        "show_other_domains_apps": False,
        "domain": domain,
    }

    portal_settings_path = Path(f"{PORTAL_SETTINGS_DIR}/{domain}.json")

    if portal_settings_path.exists():
        settings.update(read_json(str(portal_settings_path)))
        # Portal may be public (no login required)
        settings["public"] = bool(settings.pop("enable_public_apps_page", False))

    # First clear apps since it may contains private apps
    apps: dict[str, Any] = settings.pop("apps", {})
    settings["apps"] = {}

    if settings["show_other_domains_apps"]:
        # Enhanced apps with all other domain's apps
        import glob

        for path in glob.glob(f"{PORTAL_SETTINGS_DIR}/*.json"):
            if path != str(portal_settings_path):
                apps.update(read_json(path)["apps"])

    if username:
        # Add user allowed or public apps
        settings["apps"] = {
            app: infos
            for app, infos in apps.items()
            if username in infos["users"] or infos["public"]
        }
    elif settings["public"]:
        # Add public apps (e.g. with "visitors" in group permission)
        settings["apps"] = {
            app: infos
            for app, infos in apps.items()
            if infos["public"] and not infos.get("hide_from_public")
        }

    # Sort dictionnary according to the "order" info
    settings["apps"] = dict(sorted([(app, infos) for app, infos in settings["apps"].items()], key=lambda v: (v[1].get("order", 100), v[0])))

    return settings


def portal_public():
    """
    Get public settings
    If the portal is set as public, it will include the list of public apps
    """

    portal_settings = _get_portal_settings()

    try:
        Auth().get_session_cookie()
    except Exception:
        if "portal_user_intro" in portal_settings:
            del portal_settings["portal_user_intro"]

    # Prevent leaking the list of users
    for infos in portal_settings["apps"].values():
        del infos["users"]

    return portal_settings


def portal_me():
    """
    Get user informations
    """
    username, domain, user = _get_user_infos(
        ["cn", "mail", "maildrop", "mailuserquota", "memberOf", "permission"]
    )

    groups = [_ldap_path_extract(g, "cn") for g in user["memberOf"]]
    groups = [g for g in groups if g not in [username, "all_users"]]
    # Get user allowed apps
    apps = _get_portal_settings(domain, username)["apps"]

    # Prevent leaking the list of users
    for infos in apps.values():
        del infos["users"]

    result_dict = {
        "username": username,
        "fullname": user["cn"][0],
        "mail": user["mail"][0],
        "mailalias": user["mail"][1:],
        "mailforward": user["maildrop"][1:],
        "groups": groups,
        "apps": apps,
    }

    # FIXME / TODO : add mail quota status ?
    #  result_dict["mailbox-quota"] = {
    #      "limit": userquota if is_limited else m18n.n("unlimit"),
    #      "use": storage_use,
    #  }
    # Could use : doveadm -c /dev/null -f flow quota recalc -u johndoe
    # But this requires to be in the mail group ...

    return result_dict


def portal_update(
    fullname: Union[str, None] = None,
    mailforward: Union[list[str], None] = None,
    mailalias: Union[list[str], None] = None,
    currentpassword: Union[str, None] = None,
    newpassword: Union[str, None] = None,
):
    from yunohost.domain import domain_list

    domains = domain_list()["domains"]
    username, domain, current_user = _get_user_infos(
        ["givenName", "sn", "cn", "mail", "maildrop", "memberOf"]
    )
    new_attr_dict = {}

    if fullname is not None and fullname != current_user["cn"]:
        fullname = fullname.strip()
        firstname = fullname.split()[0]
        lastname = (
            " ".join(fullname.split()[1:]) or " "
        )  # Stupid hack because LDAP requires the sn/lastname attr, but it accepts a single whitespace...
        new_attr_dict["givenName"] = [firstname]  # TODO: Validate
        new_attr_dict["sn"] = [lastname]  # TODO: Validate
        new_attr_dict["cn"] = new_attr_dict["displayName"] = [
            (firstname + " " + lastname).strip()
        ]

    if mailalias is not None:
        mailalias = [mail.strip() for mail in mailalias if mail and mail.strip()]
        # keep first current mail unaltered
        mails = [current_user["mail"][0]]

        for index, mail in enumerate(mailalias):
            if mail in current_user["mail"]:
                if mail != current_user["mail"][0] and mail not in mails:
                    mails.append(mail)
                continue  # already in mails, skip validation

            local_part, domain = mail.split("@")
            if local_part in ADMIN_ALIASES:
                raise YunohostValidationError(
                    "mail_unavailable", path=f"mailalias[{index}]"
                )

            try:
                _get_ldap_interface().validate_uniqueness({"mail": mail})
            except YunohostError:
                raise YunohostValidationError(
                    "mail_already_exists", mail=mail, path=f"mailalias[{index}]"
                )

            if domain not in domains or not user_is_allowed_on_domain(username, domain):
                raise YunohostValidationError("mail_alias_unauthorized", domain=domain)

            mails.append(mail)

        new_attr_dict["mail"] = mails

    if mailforward is not None:
        new_attr_dict["maildrop"] = [current_user["maildrop"][0]] + [
            mail.strip()
            for mail in mailforward
            if mail and mail.strip() and mail != current_user["maildrop"][0]
        ]

    if newpassword:
        # Ensure compatibility and sufficiently complex password
        try:
            assert_password_is_compatible(newpassword)
            is_admin = (
                "cn=admins,ou=groups,dc=yunohost,dc=org" in current_user["memberOf"]
            )
            assert_password_is_strong_enough(
                "admin" if is_admin else "user", newpassword
            )
        except YunohostValidationError as e:
            raise YunohostValidationError(e.key, path="newpassword")

        new_attr_dict["userPassword"] = [_hash_user_password(newpassword)]

    # Check that current password is valid
    # To be able to edit the user info, an authenticated ldap session is needed
    if newpassword:
        # When setting the password, check the user provided the valid current password
        try:
            ldap_interface = LDAPInterface(username, currentpassword)
        except ldap.INVALID_CREDENTIALS:
            raise YunohostValidationError("invalid_password", path="currentpassword")
    else:
        # Otherwise we use the encrypted password stored in the cookie
        ldap_interface = LDAPInterface(
            username, Auth().get_session_cookie(decrypt_pwd=True)["pwd"]
        )

    try:
        ldap_interface.update(f"uid={username},ou=users", new_attr_dict)
    except Exception as e:
        raise YunohostError("user_update_failed", user=username, error=e)
    finally:
        del ldap_interface

    if "userPassword" in new_attr_dict:
        Auth.invalidate_all_sessions_for_user(username)

    # FIXME: Here we could want to trigger "post_user_update" hook but hooks has to
    # be run as root
    if all(field is not None for field in (fullname, mailalias, mailforward)):
        return {
            "fullname": new_attr_dict["cn"][0],
            "mailalias": new_attr_dict["mail"][1:],
            "mailforward": new_attr_dict["maildrop"][1:],
        }
    else:
        return {}
