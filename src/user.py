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

import copy
import grp
import os
import pwd
import random
import re
import subprocess
from logging import getLogger
from typing import TYPE_CHECKING, Any, Callable, Optional, TextIO, Union, cast

from moulinette import Moulinette, m18n
from moulinette.utils.process import check_output

from yunohost.log import is_unit_operation
from yunohost.service import service_status
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.system import binary_to_human

if TYPE_CHECKING:
    from bottle import HTTPResponse as HTTPResponseType
    from moulinette.utils.log import MoulinetteLogger

    from yunohost.log import OperationLogger

    logger = cast(MoulinetteLogger, getLogger("yunohost.user"))
else:
    logger = getLogger("yunohost.user")


FIELDS_FOR_IMPORT = {
    "username": r"^[a-z0-9_.]+$",
    "firstname": r"^([^\W\d_]{1,30}[ ,.\'-]{0,3})+$",
    "lastname": r"^([^\W\d_]{1,30}[ ,.\'-]{0,3})+$",
    "password": r"^|(.{3,})$",
    "mail": r"^([\w.-]+@([^\W_A-Z]+([-]*[^\W_A-Z]+)*\.)+((xn--)?[^\W_]{2,}))$",
    "mail-alias": r"^|([\w.-]+@([^\W_A-Z]+([-]*[^\W_A-Z]+)*\.)+((xn--)?[^\W_]{2,}),?)+$",
    "mail-forward": r"^|([\w\+.-]+@([^\W_A-Z]+([-]*[^\W_A-Z]+)*\.)+((xn--)?[^\W_]{2,}),?)+$",
    "mailbox-quota": r"^(\d+[bkMGT])|0|$",
    "groups": r"^|([a-z0-9_]+(,?[a-z0-9_]+)*)$",
}

ADMIN_ALIASES = ["root", "admin", "admins", "webmaster", "postmaster", "abuse"]


def user_list(fields: Optional[list[str]] = None) -> dict[str, dict[str, Any]]:
    from yunohost.utils.ldap import _get_ldap_interface

    ldap_attrs = {
        "username": "uid",
        "password": "",  # We can't request password in ldap
        "fullname": "cn",
        "firstname": "givenName",
        "lastname": "sn",
        "mail": "mail",
        "mail-alias": "mail",
        "mail-forward": "maildrop",
        "mailbox-quota": "mailuserquota",
        "groups": "memberOf",
        "shell": "loginShell",
        "home-path": "homeDirectory",
    }

    def display_default(values, _):
        return values[0] if len(values) == 1 else values

    display: dict[str, Callable[[list[str], dict], Any]] = {
        "password": lambda values, user: "",
        "mail": lambda values, user: display_default(values[:1], user),
        "mail-alias": lambda values, _: values[1:],
        "mail-forward": lambda values, user: [
            forward for forward in values if forward != user["uid"][0]
        ],
        "groups": lambda values, user: [
            group[3:].split(",")[0]
            for group in values
            if not group.startswith("cn=all_users,")
            and not group.startswith("cn=" + user["uid"][0] + ",")
        ],
        "shell": lambda values, _: len(values) > 0
        and values[0].strip() == "/bin/false",
    }

    attrs = {"uid"}
    users = {}

    if not fields:
        fields = ["username", "fullname", "mail", "mailbox-quota"]

    for field in fields:
        if field in ldap_attrs:
            attrs.add(ldap_attrs[field])
        else:
            raise YunohostError("field_invalid", field)

    ldap = _get_ldap_interface()
    result = ldap.search(
        "ou=users",
        "(&(objectclass=person)(!(uid=root))(!(uid=nobody)))",
        attrs,
    )

    for user in result:
        entry: dict[str, str] = {}
        for field in fields:
            values = []
            if ldap_attrs[field] in user:
                values = user[ldap_attrs[field]]
            entry[field] = display.get(field, display_default)(values, user)

        username: str = user["uid"][0]
        users[username] = entry

    # Dict entry 0 has incompatible type "str": "dict[Any, dict[str, Any]]";
    #                           expected "str": "dict[str, str]"  [dict-item]
    return {"users": users}


def list_shells():
    with open("/etc/shells", "r") as f:
        content = f.readlines()

    return [line.strip() for line in content if line.startswith("/")]


def shellexists(shell):
    """Check if the provided shell exists and is executable."""
    return os.path.isfile(shell) and os.access(shell, os.X_OK)


@is_unit_operation([("username", "user")])
def user_create(
    operation_logger: "OperationLogger",
    username: str,
    domain: str,
    password: str,
    fullname: str,
    mailbox_quota="0",
    admin: bool = False,
    from_import: bool = False,
    loginShell=None,
) -> dict[str, str]:
    if not fullname.strip():
        raise YunohostValidationError(
            "You should specify the fullname of the user using option -F"
        )
    fullname = fullname.strip()
    firstname = fullname.split()[0]
    lastname = (
        " ".join(fullname.split()[1:]) or " "
    )  # Stupid hack because LDAP requires the sn/lastname attr, but it accepts a single whitespace...

    from yunohost.domain import _assert_domain_exists, _get_maindomain, domain_list
    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface
    from yunohost.utils.password import (
        _hash_user_password,
        assert_password_is_compatible,
        assert_password_is_strong_enough,
    )

    # Ensure compatibility and sufficiently complex password
    assert_password_is_compatible(password)
    assert_password_is_strong_enough("admin" if admin else "user", password)

    # Validate domain used for email address account
    if domain is None:
        if Moulinette.interface.type == "api":
            raise YunohostValidationError(
                "Invalid usage, you should specify a domain argument"
            )
        else:
            # On affiche les differents domaines possibles
            Moulinette.display(m18n.n("domains_available"))
            for domain in domain_list()["domains"]:
                Moulinette.display(f"- {domain}")

            maindomain = _get_maindomain()
            domain = Moulinette.prompt(
                m18n.n("ask_user_domain") + f" (default: {maindomain})"
            )
            if not domain:
                domain = maindomain

    # Check that the domain exists
    _assert_domain_exists(domain)

    mail = username + "@" + domain
    ldap = _get_ldap_interface()

    if username in user_list()["users"]:
        raise YunohostValidationError("user_already_exists", user=username)

    # Validate uniqueness of username and mail in LDAP
    try:
        ldap.validate_uniqueness({"uid": username, "mail": mail, "cn": username})
    except Exception as e:
        raise YunohostValidationError("user_creation_failed", user=username, error=e)

    # Validate uniqueness of username in system users
    all_existing_usernames = {x.pw_name for x in pwd.getpwall()}
    if username in all_existing_usernames:
        raise YunohostValidationError("system_username_exists")

    if mail.split("@")[0] in ADMIN_ALIASES:
        raise YunohostValidationError("mail_unavailable")

    if not from_import:
        operation_logger.start()

    # Get random UID/GID
    all_uid = {str(x.pw_uid) for x in pwd.getpwall()}
    all_gid = {str(x.gr_gid) for x in grp.getgrall()}

    # Prevent users from obtaining uid 1007 which is the uid of the legacy admin,
    # and there could be a edge case where a new user becomes owner of an old, removed admin user
    all_uid.add("1007")
    all_gid.add("1007")

    uid_guid_found = False
    while not uid_guid_found:
        # LXC uid number is limited to 65536 by default
        uid: str = str(random.randint(1001, 65000))
        uid_guid_found = uid not in all_uid and uid not in all_gid

    if not loginShell:
        loginShell = "/bin/bash"
    else:
        if not shellexists(loginShell) or loginShell not in list_shells():
            raise YunohostValidationError("invalid_shell", shell=loginShell)

    attr_dict = {
        "objectClass": [
            "mailAccount",
            "inetOrgPerson",
            "posixAccount",
            "userPermissionYnh",
        ],
        "givenName": [firstname],
        "sn": [lastname],
        "displayName": [fullname],
        "cn": [fullname],
        "uid": [username],
        "mail": mail,  # NOTE: this one seems to be already a list
        "maildrop": [username],
        "mailuserquota": [mailbox_quota],
        "userPassword": [_hash_user_password(password)],
        "gidNumber": [uid],
        "uidNumber": [uid],
        "homeDirectory": ["/home/" + username],
        "loginShell": [loginShell],
    }

    try:
        ldap.add(f"uid={username},ou=users", attr_dict)
    except Exception as e:
        raise YunohostError("user_creation_failed", user=username, error=e)

    # Invalidate passwd and group to take user and group creation into account
    subprocess.call(["nscd", "-i", "passwd"])
    subprocess.call(["nscd", "-i", "group"])

    try:
        # Attempt to create user home folder
        subprocess.check_call(["mkhomedir_helper", username])
    except subprocess.CalledProcessError:
        home = f"/home/{username}"
        if not os.path.isdir(home):
            logger.warning(
                m18n.n("user_home_creation_failed", home=home), exc_info=True
            )

    try:
        subprocess.check_call(["setfacl", "-m", "g:all_users:---", f"/home/{username}"])
    except subprocess.CalledProcessError:
        logger.warning(f"Failed to protect /home/{username}", exc_info=True)

    # Create group for user and add to group 'all_users'
    user_group_create(groupname=username, gid=uid, primary_group=True, sync_perm=False)
    if admin:
        user_group_update(groupname="admins", add=username, sync_perm=False)
    user_group_update(groupname="all_users", add=username, force=True, sync_perm=True)

    # Trigger post_user_create hooks
    env_dict = {
        "YNH_USER_USERNAME": username,
        "YNH_USER_MAIL": mail,
        "YNH_USER_PASSWORD": password,
        "YNH_USER_FIRSTNAME": firstname,
        "YNH_USER_LASTNAME": lastname,
    }

    hook_callback("post_user_create", args=[username, mail], env=env_dict)

    # TODO: Send a welcome mail to user
    if not from_import:
        logger.success(m18n.n("user_created"))

    return {"fullname": fullname, "username": username, "mail": mail}


@is_unit_operation([("username", "user")])
def user_delete(
    operation_logger: "OperationLogger",
    username: str,
    purge: bool = False,
    from_import: bool = False,
    force: bool = False,
):
    from yunohost.authenticators.ldap_admin import Authenticator as AdminAuth
    from yunohost.authenticators.ldap_ynhuser import Authenticator as PortalAuth
    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface

    groups = user_group_list()["groups"]

    if username not in user_list()["users"]:
        raise YunohostValidationError("user_unknown", user=username)
    elif force and username in groups["admins"] and len(groups["admins"]) <= 1:
        raise YunohostValidationError("user_cannot_delete_last_admin")

    if not from_import:
        operation_logger.start()

    user_group_update(
        "all_users",
        remove=username,
        force=True,
        from_import=from_import,
        sync_perm=False,
    )
    for group, infos in groups.items():
        if group == "all_users":
            continue
        # If the user is in this group (and it's not the primary group),
        # remove the member from the group
        if username != group and username in infos["members"]:
            user_group_update(
                group,
                remove=username,
                sync_perm=False,
                from_import=from_import,
                force=force,
            )

    # Delete primary group if it exists (why wouldnt it exists ?  because some
    # epic bug happened somewhere else and only a partial removal was
    # performed...)
    if username in user_group_list()["groups"].keys():
        user_group_delete(username, force=True, sync_perm=True)

    ldap = _get_ldap_interface()
    try:
        ldap.remove(f"uid={username},ou=users")
    except Exception as e:
        raise YunohostError("user_deletion_failed", user=username, error=e)

    PortalAuth.invalidate_all_sessions_for_user(username)
    AdminAuth.invalidate_all_sessions_for_user(username)

    # Invalidate passwd to take user deletion into account
    subprocess.call(["nscd", "-i", "passwd"])

    if purge:
        subprocess.call(["rm", "-rf", f"/home/{username}"])
        subprocess.call(["rm", "-rf", f"/var/mail/{username}"])

    hook_callback("post_user_delete", args=[username, purge])

    if not from_import:
        logger.success(m18n.n("user_deleted"))


@is_unit_operation([("username", "user")], exclude=["change_password"])
def user_update(
    operation_logger: "OperationLogger",
    username: str,
    mail: Optional[str] = None,
    change_password: Optional[str] = None,
    add_mailforward: None | str | list[str] = None,
    remove_mailforward: None | str | list[str] = None,
    add_mailalias: None | str | list[str] = None,
    remove_mailalias: None | str | list[str] = None,
    mailbox_quota: Optional[str] = None,
    from_import: bool = False,
    fullname: Optional[str] = None,
    loginShell: Optional[str] = None,
):
    if fullname and fullname.strip():
        fullname = fullname.strip()
        firstname = fullname.split()[0]
        lastname = (
            " ".join(fullname.split()[1:]) or " "
        )  # Stupid hack because LDAP requires the sn/lastname attr, but it accepts a single whitespace...
    else:
        firstname = None
        lastname = None

    from yunohost.app import app_ssowatconf
    from yunohost.domain import domain_list
    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface
    from yunohost.utils.password import (
        _hash_user_password,
        assert_password_is_compatible,
        assert_password_is_strong_enough,
    )

    domains = domain_list()["domains"]

    # Populate user informations
    ldap = _get_ldap_interface()
    attrs_to_fetch = ["givenName", "sn", "mail", "maildrop", "memberOf"]
    result = ldap.search(
        base="ou=users",
        filter="uid=" + username,
        attrs=attrs_to_fetch,
    )
    if not result:
        raise YunohostValidationError("user_unknown", user=username)
    user = result[0]
    env_dict: dict[str, str] = {"YNH_USER_USERNAME": username}

    # Get modifications from arguments
    new_attr_dict: dict[str, Any] = {}
    if firstname:
        new_attr_dict["givenName"] = firstname  # TODO: Validate
        new_attr_dict["cn"] = new_attr_dict["displayName"] = (
            firstname + " " + user["sn"][0]
        ).strip()
        env_dict["YNH_USER_FIRSTNAME"] = firstname

    if lastname:
        new_attr_dict["sn"] = lastname  # TODO: Validate
        new_attr_dict["cn"] = new_attr_dict["displayName"] = (
            user["givenName"][0] + " " + lastname
        ).strip()
        env_dict["YNH_USER_LASTNAME"] = lastname

    if lastname and firstname:
        new_attr_dict["cn"] = new_attr_dict["displayName"] = (
            firstname + " " + lastname
        ).strip()

    # change_password is None if user_update is not called to change the password
    if change_password is not None and change_password != "":
        # when in the cli interface if the option to change the password is called
        # without a specified value, change_password will be set to the const 0.
        # In this case we prompt for the new password.
        if Moulinette.interface.type == "cli" and not change_password:
            change_password = cast(
                str,
                Moulinette.prompt(
                    m18n.n("ask_password"), is_password=True, confirm=True
                ),
            )

        # Ensure compatibility and sufficiently complex password
        assert_password_is_compatible(change_password)
        is_admin = "cn=admins,ou=groups,dc=yunohost,dc=org" in user["memberOf"]
        assert_password_is_strong_enough(
            "admin" if is_admin else "user", change_password
        )

        new_attr_dict["userPassword"] = _hash_user_password(change_password)
        env_dict["YNH_USER_PASSWORD"] = change_password

    if mail:
        # If the requested mail address is already as main address or as an alias by this user
        if mail in user["mail"]:
            if mail != user["mail"][0]:
                user["mail"].remove(mail)
        # Othewise, check that this mail address is not already used by this user
        else:
            try:
                ldap.validate_uniqueness({"mail": mail})
            except Exception as e:
                raise YunohostError("user_update_failed", user=username, error=e)
        if mail[mail.find("@") + 1 :] not in domains:
            raise YunohostError(
                "mail_domain_unknown", domain=mail[mail.find("@") + 1 :]
            )

        if mail.split("@")[0] in ADMIN_ALIASES:
            raise YunohostValidationError("mail_unavailable")

        new_attr_dict["mail"] = [mail] + user["mail"][1:]

    if add_mailalias is not None:
        if not isinstance(add_mailalias, list):
            add_mailalias = [add_mailalias]
        for mail in add_mailalias:
            if mail.split("@")[0] in ADMIN_ALIASES:
                raise YunohostValidationError("mail_unavailable")

            # (c.f. similar stuff as before)
            if mail in user["mail"]:
                continue
            else:
                try:
                    ldap.validate_uniqueness({"mail": mail})
                except Exception as e:
                    raise YunohostError("user_update_failed", user=username, error=e)
            if mail[mail.find("@") + 1 :] not in domains:
                raise YunohostError(
                    "mail_domain_unknown", domain=mail[mail.find("@") + 1 :]
                )
            user["mail"].append(mail)
        new_attr_dict["mail"] = user["mail"]

    if remove_mailalias:
        if not isinstance(remove_mailalias, list):
            remove_mailalias = [remove_mailalias]
        for mail in remove_mailalias:
            if len(user["mail"]) > 1 and mail in user["mail"][1:]:
                user["mail"].remove(mail)
            else:
                raise YunohostValidationError("mail_alias_remove_failed", mail=mail)
        new_attr_dict["mail"] = user["mail"]

    if "mail" in new_attr_dict:
        env_dict["YNH_USER_MAILS"] = ",".join(new_attr_dict["mail"])

    if add_mailforward:
        if not isinstance(add_mailforward, list):
            add_mailforward = [add_mailforward]
        new_attr_dict["maildrop"] = set(user["maildrop"])
        new_attr_dict["maildrop"].update(set(add_mailforward))

    if remove_mailforward:
        if not isinstance(remove_mailforward, list):
            remove_mailforward = [remove_mailforward]
        new_attr_dict["maildrop"] = set(user["maildrop"]) - set(remove_mailforward)

        if len(user["maildrop"]) - len(remove_mailforward) != len(
            new_attr_dict["maildrop"]
        ):
            raise YunohostValidationError("mail_forward_remove_failed", mail=mail)

    if "maildrop" in new_attr_dict:
        env_dict["YNH_USER_MAILFORWARDS"] = ",".join(new_attr_dict["maildrop"])

    if mailbox_quota is not None:
        new_attr_dict["mailuserquota"] = mailbox_quota
        env_dict["YNH_USER_MAILQUOTA"] = mailbox_quota

    if loginShell is not None:
        if not shellexists(loginShell) or loginShell not in list_shells():
            raise YunohostValidationError("invalid_shell", shell=loginShell)
        new_attr_dict["loginShell"] = loginShell
        env_dict["YNH_USER_LOGINSHELL"] = loginShell

    if not from_import:
        operation_logger.start()

    try:
        ldap.update(f"uid={username},ou=users", new_attr_dict)
    except Exception as e:
        raise YunohostError("user_update_failed", user=username, error=e)

    if "userPassword" in new_attr_dict:
        logger.info("Invalidating sessions")
        from yunohost.authenticators.ldap_ynhuser import Authenticator as PortalAuth

        PortalAuth.invalidate_all_sessions_for_user(username)

    # Invalidate passwd and group to update the loginShell
    subprocess.call(["nscd", "-i", "passwd"])
    subprocess.call(["nscd", "-i", "group"])

    # Trigger post_user_update hooks
    hook_callback("post_user_update", env=env_dict)

    if not from_import:
        app_ssowatconf()
        logger.success(m18n.n("user_updated"))
        return user_info(username)


def user_info(username: str) -> dict[str, str]:
    """
    Get user informations

    Keyword argument:
        username -- Username or mail to get informations

    """
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    user_attrs = ["cn", "mail", "uid", "maildrop", "mailuserquota", "loginShell"]

    if len(username.split("@")) == 2:
        filter = "mail=" + username
    else:
        filter = "uid=" + username

    result = ldap.search("ou=users", filter, user_attrs)

    if result:
        user = result[0]
    else:
        raise YunohostValidationError("user_unknown", user=username)

    result_dict = {
        "username": user["uid"][0],
        "fullname": user["cn"][0],
        "mail": user["mail"][0],
        "loginShell": user["loginShell"][0],
        "mail-aliases": [],
        "mail-forward": [],
    }

    if len(user["mail"]) > 1:
        result_dict["mail-aliases"] = user["mail"][1:]

    if len(user["maildrop"]) > 1:
        user["maildrop"].remove(username)
        result_dict["mail-forward"] = user["maildrop"]

    if "mailuserquota" in user:
        userquota = user["mailuserquota"][0]

        if isinstance(userquota, int):
            userquota = str(userquota)

        # Test if userquota is '0' or '0M' ( quota pattern is ^(\d+[bkMGT])|0$ )
        is_limited = not re.match("0[bkMGT]?", userquota)
        storage_use = "?"

        if service_status("dovecot")["status"] != "running":
            logger.warning(m18n.n("mailbox_used_space_dovecot_down"))
        elif username not in user_permission_info("mail.main")["corresponding_users"]:
            logger.debug(m18n.n("mailbox_disabled", user=username))
        else:
            try:
                uid_ = user["uid"][0]
                cmd_result = check_output(f"doveadm -f flow quota get -u {uid_}")
            except Exception as e:
                cmd_result = ""
                logger.warning(f"Failed to fetch quota info ... : {e}")

            # Exemple of return value for cmd:
            # """Quota name=User quota Type=STORAGE Value=0 Limit=- %=0
            # Quota name=User quota Type=MESSAGE Value=0 Limit=- %=0"""
            has_value = re.search(r"Value=(\d+)", cmd_result)

            if has_value:
                storage_use_int = int(has_value.group(1)) * 1000
                storage_use = binary_to_human(storage_use_int)

                if is_limited:
                    has_percent = re.search(r"%=(\d+)", cmd_result)

                    if has_percent:
                        percentage = int(has_percent.group(1))
                        storage_use += " (%s%%)" % percentage

        result_dict["mailbox-quota"] = {
            "limit": userquota if is_limited else m18n.n("unlimit"),
            "use": storage_use,
        }

    return result_dict


def user_export() -> Union[str, "HTTPResponseType"]:
    """
    Export users into CSV

    Keyword argument:
        csv -- CSV file with columns username;firstname;lastname;password;mailbox-quota;mail;mail-alias;mail-forward;groups

    """
    import csv  # CSV are needed only in this function
    from io import StringIO

    with StringIO() as csv_io:
        writer = csv.DictWriter(
            csv_io, list(FIELDS_FOR_IMPORT.keys()), delimiter=";", quotechar='"'
        )
        writer.writeheader()
        users = user_list(list(FIELDS_FOR_IMPORT.keys()))["users"]
        for username, user in users.items():
            user["mail-alias"] = ",".join(user["mail-alias"])
            user["mail-forward"] = ",".join(user["mail-forward"])
            user["groups"] = ",".join(user["groups"])
            writer.writerow(user)

        body = csv_io.getvalue().rstrip()
    if Moulinette.interface.type == "api":
        # We return a raw bottle HTTPresponse (instead of serializable data like
        # list/dict, ...), which is gonna be picked and used directly by moulinette
        from bottle import HTTPResponse

        response = HTTPResponse(
            body=body,
            headers={
                "Content-Disposition": "attachment; filename=users.csv",
                "Content-Type": "text/csv",
            },
        )
        return response
    else:
        return body


@is_unit_operation()
def user_import(
    operation_logger: "OperationLogger",
    csvfile: TextIO,
    update: bool = False,
    delete: bool = False,
) -> dict[str, int]:
    """
    Import users from CSV

    Keyword argument:
        csvfile -- CSV file with columns username;firstname;lastname;password;mailbox_quota;mail;alias;forward;groups

    """

    import csv  # CSV are needed only in this function

    from moulinette.utils.text import random_ascii

    from yunohost.app import app_ssowatconf
    from yunohost.domain import domain_list
    from yunohost.permission import permission_sync_to_user

    # Pre-validate data and prepare what should be done
    actions: dict[str, list[dict[str, Any]]] = {
        "created": [],
        "updated": [],
        "deleted": [],
    }
    is_well_formatted = True

    def to_list(str_list):
        L = str_list.split(",") if str_list else []
        L = [element.strip() for element in L]
        return L

    existing_users = user_list()["users"]
    existing_groups = user_group_list()["groups"]
    existing_domains = domain_list()["domains"]

    reader = csv.DictReader(csvfile, delimiter=";", quotechar='"')
    reader_fields = cast(list[str], reader.fieldnames)
    users_in_csv = []

    missing_columns: list[str] = [
        key for key in FIELDS_FOR_IMPORT.keys() if key not in reader_fields
    ]
    if missing_columns:
        raise YunohostValidationError(
            "user_import_missing_columns", columns=", ".join(missing_columns)
        )

    for user in reader:
        # Validate column values against regexes
        format_errors = [
            f"{key}: '{user[key]}' doesn't match the expected format"
            for key, validator in FIELDS_FOR_IMPORT.items()
            if user[key] is None or not re.match(validator, user[key])
        ]

        # Check for duplicated username lines
        if user["username"] in users_in_csv:
            format_errors.append(f"username '{user['username']}' duplicated")
        users_in_csv.append(user["username"])

        # Validate that groups exist
        user["groups"] = to_list(user["groups"])
        unknown_groups = [g for g in user["groups"] if g not in existing_groups]
        if unknown_groups:
            format_errors.append(
                f"username '{user['username']}': unknown groups {', '.join(unknown_groups)}"
            )

        # Validate that domains exist
        user["mail-alias"] = to_list(user["mail-alias"])
        user["mail-forward"] = to_list(user["mail-forward"])
        user["domain"] = user["mail"].split("@")[1]

        unknown_domains = []
        if user["domain"] not in existing_domains:
            unknown_domains.append(user["domain"])

        unknown_domains += [
            mail.split("@", 1)[1]
            for mail in user["mail-alias"]
            if mail.split("@", 1)[1] not in existing_domains
        ]
        unknown_domains = list(set(unknown_domains))

        if unknown_domains:
            format_errors.append(
                f"username '{user['username']}': unknown domains {', '.join(unknown_domains)}"
            )

        if format_errors:
            logger.error(
                m18n.n(
                    "user_import_bad_line",
                    line=reader.line_num,
                    details=", ".join(format_errors),
                )
            )
            is_well_formatted = False
            continue

        # Choose what to do with this line and prepare data
        user["mailbox-quota"] = user["mailbox-quota"] or "0"

        # User creation
        if user["username"] not in existing_users:
            # Generate password if not exists
            # This could be used when reset password will be merged
            if not user["password"]:
                user["password"] = random_ascii(70)
            actions["created"].append(user)
        # User update
        elif update:
            actions["updated"].append(user)

    if delete:
        actions["deleted"] = [
            {"username": user} for user in existing_users if user not in users_in_csv
        ]

    if delete and not users_in_csv:
        logger.error(
            "You used the delete option with an empty csv file ... You probably did not really mean to do that, did you !?"
        )
        is_well_formatted = False

    if not is_well_formatted:
        raise YunohostValidationError("user_import_bad_file")

    total = len(actions["created"] + actions["updated"] + actions["deleted"])

    if total == 0:
        logger.info(m18n.n("user_import_nothing_to_do"))
        return {}

    # Apply creation, update and deletion operation
    result = {"created": 0, "updated": 0, "deleted": 0, "errors": 0}

    def progress(info=""):
        progress.nb += 1
        width = 20
        bar = int(progress.nb * width / total)
        bar = "[" + "#" * bar + "." * (width - bar) + "]"
        if info:
            bar += " > " + info
        if progress.old == bar:
            return
        progress.old = bar
        logger.info(bar)

    progress.nb = 0  # type: ignore[attr-defined]
    progress.old = ""  # type: ignore[attr-defined]

    def _on_failure(user, exception):
        if exception.key == "group_cannot_remove_last_admin":
            logger.warning(
                user
                + ": "
                + m18n.n("user_import_cannot_edit_or_delete_admins", user=user)
            )
        else:
            result["errors"] += 1
            logger.error(user + ": " + str(exception))

    def _import_update(new_infos, old_infos=False):
        remove_alias = None
        remove_forward = None
        remove_groups = []
        add_groups = new_infos["groups"]
        if old_infos:
            new_infos["mail"] = (
                None if old_infos["mail"] == new_infos["mail"] else new_infos["mail"]
            )
            remove_alias = list(
                set(old_infos["mail-alias"]) - set(new_infos["mail-alias"])
            )
            remove_forward = list(
                set(old_infos["mail-forward"]) - set(new_infos["mail-forward"])
            )
            new_infos["mail-alias"] = list(
                set(new_infos["mail-alias"]) - set(old_infos["mail-alias"])
            )
            new_infos["mail-forward"] = list(
                set(new_infos["mail-forward"]) - set(old_infos["mail-forward"])
            )

            remove_groups = list(set(old_infos["groups"]) - set(new_infos["groups"]))
            add_groups = list(set(new_infos["groups"]) - set(old_infos["groups"]))

            for group, infos in existing_groups.items():
                # Loop only on groups in 'remove_groups'
                # Ignore 'all_users' and primary group
                if (
                    group in ["all_users", new_infos["username"]]
                    or group not in remove_groups
                ):
                    continue
                # If the user is in this group (and it's not the primary group),
                # remove the member from the group
                if new_infos["username"] in infos["members"]:
                    user_group_update(
                        group,
                        remove=new_infos["username"],
                        sync_perm=False,
                        from_import=True,
                    )

        user_update(
            new_infos["username"],
            fullname=(new_infos["firstname"] + " " + new_infos["lastname"]).strip(),
            change_password=new_infos["password"],
            mailbox_quota=new_infos["mailbox-quota"],
            mail=new_infos["mail"],
            add_mailalias=new_infos["mail-alias"],
            remove_mailalias=remove_alias,
            remove_mailforward=remove_forward,
            add_mailforward=new_infos["mail-forward"],
            from_import=True,
        )

        for group in add_groups:
            if group in ["all_users", new_infos["username"]]:
                continue
            user_group_update(
                group, add=new_infos["username"], sync_perm=False, from_import=True
            )

    users = user_list(list(FIELDS_FOR_IMPORT.keys()))["users"]
    operation_logger.start()
    # We do delete and update before to avoid mail uniqueness issues
    for user in actions["deleted"]:
        progress(f"Deleting {user}")
        try:
            user_delete(user["username"], purge=True, from_import=True)
            result["deleted"] += 1
        except YunohostError as e:
            _on_failure(user, e)

    for user in actions["updated"]:
        progress(f"Updating {user['username']}")
        try:
            _import_update(user, users[user["username"]])
            result["updated"] += 1
        except YunohostError as e:
            _on_failure(user["username"], e)

    for user in actions["created"]:
        progress(f"Creating {user['username']}")
        try:
            user_create(
                user["username"],
                user["domain"],
                user["password"],
                mailbox_quota=user["mailbox-quota"],
                from_import=True,
                fullname=(user["firstname"] + " " + user["lastname"]).strip(),
            )
            _import_update(user)
            result["created"] += 1
        except YunohostError as e:
            _on_failure(user["username"], e)

    permission_sync_to_user()
    app_ssowatconf()

    if result["errors"]:
        msg = m18n.n("user_import_partial_failed")
        if result["created"] + result["updated"] + result["deleted"] == 0:
            msg = m18n.n("user_import_failed")
        logger.error(msg)
        operation_logger.error(msg)
    else:
        logger.success(m18n.n("user_import_success"))
        operation_logger.success()
    return result


#
# Group subcategory
#
def user_group_list(
    full: bool = False, include_primary_groups: bool = True
) -> dict[str, dict[str, dict]]:
    """
    List users

    Keyword argument:
        full -- List all the info available for each groups
        include_primary_groups -- Include groups corresponding to users (which should always only contains this user)
                                  This option is set to false by default in the action map because we don't want to have
                                  these displayed when the user runs `yunohost user group list`, but internally we do want
                                  to list them when called from other functions
    """

    # Fetch relevant informations

    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract

    ldap = _get_ldap_interface()
    groups_infos = ldap.search(
        "ou=groups",
        "(objectclass=groupOfNamesYnh)",
        ["cn", "member", "permission"],
    )

    # Parse / organize information to be outputed

    users = user_list()["users"]
    groups: dict[str, dict[str, Any]] = {}
    for infos in groups_infos:
        name = infos["cn"][0]

        if not include_primary_groups and name in users:
            continue

        groups[name] = {}

        groups[name]["members"] = [
            _ldap_path_extract(p, "uid") for p in infos.get("member", [])
        ]

        if full:
            groups[name]["permissions"] = [
                _ldap_path_extract(p, "cn") for p in infos.get("permission", [])
            ]

    return {"groups": groups}


@is_unit_operation([("groupname", "group")])
def user_group_create(
    operation_logger: "OperationLogger",
    groupname: str,
    gid: Optional[str] = None,
    primary_group: bool = False,
    sync_perm: bool = True,
) -> dict[str, str]:
    """
    Create group

    Keyword argument:
        groupname -- Must be unique

    """
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    # Validate uniqueness of groupname in LDAP
    conflict = ldap.get_conflict({"cn": groupname}, base_dn="ou=groups")
    if conflict:
        raise YunohostValidationError("group_already_exist", group=groupname)

    # Validate uniqueness of groupname in system group
    all_existing_groupnames = {x.gr_name for x in grp.getgrall()}
    if groupname in all_existing_groupnames:
        if primary_group:
            logger.warning(
                m18n.n("group_already_exist_on_system_but_removing_it", group=groupname)
            )
            subprocess.check_call(
                f"sed --in-place '/^{groupname}:/d' /etc/group", shell=True
            )
        else:
            raise YunohostValidationError(
                "group_already_exist_on_system", group=groupname
            )

    if not gid:
        # Get random GID
        all_gid = {str(x.gr_gid) for x in grp.getgrall()}

        uid_guid_found = False
        while not uid_guid_found:
            gid = str(random.randint(200, 99999))
            uid_guid_found = gid not in all_gid

    attr_dict = {
        "objectClass": ["top", "groupOfNamesYnh", "posixGroup"],
        "cn": groupname,
        "gidNumber": [gid],
    }

    # Here we handle the creation of a primary group
    # We want to initialize this group to contain the corresponding user
    # (then we won't be able to add/remove any user in this group)
    if primary_group:
        attr_dict["member"] = ["uid=" + groupname + ",ou=users,dc=yunohost,dc=org"]

    operation_logger.start()
    try:
        ldap.add(f"cn={groupname},ou=groups", attr_dict)
    except Exception as e:
        raise YunohostError("group_creation_failed", group=groupname, error=e)

    if sync_perm:
        permission_sync_to_user()

    if not primary_group:
        logger.success(m18n.n("group_created", group=groupname))
    else:
        logger.debug(m18n.n("group_created", group=groupname))

    return {"name": groupname}


@is_unit_operation([("groupname", "group")])
def user_group_delete(
    operation_logger: "OperationLogger",
    groupname: str,
    force: bool = False,
    sync_perm: bool = True,
) -> None:
    """
    Delete user

    Keyword argument:
        groupname -- Groupname to delete

    """
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface

    existing_groups = list(user_group_list()["groups"].keys())
    if groupname not in existing_groups:
        raise YunohostValidationError("group_unknown", group=groupname)

    # Refuse to delete primary groups of a user (e.g. group 'sam' related to user 'sam')
    # without the force option...
    #
    # We also can't delete "all_users" because that's a special group...
    existing_users = list(user_list()["users"].keys())
    undeletable_groups = existing_users + ["all_users", "visitors", "admins"]
    if groupname in undeletable_groups and not force:
        raise YunohostValidationError("group_cannot_be_deleted", group=groupname)

    operation_logger.start()
    ldap = _get_ldap_interface()
    try:
        ldap.remove(f"cn={groupname},ou=groups")
    except Exception as e:
        raise YunohostError("group_deletion_failed", group=groupname, error=e)

    if sync_perm:
        permission_sync_to_user()

    if groupname not in existing_users:
        logger.success(m18n.n("group_deleted", group=groupname))
    else:
        logger.debug(m18n.n("group_deleted", group=groupname))


@is_unit_operation([("groupname", "group")])
def user_group_update(
    operation_logger: "OperationLogger",
    groupname: str,
    add: None | str | list[str] = None,
    remove: None | str | list[str] = None,
    add_mailalias: None | str | list[str] = None,
    remove_mailalias: None | str | list[str] = None,
    force: bool = False,
    sync_perm: bool = True,
    from_import: bool = False,
) -> None | dict[str, Any]:
    from yunohost.hook import hook_callback
    from yunohost.permission import permission_sync_to_user
    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract

    existing_users = list(user_list()["users"].keys())

    # Refuse to edit a primary group of a user (e.g. group 'sam' related to user 'sam')
    # Those kind of group should only ever contain the user (e.g. sam) and only this one.
    # We also can't edit "all_users" without the force option because that's a special group...
    # Also prevent to remove the last admin
    if not force:
        if groupname == "all_users":
            raise YunohostValidationError("group_cannot_edit_all_users")
        elif groupname == "visitors":
            raise YunohostValidationError("group_cannot_edit_visitors")
        elif groupname in existing_users:
            raise YunohostValidationError(
                "group_cannot_edit_primary_group", group=groupname
            )
        elif groupname == "admins" and remove:
            admins = user_group_info("admins")["members"]
            if isinstance(remove, str):
                remove = [remove]
            if admins and not set(admins) - set(remove):
                raise YunohostValidationError(
                    "group_cannot_remove_last_admin", user=remove[0]
                )

    ldap = _get_ldap_interface()

    # Fetch info for this group
    result = ldap.search(
        "ou=groups",
        "cn=" + groupname,
        ["cn", "member", "permission", "mail", "objectClass"],
    )

    if not result:
        raise YunohostValidationError("group_unknown", group=groupname)

    group = result[0]

    # We extract the uid for each member of the group to keep a simple flat list of members
    current_group_mail = group.get("mail", [])
    new_group_mail = copy.copy(current_group_mail)
    current_group_members = [
        _ldap_path_extract(p, "uid") for p in group.get("member", [])
    ]
    new_group_members = copy.copy(current_group_members)
    new_attr_dict: dict[str, Any] = {}

    # Group permissions
    current_group_permissions = [
        _ldap_path_extract(p, "cn") for p in group.get("permission", [])
    ]

    if add:
        users_to_add = [add] if not isinstance(add, list) else add

        for user in users_to_add:
            if user not in existing_users:
                raise YunohostValidationError("user_unknown", user=user)

            if user in current_group_members:
                logger.warning(
                    m18n.n("group_user_already_in_group", user=user, group=groupname)
                )
            else:
                operation_logger.related_to.append(("user", user))
                logger.info(m18n.n("group_user_add", group=groupname, user=user))

        new_group_members += users_to_add

    if remove:
        users_to_remove = [remove] if not isinstance(remove, list) else remove

        for user in users_to_remove:
            if user not in current_group_members:
                logger.warning(
                    m18n.n("group_user_not_in_group", user=user, group=groupname)
                )
            else:
                operation_logger.related_to.append(("user", user))
                logger.info(m18n.n("group_user_remove", group=groupname, user=user))

        # Remove users_to_remove from new_group_members
        # Kinda like a new_group_members -= users_to_remove
        new_group_members = [u for u in new_group_members if u not in users_to_remove]

    # If something changed, we add this to the stuff to commit later in the code
    if set(new_group_members) != set(current_group_members):
        new_group_members_dns = [
            "uid=" + user + ",ou=users,dc=yunohost,dc=org" for user in new_group_members
        ]
        new_attr_dict["member"] = list(set(new_group_members_dns))
        new_attr_dict["memberUid"] = list(set(new_group_members))

    # Check the whole alias situation
    if add_mailalias:
        from yunohost.domain import domain_list

        domains = domain_list()["domains"]

        if not isinstance(add_mailalias, list):
            add_mailalias = [add_mailalias]
        for mail in add_mailalias:
            if mail.split("@")[0] in ADMIN_ALIASES and groupname != "admins":
                raise YunohostValidationError("mail_unavailable")
            if mail in current_group_mail:
                continue
            try:
                ldap.validate_uniqueness({"mail": mail})
            except Exception as e:
                raise YunohostError("group_update_failed", group=groupname, error=e)
            if mail[mail.find("@") + 1 :] not in domains:
                raise YunohostError(
                    "mail_domain_unknown", domain=mail[mail.find("@") + 1 :]
                )
            new_group_mail.append(mail)
            logger.info(m18n.n("group_mailalias_add", group=groupname, mail=mail))

    if remove_mailalias:
        from yunohost.domain import _get_maindomain

        if not isinstance(remove_mailalias, list):
            remove_mailalias = [remove_mailalias]
        for mail in remove_mailalias:
            if (
                "@" in mail
                and mail.split("@")[0] in ADMIN_ALIASES
                and groupname == "admins"
                and mail.split("@")[1] == _get_maindomain()
            ):
                raise YunohostValidationError(
                    f"The alias {mail} can not be removed from the 'admins' group",
                    raw_msg=True,
                )
            if mail in new_group_mail:
                new_group_mail.remove(mail)
                logger.info(
                    m18n.n("group_mailalias_remove", group=groupname, mail=mail)
                )
            else:
                raise YunohostValidationError("mail_alias_remove_failed", mail=mail)

    if set(new_group_mail) != set(current_group_mail):
        logger.info(m18n.n("group_update_aliases", group=groupname))
        new_attr_dict["mail"] = list(set(new_group_mail))

        if new_attr_dict["mail"]:
            new_attr_dict["objectClass"] = set(group["objectClass"])
            new_attr_dict["objectClass"].add("mailGroup")
        else:
            new_attr_dict["objectClass"] = set(group["objectClass"]) - {
                "mailGroup",
                "mailAccount",
            }

    if new_attr_dict:
        if not from_import:
            operation_logger.start()
        try:
            ldap.update(f"cn={groupname},ou=groups", new_attr_dict)
        except Exception as e:
            raise YunohostError("group_update_failed", group=groupname, error=e)

    if groupname == "admins" and remove:
        from yunohost.authenticators.ldap_admin import Authenticator as AdminAuth

        for user in users_to_remove:
            AdminAuth.invalidate_all_sessions_for_user(user)

    if sync_perm:
        permission_sync_to_user()

    if add and users_to_add:
        for permission in current_group_permissions:
            app = permission.split(".")[0]
            sub_permission = permission.split(".")[1]

            hook_callback(
                "post_app_addaccess",
                args=[app, ",".join(users_to_add), sub_permission, ""],
            )

    if remove and users_to_remove:
        for permission in current_group_permissions:
            app = permission.split(".")[0]
            sub_permission = permission.split(".")[1]

            hook_callback(
                "post_app_removeaccess",
                args=[app, ",".join(users_to_remove), sub_permission, ""],
            )

    if not from_import:
        if groupname != "all_users":
            if not new_attr_dict:
                logger.info(m18n.n("group_no_change", group=groupname))
            else:
                logger.success(m18n.n("group_updated", group=groupname))
        else:
            logger.debug(m18n.n("group_updated", group=groupname))

        return user_group_info(groupname)

    return None


def user_group_info(groupname: str) -> dict[str, Any]:
    """
    Get user informations

    Keyword argument:
        groupname -- Groupname to get informations

    """

    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract

    ldap = _get_ldap_interface()

    # Fetch info for this group
    result = ldap.search(
        "ou=groups",
        "cn=" + groupname,
        ["cn", "member", "permission", "mail"],
    )

    if not result:
        raise YunohostValidationError("group_unknown", group=groupname)

    infos = result[0]

    # Format data

    return {
        "members": [_ldap_path_extract(p, "uid") for p in infos.get("member", [])],
        "permissions": [
            _ldap_path_extract(p, "cn") for p in infos.get("permission", [])
        ],
        "mail-aliases": [m for m in infos.get("mail", [])],
    }


def user_group_add(
    groupname: str, usernames: list[str], force: bool = False, sync_perm: bool = True
) -> Optional[dict[str, Any]]:
    """
    Add user(s) to a group

    Keyword argument:
        groupname -- Groupname to update
        usernames -- User(s) to add in the group

    """
    return user_group_update(groupname, add=usernames, force=force, sync_perm=sync_perm)


def user_group_remove(
    groupname: str, usernames: list[str], force: bool = False, sync_perm: bool = True
) -> Optional[dict[str, Any]]:
    """
    Remove user(s) from a group

    Keyword argument:
        groupname -- Groupname to update
        usernames -- User(s) to remove from the group

    """
    return user_group_update(
        groupname, remove=usernames, force=force, sync_perm=sync_perm
    )


def user_group_add_mailalias(
    groupname: str, aliases: list[str], force: bool = False
) -> Optional[dict[str, Any]]:
    return user_group_update(
        groupname, add_mailalias=aliases, force=force, sync_perm=False
    )


def user_group_remove_mailalias(
    groupname: str, aliases: list[str], force: bool = False
) -> Optional[dict[str, Any]]:
    return user_group_update(
        groupname, remove_mailalias=aliases, force=force, sync_perm=False
    )


#
# Permission subcategory
#


# FIXME: missing return type
def user_permission_list(short: bool = False, full: bool = False, apps: list[str] = []):
    from yunohost.permission import user_permission_list

    return user_permission_list(short, full, absolute_urls=True, apps=apps)


# FIXME: missing return type
def user_permission_update(
    permission: str,
    label: Optional[str] = None,
    show_tile: Optional[bool] = None,
    sync_perm: bool = True,
):
    from yunohost.permission import user_permission_update

    return user_permission_update(
        permission, label=label, show_tile=show_tile, sync_perm=sync_perm
    )


# FIXME: missing return type
def user_permission_add(
    permission: str,
    names: list[str],
    protected: Optional[bool] = None,
    force: bool = False,
    sync_perm: bool = True,
):
    from yunohost.permission import user_permission_update

    return user_permission_update(
        permission, add=names, protected=protected, force=force, sync_perm=sync_perm
    )


# FIXME: missing return type
def user_permission_remove(
    permission: str,
    names: list[str],
    protected: Optional[bool] = None,
    force: bool = False,
    sync_perm: bool = True,
):
    from yunohost.permission import user_permission_update

    return user_permission_update(
        permission, remove=names, protected=protected, force=force, sync_perm=sync_perm
    )


# FIXME: missing return type
def user_permission_reset(permission: str, sync_perm: bool = True):
    from yunohost.permission import user_permission_reset

    return user_permission_reset(permission, sync_perm=sync_perm)


# FIXME: missing return type
def user_permission_info(permission: str):
    from yunohost.permission import user_permission_info

    return user_permission_info(permission)


#
# SSH subcategory
#
import yunohost.ssh


def user_ssh_list_keys(username: str) -> dict[str, dict[str, str]]:
    return yunohost.ssh.user_ssh_list_keys(username)


def user_ssh_add_key(username: str, key: str, comment: Optional[str] = None) -> None:
    return yunohost.ssh.user_ssh_add_key(username, key, comment)


def user_ssh_remove_key(username: str, key: str) -> None:
    return yunohost.ssh.user_ssh_remove_key(username, key)


#
# End SSH subcategory
#


def _update_admins_group_aliases(old_main_domain: str, new_main_domain: str) -> None:
    current_admin_aliases = user_group_info("admins")["mail-aliases"]

    aliases_to_remove = [
        a
        for a in current_admin_aliases
        if "@" in a
        and a.split("@")[1] == old_main_domain
        and a.split("@")[0] in ADMIN_ALIASES
    ]
    aliases_to_add = [f"{a}@{new_main_domain}" for a in ADMIN_ALIASES]

    user_group_update(
        "admins", add_mailalias=aliases_to_add, remove_mailalias=aliases_to_remove
    )
