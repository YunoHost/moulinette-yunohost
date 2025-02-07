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
import random
import re
import os
from logging import getLogger
from typing import TYPE_CHECKING, BinaryIO, Literal, TypedDict, NotRequired, cast

from moulinette import m18n
from moulinette.utils.filesystem import read_yaml, write_to_yaml
from yunohost.utils.error import YunohostError, YunohostValidationError

if TYPE_CHECKING:
    from moulinette.utils.log import MoulinetteLogger
    logger = cast(MoulinetteLogger, getLogger("yunohost.permission"))
else:
    logger = getLogger("yunohost.permission")

SYSTEM_PERMS = {
    "mail": {"label": "Email", "gid": 5001},
    "sftp": {"label": "SFTP", "gid": 5004},
    "ssh": {"label": "SSH", "gid": 5003},
}
SYSTEM_PERM_CONF = "/etc/yunohost/permissions.yml"


class SystemPermInfos(TypedDict):
    label: str
    allowed: list[str]
    corresponding_users: NotRequired[list[str] | set[str]]


class AppPermInfos(SystemPermInfos):
    url: str | None
    additional_urls: list[str]
    auth_header: bool
    protected: bool
    show_tile: bool | None
    hide_from_public: NotRequired[bool]
    logo_hash: NotRequired[str]
    description: NotRequired[str]
    order: NotRequired[int]


PermInfos = AppPermInfos | SystemPermInfos

#
#
#  The followings are the methods exposed through the "yunohost user permission" interface
#
#


def user_permission_list(
    full: bool = False,
    ignore_system_perms: bool = False,
    absolute_urls: bool = False,
    apps: list[str] = [],
) -> dict[Literal["permissions"], dict[str, PermInfos]]:
    """
    List permissions and corresponding accesses
    """

    # Fetch relevant informations
    from yunohost.app import _installed_apps, _get_app_settings
    from yunohost.user import user_group_list

    # Parse / organize information to be outputed
    filter_ = apps
    if filter_:
        apps = sorted(a for a in filter_ if a not in SYSTEM_PERMS)
    else:
        apps = sorted(_installed_apps())

    permissions: dict[str, PermInfos] = {}
    for app in apps:
        settings = _get_app_settings(app)

        subperms = settings.get("_permissions", {})
        if "main" not in subperms:
            subperms["main"] = {}

        app_label = subperms["main"].get("label") or settings.get("label") or app.title()

        for subperm, infos in subperms.items():
            name = f"{app}.{subperm}"
            perm: AppPermInfos = {
                "label": "",
                "url": None,
                "additional_urls": [],
                "auth_header": True,
                "show_tile": None,  # Automagically set to True by default if an url is defined and show_tile not provided
                "protected": False,
                "allowed": [],
            }
            perm.update(infos)
            if subperm != "main":
                # Redefine the subperm label to : <main_label> (<subperm>)
                subperm_label = (perm["label"] or subperm.title())
                perm["label"] = f"{app_label} ({subperm_label})"
            elif not perm["label"]:
                perm["label"] = app_label

            if perm["show_tile"] is None and perm["url"] is not None:
                perm["show_tile"] = True

            if absolute_urls:
                if "domain" in settings and "path" in settings:
                    app_base_path = settings["domain"] + settings["path"]
                else:
                    # Meh in some situation where the app is currently installed/removed,
                    # this function may be called and we still need to act as if the corresponding
                    # permission indeed exists ... dunno if that's really the right way to proceed but okay.
                    app_base_path = ""

                perm["url"] = (
                    _get_absolute_url(perm["url"], app_base_path)
                    if perm["url"] is not None
                    else None
                )
                perm["additional_urls"] = [
                    _get_absolute_url(url, app_base_path)
                    for url in perm["additional_urls"]
                ]
            permissions[name] = perm

    if not ignore_system_perms and (
        not filter_ or any(p in filter_ for p in SYSTEM_PERMS.keys())
    ):
        system_perm_conf = _get_system_perms()
        for name, infos in SYSTEM_PERMS.items():
            if filter_ and name not in filter_:
                continue
            permissions[f"{name}.main"] = system_perm_conf[name]

    if full:
        map_group_to_users = {
            g: infos["members"] for g, infos in user_group_list()["groups"].items()
        }
        for infos in permissions.values():
            infos["corresponding_users"] = set()
            for group in infos["allowed"]:
                # FIXME: somewhere we may want to have some sort of garbage collection
                # to automatically remove user/groups from the "allowed" info when they
                # somehow disappeared from the system (for example this may happen when
                # restoring an app on which not all the user/group exist)
                users_in_group = set(map_group_to_users.get(group, []))
                infos["corresponding_users"] |= users_in_group
            infos["corresponding_users"] = list(
                sorted(infos["corresponding_users"])
            )
    else:
        # Keep the output concise when used without --full, meant to not bloat CLI
        for infos in permissions.values():
            for key in ["additional_urls", "auth_header", "logo_hash", "order", "protected", "show_tile"]:
                if key in infos:
                    del infos[key]

    return {"permissions": permissions}


def user_permission_update(
    permission: str,
    add: str | list[str] | None = None,
    remove: str | list[str] | None = None,
    label: str | None = None,
    show_tile: bool | None = None,
    protected: bool | None = None,
    force: bool = False,
    sync_perm: bool = True,
    log_success_as_debug: bool = False,
) -> PermInfos:
    """
    Allow or Disallow a user or group to a permission for a specific application

    Keyword argument:
        permission     -- Name of the permission (e.g. mail or or wordpress or wordpress.editors)
        add            -- (optional) List of groups or usernames to add to this permission
        remove         -- (optional) List of groups or usernames to remove from to this permission
        label          -- (optional) Define a name for the permission. This label will be shown on the SSO and in the admin
        show_tile      -- (optional) Define if a tile will be shown in the SSO
        protected      -- (optional) Define if the permission can be added/removed to the visitor group
        force          -- (optional) Give the possibility to add/remove access from the visitor group to a protected permission
    """
    from yunohost.user import user_group_list
    from yunohost.app import app_ssowatconf

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    app = permission.split(".")[0]
    existing_permission = user_permission_info(permission)

    if app in SYSTEM_PERMS:
        # Refuse to add "visitors" to mail/ssh/sftp ... they require an account to make sense.
        if add and "visitors" in add:
            raise YunohostValidationError(
                "permission_require_account", permission=permission
            )
        # Refuse to add "all_users" to ssh/sftp permissions
        if app in ["ssh", "sftp"] and (add and "all_users" in add) and not force:
            raise YunohostValidationError(
                "permission_cant_add_to_all_users", permission=permission
            )
        # Label, show_tile and protected only make sense for actual apps
        if any(v is not None for v in [label, show_tile, protected]):
            raise YunohostValidationError(
                f"Cannot change label, show_tile or protected for system permission {app}",
                raw_msg=True,
            )
    else:
        # Refuse to add "visitors" to protected permission
        if (
            ((add and "visitors" in add) or (remove and "visitors"))
            and existing_permission.get("protected")
            and not force
        ):
            raise YunohostValidationError("permission_protected", permission=permission)

    # Fetch currently allowed groups for this permission
    current_allowed_groups = existing_permission["allowed"]

    # Compute new allowed group list (and make sure what we're doing make sense)
    new_allowed_groups = copy.copy(current_allowed_groups)
    all_existing_groups = user_group_list()["groups"].keys()

    if add:
        groups_to_add = [add] if not isinstance(add, list) else add
        for group in groups_to_add:
            if group not in all_existing_groups:
                raise YunohostValidationError("group_unknown", group=group)
            if group in current_allowed_groups:
                logger.warning(
                    m18n.n(
                        "permission_already_allowed", permission=permission, group=group
                    )
                )
            else:
                new_allowed_groups += [group]

    if remove:
        groups_to_remove = [remove] if not isinstance(remove, list) else remove
        for group in groups_to_remove:
            if group not in current_allowed_groups:
                logger.warning(
                    m18n.n(
                        "permission_already_disallowed",
                        permission=permission,
                        group=group,
                    )
                )

        new_allowed_groups = [
            g for g in new_allowed_groups if g not in groups_to_remove
        ]

    # If we end up with something like allowed groups is ["all_users", "volunteers"]
    # we shall warn the users that they should probably choose between one or
    # the other, because the current situation is probably not what they expect
    # / is temporary ?  Note that it's fine to have ["all_users", "visitors"]
    # though, but it's not fine to have ["all_users", "visitors", "volunteers"]
    if "all_users" in new_allowed_groups and len(new_allowed_groups) >= 2:
        if "visitors" not in new_allowed_groups or len(new_allowed_groups) >= 3:
            logger.warning(m18n.n("permission_currently_allowed_for_all_users"))

    if (
        existing_permission.get("url")
        and existing_permission["url"].startswith("re:")  # type: ignore
        and show_tile
    ):
        logger.warning(
            m18n.n(
                "regex_incompatible_with_tile",
                regex=existing_permission["url"],  # type: ignore
                permission=permission,
            )
        )

    # Commit the new allowed group list
    if app not in SYSTEM_PERMS:
        _update_app_permission_setting(
            permission=permission,
            label=label,
            show_tile=show_tile,
            protected=protected,
            allowed=new_allowed_groups,
        )
    else:
        system_perms = _get_system_perms()
        system_perms[app]["allowed"] = list(sorted(new_allowed_groups))
        _set_system_perms(system_perms)

    if sync_perm:
        _sync_permissions_with_ldap()
        if app not in SYSTEM_PERMS:
            app_ssowatconf()

    # This is meant to reduce noise during resource update/provisioning
    # but display a "success" flash message when admins trigger this operation manually ?
    if log_success_as_debug:
        logger.debug(m18n.n("permission_updated", permission=permission))
    else:
        logger.success(m18n.n("permission_updated", permission=permission))

    return user_permission_info(permission)


def user_permission_info(permission: str) -> PermInfos:
    """
    Return informations about a specific permission

    Keyword argument:
        permission -- Name of the permission (e.g. mail or nextcloud or wordpress.editors)
    """

    if "." in permission:
        app = permission.split(".")[0]
    else:
        # By default, manipulate main permission if only an app name is provided
        app = permission
        permission = permission + ".main"

    # Fetch existing permission

    perms = user_permission_list(full=True, apps=[app])["permissions"]
    perm = perms.get(permission)
    if perm is None:
        raise YunohostValidationError("permission_not_found", permission=permission)

    return perm


#
#
#  The followings methods are *not* directly exposed.
#  They are used to create/delete the permissions (e.g. during app install/remove)
#  and by some app helpers to possibly add additional permissions
#
#


def permission_create(
    permission: str,
    allowed: str | list[str] | None = None,
    url: str | None = None,
    additional_urls: list[str] | None = None,
    auth_header: bool = True,
    show_tile: bool = False,
    protected: bool = False,
    sync_perm: bool = True,
) -> PermInfos:
    """
    Create a new permission for a specific application

    Keyword argument:
        permission      -- Name of the permission (e.g. mail or nextcloud or wordpress.editors)
        allowed         -- (optional) List of group/user to allow for the permission
        url             -- (optional) URL for which access will be allowed/forbidden
        additional_urls -- (optional) List of additional URL for which access will be allowed/forbidden
        auth_header     -- (optional) Define for the URL of this permission, if SSOwat pass the authentication header to the application
        show_tile       -- (optional) Define if a tile will be shown in the SSO
        protected       -- (optional) Define if the permission can be added/removed to the visitor group

    If provided, 'url' is assumed to be relative to the app domain/path if they
    start with '/'.  For example:
       /                             -> domain.tld/app
       /admin                        -> domain.tld/app/admin
       domain.tld/app/api            -> domain.tld/app/api

    'url' can be later treated as a regex if it starts with "re:".
    For example:
       re:/api/[A-Z]*$               -> domain.tld/app/api/[A-Z]*$
       re:domain.tld/app/api/[A-Z]*$ -> domain.tld/app/api/[A-Z]*$
    """

    from yunohost.app import _is_installed, app_ssowatconf
    from yunohost.user import user_group_list

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    # Get random GID
    all_gid = {x.gr_gid for x in grp.getgrall()}

    uid_guid_found = False
    while not uid_guid_found:
        gid = str(random.randint(200, 99999))
        uid_guid_found = gid not in all_gid

    app, subperm = permission.split(".")

    if allowed is not None:
        if not isinstance(allowed, list):
            allowed = [allowed]

    # Validate that the groups to add actually exist
    all_existing_groups = user_group_list()["groups"].keys()
    for group in allowed or []:
        if group not in all_existing_groups:
            raise YunohostValidationError("group_unknown", group=group)

    assert _is_installed(
        app
    ), f"'{app}' is not a currently installed app, can not create perm {permission}"

    permission_url(
        permission,
        url=url,
        add_url=additional_urls,
        auth_header=auth_header,
        sync_perm=False,
    )

    _update_app_permission_setting(
        permission=permission,
        show_tile=show_tile,
        protected=protected,
        allowed=allowed or [],
    )

    if sync_perm:
        _sync_permissions_with_ldap()
        app_ssowatconf()

    logger.debug(m18n.n("permission_created", permission=permission))
    return user_permission_info(permission)


def permission_url(
    permission: str,
    url: str | None = None,
    add_url: list[str] | None = None,
    remove_url: list[str] | None = None,
    set_url: list[str] | None = None,
    auth_header: bool | None = None,
    clear_urls: bool = False,
    sync_perm: bool = True,
) -> PermInfos:
    """
    Update urls related to a permission for a specific application

    Keyword argument:
        permission  -- Name of the permission (e.g. mail or nextcloud or wordpress.editors)
        url         -- (optional) URL for which access will be allowed/forbidden.
        add_url     -- (optional) List of additional url to add for which access will be allowed/forbidden
        remove_url  -- (optional) List of additional url to remove for which access will be allowed/forbidden
        set_url     -- (optional) List of additional url to set/replace for which access will be allowed/forbidden
        auth_header -- (optional) Define for the URL of this permission, if SSOwat pass the authentication header to the application
        clear_urls  -- (optional) Clean all urls (url and additional_urls)
    """
    from yunohost.app import app_setting, app_ssowatconf

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    app, sub_permission = permission.split(".")

    if app in SYSTEM_PERMS:
        logger.warning(f"Cannot change urls / auth_header for system perm {permission}")

    if url or add_url:
        domain = app_setting(app, "domain")
        path = app_setting(app, "path")
        if domain is None or path is None:
            raise YunohostError("unknown_main_domain_path", app=app)
        else:
            app_main_path = domain + path

    # Fetch existing permission
    update_settings: AppPermInfos = {}  # type: ignore
    existing_permission = app_setting(app, "_permissions") or {}
    if sub_permission not in existing_permission:
        existing_permission[sub_permission] = {}
    existing_permission = existing_permission[sub_permission]

    if url is not None:

        url = _validate_and_sanitize_permission_url(url, app_main_path, app)
        update_settings["url"] = url
        assert url
        if url.startswith("re:") and existing_permission.get("show_tile"):
            logger.warning(
                m18n.n("regex_incompatible_with_tile", regex=url, permission=permission)
            )
            update_settings["show_tile"] = False

    current_additional_urls = existing_permission.get("additional_urls", [])
    new_additional_urls: list[str] = copy.copy(current_additional_urls)

    if add_url:
        for ur in add_url:
            if ur in current_additional_urls:
                logger.warning(
                    m18n.n(
                        "additional_urls_already_added", permission=permission, url=ur
                    )
                )
            else:
                ur = _validate_and_sanitize_permission_url(ur, app_main_path, app)
                new_additional_urls += [ur]

    if remove_url:
        for ur in remove_url:
            if ur not in current_additional_urls:
                logger.warning(
                    m18n.n(
                        "additional_urls_already_removed", permission=permission, url=ur
                    )
                )

        new_additional_urls = [u for u in new_additional_urls if u not in remove_url]

    if set_url:
        new_additional_urls = set_url

    # Guarantee uniqueness of all values, which would otherwise make ldap.update angry.
    update_settings["additional_urls"] = list(set(new_additional_urls))

    if auth_header is not None:
        update_settings["auth_header"] = auth_header

    if clear_urls:
        update_settings["url"] = None
        update_settings["additional_urls"] = []
        update_settings["show_tile"] = False

    # Actually commit the change
    try:
        perm_settings = app_setting(app, "_permissions") or {}
        if sub_permission not in perm_settings:
            perm_settings[sub_permission] = {}

        perm_settings[sub_permission].update(update_settings)
        app_setting(app, "_permissions", perm_settings)
    except Exception as e:
        raise YunohostError("permission_update_failed", permission=permission, error=e)

    if sync_perm:
        # In the past, this was a call to _sync_permissions_with_ldap but nowadays these changes dont impact ldap, only the ssowat conf
        app_ssowatconf()

    logger.debug(m18n.n("permission_updated", permission=permission))
    return user_permission_info(permission)


def permission_delete(
    permission: str, force: bool = False, sync_perm: bool = True
) -> None:
    from yunohost.app import app_setting, _assert_is_installed, app_ssowatconf

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    if permission.endswith(".main") and not force:
        raise YunohostValidationError("permission_cannot_remove_main")

    app, subperm = permission.split(".")

    if app in SYSTEM_PERMS:
        raise YunohostValidationError(f"Cannot delete system permission {permission}", raw_msg=True)

    _assert_is_installed(app)

    # Actually delete the permission
    perm_settings = app_setting(app, "_permissions") or {}
    if subperm in perm_settings:
        del perm_settings[subperm]
    app_setting(app, "_permissions", perm_settings)

    if sync_perm:
        _sync_permissions_with_ldap()
        app_ssowatconf()

    logger.debug(m18n.n("permission_deleted", permission=permission))


def _sync_permissions_with_ldap() -> None:
    """
    Sychronize the 'memberUid' / 'inheritPermission' attributes in the ldap permission object
    according to the group members and permission "allowed" info from app settings (from user_permission_list)
    """
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    permissions_wanted = {
        perm: set(infos["corresponding_users"])
        for perm, infos in user_permission_list(full=True)["permissions"].items()
    }
    permissions_current = {
        entry["cn"][0]: set(entry.get("memberUid", []))
        for entry in ldap.search(
            "ou=permission", "(objectclass=permissionYnh)", ["cn", "memberUid"]
        )
    }

    # Compute the todolist by comparing the current state vs. the wanted state for each perm

    todos: dict[str, dict[str, set[str]] | list[str]] = {
        "create": {},
        "delete": [],
        "update": {},
    }

    for perm in permissions_current.keys():
        if perm not in permissions_wanted:
            todos["delete"].append(perm)  # type: ignore
    for perm, members_wanted in permissions_wanted.items():
        if perm not in permissions_current:
            todos["create"][perm] = members_wanted
        elif members_wanted != permissions_current[perm]:
            todos["update"][perm] = members_wanted

    # Actually perform the delete / create / update operations

    for perm in todos["delete"]:
        logger.debug(f"Removing LDAP perm {perm}")
        try:
            ldap.remove(f"cn={perm},ou=permission")
        except Exception as e:
            raise YunohostError("permission_deletion_failed", permission=perm, error=e)

    all_gids = {str(x.gr_gid) for x in grp.getgrall()}
    for perm in todos["create"]:
        logger.debug(f"Creating LDAP perm {perm}")
        app = perm.split(".")[0]
        if app in SYSTEM_PERMS:
            gid = str(SYSTEM_PERMS[app]["gid"])
        else:
            while True:
                gid = str(random.randint(200, 99999))
                if gid not in all_gids:
                    break

        # Save the gid to the list of existing gid, to avoid picking the same gid twice in the unlikely case where we would be creating several perm at the same time
        all_gids.add(gid)

        attr_dict = {
            "objectClass": ["top", "permissionYnh", "posixGroup"],
            "cn": perm,
            "gidNumber": gid,
            # NB: the "inheritPermission" and "memberUid" info is redundant
            # but is needed because "memberUid" corresponds to the posixGroup object
            # whereas inheritPermission automatically creates the symetric link
            # from user to perm (cf the "permission" key on users)
            # (cf the olcOverlay={2}memberof )
            "inheritPermission": list(
                sorted(
                    f"uid={u},ou=users,dc=yunohost,dc=org"
                    for u in permissions_wanted[perm]
                )
            ),
            "memberUid": list(sorted(permissions_wanted[perm])),
        }
        try:
            ldap.add(f"cn={perm},ou=permission", attr_dict)
        except Exception as e:
            raise YunohostError("permission_creation_failed", permission=perm, error=e)
    for perm in todos["update"]:
        logger.debug(f"Updating LDAP perm {perm}")
        try:
            # Same note about redundant memberUid vs inheritPermission as before
            ldap.update(
                f"cn={perm},ou=permission",
                {
                    "inheritPermission": list(
                        sorted(
                            f"uid={u},ou=users,dc=yunohost,dc=org"
                            for u in permissions_wanted[perm]
                        )
                    ),
                    "memberUid": list(sorted(permissions_wanted[perm])),
                },
            )
        except Exception as e:
            raise YunohostError("permission_update_failed", permission=perm, error=e)

    logger.debug("Permissions were resynchronized to LDAP")

    # Reload/invalidate unscd cache to full propagate the changes
    os.system("nscd --invalidate=passwd")
    os.system("nscd --invalidate=group")


def _update_app_permission_setting(
    permission: str,
    label: str | None = None,
    show_tile: bool | None = None,
    protected: bool | None = None,
    allowed: str | list[str] | None = None,
    logo: BinaryIO | None = None,
    description: str | None = None,
    hide_from_public: bool | None = None,
    order: int | None = None,
) -> None:
    from yunohost.app import app_setting

    app, sub_permission = permission.split(".")
    update_settings: AppPermInfos = {}  # type: ignore
    perm_settings = app_setting(app, "_permissions") or {}
    if sub_permission not in perm_settings:
        perm_settings[sub_permission] = {}

    if label is not None:
        update_settings["label"] = str(label)

    if description is not None:
        update_settings["description"] = description

    if hide_from_public is not None:
        update_settings["hide_from_public"] = hide_from_public

    if order is not None:
        update_settings["order"] = order

    if logo is not None:

        from yunohost.app import APPS_CATALOG_LOGOS
        import hashlib

        logo_content = logo.read()
        if not logo_content.startswith(b"\x89PNG\r\n\x1a\n"):
            raise YunohostValidationError("The provided logo file doesn't seem to be a PNG file. Only PNG logos are supported.", raw_msg=True)

        logo_hash = hashlib.sha256(logo_content).hexdigest()
        with open(f"{APPS_CATALOG_LOGOS}/{logo_hash}.png", "wb") as f:
            f.write(logo_content)

        update_settings["logo_hash"] = logo_hash

    if protected is not None:
        update_settings["protected"] = protected

    if show_tile is not None:
        update_settings["show_tile"] = show_tile
        existing_permission_url = perm_settings[sub_permission].get("url")
        if show_tile is True:
            if not existing_permission_url:
                logger.warning(
                    m18n.n(
                        "show_tile_cant_be_enabled_for_url_not_defined",
                        permission=permission,
                    )
                )
                update_settings["show_tile"] = False
            elif existing_permission_url.startswith("re:"):
                logger.warning(
                    m18n.n("show_tile_cant_be_enabled_for_regex", permission=permission)
                )
                update_settings["show_tile"] = False

    if "label" in update_settings and sub_permission == "main":
        label = update_settings["label"]
        app_setting(app, "label", label)

    if allowed is not None:
        old_permission = user_permission_info(permission)
        assert isinstance(allowed, list) or isinstance(allowed, str)
        allowed = [allowed] if not isinstance(allowed, list) else allowed
        # Guarantee uniqueness of values in allowed, which would otherwise make ldap.update angry.
        allowed = list(set(allowed))
        update_settings["allowed"] = allowed

    # Actually update the settings
    perm_settings[sub_permission].update(update_settings)
    app_setting(app, "_permissions", perm_settings)

    # If we updated the allowed users
    if allowed is not None:
        # Trigger app callbacks
        new_permission = user_permission_info(permission)

        old_corresponding_users = set(old_permission["corresponding_users"])
        new_corresponding_users = set(new_permission["corresponding_users"])

        old_allowed_users = set(old_permission["allowed"])
        new_allowed_users = set(new_permission["allowed"])

        effectively_added_users = new_corresponding_users - old_corresponding_users
        effectively_removed_users = old_corresponding_users - new_corresponding_users

        effectively_added_group = (
            new_allowed_users - old_allowed_users - effectively_added_users
        )
        effectively_removed_group = (
            old_allowed_users - new_allowed_users - effectively_removed_users
        )

        from yunohost.hook import hook_callback

        if effectively_added_users or effectively_added_group:
            hook_callback(
                "post_app_addaccess",
                args=[
                    app,
                    ",".join(effectively_added_users),
                    sub_permission,
                    ",".join(effectively_added_group),
                ],
            )
        if effectively_removed_users or effectively_removed_group:
            hook_callback(
                "post_app_removeaccess",
                args=[
                    app,
                    ",".join(effectively_removed_users),
                    sub_permission,
                    ",".join(effectively_removed_group),
                ],
            )


def _get_system_perms() -> dict[str, SystemPermInfos]:
    try:
        system_perm_conf = read_yaml(SYSTEM_PERM_CONF) or {}
        assert isinstance(
            system_perm_conf, dict
        ), "Uhoh, the system perm conf read is not a dict ?!"
    except Exception as e:
        logger.warning(f"Failed to read system perm configuration ? : {e}")
        system_perm_conf = {}

    for p, infos in system_perm_conf.items():
        if p not in SYSTEM_PERMS.keys():
            logger.warning("Ignoring unexpected key '{p}' in system perm conf")
            del system_perm_conf[p]
        if "allowed" not in infos:
            infos["allowed"] = []

    # Try to have a failsafe to keep admins allowed for ssh access and mail
    # when the conf is broken for some reason...
    if "ssh" not in system_perm_conf:
        system_perm_conf["ssh"] = {"allowed": ["admins"]}
    if "mail" not in system_perm_conf:
        system_perm_conf["mail"] = {"allowed": ["admins"]}
    if "sftp" not in system_perm_conf:
        system_perm_conf["sftp"] = {"allowed": []}

    for p, infos in system_perm_conf.items():
        infos["label"] = SYSTEM_PERMS[p]["label"]

    return system_perm_conf


def _set_system_perms(system_perm_conf: dict[str, SystemPermInfos]) -> None:

    # We actually only write the 'allowed' groups info
    conf_to_write = {
        p: {"allowed": infos["allowed"]} for p, infos in system_perm_conf.items()
    }

    try:
        write_to_yaml(SYSTEM_PERM_CONF, conf_to_write)
    except Exception as e:
        raise YunohostError(
            f"Failed to write system perm configuration ? : {e}", raw_msg=True
        )


def _get_absolute_url(url: str, base_path: str) -> str:
    """
    For example transform:
       (/,    domain.tld/)                  into  domain.tld (no trailing /)
       (/api, domain.tld/nextcloud)         into  domain.tld/nextcloud/api
       (/api, domain.tld/nextcloud/)        into  domain.tld/nextcloud/api
       (re:/foo.*, domain.tld/app)          into  re:domain\\.tld/app/foo.*
       (domain.tld/bar, domain.tld/app)     into  domain.tld/bar
       (some.other.domain/, domain.tld/app) into  some.other.domain (no trailing /)
    """
    base_path = base_path.rstrip("/")
    if url.startswith("/"):
        return base_path + url.rstrip("/")
    if url.startswith("re:/"):
        return "re:" + base_path.replace(".", "\\.") + url[3:]
    else:
        return url.rstrip("/")


def _validate_and_sanitize_permission_url(
    url: str, app_base_path: str, app: str
) -> str:
    """
    Check and normalize the urls passed for all permissions
    Also check that the Regex is valid

    As documented in the 'ynh_permission_create' helper:

    If provided, 'url' is assumed to be relative to the app domain/path if they
    start with '/'.  For example:
       /                             -> domain.tld/app
       /admin                        -> domain.tld/app/admin
       domain.tld/app/api            -> domain.tld/app/api
       domain.tld                    -> domain.tld

    'url' can be later treated as a regex if it starts with "re:".
    For example:
       re:/api/[A-Z]*$               -> domain.tld/app/api/[A-Z]*$
       re:domain.tld/app/api/[A-Z]*$ -> domain.tld/app/api/[A-Z]*$

    We can also have less-trivial regexes like:
        re:^/api/.*|/scripts/api.js$
    """

    from yunohost.app import _assert_no_conflicting_apps
    from yunohost.domain import _assert_domain_exists

    #
    # Regexes
    #

    def validate_regex(regex):
        if "%" in regex:
            logger.warning(
                "/!\\ Packagers! You are probably using a lua regex. You should use a PCRE regex instead."
            )
            return

        try:
            re.compile(regex)
        except Exception:
            raise YunohostValidationError("invalid_regex", regex=regex)

    if url.startswith("re:"):
        # regex without domain
        # we check for the first char after 're:'
        if url[3] in ["/", "^", "\\"]:
            validate_regex(url[3:])
            return url

        # regex with domain

        if "/" not in url:
            raise YunohostValidationError("regex_with_only_domain")
        domain, path = url[3:].split("/", 1)
        path = "/" + path

        domain_with_no_regex = domain.replace("%", "").replace("\\", "")
        _assert_domain_exists(domain_with_no_regex)

        validate_regex(path)

        return "re:" + domain + path

    #
    # "Regular" URIs
    #

    def split_domain_path(url: str) -> tuple[str, str]:
        url = url.strip("/")
        (domain, path) = url.split("/", 1) if "/" in url else (url, "/")
        if path != "/":
            path = "/" + path
        return (domain, path)

    # uris without domain
    if url.startswith("/"):
        # if url is for example /admin/
        # we want sanitized_url to be: /admin
        # and (domain, path) to be   : (domain.tld, /app/admin)
        sanitized_url = "/" + url.strip("/")
        domain, path = split_domain_path(app_base_path)
        path = "/" + path.strip("/") + sanitized_url

    # uris with domain
    else:
        # if url is for example domain.tld/wat/
        # we want sanitized_url to be: domain.tld/wat
        # and (domain, path) to be   : (domain.tld, /wat)
        domain, path = split_domain_path(url)
        sanitized_url = domain + path

        _assert_domain_exists(domain)

    _assert_no_conflicting_apps(domain, path, ignore_app=app)

    return sanitized_url
