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
from logging import getLogger

from moulinette import m18n

from yunohost.log import is_unit_operation
from yunohost.utils.error import YunohostError, YunohostValidationError

logger = getLogger("yunohost.user")

SYSTEM_PERMS = ["mail", "sftp", "ssh"]

#
#
#  The followings are the methods exposed through the "yunohost user permission" interface
#
#


def user_permission_list(
    short=False, full=False, ignore_system_perms=False, absolute_urls=False, apps=[]
):
    """
    List permissions and corresponding accesses
    """

    # Fetch relevant informations
    from yunohost.app import _installed_apps, app_setting
    from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract

    ldap = _get_ldap_interface()
    permissions_infos = ldap.search(
        "ou=permission",
        "(objectclass=permissionYnh)",
        [
            "cn",
            "groupPermission",
            "inheritPermission",
            "URL",
            "additionalUrls",
            "authHeader",
            "label",
            "showTile",
            "isProtected",
        ],
    )

    # Parse / organize information to be outputed
    installed_apps = sorted(_installed_apps())
    filter_ = apps
    apps = filter_ if filter_ else installed_apps
    apps_base_path = {
        app: app_setting(app, "domain") + app_setting(app, "path")
        for app in apps
        if app in installed_apps
        and app_setting(app, "domain")
        and app_setting(app, "path")
    }

    permissions = {}
    for infos in permissions_infos:
        name = infos["cn"][0]
        app = name.split(".")[0]

        if ignore_system_perms and app in SYSTEM_PERMS:
            continue
        if filter_ and app not in apps:
            continue

        perm = {}
        perm["allowed"] = [
            _ldap_path_extract(p, "cn") for p in infos.get("groupPermission", [])
        ]

        if full:
            perm["corresponding_users"] = [
                _ldap_path_extract(p, "uid") for p in infos.get("inheritPermission", [])
            ]
            perm["auth_header"] = infos.get("authHeader", [False])[0] == "TRUE"
            perm["label"] = infos.get("label", [None])[0]
            perm["show_tile"] = infos.get("showTile", [False])[0] == "TRUE"
            perm["protected"] = infos.get("isProtected", [False])[0] == "TRUE"
            perm["url"] = infos.get("URL", [None])[0]
            perm["additional_urls"] = infos.get("additionalUrls", [])

            if absolute_urls:
                app_base_path = (
                    apps_base_path[app] if app in apps_base_path else ""
                )  # Meh in some situation where the app is currently installed/removed, this function may be called and we still need to act as if the corresponding permission indeed exists ... dunno if that's really the right way to proceed but okay.
                perm["url"] = _get_absolute_url(perm["url"], app_base_path)
                perm["additional_urls"] = [
                    _get_absolute_url(url, app_base_path)
                    for url in perm["additional_urls"]
                ]

        permissions[name] = perm

    # Make sure labels for sub-permissions are the form " Applabel (Sublabel) "
    if full:
        subpermissions = {
            k: v for k, v in permissions.items() if not k.endswith(".main")
        }
        for name, infos in subpermissions.items():
            main_perm_name = name.split(".")[0] + ".main"
            if main_perm_name not in permissions:
                logger.debug(
                    f"Uhoh, unknown permission {main_perm_name} ? (Maybe we're in the process or deleting the perm for this app...)"
                )
                continue
            main_perm_label = permissions[main_perm_name]["label"]
            infos["sublabel"] = infos["label"]
            label_ = infos["label"]
            infos["label"] = f"{main_perm_label} ({label_})"

    if short:
        permissions = list(permissions.keys())

    return {"permissions": permissions}


@is_unit_operation()
def user_permission_update(
    operation_logger,
    permission,
    add=None,
    remove=None,
    label=None,
    show_tile=None,
    protected=None,
    force=False,
    sync_perm=True,
):
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

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    existing_permission = user_permission_info(permission)

    # Refuse to add "visitors" to mail ... they require an account to make sense.
    if add and "visitors" in add and permission.split(".")[0] in SYSTEM_PERMS:
        raise YunohostValidationError(
            "permission_require_account", permission=permission
        )

    # Refuse to add "visitors" to protected permission
    if (
        (add and "visitors" in add and existing_permission["protected"])
        or (remove and "visitors" in remove and existing_permission["protected"])
    ) and not force:
        raise YunohostValidationError("permission_protected", permission=permission)

    # Refuse to add "all_users" to ssh/sftp permissions
    if (
        permission.split(".")[0] in ["ssh", "sftp"]
        and (add and "all_users" in add)
        and not force
    ):
        raise YunohostValidationError(
            "permission_cant_add_to_all_users", permission=permission
        )

    # Fetch currently allowed groups for this permission

    current_allowed_groups = existing_permission["allowed"]
    operation_logger.related_to.append(("app", permission.split(".")[0]))

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
                operation_logger.related_to.append(("group", group))
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
            else:
                operation_logger.related_to.append(("group", group))

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

    # Note that we can get this argument as string if we it come from the CLI
    if isinstance(show_tile, str):
        if show_tile.lower() == "true":
            show_tile = True
        else:
            show_tile = False

    if (
        existing_permission["url"]
        and existing_permission["url"].startswith("re:")
        and show_tile
    ):
        logger.warning(
            m18n.n(
                "regex_incompatible_with_tile",
                regex=existing_permission["url"],
                permission=permission,
            )
        )

    # Commit the new allowed group list
    operation_logger.start()

    new_permission = _update_ldap_group_permission(
        permission=permission,
        allowed=new_allowed_groups,
        label=label,
        show_tile=show_tile,
        protected=protected,
        sync_perm=sync_perm,
    )

    logger.debug(m18n.n("permission_updated", permission=permission))

    return new_permission


@is_unit_operation()
def user_permission_reset(operation_logger, permission, sync_perm=True):
    """
    Reset a given permission to just 'all_users'

    Keyword argument:
        permission -- Name of the permission (e.g. mail or nextcloud or wordpress.editors)
    """

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    # Fetch existing permission

    existing_permission = user_permission_info(permission)

    if existing_permission["allowed"] == ["all_users"]:
        logger.warning(m18n.n("permission_already_up_to_date"))
        return

    # Update permission with default (all_users)

    operation_logger.related_to.append(("app", permission.split(".")[0]))
    operation_logger.start()

    new_permission = _update_ldap_group_permission(
        permission=permission, allowed="all_users", sync_perm=sync_perm
    )

    logger.debug(m18n.n("permission_updated", permission=permission))

    return new_permission


def user_permission_info(permission):
    """
    Return informations about a specific permission

    Keyword argument:
        permission -- Name of the permission (e.g. mail or nextcloud or wordpress.editors)
    """

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    # Fetch existing permission

    existing_permission = user_permission_list(full=True)["permissions"].get(
        permission, None
    )
    if existing_permission is None:
        raise YunohostValidationError("permission_not_found", permission=permission)

    return existing_permission


#
#
#  The followings methods are *not* directly exposed.
#  They are used to create/delete the permissions (e.g. during app install/remove)
#  and by some app helpers to possibly add additional permissions
#
#


@is_unit_operation()
def permission_create(
    operation_logger,
    permission,
    allowed=None,
    url=None,
    additional_urls=None,
    auth_header=True,
    label=None,
    show_tile=False,
    protected=False,
    sync_perm=True,
):
    """
    Create a new permission for a specific application

    Keyword argument:
        permission      -- Name of the permission (e.g. mail or nextcloud or wordpress.editors)
        allowed         -- (optional) List of group/user to allow for the permission
        url             -- (optional) URL for which access will be allowed/forbidden
        additional_urls -- (optional) List of additional URL for which access will be allowed/forbidden
        auth_header     -- (optional) Define for the URL of this permission, if SSOwat pass the authentication header to the application
        label           -- (optional) Define a name for the permission. This label will be shown on the SSO and in the admin. Default is "permission name"
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

    from yunohost.user import user_group_list
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    # Validate uniqueness of permission in LDAP
    if ldap.get_conflict({"cn": permission}, base_dn="ou=permission"):
        raise YunohostValidationError("permission_already_exist", permission=permission)

    # Get random GID
    all_gid = {x.gr_gid for x in grp.getgrall()}

    uid_guid_found = False
    while not uid_guid_found:
        gid = str(random.randint(200, 99999))
        uid_guid_found = gid not in all_gid

    app, subperm = permission.split(".")

    attr_dict = {
        "objectClass": ["top", "permissionYnh", "posixGroup"],
        "cn": str(permission),
        "gidNumber": gid,
        "authHeader": ["TRUE"],
        "label": [
            str(label) if label else (subperm if subperm != "main" else app.title())
        ],
        "showTile": [
            "FALSE"
        ],  # Dummy value, it will be fixed when we call '_update_ldap_group_permission'
        "isProtected": [
            "FALSE"
        ],  # Dummy value, it will be fixed when we call '_update_ldap_group_permission'
    }

    if allowed is not None:
        if not isinstance(allowed, list):
            allowed = [allowed]

    # Validate that the groups to add actually exist
    all_existing_groups = user_group_list()["groups"].keys()
    for group in allowed or []:
        if group not in all_existing_groups:
            raise YunohostValidationError("group_unknown", group=group)

    operation_logger.related_to.append(("app", permission.split(".")[0]))
    operation_logger.start()

    try:
        ldap.add(f"cn={permission},ou=permission", attr_dict)
    except Exception as e:
        raise YunohostError(
            "permission_creation_failed", permission=permission, error=e
        )

    try:
        permission_url(
            permission,
            url=url,
            add_url=additional_urls,
            auth_header=auth_header,
            sync_perm=False,
        )

        new_permission = _update_ldap_group_permission(
            permission=permission,
            allowed=allowed,
            label=label,
            show_tile=show_tile,
            protected=protected,
            sync_perm=sync_perm,
        )
    except Exception:
        permission_delete(permission, force=True)
        raise

    logger.debug(m18n.n("permission_created", permission=permission))
    return new_permission


@is_unit_operation()
def permission_url(
    operation_logger,
    permission,
    url=None,
    add_url=None,
    remove_url=None,
    set_url=None,
    auth_header=None,
    clear_urls=False,
    sync_perm=True,
):
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
    from yunohost.app import app_setting
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    app = permission.split(".")[0]

    if url or add_url:
        domain = app_setting(app, "domain")
        path = app_setting(app, "path")
        if domain is None or path is None:
            raise YunohostError("unknown_main_domain_path", app=app)
        else:
            app_main_path = domain + path

    # Fetch existing permission

    existing_permission = user_permission_info(permission)

    show_tile = existing_permission["show_tile"]

    if url is None:
        url = existing_permission["url"]
    else:
        url = _validate_and_sanitize_permission_url(url, app_main_path, app)

        if url.startswith("re:") and existing_permission["show_tile"]:
            logger.warning(
                m18n.n("regex_incompatible_with_tile", regex=url, permission=permission)
            )
            show_tile = False

    current_additional_urls = existing_permission["additional_urls"]
    new_additional_urls = copy.copy(current_additional_urls)

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

    if auth_header is None:
        auth_header = existing_permission["auth_header"]

    if clear_urls:
        url = None
        new_additional_urls = []
        show_tile = False

    # Guarantee uniqueness of all values, which would otherwise make ldap.update angry.
    new_additional_urls = set(new_additional_urls)

    # Actually commit the change

    operation_logger.related_to.append(("app", permission.split(".")[0]))
    operation_logger.start()

    try:
        ldap.update(
            f"cn={permission},ou=permission",
            {
                "URL": url if url is not None else set(),
                "additionalUrls": new_additional_urls,
                "authHeader": str(auth_header).upper(),
                "showTile": str(show_tile).upper(),
            },
        )
    except Exception as e:
        raise YunohostError("permission_update_failed", permission=permission, error=e)

    if sync_perm:
        permission_sync_to_user()

    logger.debug(m18n.n("permission_updated", permission=permission))
    return user_permission_info(permission)


@is_unit_operation()
def permission_delete(operation_logger, permission, force=False, sync_perm=True):
    """
    Delete a permission

    Keyword argument:
        permission -- Name of the permission (e.g. mail or nextcloud or wordpress.editors)
    """

    # By default, manipulate main permission
    if "." not in permission:
        permission = permission + ".main"

    if permission.endswith(".main") and not force:
        raise YunohostValidationError("permission_cannot_remove_main")

    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    # Make sure this permission exists

    _ = user_permission_info(permission)

    # Actually delete the permission

    operation_logger.related_to.append(("app", permission.split(".")[0]))
    operation_logger.start()

    try:
        ldap.remove(f"cn={permission},ou=permission")
    except Exception as e:
        raise YunohostError(
            "permission_deletion_failed", permission=permission, error=e
        )

    if sync_perm:
        permission_sync_to_user()
    logger.debug(m18n.n("permission_deleted", permission=permission))


def permission_sync_to_user():
    """
    Sychronise the inheritPermission attribut in the permission object from the
    user<->group link and the group<->permission link
    """
    import os

    from yunohost.app import app_ssowatconf
    from yunohost.user import user_group_list
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    groups = user_group_list(full=True)["groups"]
    permissions = user_permission_list(full=True)["permissions"]

    for permission_name, permission_infos in permissions.items():
        # These are the users currently allowed because there's an 'inheritPermission' object corresponding to it
        currently_allowed_users = set(permission_infos["corresponding_users"])

        # These are the users that should be allowed because they are member of a group that is allowed for this permission ...
        should_be_allowed_users = {
            user
            for group in permission_infos["allowed"]
            for user in groups[group]["members"]
        }

        # Note that a LDAP operation with the same value that is in LDAP crash SLAP.
        # So we need to check before each ldap operation that we really change something in LDAP
        if currently_allowed_users == should_be_allowed_users:
            # We're all good, this permission is already correctly synchronized !
            continue

        new_inherited_perms = {
            "inheritPermission": {
                f"uid={u},ou=users,dc=yunohost,dc=org" for u in should_be_allowed_users
            },
            "memberUid": should_be_allowed_users,
        }

        # Commit the change with the new inherited stuff
        try:
            ldap.update(f"cn={permission_name},ou=permission", new_inherited_perms)
        except Exception as e:
            raise YunohostError(
                "permission_update_failed", permission=permission_name, error=e
            )

    logger.debug("The permission database has been resynchronized")

    app_ssowatconf()

    # Reload unscd, otherwise the group ain't propagated to the LDAP database
    os.system("nscd --invalidate=passwd")
    os.system("nscd --invalidate=group")


def _update_ldap_group_permission(
    permission, allowed, label=None, show_tile=None, protected=None, sync_perm=True
):
    """
    Internal function that will rewrite user permission

    permission      -- Name of the permission (e.g. mail or nextcloud or wordpress.editors)
    allowed         -- (optional) A list of group/user to allow for the permission
    label           -- (optional) Define a name for the permission. This label will be shown on the SSO and in the admin
    show_tile       -- (optional) Define if a tile will be shown in the SSO
    protected       -- (optional) Define if the permission can be added/removed to the visitor group


    Assumptions made, that should be checked before calling this function:
    - the permission does currently exists ...
    - the 'allowed' list argument is *different* from the current
      permission state ... otherwise ldap will miserably fail in such
      case...
    - the 'allowed' list contains *existing* groups.
    """

    from yunohost.hook import hook_callback
    from yunohost.utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    existing_permission = user_permission_info(permission)

    update = {}

    if allowed is not None:
        allowed = [allowed] if not isinstance(allowed, list) else allowed
        # Guarantee uniqueness of values in allowed, which would otherwise make ldap.update angry.
        allowed = set(allowed)
        update["groupPermission"] = {
            "cn=" + g + ",ou=groups,dc=yunohost,dc=org" for g in allowed
        }

    if label is not None:
        update["label"] = str(label)

    if protected is not None:
        update["isProtected"] = str(protected).upper()

    if show_tile is not None:
        if show_tile is True:
            if not existing_permission["url"]:
                logger.warning(
                    m18n.n(
                        "show_tile_cant_be_enabled_for_url_not_defined",
                        permission=permission,
                    )
                )
                show_tile = False
            elif existing_permission["url"].startswith("re:"):
                logger.warning(
                    m18n.n("show_tile_cant_be_enabled_for_regex", permission=permission)
                )
                show_tile = False
        update["showTile"] = str(show_tile).upper()

    try:
        ldap.update(f"cn={permission},ou=permission", update)
    except Exception as e:
        raise YunohostError("permission_update_failed", permission=permission, error=e)

    # Trigger permission sync if asked

    if sync_perm:
        permission_sync_to_user()

    new_permission = user_permission_info(permission)

    # Trigger app callbacks

    app = permission.split(".")[0]
    sub_permission = permission.split(".")[1]

    old_corresponding_users = set(existing_permission["corresponding_users"])
    new_corresponding_users = set(new_permission["corresponding_users"])

    old_allowed_users = set(existing_permission["allowed"])
    new_allowed_users = set(new_permission["allowed"])

    effectively_added_users = new_corresponding_users - old_corresponding_users
    effectively_removed_users = old_corresponding_users - new_corresponding_users

    effectively_added_group = (
        new_allowed_users - old_allowed_users - effectively_added_users
    )
    effectively_removed_group = (
        old_allowed_users - new_allowed_users - effectively_removed_users
    )

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

    return new_permission


def _get_absolute_url(url, base_path):
    #
    # For example transform:
    #    (/,    domain.tld/)                  into  domain.tld (no trailing /)
    #    (/api, domain.tld/nextcloud)         into  domain.tld/nextcloud/api
    #    (/api, domain.tld/nextcloud/)        into  domain.tld/nextcloud/api
    #    (re:/foo.*, domain.tld/app)          into  re:domain\.tld/app/foo.*
    #    (domain.tld/bar, domain.tld/app)     into  domain.tld/bar
    #    (some.other.domain/, domain.tld/app) into  some.other.domain (no trailing /)
    #
    base_path = base_path.rstrip("/")
    if url is None:
        return None
    if url.startswith("/"):
        return base_path + url.rstrip("/")
    if url.startswith("re:/"):
        return "re:" + base_path.replace(".", "\\.") + url[3:]
    else:
        return url.rstrip("/")


def _validate_and_sanitize_permission_url(url, app_base_path, app):
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

    def split_domain_path(url):
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
