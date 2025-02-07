import os
from logging import getLogger

from moulinette.utils.filesystem import read_yaml
from yunohost.utils.ldap import _get_ldap_interface, _ldap_path_extract
from yunohost.tools import Migration
from yunohost.regenconf import regen_conf
from yunohost.permission import _sync_permissions_with_ldap, _set_system_perms, permission_create
from yunohost.app import app_setting, app_ssowatconf
from yunohost.user import user_group_list


logger = getLogger("yunohost.migration")

SYSTEM_PERMS = ["mail", "sftp", "ssh"]


class MyMigration(Migration):

    introduced_in_version = "12.1"
    dependencies = []

    ldap_migration_started = False

    @Migration.ldap_migration
    def run(self, *args):

        regen_conf(["slapd"], force=True)

        self.ldap_migration_started = True

        permissions_per_app, permission_system = self.read_legacy_permissions()
        for app, permissions in permissions_per_app.items():
            app_setting(app, "_permissions", permissions)

        _set_system_perms(permission_system)

        self.delete_legacy_permissions()
        _sync_permissions_with_ldap()

    def run_after_system_restore(self):

        _, permission_system = self.read_legacy_permissions()
        _set_system_perms(permission_system)

        self.delete_legacy_permissions()
        _sync_permissions_with_ldap()

    def run_before_app_restore(self, app_id):

        # Prior to 12.1, the truth source for app permission was the LDAP db rather than app settings.
        # The LDAP db corresponding to the app was dump into a separate yaml
        permfile = f"/etc/yunohost/apps/{app_id}/permissions.yml"
        if not os.path.isfile(permfile):
            logger.warning("Uhoh, this app backup is from yunohost <= 12.0, but there is no 'permissions.yml' ? Skipping perm restoration … You might have to reconfigure permissions yourself.")
            return

        legacy_permissions_yml = read_yaml(permfile)

        existing_groups = user_group_list()["groups"]

        for permission_name, permission_infos in legacy_permissions_yml.items():
            if "allowed" not in permission_infos:
                logger.warning(
                    f"'allowed' key corresponding to allowed groups for permission {permission_name} not found when restoring app {app_id} … You might have to reconfigure permissions yourself."
                )
                should_be_allowed = ["all_users"]
            else:
                should_be_allowed = [
                    g for g in permission_infos["allowed"] if g in existing_groups
                ]

            permission_create(
                permission_name,
                allowed=should_be_allowed,
                url=permission_infos.get("url"),
                additional_urls=permission_infos.get("additional_urls"),
                auth_header=permission_infos.get("auth_header"),
                show_tile=permission_infos.get("show_tile", True),
                protected=permission_infos.get("protected", False),
                sync_perm=False,
            )

        os.remove(permfile)

        _sync_permissions_with_ldap()
        app_ssowatconf()

    def read_legacy_permissions(self):

        ldap = _get_ldap_interface()
        permissions_infos = ldap.search(
            "ou=permission",
            "(objectclass=permissionYnh)",
            [
                "cn",
                "URL",
                "additionalUrls",
                "authHeader",
                "label",
                "showTile",
                "isProtected",
                "groupPermission",
            ],
        )

        permissions_per_app = {}
        permissions_system = {p: {"allowed": []} for p in SYSTEM_PERMS}

        for infos in permissions_infos:
            app, name = infos["cn"][0].split(".")

            if app in SYSTEM_PERMS:
                if name == "main":
                    permissions_system[app]["allowed"] = [_ldap_path_extract(p, "cn") for p in infos.get("groupPermission", [])]
                continue

            if app not in permissions_per_app:
                permissions_per_app[app] = {}

            permissions_per_app[app][name] = {
                "label": infos.get("label", [None])[0],
                "show_tile": infos.get("showTile", [False])[0] == "TRUE",
                "auth_header": infos.get("authHeader", [False])[0] == "TRUE",
                "protected": infos.get("isProtected", [False])[0] == "TRUE",
                "url": infos.get("URL", [None])[0],
                "additional_urls": infos.get("additionalUrls", []),
                "allowed": [_ldap_path_extract(p, "cn") for p in infos.get("groupPermission", [])],
            }

        return permissions_per_app, permissions_system

    def delete_legacy_permissions(self):

        ldap = _get_ldap_interface()
        permissions_infos = ldap.search(
            "ou=permission",
            "(objectclass=permissionYnh)",
            ["cn"],
        )
        for infos in permissions_infos:
            # LDAP won't delete the old, obsolete info,
            # we have to do it ourselves ~_~
            ldap.update(
                f'cn={infos["cn"][0]},ou=permission',
                {
                    "label": [],
                    "authHeader": [],
                    "showTile": [],
                    "isProtected": [],
                    "URL": [],
                    "additionalUrls": [],
                    "groupPermission": [],
                },
            )
