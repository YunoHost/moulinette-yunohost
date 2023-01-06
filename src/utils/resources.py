#
# Copyright (c) 2022 YunoHost Contributors
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
import os
import copy
import shutil
import random
from typing import Dict, Any, List

from moulinette import m18n
from moulinette.utils.process import check_output
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import mkdir, chown, chmod, write_to_file
from moulinette.utils.filesystem import (
    rm,
)

from yunohost.utils.error import YunohostError, YunohostValidationError

logger = getActionLogger("yunohost.app_resources")


class AppResourceManager:
    def __init__(self, app: str, current: Dict, wanted: Dict):

        self.app = app
        self.current = current
        self.wanted = wanted

        if "resources" not in self.current:
            self.current["resources"] = {}
        if "resources" not in self.wanted:
            self.wanted["resources"] = {}

    def apply(
        self, rollback_and_raise_exception_if_failure, operation_logger=None, **context
    ):

        todos = list(self.compute_todos())
        completed = []
        rollback = False
        exception = None

        for todo, name, old, new in todos:
            try:
                if todo == "deprovision":
                    # FIXME : i18n, better info strings
                    logger.info(f"Deprovisionning {name} ...")
                    old.deprovision(context=context)
                elif todo == "provision":
                    logger.info(f"Provisionning {name} ...")
                    new.provision_or_update(context=context)
                elif todo == "update":
                    logger.info(f"Updating {name} ...")
                    new.provision_or_update(context=context)
            except (KeyboardInterrupt, Exception) as e:
                exception = e
                if isinstance(e, KeyboardInterrupt):
                    logger.error(m18n.n("operation_interrupted"))
                else:
                    logger.warning(f"Failed to {todo} {name} : {e}")
                if rollback_and_raise_exception_if_failure:
                    rollback = True
                    completed.append((todo, name, old, new))
                    break
                else:
                    pass
            else:
                completed.append((todo, name, old, new))

        if rollback:
            for todo, name, old, new in completed:
                try:
                    # (NB. here we want to undo the todo)
                    if todo == "deprovision":
                        # FIXME : i18n, better info strings
                        logger.info(f"Reprovisionning {name} ...")
                        old.provision_or_update(context=context)
                    elif todo == "provision":
                        logger.info(f"Deprovisionning {name} ...")
                        new.deprovision(context=context)
                    elif todo == "update":
                        logger.info(f"Reverting {name} ...")
                        old.provision_or_update(context=context)
                except (KeyboardInterrupt, Exception) as e:
                    if isinstance(e, KeyboardInterrupt):
                        logger.error(m18n.n("operation_interrupted"))
                    else:
                        logger.error(f"Failed to rollback {name} : {e}")

        if exception:
            if rollback_and_raise_exception_if_failure:
                logger.error(
                    m18n.n("app_resource_failed", app=self.app, error=exception)
                )
                if operation_logger:
                    failure_message_with_debug_instructions = operation_logger.error(
                        str(exception)
                    )
                    raise YunohostError(
                        failure_message_with_debug_instructions, raw_msg=True
                    )
                else:
                    raise YunohostError(str(exception), raw_msg=True)
            else:
                logger.error(exception)

    def compute_todos(self):

        for name, infos in reversed(self.current["resources"].items()):
            if name not in self.wanted["resources"].keys():
                resource = AppResourceClassesByType[name](infos, self.app, self)
                yield ("deprovision", name, resource, None)

        for name, infos in self.wanted["resources"].items():
            wanted_resource = AppResourceClassesByType[name](infos, self.app, self)
            if name not in self.current["resources"].keys():
                yield ("provision", name, None, wanted_resource)
            else:
                infos_ = self.current["resources"][name]
                current_resource = AppResourceClassesByType[name](
                    infos_, self.app, self
                )
                yield ("update", name, current_resource, wanted_resource)


class AppResource:

    type: str = ""
    default_properties: Dict[str, Any] = {}

    def __init__(self, properties: Dict[str, Any], app: str, manager=None):

        self.app = app
        self.manager = manager

        for key, value in self.default_properties.items():
            if isinstance(value, str):
                value = value.replace("__APP__", self.app)
            setattr(self, key, value)

        for key, value in properties.items():
            if isinstance(value, str):
                value = value.replace("__APP__", self.app)
            setattr(self, key, value)

    def get_setting(self, key):
        from yunohost.app import app_setting

        return app_setting(self.app, key)

    def set_setting(self, key, value):
        from yunohost.app import app_setting

        app_setting(self.app, key, value=value)

    def delete_setting(self, key):
        from yunohost.app import app_setting

        app_setting(self.app, key, delete=True)

    def _run_script(self, action, script, env={}, user="root"):

        from yunohost.app import (
            _make_tmp_workdir_for_app,
            _make_environment_for_app_script,
        )
        from yunohost.hook import hook_exec_with_script_debug_if_failure

        tmpdir = _make_tmp_workdir_for_app(app=self.app)

        env_ = _make_environment_for_app_script(
            self.app, workdir=tmpdir, action=f"{action}_{self.type}"
        )
        env_.update(env)

        script_path = f"{tmpdir}/{action}_{self.type}"
        script = f"""
source /usr/share/yunohost/helpers
ynh_abort_if_errors

{script}
"""

        write_to_file(script_path, script)

        from yunohost.log import OperationLogger

        if OperationLogger._instances:
            # FIXME ? : this is an ugly hack :(
            operation_logger = OperationLogger._instances[-1]
        else:
            operation_logger = OperationLogger(
                "resource_snippet", [("app", self.app)], env=env_
            )
            operation_logger.start()

        try:
            (
                call_failed,
                failure_message_with_debug_instructions,
            ) = hook_exec_with_script_debug_if_failure(
                script_path,
                env=env_,
                operation_logger=operation_logger,
                error_message_if_script_failed="An error occured inside the script snippet",
                error_message_if_failed=lambda e: f"{action} failed for {self.type} : {e}",
            )
        finally:
            if call_failed:
                raise YunohostError(
                    failure_message_with_debug_instructions, raw_msg=True
                )
            else:
                # FIXME: currently in app install code, we have
                # more sophisticated code checking if this broke something on the system etc ...
                # dunno if we want to do this here or manage it elsewhere
                pass

        # print(ret)


class PermissionsResource(AppResource):
    """
    Configure the SSO permissions/tiles. Typically, webapps are expected to have a 'main' permission mapped to '/', meaning that a tile pointing to the `$domain/$path` will be available in the SSO for users allowed to access that app.

    Additional permissions can be created, typically to have a specific tile and/or access rules for the admin part of a webapp.

    The list of allowed user/groups may be initialized using the content of the `init_{perm}_permission` question from the manifest, hence `init_main_permission` replaces the `is_public` question and shall contain a group name (typically, `all_users` or `visitors`).

    ##### Example:
    ```toml
    [resources.permissions]
    main.url = "/"
    # (these two previous lines should be enough in the majority of cases)

    admin.url = "/admin"
    admin.show_tile = false
    admin.allowed = "admins"   # Assuming the "admins" group exists (cf future developments ;))
    ```

    ##### Properties (for each perm name):
    - `url`: The relative URI corresponding to this permission. Typically `/` or `/something`. This property may be omitted for non-web permissions.
    - `show_tile`: (default: `true` if `url` is defined) Wether or not a tile should be displayed for that permission in the user portal
    - `allowed`: (default: nobody) The group initially allowed to access this perm, if `init_{perm}_permission` is not defined in the manifest questions. Note that the admin may tweak who is allowed/unallowed on that permission later on, this is only meant to **initialize** the permission.
    - `auth_header`: (default: `true`) Define for the URL of this permission, if SSOwat pass the authentication header to the application. Default is true
    - `protected`: (default: `false`) Define if this permission is protected. If it is protected the administrator won't be able to add or remove the visitors group of this permission. Defaults to 'false'.
    - `additional_urls`: (default: none) List of additional URL for which access will be allowed/forbidden

    ##### Provision/Update:
    - Delete any permissions that may exist and be related to this app yet is not declared anymore
    - Loop over the declared permissions and create them if needed or update them with the new values

    ##### Deprovision:
    - Delete all permission related to this app

    ##### Legacy management:
    - Legacy `is_public` setting will be deleted if it exists
    """

    # Notes for future ?
    # deep_clean  -> delete permissions for any __APP__.foobar where app not in app list...
    # backup -> handled elsewhere by the core, should be integrated in there (dump .ldif/yml?)
    # restore -> handled by the core, should be integrated in there (restore .ldif/yml?)

    type = "permissions"
    priority = 80

    default_properties: Dict[str, Any] = {}

    default_perm_properties: Dict[str, Any] = {
        "url": None,
        "additional_urls": [],
        "auth_header": True,
        "allowed": None,
        "show_tile": None,  # To be automagically set to True by default if an url is defined and show_tile not provided
        "protected": False,
    }

    permissions: Dict[str, Dict[str, Any]] = {}

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):

        # FIXME : if url != None, we should check that there's indeed a domain/path defined ? ie that app is a webapp

        for perm, infos in properties.items():
            properties[perm] = copy.copy(self.default_perm_properties)
            properties[perm].update(infos)
            if properties[perm]["show_tile"] is None:
                properties[perm]["show_tile"] = bool(properties[perm]["url"])

        if (
            isinstance(properties["main"]["url"], str)
            and properties["main"]["url"] != "/"
        ):
            raise YunohostError(
                "URL for the 'main' permission should be '/' for webapps (or undefined/None for non-webapps). Note that / refers to the install url of the app"
            )

        super().__init__({"permissions": properties}, *args, **kwargs)

    def provision_or_update(self, context: Dict = {}):

        from yunohost.permission import (
            permission_create,
            permission_url,
            permission_delete,
            user_permission_list,
            user_permission_update,
            permission_sync_to_user,
        )

        # Delete legacy is_public setting if not already done
        self.delete_setting("is_public")

        existing_perms = user_permission_list(short=True, apps=[self.app])[
            "permissions"
        ]
        for perm in existing_perms:
            if perm.split(".")[1] not in self.permissions.keys():
                permission_delete(perm, force=True, sync_perm=False)

        for perm, infos in self.permissions.items():
            perm_id = f"{self.app}.{perm}"
            if perm_id not in existing_perms:
                # Use the 'allowed' key from the manifest,
                # or use the 'init_{perm}_permission' from the install questions
                # which is temporarily saved as a setting as an ugly hack to pass the info to this piece of code...
                init_allowed = (
                    infos["allowed"]
                    or self.get_setting(f"init_{perm}_permission")
                    or []
                )
                permission_create(
                    perm_id,
                    allowed=init_allowed,
                    # This is why the ugly hack with self.manager exists >_>
                    label=self.manager.wanted["name"] if perm == "main" else perm,
                    url=infos["url"],
                    additional_urls=infos["additional_urls"],
                    auth_header=infos["auth_header"],
                    sync_perm=False,
                )
                self.delete_setting(f"init_{perm}_permission")

            user_permission_update(
                perm_id,
                show_tile=infos["show_tile"],
                protected=infos["protected"],
                sync_perm=False,
            )
            permission_url(
                perm_id,
                url=infos["url"],
                set_url=infos["additional_urls"],
                auth_header=infos["auth_header"],
                sync_perm=False,
            )

        permission_sync_to_user()

    def deprovision(self, context: Dict = {}):

        from yunohost.permission import (
            permission_delete,
            user_permission_list,
            permission_sync_to_user,
        )

        existing_perms = user_permission_list(short=True, apps=[self.app])[
            "permissions"
        ]
        for perm in existing_perms:
            permission_delete(perm, force=True, sync_perm=False)

        permission_sync_to_user()


class SystemuserAppResource(AppResource):
    """
    Provision a system user to be used by the app. The username is exactly equal to the app id

    ##### Example:
    ```toml
    [resources.system_user]
    # (empty - defaults are usually okay)
    ```

    ##### Properties:
    - `allow_ssh`: (default: False) Adds the user to the ssh.app group, allowing SSH connection via this user
    - `allow_sftp`: (defalt: False) Adds the user to the sftp.app group, allowing SFTP connection via this user

    ##### Provision/Update:
    - will create the system user if it doesn't exists yet
    - will add/remove the ssh/sftp.app groups

    ##### Deprovision:
    - deletes the user and group
    """

    # Notes for future?
    #
    # deep_clean  -> uuuuh ? delete any user that could correspond to an app x_x ?
    #
    # backup -> nothing
    # restore -> provision

    type = "system_user"
    priority = 20

    default_properties: Dict[str, Any] = {"allow_ssh": False, "allow_sftp": False}

    # FIXME : wat do regarding ssl-cert, multimedia
    # FIXME : wat do about home dir

    allow_ssh: bool = False
    allow_sftp: bool = False

    def provision_or_update(self, context: Dict = {}):

        # FIXME : validate that no yunohost user exists with that name?
        # and/or that no system user exists during install ?

        if not check_output(f"getent passwd {self.app} &>/dev/null || true").strip():
            # FIXME: improve logging ? os.system wont log stdout / stderr
            cmd = f"useradd --system --user-group {self.app}"
            ret = os.system(cmd)
            assert ret == 0, f"useradd command failed with exit code {ret}"

        if not check_output(f"getent passwd {self.app} &>/dev/null || true").strip():
            raise YunohostError(
                f"Failed to create system user for {self.app}", raw_msg=True
            )

        groups = set(check_output(f"groups {self.app}").strip().split()[2:])

        if self.allow_ssh:
            groups.add("ssh.app")
        elif "ssh.app" in groups:
            groups.remove("ssh.app")

        if self.allow_sftp:
            groups.add("sftp.app")
        elif "sftp.app" in groups:
            groups.remove("sftp.app")

        os.system(f"usermod -G {','.join(groups)} {self.app}")

    def deprovision(self, context: Dict = {}):

        if check_output(f"getent passwd {self.app} &>/dev/null || true").strip():
            os.system(f"deluser {self.app} >/dev/null")
        if check_output(f"getent passwd {self.app} &>/dev/null || true").strip():
            raise YunohostError(f"Failed to delete system user for {self.app}")

        if check_output(f"getent group {self.app} &>/dev/null || true").strip():
            os.system(f"delgroup {self.app} >/dev/null")
        if check_output(f"getent group {self.app} &>/dev/null || true").strip():
            raise YunohostError(f"Failed to delete system user for {self.app}")

        # FIXME : better logging and error handling, add stdout/stderr from the deluser/delgroup commands...


class InstalldirAppResource(AppResource):
    """
    Creates a directory to be used by the app as the installation directory, typically where the app sources and assets are located. The corresponding path is stored in the settings as `install_dir`

    ##### Example:
    ```toml
    [resources.install_dir]
    # (empty - defaults are usually okay)
    ```

    ##### Properties:
    - `dir`: (default: `/var/www/__APP__`) The full path of the install dir
    - `owner`: (default: `__APP__:rx`) The owner (and owner permissions) for the install dir
    - `group`: (default: `__APP__:rx`) The group (and group permissions) for the install dir

    ##### Provision/Update:
    - during install, the folder will be deleted if it already exists (FIXME: is this what we want?)
    - if the dir path changed and a folder exists at the old location, the folder will be `mv`'ed to the new location
    - otherwise, creates the directory if it doesn't exists yet
    - (re-)apply permissions (only on the folder itself, not recursively)
    - save the value of `dir` as `install_dir` in the app's settings, which can be then used by the app scripts (`$install_dir`) and conf templates (`__INSTALL_DIR__`)

    ##### Deprovision:
    - recursively deletes the directory if it exists

    ##### Legacy management:
    - In the past, the setting was called `final_path`. The code will automatically rename it as `install_dir`.
    - As explained in the 'Provision/Update' section, the folder will also be moved if the location changed

    """

    # Notes for future?
    # deep_clean  -> uuuuh ? delete any dir in /var/www/ that would not correspond to an app x_x ?
    # backup -> cp install dir
    # restore -> cp install dir

    type = "install_dir"
    priority = 30

    default_properties: Dict[str, Any] = {
        "dir": "/var/www/__APP__",
        "owner": "__APP__:rx",
        "group": "__APP__:rx",
    }

    dir: str = ""
    owner: str = ""
    group: str = ""

    # FIXME: change default dir to /opt/stuff if app ain't a webapp ...

    def provision_or_update(self, context: Dict = {}):

        assert self.dir.strip()  # Be paranoid about self.dir being empty...
        assert self.owner.strip()
        assert self.group.strip()

        current_install_dir = self.get_setting("install_dir") or self.get_setting(
            "final_path"
        )

        # If during install, /var/www/$app already exists, assume that it's okay to remove and recreate it
        # FIXME : is this the right thing to do ?
        if not current_install_dir and os.path.isdir(self.dir):
            rm(self.dir, recursive=True)

        # isdir will be True if the path is a symlink pointing to a dir
        # This should cover cases where people moved the data dir to another place via a symlink (ie we dont enter the if)
        if not os.path.isdir(self.dir):
            # Handle case where install location changed, in which case we shall move the existing install dir
            # FIXME: confirm that's what we wanna do
            # Maybe a middle ground could be to compute the size, check that it's not too crazy (eg > 1G idk),
            # and check for available space on the destination
            if current_install_dir and os.path.isdir(current_install_dir):
                logger.warning(
                    f"Moving {current_install_dir} to {self.dir} ... (this may take a while)"
                )
                shutil.move(current_install_dir, self.dir)
            else:
                mkdir(self.dir)

        owner, owner_perm = self.owner.split(":")
        group, group_perm = self.group.split(":")
        owner_perm_octal = (
            (4 if "r" in owner_perm else 0)
            + (2 if "w" in owner_perm else 0)
            + (1 if "x" in owner_perm else 0)
        )
        group_perm_octal = (
            (4 if "r" in group_perm else 0)
            + (2 if "w" in group_perm else 0)
            + (1 if "x" in group_perm else 0)
        )

        perm_octal = 0o100 * owner_perm_octal + 0o010 * group_perm_octal

        # NB: we use realpath here to cover cases where self.dir could actually be a symlink
        # in which case we want to apply the perm to the pointed dir, not to the symlink
        chmod(os.path.realpath(self.dir), perm_octal)
        chown(os.path.realpath(self.dir), owner, group)
        # FIXME: shall we apply permissions recursively ?

        self.set_setting("install_dir", self.dir)
        self.delete_setting("final_path")  # Legacy

    def deprovision(self, context: Dict = {}):

        assert self.dir.strip()  # Be paranoid about self.dir being empty...
        assert self.owner.strip()
        assert self.group.strip()

        # FIXME : check that self.dir has a sensible value to prevent catastrophes
        if os.path.isdir(self.dir):
            rm(self.dir, recursive=True)
        # FIXME : in fact we should delete settings to be consistent


class DatadirAppResource(AppResource):
    """
    Creates a directory to be used by the app as the data store directory, typically where the app multimedia or large assets added by users are located. The corresponding path is stored in the settings as `data_dir`. This resource behaves very similarly to install_dir.

    ##### Example:
    ```toml
    [resources.data_dir]
    # (empty - defaults are usually okay)
    ```

    ##### Properties:
    - `dir`: (default: `/home/yunohost.app/__APP__`) The full path of the data dir
    - `owner`: (default: `__APP__:rx`) The owner (and owner permissions) for the data dir
    - `group`: (default: `__APP__:rx`) The group (and group permissions) for the data dir

    ##### Provision/Update:
    - if the dir path changed and a folder exists at the old location, the folder will be `mv`'ed to the new location
    - otherwise, creates the directory if it doesn't exists yet
    - (re-)apply permissions (only on the folder itself, not recursively)
    - save the value of `dir` as `data_dir` in the app's settings, which can be then used by the app scripts (`$data_dir`) and conf templates (`__DATA_DIR__`)

    ##### Deprovision:
    - (only if the purge option is chosen by the user) recursively deletes the directory if it exists
    - also delete the corresponding setting

    ##### Legacy management:
    - In the past, the setting may have been called `datadir`. The code will automatically rename it as `data_dir`.
    - As explained in the 'Provision/Update' section, the folder will also be moved if the location changed

    """

    # notes for future ?
    # deep_clean  -> zblerg idk nothing
    # backup -> cp data dir ? (if not backup_core_only)
    # restore -> cp data dir ? (if in backup)

    type = "data_dir"
    priority = 40

    default_properties: Dict[str, Any] = {
        "dir": "/home/yunohost.app/__APP__",
        "owner": "__APP__:rx",
        "group": "__APP__:rx",
    }

    dir: str = ""
    owner: str = ""
    group: str = ""

    def provision_or_update(self, context: Dict = {}):

        assert self.dir.strip()  # Be paranoid about self.dir being empty...
        assert self.owner.strip()
        assert self.group.strip()

        current_data_dir = self.get_setting("data_dir") or self.get_setting("datadir")

        # isdir will be True if the path is a symlink pointing to a dir
        # This should cover cases where people moved the data dir to another place via a symlink (ie we dont enter the if)
        if not os.path.isdir(self.dir):
            # Handle case where install location changed, in which case we shall move the existing install dir
            # FIXME: same as install_dir, is this what we want ?
            if current_data_dir and os.path.isdir(current_data_dir):
                logger.warning(
                    f"Moving {current_data_dir} to {self.dir} ... (this may take a while)"
                )
                shutil.move(current_data_dir, self.dir)
            else:
                mkdir(self.dir)

        owner, owner_perm = self.owner.split(":")
        group, group_perm = self.group.split(":")
        owner_perm_octal = (
            (4 if "r" in owner_perm else 0)
            + (2 if "w" in owner_perm else 0)
            + (1 if "x" in owner_perm else 0)
        )
        group_perm_octal = (
            (4 if "r" in group_perm else 0)
            + (2 if "w" in group_perm else 0)
            + (1 if "x" in group_perm else 0)
        )
        perm_octal = 0o100 * owner_perm_octal + 0o010 * group_perm_octal

        # NB: we use realpath here to cover cases where self.dir could actually be a symlink
        # in which case we want to apply the perm to the pointed dir, not to the symlink
        chmod(os.path.realpath(self.dir), perm_octal)
        chown(os.path.realpath(self.dir), owner, group)

        self.set_setting("data_dir", self.dir)
        self.delete_setting("datadir")  # Legacy

    def deprovision(self, context: Dict = {}):

        assert self.dir.strip()  # Be paranoid about self.dir being empty...
        assert self.owner.strip()
        assert self.group.strip()

        if context.get("purge_data_dir", False) and os.path.isdir(self.dir):
            rm(self.dir, recursive=True)

        self.delete_setting("data_dir")


class AptDependenciesAppResource(AppResource):
    """
    Create a virtual package in apt, depending on the list of specified packages that the app needs. The virtual packages is called `$app-ynh-deps` (with `_` being replaced by `-` in the app name, see `ynh_install_app_dependencies`)

    ##### Example:
    ```toml
    [resources.apt]
    packages = "nyancat, lolcat, sl"

    # (this part is optional and corresponds to the legacy ynh_install_extra_app_dependencies helper)
    extras.yarn.repo = "deb https://dl.yarnpkg.com/debian/ stable main"
    extras.yarn.key = "https://dl.yarnpkg.com/debian/pubkey.gpg"
    extras.yarn.packages = "yarn"
    ```

    ##### Properties:
    - `packages`: Comma-separated list of packages to be installed via `apt`
    - `extras`: A dict of (repo, key, packages) corresponding to "extra" repositories to fetch dependencies from

    ##### Provision/Update:
    - The code literally calls the bash helpers `ynh_install_app_dependencies` and `ynh_install_extra_app_dependencies`, similar to what happens in v1.

    ##### Deprovision:
    - The code literally calls the bash helper `ynh_remove_app_dependencies`
    """

    # Notes for future?
    # deep_clean  -> remove any __APP__-ynh-deps for app not in app list
    # backup -> nothing
    # restore = provision

    type = "apt"
    priority = 50

    default_properties: Dict[str, Any] = {"packages": [], "extras": {}}

    packages: List = []
    extras: Dict[str, Dict[str, str]] = {}

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):

        for key, values in properties.get("extras", {}).items():
            if not all(
                isinstance(values.get(k), str) for k in ["repo", "key", "packages"]
            ):
                raise YunohostError(
                    "In apt resource in the manifest: 'extras' repo should have the keys 'repo', 'key' and 'packages' defined and be strings"
                )

        super().__init__(properties, *args, **kwargs)

    def provision_or_update(self, context: Dict = {}):

        script = [f"ynh_install_app_dependencies {self.packages}"]
        for repo, values in self.extras.items():
            script += [
                f"ynh_install_extra_app_dependencies --repo='{values['repo']}' --key='{values['key']}' --package='{values['packages']}'"
            ]
            # FIXME : we're feeding the raw value of values['packages'] to the helper .. if we want to be consistent, may they should be comma-separated, though in the majority of cases, only a single package is installed from an extra repo..

        self._run_script("provision_or_update", "\n".join(script))

    def deprovision(self, context: Dict = {}):

        self._run_script("deprovision", "ynh_remove_app_dependencies")


class PortsResource(AppResource):
    """
    Book port(s) to be used by the app, typically to be used to the internal reverse-proxy between nginx and the app process.

    Note that because multiple ports can be booked, each properties is prefixed by the name of the port. `main` is a special name and will correspond to the setting `$port`, whereas for example `xmpp_client` will correspond to the setting `$port_xmpp_client`.

    ##### Example:
    ```toml
    [resources.port]
    # (empty should be fine for most apps ... though you can customize stuff if absolutely needed)

    main.default = 12345    # if you really want to specify a prefered value .. but shouldnt matter in the majority of cases

    xmpp_client.default = 5222  # if you need another port, pick a name for it (here, "xmpp_client")
    xmpp_client.exposed = "TCP" # here, we're telling that the port needs to be publicly exposed on TCP on the firewall
    ```

    ##### Properties (for every port name):
    - `default`: The prefered value for the port. If this port is already being used by another process right now, or is booked in another app's setting, the code will increment the value until it finds a free port and store that value as the setting. If no value is specified, a random value between 10000 and 60000 is used.
    - `exposed`: (default: `false`) Wether this port should be opened on the firewall and be publicly reachable. This should be kept to `false` for the majority of apps than only need a port for internal reverse-proxying! Possible values: `false`, `true`(=`Both`), `Both`, `TCP`, `UDP`. This will result in the port being opened on the firewall, and the diagnosis checking that a program answers on that port.
    - `fixed`: (default: `false`) Tells that the app absolutely needs the specific value provided in `default`, typically because it's needed for a specific protocol

    ##### Provision/Update (for every port name):
    - If not already booked, look for a free port, starting with the `default` value (or a random value between 10000 and 60000 if no `default` set)
    - If `exposed` is not `false`, open the port in the firewall accordingly - otherwise make sure it's closed.
    - The value of the port is stored in the `$port` setting for the `main` port, or `$port_NAME` for other `NAME`s

    ##### Deprovision:
    - Close the ports on the firewall if relevant
    - Deletes all the port settings

    ##### Legacy management:
    - In the past, some settings may have been named `NAME_port` instead of `port_NAME`, in which case the code will automatically rename the old setting.
    """

    # Notes for future?
    # deep_clean  -> ?
    # backup -> nothing (backup port setting)
    # restore -> nothing (restore port setting)

    type = "ports"
    priority = 70

    default_properties: Dict[str, Any] = {}

    default_port_properties = {
        "default": None,
        "exposed": False,  # or True(="Both"), "TCP", "UDP"
        "fixed": False,
    }

    ports: Dict[str, Dict[str, Any]]

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):

        if "main" not in properties:
            properties["main"] = {}

        for port, infos in properties.items():
            properties[port] = copy.copy(self.default_port_properties)
            properties[port].update(infos)

            if properties[port]["default"] is None:
                properties[port]["default"] = random.randint(10000, 60000)

        super().__init__({"ports": properties}, *args, **kwargs)

    def _port_is_used(self, port):

        # FIXME : this could be less brutal than two os.system ...
        cmd1 = (
            "ss --numeric --listening --tcp --udp | awk '{print$5}' | grep --quiet --extended-regexp ':%s$'"
            % port
        )
        # This second command is mean to cover (most) case where an app is using a port yet ain't currently using it for some reason (typically service ain't up)
        cmd2 = f"grep --quiet \"port: '{port}'\" /etc/yunohost/apps/*/settings.yml"
        return os.system(cmd1) == 0 and os.system(cmd2) == 0

    def provision_or_update(self, context: Dict = {}):

        from yunohost.firewall import firewall_allow, firewall_disallow

        for name, infos in self.ports.items():

            setting_name = f"port_{name}" if name != "main" else "port"
            port_value = self.get_setting(setting_name)
            if not port_value and name != "main":
                # Automigrate from legacy setting foobar_port (instead of port_foobar)
                legacy_setting_name = "{name}_port"
                port_value = self.get_setting(legacy_setting_name)
                if port_value:
                    self.set_setting(setting_name, port_value)
                    self.delete_setting(legacy_setting_name)
                    continue

            if not port_value:
                port_value = infos["default"]

                if infos["fixed"]:
                    if self._port_is_used(port_value):
                        raise YunohostValidationError(
                            f"Port {port_value} is already used by another process or app."
                        )
                else:
                    while self._port_is_used(port_value):
                        port_value += 1

            self.set_setting(setting_name, port_value)

            if infos["exposed"]:
                firewall_allow(infos["exposed"], port_value, reload_only_if_change=True)
            else:
                firewall_disallow(
                    infos["exposed"], port_value, reload_only_if_change=True
                )

    def deprovision(self, context: Dict = {}):

        from yunohost.firewall import firewall_disallow

        for name, infos in self.ports.items():
            setting_name = f"port_{name}" if name != "main" else "port"
            value = self.get_setting(setting_name)
            self.delete_setting(setting_name)
            if value and str(value).strip():
                firewall_disallow(
                    infos["exposed"], int(value), reload_only_if_change=True
                )


class DatabaseAppResource(AppResource):
    """
    Initialize a database, either using MySQL or Postgresql. Relevant DB infos are stored in settings `$db_name`, `$db_user` and `$db_pwd`.

    NB: only one DB can be handled in such a way (is there really an app that would need two completely different DB ?...)

    NB2: no automagic migration will happen in an suddenly change `type` from `mysql` to `postgresql` or viceversa in its life

    ##### Example:
    ```toml
    [resources.database]
    type = "mysql"   # or : "postgresql". Only these two values are supported
    ```

    ##### Properties:
    - `type`: The database type, either `mysql` or `postgresql`

    ##### Provision/Update:
    - (Re)set the `$db_name` and `$db_user` settings with the sanitized app name (replacing `-` and `.` with `_`)
    - If `$db_pwd` doesn't already exists, pick a random database password and store it in that setting
    - If the database doesn't exists yet, create the SQL user and DB using `ynh_mysql_create_db` or `ynh_psql_create_db`.

    ##### Deprovision:
    - Drop the DB using `ynh_mysql_remove_db` or `ynh_psql_remove_db`
    - Deletes the `db_name`, `db_user` and `db_pwd` settings

    ##### Legacy management:
    - In the past, the sql passwords may have been named `mysqlpwd` or `psqlpwd`, in which case it will automatically be renamed as `db_pwd`
    """

    # Notes for future?
    # deep_clean  -> ... idk look into any db name that would not be related to any app ...
    # backup -> dump db
    # restore -> setup + inject db dump

    type = "database"
    priority = 90
    dbtype: str = ""

    default_properties: Dict[str, Any] = {
        "dbtype": None,
    }

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):

        if "type" not in properties or properties["type"] not in [
            "mysql",
            "postgresql",
        ]:
            raise YunohostError(
                "Specifying the type of db ('mysql' or 'postgresql') is mandatory for db resources",
                raw_msg=True,
            )

        # Hack so that people can write type = "mysql/postgresql" in toml but it's loaded as dbtype
        # to avoid conflicting with the generic self.type of the resource object ...
        # dunno if that's really a good idea :|
        properties = {"dbtype": properties["type"]}

        super().__init__(properties, *args, **kwargs)

    def db_exists(self, db_name):

        if self.dbtype == "mysql":
            return os.system(f"mysqlshow '{db_name}' >/dev/null 2>/dev/null") == 0
        elif self.dbtype == "postgresql":
            return (
                os.system(
                    f"sudo --login --user=postgres psql -c '' '{db_name}' >/dev/null 2>/dev/null"
                )
                == 0
            )
        else:
            return False

    def provision_or_update(self, context: Dict = {}):

        # This is equivalent to ynh_sanitize_dbid
        db_name = self.app.replace("-", "_").replace(".", "_")
        db_user = db_name
        self.set_setting("db_name", db_name)
        self.set_setting("db_user", db_user)

        db_pwd = None
        if self.get_setting("db_pwd"):
            db_pwd = self.get_setting("db_pwd")
        else:
            # Legacy setting migration
            legacypasswordsetting = (
                "psqlpwd" if self.dbtype == "postgresql" else "mysqlpwd"
            )
            if self.get_setting(legacypasswordsetting):
                db_pwd = self.get_setting(legacypasswordsetting)
                self.delete_setting(legacypasswordsetting)
                self.set_setting("db_pwd", db_pwd)

        if not db_pwd:
            from moulinette.utils.text import random_ascii

            db_pwd = random_ascii(24)
            self.set_setting("db_pwd", db_pwd)

        if not self.db_exists(db_name):

            if self.dbtype == "mysql":
                self._run_script(
                    "provision",
                    f"ynh_mysql_create_db '{db_name}' '{db_user}' '{db_pwd}'",
                )
            elif self.dbtype == "postgresql":
                self._run_script(
                    "provision",
                    f"ynh_psql_create_user '{db_user}' '{db_pwd}'; ynh_psql_create_db '{db_name}' '{db_user}'",
                )

    def deprovision(self, context: Dict = {}):

        db_name = self.app.replace("-", "_").replace(".", "_")
        db_user = db_name

        if self.dbtype == "mysql":
            self._run_script(
                "deprovision", f"ynh_mysql_remove_db '{db_name}' '{db_user}'"
            )
        elif self.dbtype == "postgresql":
            self._run_script(
                "deprovision", f"ynh_psql_remove_db '{db_name}' '{db_user}'"
            )

        self.delete_setting("db_name")
        self.delete_setting("db_user")
        self.delete_setting("db_pwd")


AppResourceClassesByType = {c.type: c for c in AppResource.__subclasses__()}
