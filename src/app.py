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

import time
import glob
import os
import shutil
import yaml
import re
import subprocess
import tempfile
from typing import TYPE_CHECKING, List, Tuple, Dict, Any, Iterator, Optional, Union
from packaging import version
from logging import getLogger
from pathlib import Path

from moulinette import Moulinette, m18n
from moulinette.utils.process import run_commands, check_output
from moulinette.utils.filesystem import (
    read_file,
    read_json,
    read_toml,
    write_to_file,
    write_to_json,
    cp,
    rm,
    chown,
    chmod,
)

from yunohost.utils.i18n import _value_for_locale
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.system import (
    free_space_in_directory,
    dpkg_is_broken,
    get_ynh_package_version,
    system_arch,
    debian_version,
    human_to_binary,
    binary_to_human,
    ram_available,
)
from yunohost.log import is_unit_operation, OperationLogger
from yunohost.app_catalog import (  # noqa
    app_catalog,
    app_search,
    _load_apps_catalog,
    APPS_CATALOG_LOGOS,
)

if TYPE_CHECKING:
    from pydantic.typing import AbstractSetIntStr, MappingIntStrAny

    from yunohost.utils.configpanel import RawSettings, ConfigPanelModel
    from yunohost.utils.form import FormModel

logger = getLogger("yunohost.app")

APPS_SETTING_PATH = "/etc/yunohost/apps/"
APP_TMP_WORKDIRS = "/var/cache/yunohost/app_tmp_work_dirs"

re_app_instance_name = re.compile(
    r"^(?P<appid>[\w-]+?)(__(?P<appinstancenb>[1-9][0-9]*))?$"
)

APP_REPO_URL = re.compile(
    r"^https://[a-zA-Z0-9-_.]+/[a-zA-Z0-9-_./~]+/[a-zA-Z0-9-_.]+_ynh(/?(-/)?(tree|src/(branch|tag|commit))/[a-zA-Z0-9-_.]+)?(\.git)?/?$"
)

APP_FILES_TO_COPY = [
    "manifest.json",
    "manifest.toml",
    "actions.json",
    "actions.toml",
    "config_panel.toml",
    "scripts",
    "conf",
    "hooks",
    "doc",
]

PORTAL_SETTINGS_DIR = "/etc/yunohost/portal"


def app_list(full=False, upgradable=False):
    """
    List installed apps
    """

    out = []
    for app_id in sorted(_installed_apps()):
        try:
            app_info_dict = app_info(app_id, full=full, upgradable=upgradable)
        except Exception as e:
            logger.error(f"Failed to read info for {app_id} : {e}")
            continue
        app_info_dict["id"] = app_id
        if upgradable and app_info_dict.get("upgradable") != "yes":
            continue
        out.append(app_info_dict)

    return {"apps": out}


def app_info(app, full=False, upgradable=False):
    """
    Get info for a specific app
    """
    from yunohost.domain import _get_raw_domain_settings
    from yunohost.permission import user_permission_list

    _assert_is_installed(app)

    setting_path = os.path.join(APPS_SETTING_PATH, app)
    local_manifest = _get_manifest_of_app(setting_path)
    permissions = user_permission_list(full=True, absolute_urls=True, apps=[app])[
        "permissions"
    ]

    settings = _get_app_settings(app)

    ret = {
        "description": _value_for_locale(local_manifest["description"]),
        "name": permissions.get(app + ".main", {}).get("label", local_manifest["name"]),
        "version": local_manifest.get("version", "-"),
    }

    if "domain" in settings and "path" in settings:
        ret["domain_path"] = settings["domain"] + settings["path"]

    if not upgradable and not full:
        return ret

    absolute_app_name, _ = _parse_app_instance_name(app)
    from_catalog = _load_apps_catalog()["apps"].get(absolute_app_name, {})

    # Check if $app.png exists in the app logo folder, this is a trick to be able to easily customize the logo
    # of an app just by creating $app.png (instead of the hash.png) in the corresponding folder
    ret["logo"] = (
        app
        if os.path.exists(f"{APPS_CATALOG_LOGOS}/{app}.png")
        else from_catalog.get("logo_hash")
    )
    ret["upgradable"] = _app_upgradable({**ret, "from_catalog": from_catalog})

    if ret["upgradable"] == "yes":
        ret["current_version"] = ret.get("version", "?")
        ret["new_version"] = from_catalog.get("manifest", {}).get("version", "?")

        if ret["current_version"] == ret["new_version"]:
            current_revision = settings.get("current_revision", "?")[:7]
            new_revision = from_catalog.get("git", {}).get("revision", "?")[:7]

            ret["current_version"] = f" ({current_revision})"
            ret["new_version"] = f" ({new_revision})"

    ret["settings"] = settings

    if not full:
        return ret

    ret["setting_path"] = setting_path
    ret["manifest"] = local_manifest

    # FIXME: maybe this is not needed ? default ask questions are
    # already set during the _get_manifest_of_app earlier ?
    ret["manifest"]["install"] = _set_default_ask_questions(
        ret["manifest"].get("install", {})
    )

    ret["from_catalog"] = from_catalog

    # Hydrate app notifications and doc
    rendered_doc = {}
    for pagename, content_per_lang in ret["manifest"]["doc"].items():
        for lang, content in content_per_lang.items():
            rendered_content = _hydrate_app_template(content, settings)
            # Rendered content may be empty because of conditional blocks
            if not rendered_content:
                continue
            if pagename not in rendered_doc:
                rendered_doc[pagename] = {}
            rendered_doc[pagename][lang] = rendered_content
    ret["manifest"]["doc"] = rendered_doc

    # Filter dismissed notification
    ret["manifest"]["notifications"] = {
        k: v
        for k, v in ret["manifest"]["notifications"].items()
        if not _notification_is_dismissed(k, settings)
    }

    # Hydrate notifications (also filter uneeded post_upgrade notification based on version)
    for step, notifications in ret["manifest"]["notifications"].items():
        rendered_notifications = {}
        for name, content_per_lang in notifications.items():
            for lang, content in content_per_lang.items():
                rendered_content = _hydrate_app_template(content, settings)
                if not rendered_content:
                    continue
                if name not in rendered_notifications:
                    rendered_notifications[name] = {}
                rendered_notifications[name][lang] = rendered_content
        ret["manifest"]["notifications"][step] = rendered_notifications

    ret["is_webapp"] = (
        "domain" in settings and settings["domain"] and "path" in settings
    )

    if ret["is_webapp"]:
        ret["is_default"] = (
            _get_raw_domain_settings(settings["domain"]).get("default_app") == app
        )

    ret["supports_change_url"] = os.path.exists(
        os.path.join(setting_path, "scripts", "change_url")
    )
    ret["supports_backup_restore"] = os.path.exists(
        os.path.join(setting_path, "scripts", "backup")
    ) and os.path.exists(os.path.join(setting_path, "scripts", "restore"))
    ret["supports_multi_instance"] = local_manifest.get("integration", {}).get(
        "multi_instance", False
    )
    ret["supports_config_panel"] = os.path.exists(
        os.path.join(setting_path, "config_panel.toml")
    )
    ret["supports_purge"] = local_manifest["resources"].get("data_dir") is not None

    ret["permissions"] = permissions
    ret["label"] = permissions.get(app + ".main", {}).get("label")

    if not ret["label"]:
        logger.debug(f"Failed to get label for app {app}, maybe it is not a webapp?")
        ret["label"] = local_manifest["name"]
    return ret


def _app_upgradable(app_infos):
    # Determine upgradability

    app_in_catalog = app_infos.get("from_catalog")
    installed_version = _parse_app_version(app_infos.get("version", "0~ynh0"))
    version_in_catalog = _parse_app_version(
        app_infos.get("from_catalog", {}).get("manifest", {}).get("version", "0~ynh0")
    )

    if not app_in_catalog:
        return "url_required"

    # Do not advertise upgrades for bad-quality apps
    level = app_in_catalog.get("level", -1)
    if (
        not (isinstance(level, int) and level >= 5)
        or app_in_catalog.get("state") != "working"
    ):
        return "bad_quality"

    if installed_version < version_in_catalog:
        return "yes"
    else:
        return "no"


def app_map(app=None, raw=False, user=None):
    """
    Returns a map of url <-> app id such as :

    {
       "domain.tld/foo": "foo__2",
       "domain.tld/mail: "rainloop",
       "other.tld/": "bar",
       "sub.other.tld/pwet": "pwet",
    }

    When using "raw", the structure changes to :

    {
        "domain.tld": {
            "/foo": {"label": "App foo", "id": "foo__2"},
            "/mail": {"label": "Rainloop", "id: "rainloop"},
        },
        "other.tld": {
            "/": {"label": "Bar", "id": "bar"},
        },
        "sub.other.tld": {
            "/pwet": {"label": "Pwet", "id": "pwet"}
        }
    }
    """

    from yunohost.permission import user_permission_list

    apps = []
    result = {}

    if app is not None:
        _assert_is_installed(app)
        apps = [
            app,
        ]
    else:
        apps = _installed_apps()

    permissions = user_permission_list(full=True, absolute_urls=True, apps=apps)[
        "permissions"
    ]
    for app in apps:
        app_settings = _get_app_settings(app)
        if not app_settings:
            continue
        if "domain" not in app_settings:
            continue
        if "path" not in app_settings:
            # we assume that an app that doesn't have a path doesn't have an HTTP api
            continue
        # This 'no_sso' settings sound redundant to not having $path defined ....
        # At least from what I can see, all apps using it don't have a path defined ...
        if (
            "no_sso" in app_settings
        ):  # I don't think we need to check for the value here
            continue
        # Users must at least have access to the main permission to have access to extra permissions
        if user:
            if not app + ".main" in permissions:
                logger.warning(
                    f"Uhoh, no main permission was found for app {app} ... sounds like an app was only partially removed due to another bug :/"
                )
                continue
            main_perm = permissions[app + ".main"]
            if user not in main_perm["corresponding_users"]:
                continue

        this_app_perms = {
            p: i
            for p, i in permissions.items()
            if p.startswith(app + ".") and (i["url"] or i["additional_urls"])
        }

        for perm_name, perm_info in this_app_perms.items():
            # If we're building the map for a specific user, check the user
            # actually is allowed for this specific perm
            if user and user not in perm_info["corresponding_users"]:
                continue

            perm_label = perm_info["label"]
            perm_all_urls = (
                []
                + ([perm_info["url"]] if perm_info["url"] else [])
                + perm_info["additional_urls"]
            )

            for url in perm_all_urls:
                # Here, we decide to completely ignore regex-type urls ...
                # Because :
                # - displaying them in regular "yunohost app map" output creates
                # a pretty big mess when there are multiple regexes for the same
                # app ? (c.f. for example lufi)
                # - it doesn't really make sense when checking app conflicts to
                # compare regexes ? (Or it could in some cases but ugh ?)
                #
                if url.startswith("re:"):
                    continue

                if not raw:
                    result[url] = perm_label
                else:
                    if "/" in url:
                        perm_domain, perm_path = url.split("/", 1)
                        perm_path = "/" + perm_path
                    else:
                        perm_domain = url
                        perm_path = "/"
                    if perm_domain not in result:
                        result[perm_domain] = {}
                    result[perm_domain][perm_path] = {"label": perm_label, "id": app}

    return result


@is_unit_operation()
def app_change_url(operation_logger, app, domain, path):
    """
    Modify the URL at which an application is installed.

    Keyword argument:
        app -- Taget app instance name
        domain -- New app domain on which the application will be moved
        path -- New path at which the application will be move

    """
    from yunohost.utils.form import DomainOption, WebPathOption
    from yunohost.hook import hook_exec_with_script_debug_if_failure, hook_callback
    from yunohost.service import service_reload_or_restart

    installed = _is_installed(app)
    if not installed:
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )

    if not os.path.exists(
        os.path.join(APPS_SETTING_PATH, app, "scripts", "change_url")
    ):
        raise YunohostValidationError("app_change_url_no_script", app_name=app)

    old_domain = app_setting(app, "domain")
    old_path = app_setting(app, "path")

    # Normalize path and domain format

    domain = DomainOption.normalize(domain)
    old_domain = DomainOption.normalize(old_domain)
    path = WebPathOption.normalize(path)
    old_path = WebPathOption.normalize(old_path)

    if (domain, path) == (old_domain, old_path):
        raise YunohostValidationError(
            "app_change_url_identical_domains", domain=domain, path=path
        )

    app_setting_path = os.path.join(APPS_SETTING_PATH, app)
    path_requirement = _guess_webapp_path_requirement(app_setting_path)
    _validate_webpath_requirement(
        {"domain": domain, "path": path}, path_requirement, ignore_app=app
    )
    if path_requirement == "full_domain" and path != "/":
        raise YunohostValidationError("app_change_url_require_full_domain", app=app)

    tmp_workdir_for_app = _make_tmp_workdir_for_app(app=app)

    # Prepare env. var. to pass to script
    env_dict = _make_environment_for_app_script(
        app, workdir=tmp_workdir_for_app, action="change_url"
    )

    env_dict["YNH_APP_OLD_DOMAIN"] = old_domain
    env_dict["YNH_APP_OLD_PATH"] = old_path
    env_dict["YNH_APP_NEW_DOMAIN"] = domain
    env_dict["YNH_APP_NEW_PATH"] = path

    env_dict["old_domain"] = old_domain
    env_dict["old_path"] = old_path
    env_dict["new_domain"] = domain
    env_dict["new_path"] = path
    env_dict["domain"] = domain
    env_dict["path"] = path
    env_dict["path_url"] = path
    env_dict["change_path"] = "1" if old_path != path else "0"
    env_dict["change_domain"] = "1" if old_domain != domain else "0"

    if domain != old_domain:
        operation_logger.related_to.append(("domain", old_domain))
    operation_logger.extra.update({"env": env_dict})
    operation_logger.start()

    old_nginx_conf_path = f"/etc/nginx/conf.d/{old_domain}.d/{app}.conf"
    new_nginx_conf_path = f"/etc/nginx/conf.d/{domain}.d/{app}.conf"
    old_nginx_conf_backup = None
    if not os.path.exists(old_nginx_conf_path):
        logger.warning(
            f"Current nginx config file {old_nginx_conf_path} doesn't seem to exist ... wtf ?"
        )
    else:
        old_nginx_conf_backup = read_file(old_nginx_conf_path)

    change_url_script = os.path.join(tmp_workdir_for_app, "scripts/change_url")

    # Execute App change_url script
    change_url_failed = True
    try:
        (
            change_url_failed,
            failure_message_with_debug_instructions,
        ) = hook_exec_with_script_debug_if_failure(
            change_url_script,
            env=env_dict,
            operation_logger=operation_logger,
            error_message_if_script_failed=m18n.n("app_change_url_script_failed"),
            error_message_if_failed=lambda e: m18n.n(
                "app_change_url_failed", app=app, error=e
            ),
        )
    finally:
        shutil.rmtree(tmp_workdir_for_app)

        if change_url_failed:
            logger.warning("Restoring initial nginx config file")
            if old_nginx_conf_path != new_nginx_conf_path and os.path.exists(
                new_nginx_conf_path
            ):
                rm(new_nginx_conf_path, force=True)
            if old_nginx_conf_backup:
                write_to_file(old_nginx_conf_path, old_nginx_conf_backup)
                service_reload_or_restart("nginx")

            # restore values modified by app_checkurl
            # see begining of the function
            app_setting(app, "domain", value=old_domain)
            app_setting(app, "path", value=old_path)
            raise YunohostError(failure_message_with_debug_instructions, raw_msg=True)
        else:
            # make sure the domain/path setting are propagated
            app_setting(app, "domain", value=domain)
            app_setting(app, "path", value=path)

            app_ssowatconf()

            service_reload_or_restart("nginx")

            logger.success(
                m18n.n("app_change_url_success", app=app, domain=domain, path=path)
            )

            hook_callback("post_app_change_url", env=env_dict)


def app_upgrade(
    app=[],
    url=None,
    file=None,
    force=False,
    no_safety_backup=False,
    continue_on_failure=False,
):
    """
    Upgrade app

    Keyword argument:
        file -- Folder or tarball for upgrade
        app -- App(s) to upgrade (default all)
        url -- Git url to fetch for upgrade
        no_safety_backup -- Disable the safety backup during upgrade

    """
    from yunohost.hook import (
        hook_add,
        hook_remove,
        hook_callback,
        hook_exec_with_script_debug_if_failure,
    )
    from yunohost.permission import permission_sync_to_user
    from yunohost.regenconf import manually_modified_files
    from yunohost.backup import (
        backup_list,
        backup_create,
        backup_delete,
        backup_restore,
    )

    apps = app
    # Check if disk space available
    if free_space_in_directory("/") <= 512 * 1000 * 1000:
        raise YunohostValidationError("disk_space_not_sufficient_update")
    # If no app is specified, upgrade all apps
    if not apps:
        # FIXME : not sure what's supposed to happen if there is a url and a file but no apps...
        if not url and not file:
            apps = _installed_apps()
    elif not isinstance(app, list):
        apps = [app]

    # Remove possible duplicates
    apps = [app_ for i, app_ in enumerate(apps) if app_ not in apps[:i]]

    # Abort if any of those app is in fact not installed..
    for app_ in apps:
        _assert_is_installed(app_)

    if len(apps) == 0:
        raise YunohostValidationError("apps_already_up_to_date")
    if len(apps) > 1:
        logger.info(m18n.n("app_upgrade_several_apps", apps=", ".join(apps)))

    notifications = {}
    failed_to_upgrade_apps = []

    for number, app_instance_name in enumerate(apps):
        logger.info(m18n.n("app_upgrade_app_name", app=app_instance_name))

        app_dict = app_info(app_instance_name, full=True)

        if file and isinstance(file, dict):
            # We use this dirty hack to test chained upgrades in unit/functional tests
            new_app_src = file[app_instance_name]
        elif file:
            new_app_src = file
        elif url:
            new_app_src = url
        elif app_dict["upgradable"] == "url_required":
            logger.warning(m18n.n("custom_app_url_required", app=app_instance_name))
            continue
        elif app_dict["upgradable"] == "yes" or force:
            new_app_src = app_dict["manifest"]["id"]
        else:
            logger.success(m18n.n("app_already_up_to_date", app=app_instance_name))
            continue

        manifest, extracted_app_folder = _extract_app(new_app_src)

        # Manage upgrade type and avoid any upgrade if there is nothing to do
        upgrade_type = "UNKNOWN"
        # Get current_version and new version
        app_new_version_raw = manifest.get("version", "?")
        app_current_version_raw = app_dict.get("version", "?")
        app_new_version = _parse_app_version(app_new_version_raw)
        app_current_version = _parse_app_version(app_current_version_raw)
        if "~ynh" in str(app_current_version_raw) and "~ynh" in str(
            app_new_version_raw
        ):
            if app_current_version >= app_new_version and not force:
                # In case of upgrade from file or custom repository
                # No new version available
                logger.success(m18n.n("app_already_up_to_date", app=app_instance_name))
                # Save update time
                now = int(time.time())
                app_setting(app_instance_name, "update_time", now)
                app_setting(
                    app_instance_name,
                    "current_revision",
                    manifest.get("remote", {}).get("revision", "?"),
                )
                continue

            if app_current_version > app_new_version:
                upgrade_type = "DOWNGRADE"
            elif app_current_version == app_new_version:
                upgrade_type = "UPGRADE_SAME"
            else:
                app_current_version_upstream, _ = str(app_current_version_raw).split(
                    "~ynh"
                )
                app_new_version_upstream, _ = str(app_new_version_raw).split("~ynh")
                if app_current_version_upstream == app_new_version_upstream:
                    upgrade_type = "UPGRADE_PACKAGE"
                else:
                    upgrade_type = "UPGRADE_APP"

        # Check requirements
        for name, passed, values, err in _check_manifest_requirements(
            manifest, action="upgrade"
        ):
            if not passed:
                if name == "ram":
                    # i18n: confirm_app_insufficient_ram
                    _ask_confirmation(
                        "confirm_app_insufficient_ram", params=values, force=force
                    )
                else:
                    raise YunohostValidationError(err, **values)

        # Display pre-upgrade notifications and ask for simple confirm
        if (
            manifest["notifications"]["PRE_UPGRADE"]
            and Moulinette.interface.type == "cli"
        ):
            settings = _get_app_settings(app_instance_name)
            notifications = _filter_and_hydrate_notifications(
                manifest["notifications"]["PRE_UPGRADE"],
                current_version=app_current_version_raw,
                data=settings,
            )
            _display_notifications(notifications, force=force)

        if no_safety_backup:
            # FIXME: i18n
            logger.warning(
                "Skipping the creation of a backup prior to the upgrade."
            )
        else:
            # FIXME: i18n
            logger.info("Creating a safety backup prior to the upgrade")

            # Switch between pre-upgrade1 or pre-upgrade2
            safety_backup_name = f"{app_instance_name}-pre-upgrade1"
            other_safety_backup_name = f"{app_instance_name}-pre-upgrade2"
            if safety_backup_name in backup_list()["archives"]:
                safety_backup_name = f"{app_instance_name}-pre-upgrade2"
                other_safety_backup_name = f"{app_instance_name}-pre-upgrade1"

            tweaked_backup_core_only = False
            if "BACKUP_CORE_ONLY" not in os.environ:
                tweaked_backup_core_only = True
                os.environ["BACKUP_CORE_ONLY"] = "1"
            try:
                backup_create(
                    name=safety_backup_name, apps=[app_instance_name], system=None
                )
            finally:
                if tweaked_backup_core_only:
                    del os.environ["BACKUP_CORE_ONLY"]

            if safety_backup_name in backup_list()["archives"]:
                # if the backup suceeded, delete old safety backup to save space
                if other_safety_backup_name in backup_list()["archives"]:
                    backup_delete(other_safety_backup_name)
            else:
                # Is this needed ? Shouldn't backup_create report an expcetion if backup failed ?
                raise YunohostError(
                    "Uhoh the safety backup failed ?! Aborting the upgrade process.",
                    raw_msg=True,
                )

        _assert_system_is_sane_for_app(manifest, "pre")

        # We'll check that the app didn't brutally edit some system configuration
        manually_modified_files_before_install = manually_modified_files()

        app_setting_path = os.path.join(APPS_SETTING_PATH, app_instance_name)

        # Prepare env. var. to pass to script
        env_dict = _make_environment_for_app_script(
            app_instance_name, workdir=extracted_app_folder, action="upgrade"
        )

        env_dict_more = {
            "YNH_APP_UPGRADE_TYPE": upgrade_type,
            "YNH_APP_MANIFEST_VERSION": str(app_new_version_raw),
            "YNH_APP_CURRENT_VERSION": str(app_current_version_raw),
        }

        env_dict.update(env_dict_more)

        # Start register change on system
        related_to = [("app", app_instance_name)]
        operation_logger = OperationLogger("app_upgrade", related_to, env=env_dict)
        operation_logger.start()

        from yunohost.utils.resources import AppResourceManager

        AppResourceManager(
            app_instance_name,
            wanted=manifest,
            current=app_dict["manifest"],
            workdir=extracted_app_folder,
        ).apply(
            rollback_and_raise_exception_if_failure=True,
            operation_logger=operation_logger,
            action="upgrade",
        )

        # Boring stuff : the resource upgrade may have added/remove/updated setting
        # so we need to reflect this in the env_dict used to call the actual upgrade script x_x
        # Or: the old manifest may be in v1 and the new in v2, so force to add the setting in env
        env_dict = _make_environment_for_app_script(
            app_instance_name,
            workdir=extracted_app_folder,
            action="upgrade",
        )
        env_dict.update(env_dict_more)

        # Execute the app upgrade script
        upgrade_failed = True
        try:
            (
                upgrade_failed,
                failure_message_with_debug_instructions,
            ) = hook_exec_with_script_debug_if_failure(
                extracted_app_folder + "/scripts/upgrade",
                env=env_dict,
                operation_logger=operation_logger,
                error_message_if_script_failed=m18n.n("app_upgrade_script_failed"),
                error_message_if_failed=lambda e: m18n.n(
                    "app_upgrade_failed", app=app_instance_name, error=e
                ),
            )
        finally:
            # If upgrade failed, try to restore the safety backup
            if upgrade_failed and not no_safety_backup:
                logger.warning(
                    "Upgrade failed ... attempting to restore the safety backup (Yunohost first need to remove the app for this) ..."
                )

                app_remove(app_instance_name, force_workdir=extracted_app_folder)
                backup_restore(
                    name=safety_backup_name, apps=[app_instance_name], force=True
                )
                if not _is_installed(app_instance_name):
                    logger.error(
                        "Uhoh ... Yunohost failed to restore the app to the way it was before the failed upgrade :|"
                    )

            # Whatever happened (install success or failure) we check if it broke the system
            # and warn the user about it
            try:
                broke_the_system = False
                _assert_system_is_sane_for_app(manifest, "post")
            except Exception as e:
                broke_the_system = True
                logger.error(
                    m18n.n("app_upgrade_failed", app=app_instance_name, error=str(e))
                )
                failure_message_with_debug_instructions = operation_logger.error(str(e))

            # We'll check that the app didn't brutally edit some system configuration
            manually_modified_files_after_install = manually_modified_files()
            manually_modified_files_by_app = set(
                manually_modified_files_after_install
            ) - set(manually_modified_files_before_install)
            if manually_modified_files_by_app:
                logger.error(
                    "Packagers /!\\ This app manually modified some system configuration files! This should not happen! If you need to do so, you should implement a proper conf_regen hook. Those configuration were affected:\n    - "
                    + "\n     -".join(manually_modified_files_by_app)
                )

            # If the upgrade didnt fail, update the revision and app files (even if it broke the system, otherwise we end up in a funky intermediate state where the app files don't match the installed version or settings, for example for v1->v2 upgrade marked as "broke the system" for some reason)
            if not upgrade_failed:
                now = int(time.time())
                app_setting(app_instance_name, "update_time", now)
                app_setting(
                    app_instance_name,
                    "current_revision",
                    manifest.get("remote", {}).get("revision", "?"),
                )

                # Clean hooks and add new ones
                hook_remove(app_instance_name)
                if "hooks" in os.listdir(extracted_app_folder):
                    for hook in os.listdir(extracted_app_folder + "/hooks"):
                        hook_add(
                            app_instance_name, extracted_app_folder + "/hooks/" + hook
                        )

                # Replace scripts and manifest and conf (if exists)
                # Move scripts and manifest to the right place
                for file_to_copy in APP_FILES_TO_COPY:
                    rm(f"{app_setting_path}/{file_to_copy}", recursive=True, force=True)
                    if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
                        cp(
                            f"{extracted_app_folder}/{file_to_copy}",
                            f"{app_setting_path}/{file_to_copy}",
                            recursive=True,
                        )

                # Clean and set permissions
                shutil.rmtree(extracted_app_folder)
                chmod(app_setting_path, 0o600)
                chmod(f"{app_setting_path}/settings.yml", 0o400)
                chown(app_setting_path, "root", recursive=True)

            # If upgrade failed or broke the system,
            # raise an error and interrupt all other pending upgrades
            if upgrade_failed or broke_the_system:
                if not continue_on_failure or broke_the_system:
                    # display this if there are remaining apps
                    if apps[number + 1 :]:
                        not_upgraded_apps = apps[number:]
                        if broke_the_system and not continue_on_failure:
                            logger.error(
                                m18n.n(
                                    "app_not_upgraded_broken_system",
                                    failed_app=app_instance_name,
                                    apps=", ".join(not_upgraded_apps),
                                )
                            )
                        elif broke_the_system and continue_on_failure:
                            logger.error(
                                m18n.n(
                                    "app_not_upgraded_broken_system_continue",
                                    failed_app=app_instance_name,
                                    apps=", ".join(not_upgraded_apps),
                                )
                            )
                        else:
                            logger.error(
                                m18n.n(
                                    "app_not_upgraded",
                                    failed_app=app_instance_name,
                                    apps=", ".join(not_upgraded_apps),
                                )
                            )

                    raise YunohostError(
                        failure_message_with_debug_instructions, raw_msg=True
                    )

                else:
                    operation_logger.close()
                    logger.error(
                        m18n.n(
                            "app_failed_to_upgrade_but_continue",
                            failed_app=app_instance_name,
                            operation_logger_name=operation_logger.name,
                        )
                    )
                    failed_to_upgrade_apps.append(
                        (app_instance_name, operation_logger.name)
                    )

            # Otherwise we're good and keep going !

            # So much win
            logger.success(m18n.n("app_upgraded", app=app_instance_name))

            # Format post-upgrade notifications
            if manifest["notifications"]["POST_UPGRADE"]:
                # Get updated settings to hydrate notifications
                settings = _get_app_settings(app_instance_name)
                notifications = _filter_and_hydrate_notifications(
                    manifest["notifications"]["POST_UPGRADE"],
                    current_version=app_current_version_raw,
                    data=settings,
                )
                if Moulinette.interface.type == "cli":
                    # ask for simple confirm
                    _display_notifications(notifications, force=force)

            # Reset the dismiss flag for post upgrade notification
            app_setting(
                app_instance_name, "_dismiss_notification_post_upgrade", delete=True
            )

            hook_callback("post_app_upgrade", env=env_dict)
            operation_logger.success()

    permission_sync_to_user()

    logger.success(m18n.n("upgrade_complete"))

    if failed_to_upgrade_apps:
        apps = ""
        for app_id, operation_logger_name in failed_to_upgrade_apps:
            apps += m18n.n(
                "apps_failed_to_upgrade_line",
                app_id=app_id,
                operation_logger_name=operation_logger_name,
            )

        logger.warning(m18n.n("apps_failed_to_upgrade", apps=apps))

    if Moulinette.interface.type == "api":
        return {"notifications": {"POST_UPGRADE": notifications}}


def app_manifest(app, with_screenshot=False):
    from yunohost.utils.form import parse_raw_options

    manifest, extracted_app_folder = _extract_app(app)

    manifest["install"] = parse_raw_options(manifest.get("install", {}), serialize=True)

    # Add a base64 image to be displayed in web-admin
    if with_screenshot and Moulinette.interface.type == "api":
        import base64

        manifest["screenshot"] = None
        screenshots_folder = os.path.join(extracted_app_folder, "doc", "screenshots")

        if os.path.exists(screenshots_folder):
            with os.scandir(screenshots_folder) as it:
                for entry in it:
                    ext = os.path.splitext(entry.name)[1].replace(".", "").lower()
                    if entry.is_file() and ext in ("png", "jpg", "jpeg", "webp", "gif"):
                        with open(entry.path, "rb") as img_file:
                            data = base64.b64encode(img_file.read()).decode("utf-8")
                            manifest["screenshot"] = (
                                f"data:image/{ext};charset=utf-8;base64,{data}"
                            )
                        break

    shutil.rmtree(extracted_app_folder)

    manifest["requirements"] = {}
    for name, passed, values, err in _check_manifest_requirements(
        manifest, action="install"
    ):
        if Moulinette.interface.type == "api":
            manifest["requirements"][name] = {
                "pass": passed,
                "values": values,
            }
        else:
            manifest["requirements"][name] = "ok" if passed else m18n.n(err, **values)

    return manifest


def _confirm_app_install(app, force=False):
    # Ignore if there's nothing for confirm (good quality app), if --force is used
    # or if request on the API (confirm already implemented on the API side)
    if force or Moulinette.interface.type == "api":
        return

    quality = _app_quality(app)
    if quality == "success":
        return

    # i18n: confirm_app_install_warning
    # i18n: confirm_app_install_danger
    # i18n: confirm_app_install_thirdparty

    if quality in ["danger", "thirdparty"]:
        _ask_confirmation("confirm_app_install_" + quality, kind="hard")
    else:
        _ask_confirmation("confirm_app_install_" + quality, kind="soft")


@is_unit_operation()
def app_install(
    operation_logger,
    app,
    label=None,
    args=None,
    no_remove_on_failure=False,
    force=False,
):
    """
    Install apps

    Keyword argument:
        app -- Name, local path or git URL of the app to install
        label -- Custom name for the app
        args -- Serialize arguments for app installation
        no_remove_on_failure -- Debug option to avoid removing the app on a failed installation
        force -- Do not ask for confirmation when installing experimental / low-quality apps
    """

    from yunohost.hook import (
        hook_add,
        hook_remove,
        hook_callback,
        hook_exec,
        hook_exec_with_script_debug_if_failure,
    )
    from yunohost.log import OperationLogger
    from yunohost.permission import (
        permission_create,
        permission_sync_to_user,
    )
    from yunohost.regenconf import manually_modified_files
    from yunohost.utils.form import ask_questions_and_parse_answers
    from yunohost.utils.resources import AppResourceManager
    from yunohost.user import user_list

    # Check if disk space available
    if free_space_in_directory("/") <= 512 * 1000 * 1000:
        raise YunohostValidationError("disk_space_not_sufficient_install")

    _confirm_app_install(app, force)
    manifest, extracted_app_folder = _extract_app(app)

    # Display pre_install notices in cli mode
    if manifest["notifications"]["PRE_INSTALL"] and Moulinette.interface.type == "cli":
        notifications = _filter_and_hydrate_notifications(
            manifest["notifications"]["PRE_INSTALL"]
        )
        _display_notifications(notifications, force=force)

    # Check ID
    if "id" not in manifest or "__" in manifest["id"] or "." in manifest["id"]:
        raise YunohostValidationError("app_id_invalid")

    app_id = manifest["id"]

    if app_id in user_list()["users"].keys():
        raise YunohostValidationError(
            f"There is already a YunoHost user called {app_id} ...", raw_msg=True
        )

    # Check requirements
    for name, passed, values, err in _check_manifest_requirements(
        manifest, action="install"
    ):
        if not passed:
            if name == "ram":
                _ask_confirmation(
                    "confirm_app_insufficient_ram", params=values, force=force
                )
            else:
                raise YunohostValidationError(err, **values)

    _assert_system_is_sane_for_app(manifest, "pre")

    # Check if app can be forked
    instance_number = _next_instance_number_for_app(app_id)
    if instance_number > 1:
        # Change app_id to the forked app id
        app_instance_name = app_id + "__" + str(instance_number)
    else:
        app_instance_name = app_id

    app_setting_path = os.path.join(APPS_SETTING_PATH, app_instance_name)

    # Retrieve arguments list for install script
    raw_options = manifest["install"]
    options, form = ask_questions_and_parse_answers(raw_options, prefilled_answers=args)
    args = form.model_dump(exclude_none=True)

    # Validate domain / path availability for webapps
    # (ideally this should be handled by the resource system for manifest v >= 2
    path_requirement = _guess_webapp_path_requirement(extracted_app_folder)
    _validate_webpath_requirement(args, path_requirement)

    # We'll check that the app didn't brutally edit some system configuration
    manually_modified_files_before_install = manually_modified_files()

    operation_logger.related_to = [
        s for s in operation_logger.related_to if s[0] != "app"
    ]
    operation_logger.related_to.append(("app", app_id))
    operation_logger.start()

    logger.info(m18n.n("app_start_install", app=app_id))

    # Create app directory
    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)
    os.makedirs(app_setting_path)

    # Set initial app settings
    app_settings = {
        "id": app_instance_name,
        "install_time": int(time.time()),
        "current_revision": manifest.get("remote", {}).get("revision", "?"),
    }

    # Save all install options as settings
    for option in options:
        # Except readonly "questions" that don't even have a value
        if option.readonly:
            continue
        # Except user-provider passwords
        # ... which we need to reinject later in the env_dict
        if option.type == "password":
            continue

        app_settings[option.id] = form[option.id]

    _set_app_settings(app_instance_name, app_settings)

    # Move scripts and manifest to the right place
    for file_to_copy in APP_FILES_TO_COPY:
        if os.path.exists(os.path.join(extracted_app_folder, file_to_copy)):
            cp(
                f"{extracted_app_folder}/{file_to_copy}",
                f"{app_setting_path}/{file_to_copy}",
                recursive=True,
            )

    # Hotfix for bug in the webadmin while we fix the actual issue :D
    if label == "undefined":
        label = None

    # Override manifest name by given label
    # This info is also later picked-up by the 'permission' resource initialization
    if label:
        manifest["name"] = label

    try:
        AppResourceManager(app_instance_name, wanted=manifest, current={}).apply(
            rollback_and_raise_exception_if_failure=True,
            operation_logger=operation_logger,
            action="install",
        )
    except (KeyboardInterrupt, EOFError, Exception) as e:
        shutil.rmtree(app_setting_path)
        raise e
    else:
        # Initialize the main permission for the app
        # The permission is initialized with no url associated, and with tile disabled
        # For web app, the root path of the app will be added as url and the tile
        # will be enabled during the app install. C.f. 'app_register_url()' below
        # or the webpath resource
        permission_create(
            app_instance_name + ".main",
            allowed=["all_users"],
            label=manifest["name"],
            show_tile=False,
            protected=False,
        )

    # Prepare env. var. to pass to script
    env_dict = _make_environment_for_app_script(
        app_instance_name, args=args, workdir=extracted_app_folder, action="install"
    )

    # Save all install options as settings
    for option in options:
        # Reinject user-provider passwords which are not in the app settings
        # (cf a few line before)
        if option.type == "password":
            env_dict[option.id] = form[option.id]

    # We want to hav the env_dict in the log ... but not password values
    env_dict_for_logging = env_dict.copy()
    for option in options:
        # Or should it be more generally option.redact ?
        if option.type == "password":
            if f"YNH_APP_ARG_{option.id.upper()}" in env_dict_for_logging:
                del env_dict_for_logging[f"YNH_APP_ARG_{option.id.upper()}"]
            if option.id in env_dict_for_logging:
                del env_dict_for_logging[option.id]

    operation_logger.extra.update({"env": env_dict_for_logging})

    # Execute the app install script
    install_failed = True
    try:
        (
            install_failed,
            failure_message_with_debug_instructions,
        ) = hook_exec_with_script_debug_if_failure(
            os.path.join(extracted_app_folder, "scripts/install"),
            env=env_dict,
            operation_logger=operation_logger,
            error_message_if_script_failed=m18n.n("app_install_script_failed"),
            error_message_if_failed=lambda e: m18n.n(
                "app_install_failed", app=app_id, error=e
            ),
        )
    finally:
        # If success so far, validate that app didn't break important stuff
        if not install_failed:
            try:
                broke_the_system = False
                _assert_system_is_sane_for_app(manifest, "post")
            except Exception as e:
                broke_the_system = True
                logger.error(m18n.n("app_install_failed", app=app_id, error=str(e)))
                failure_message_with_debug_instructions = operation_logger.error(str(e))

        # We'll check that the app didn't brutally edit some system configuration
        manually_modified_files_after_install = manually_modified_files()
        manually_modified_files_by_app = set(
            manually_modified_files_after_install
        ) - set(manually_modified_files_before_install)
        if manually_modified_files_by_app:
            logger.error(
                "Packagers /!\\ This app manually modified some system configuration files! This should not happen! If you need to do so, you should implement a proper conf_regen hook. Those configuration were affected:\n    - "
                + "\n     -".join(manually_modified_files_by_app)
            )
            broke_the_system = True

        # If the install failed or broke the system, we remove it
        if install_failed or broke_the_system:
            # This option is meant for packagers to debug their apps more easily
            if no_remove_on_failure:
                raise YunohostError(
                    f"The installation of {app_id} failed, but was not cleaned up as requested by --no-remove-on-failure.",
                    raw_msg=True,
                )
            else:
                logger.warning(m18n.n("app_remove_after_failed_install"))

            # Setup environment for remove script
            env_dict_remove = _make_environment_for_app_script(
                app_instance_name, workdir=extracted_app_folder, action="remove"
            )

            # Execute remove script
            operation_logger_remove = OperationLogger(
                "remove_on_failed_install",
                [("app", app_instance_name)],
                env=env_dict_remove,
            )
            operation_logger_remove.start()

            # Try to remove the app
            try:
                remove_retcode = hook_exec(
                    os.path.join(extracted_app_folder, "scripts/remove"),
                    args=[app_instance_name],
                    env=env_dict_remove,
                )[0]

            # Here again, calling hook_exec could fail miserably, or get
            # manually interrupted (by mistake or because script was stuck)
            # In that case we still want to proceed with the rest of the
            # removal (permissions, /etc/yunohost/apps/{app} ...)
            except (KeyboardInterrupt, EOFError, Exception):
                remove_retcode = -1
                import traceback

                logger.error(
                    m18n.n("unexpected_error", error="\n" + traceback.format_exc())
                )

            from yunohost.utils.resources import AppResourceManager

            AppResourceManager(
                app_instance_name, wanted={}, current=manifest
            ).apply(rollback_and_raise_exception_if_failure=False, action="remove")

            if remove_retcode != 0:
                msg = m18n.n("app_not_properly_removed", app=app_instance_name)
                logger.warning(msg)
                operation_logger_remove.error(msg)
            else:
                try:
                    _assert_system_is_sane_for_app(manifest, "post")
                except Exception as e:
                    operation_logger_remove.error(e)
                else:
                    operation_logger_remove.success()

            # Clean tmp folders
            shutil.rmtree(app_setting_path)
            shutil.rmtree(extracted_app_folder)

            permission_sync_to_user()

            raise YunohostError(failure_message_with_debug_instructions, raw_msg=True)

    # Clean hooks and add new ones
    hook_remove(app_instance_name)
    if "hooks" in os.listdir(extracted_app_folder):
        for file in os.listdir(extracted_app_folder + "/hooks"):
            hook_add(app_instance_name, extracted_app_folder + "/hooks/" + file)

    # Clean and set permissions
    shutil.rmtree(extracted_app_folder)
    chmod(app_setting_path, 0o600)
    chmod(f"{app_setting_path}/settings.yml", 0o400)
    chown(app_setting_path, "root", recursive=True)

    logger.success(m18n.n("installation_complete"))

    # Get the generated settings to hydrate notifications
    settings = _get_app_settings(app_instance_name)
    notifications = _filter_and_hydrate_notifications(
        manifest["notifications"]["POST_INSTALL"], data=settings
    )

    # Display post_install notices in cli mode
    if notifications and Moulinette.interface.type == "cli":
        _display_notifications(notifications, force=force)

    # Call postinstall hook
    hook_callback("post_app_install", env=env_dict)

    # Return hydrated post install notif for API
    if Moulinette.interface.type == "api":
        return {"notifications": notifications}


@is_unit_operation()
def app_remove(operation_logger, app, purge=False, force_workdir=None):
    """
    Remove app

    Keyword arguments:
        app -- App(s) to delete
        purge -- Remove with all app data
        force_workdir -- Special var to force the working directoy to use, in context such as remove-after-failed-upgrade or remove-after-failed-restore
    """
    from yunohost.utils.resources import AppResourceManager
    from yunohost.hook import hook_exec, hook_remove, hook_callback
    from yunohost.permission import permission_sync_to_user
    from yunohost.domain import domain_list, domain_config_set, _get_raw_domain_settings

    _assert_is_installed(app)

    operation_logger.start()

    logger.info(m18n.n("app_start_remove", app=app))
    app_setting_path = os.path.join(APPS_SETTING_PATH, app)

    if force_workdir:
        # This is when e.g. calling app_remove() from the upgrade-failed case
        # where we want to remove using the *new* remove script and not the old one
        # and also get the new manifest
        # It's especially important during v1->v2 app format transition where the
        # setting names change (e.g. install_dir instead of final_path) and
        # running the old remove script doesnt make sense anymore ...
        tmp_workdir_for_app = tempfile.mkdtemp(prefix="app_", dir=APP_TMP_WORKDIRS)
        os.system(f"cp -a {force_workdir}/* {tmp_workdir_for_app}/")
    else:
        tmp_workdir_for_app = _make_tmp_workdir_for_app(app=app)

    manifest = _get_manifest_of_app(tmp_workdir_for_app)

    remove_script = f"{tmp_workdir_for_app}/scripts/remove"

    env_dict = {}
    env_dict = _make_environment_for_app_script(
        app, workdir=tmp_workdir_for_app, action="remove"
    )
    env_dict["YNH_APP_PURGE"] = str(1 if purge else 0)

    operation_logger.extra.update({"env": env_dict})
    operation_logger.flush()

    try:
        ret = hook_exec(remove_script, env=env_dict)[0]
    # Here again, calling hook_exec could fail miserably, or get
    # manually interrupted (by mistake or because script was stuck)
    # In that case we still want to proceed with the rest of the
    # removal (permissions, /etc/yunohost/apps/{app} ...)
    except (KeyboardInterrupt, EOFError, Exception):
        ret = -1
        import traceback

        logger.error(m18n.n("unexpected_error", error="\n" + traceback.format_exc()))
    finally:
        shutil.rmtree(tmp_workdir_for_app)

    AppResourceManager(app, wanted={}, current=manifest).apply(
        rollback_and_raise_exception_if_failure=False,
        purge_data_dir=purge,
        action="remove",
    )

    if purge and os.path.exists(f"/var/log/{app}"):
        shutil.rmtree(f"/var/log/{app}")

    if os.path.exists(app_setting_path):
        shutil.rmtree(app_setting_path)

    hook_remove(app)

    for domain in domain_list()["domains"]:
        if _get_raw_domain_settings(domain).get("default_app") == app:
            domain_config_set(domain, "feature.app.default_app", "_none")

    if ret == 0:
        logger.success(m18n.n("app_removed", app=app))
        hook_callback("post_app_remove", env=env_dict)
    else:
        logger.warning(m18n.n("app_not_properly_removed", app=app))

    permission_sync_to_user()
    _assert_system_is_sane_for_app(manifest, "post")


@is_unit_operation()
def app_makedefault(operation_logger, app, domain=None, undo=False):
    """
    Redirect domain root to an app

    Keyword argument:
        app
        domain

    """
    from yunohost.domain import _assert_domain_exists, domain_config_set

    app_settings = _get_app_settings(app)
    app_domain = app_settings["domain"]

    if domain is None:
        domain = app_domain

    _assert_domain_exists(domain)

    operation_logger.related_to.append(("domain", domain))

    operation_logger.start()

    if undo:
        domain_config_set(domain, "feature.app.default_app", "_none")
    else:
        domain_config_set(domain, "feature.app.default_app", app)


def app_setting(app, key, value=None, delete=False):
    """
    Set or get an app setting value

    Keyword argument:
        value -- Value to set
        app -- App ID
        key -- Key to get/set
        delete -- Delete the key

    """
    app_settings = _get_app_settings(app) or {}

    # GET
    if value is None and not delete:
        return app_settings.get(key, None)

    # DELETE
    if delete:
        if key in app_settings:
            del app_settings[key]
        else:
            # Don't call _set_app_settings to avoid unecessary writes...
            return

    # SET
    else:
        app_settings[key] = value

    _set_app_settings(app, app_settings)


def app_shell(app):
    """
    Open an interactive shell with the app environment already loaded

    Keyword argument:
        app -- App ID

    """
    subprocess.run(
        [
            "/bin/bash",
            "-c",
            "source /usr/share/yunohost/helpers && ynh_spawn_app_shell " + app,
        ]
    )


def app_register_url(app, domain, path):
    """
    Book/register a web path for a given app

    Keyword argument:
        app -- App which will use the web path
        domain -- The domain on which the app should be registered (e.g. your.domain.tld)
        path -- The path to be registered (e.g. /coffee)
    """
    from yunohost.utils.form import DomainOption, WebPathOption
    from yunohost.permission import (
        permission_url,
        user_permission_update,
        permission_sync_to_user,
    )

    domain = DomainOption.normalize(domain)
    path = WebPathOption.normalize(path)

    # We cannot change the url of an app already installed simply by changing
    # the settings...

    if _is_installed(app):
        settings = _get_app_settings(app)
        if "path" in settings.keys() and "domain" in settings.keys():
            raise YunohostValidationError("app_already_installed_cant_change_url")

    # Check the url is available
    _assert_no_conflicting_apps(domain, path, ignore_app=app)

    app_setting(app, "domain", value=domain)
    app_setting(app, "path", value=path)

    # Initially, the .main permission is created with no url at all associated
    # When the app register/books its web url, we also add the url '/'
    # (meaning the root of the app, domain.tld/path/)
    # and enable the tile to the SSO, and both of this should match 95% of apps
    # For more specific cases, the app is free to change / add urls or disable
    # the tile using the permission helpers.
    permission_url(app + ".main", url="/", sync_perm=False)
    user_permission_update(app + ".main", show_tile=True, sync_perm=False)
    permission_sync_to_user()


def app_ssowatconf():
    """
    Regenerate SSOwat configuration file


    """
    from yunohost.domain import (
        domain_list,
        _get_raw_domain_settings,
        _get_domain_portal_dict,
    )
    from yunohost.permission import user_permission_list

    domain_portal_dict = _get_domain_portal_dict()

    domains = domain_list()["domains"]
    portal_domains = domain_list(exclude_subdomains=True)["domains"]
    all_permissions = user_permission_list(
        full=True, ignore_system_perms=True, absolute_urls=True
    )["permissions"]

    permissions = {
        "core_skipped": {
            "users": [],
            "auth_header": False,
            "public": True,
            "uris": [domain + "/yunohost/admin" for domain in domains]
            + [domain + "/yunohost/api" for domain in domains]
            + [domain + "/yunohost/portalapi" for domain in domains]
            + [
                r"re:^[^/]*/502\.html$",
                r"re:^[^/]*/\.well-known/ynh-diagnosis/.*$",
                r"re:^[^/]*/\.well-known/acme-challenge/.*$",
                r"re:^[^/]*/\.well-known/autoconfig/mail/config-v1\.1\.xml.*$",
            ],
        }
    }

    # FIXME : this could be handled by nginx's regen conf to further simplify ssowat's code ...
    redirected_urls = {}
    for domain in domains:
        default_app = _get_raw_domain_settings(domain).get("default_app")

        if default_app not in ["_none", None] and _is_installed(default_app):
            app_settings = _get_app_settings(default_app)
            app_domain = app_settings["domain"]
            app_path = app_settings["path"]

            # Prevent infinite redirect loop...
            if domain + "/" != app_domain + app_path:
                redirected_urls[domain + "/"] = app_domain + app_path
        elif bool(
            _get_raw_domain_settings(domain).get("enable_public_apps_page", False)
        ):
            redirected_urls[domain + "/"] = domain_portal_dict[domain]

    # Will organize apps by portal domain
    portal_domains_apps = {domain: {} for domain in portal_domains}
    apps_catalog = _load_apps_catalog()["apps"]

    # New permission system
    for perm_name, perm_info in all_permissions.items():
        uris = (
            []
            + ([perm_info["url"]] if perm_info["url"] else [])
            + perm_info["additional_urls"]
        )

        # Ignore permissions for which there's no url defined
        if not uris:
            continue

        app_id = perm_name.split(".")[0]
        app_settings = _get_app_settings(app_id)

        if perm_info["auth_header"]:
            if app_settings.get("auth_header"):
                auth_header = app_settings.get("auth_header")
                assert auth_header in ["basic-with-password", "basic-without-password"]
            else:
                auth_header = "basic-with-password"
        else:
            auth_header = False

        permissions[perm_name] = {
            "users": perm_info["corresponding_users"],
            "auth_header": auth_header,
            "public": "visitors" in perm_info["allowed"],
            "uris": uris,
        }

        # Apps can opt out of the auth spoofing protection using this if they really need to,
        # but that's a huge security hole and ultimately should never happen...
        # ... But some apps live caldav/webdav need this to not break external clients x_x
        apps_that_need_external_auth_maybe = [
            "agendav",
            "baikal",
            "ihatemoney",
            "keeweb",
            "monica",
            "nextcloud",
            "owncloud",
            "paheko",
            "radicale",
            "tracim",
            "vikunja",
            "z-push",
        ]
        protect_against_basic_auth_spoofing = app_settings.get(
            "protect_against_basic_auth_spoofing"
        )
        if protect_against_basic_auth_spoofing is not None:
            permissions[perm_name]["protect_against_basic_auth_spoofing"] = (
                protect_against_basic_auth_spoofing
                not in [False, "False", "false", "0", 0]
            )
        elif app_id.split("__")[0] in apps_that_need_external_auth_maybe:
            permissions[perm_name]["protect_against_basic_auth_spoofing"] = False

        # Next: portal related
        # No need to keep apps that aren't supposed to be displayed in portal
        if not perm_info.get("show_tile", False):
            continue

        setting_path = os.path.join(APPS_SETTING_PATH, app_id)
        local_manifest = _get_manifest_of_app(setting_path)

        app_domain = uris[0].split("/")[0]
        # get "topest" domain
        app_portal_domain = next(
            domain for domain in portal_domains if domain in app_domain
        )
        app_portal_info = {
            "label": perm_info["label"],
            "users": perm_info["corresponding_users"],
            "public": "visitors" in perm_info["allowed"],
            "url": uris[0],
            "description": local_manifest["description"],
        }

        # FIXME : find a smarter way to get this info ? (in the settings maybe..)
        # Also ideally we should not rely on the webadmin route for this, maybe expose these through a different route in nginx idk
        # Also related to "people will want to customize those.."
        app_catalog_info = apps_catalog.get(app_id.split("__")[0])
        if app_catalog_info and "logo_hash" in app_catalog_info:
            app_portal_info["logo"] = (
                f"/yunohost/sso/applogos/{app_catalog_info['logo_hash']}.png"
            )

        portal_domains_apps[app_portal_domain][perm_name] = app_portal_info

    conf_dict = {
        "cookie_secret_file": "/etc/yunohost/.ssowat_cookie_secret",
        "session_folder": "/var/cache/yunohost-portal/sessions",
        "cookie_name": "yunohost.portal",
        "redirected_urls": redirected_urls,
        "domain_portal_urls": domain_portal_dict,
        "permissions": permissions,
    }

    write_to_json("/etc/ssowat/conf.json", conf_dict, sort_keys=True, indent=4)

    # Generate a file per possible portal with available apps
    for domain, apps in portal_domains_apps.items():
        portal_settings = {}

        portal_settings_path = Path(PORTAL_SETTINGS_DIR) / f"{domain}.json"
        if portal_settings_path.exists():
            portal_settings.update(read_json(str(portal_settings_path)))

        # Do no override anything else than "apps" since the file is shared
        # with domain's config panel "portal" options
        portal_settings["apps"] = apps

        write_to_json(
            str(portal_settings_path), portal_settings, sort_keys=True, indent=4
        )

    # Cleanup old files from possibly old domains
    for setting_file in Path(PORTAL_SETTINGS_DIR).iterdir():
        if setting_file.name.endswith(".json"):
            domain = setting_file.name[: -len(".json")]
            if domain not in portal_domains_apps:
                setting_file.unlink()

    logger.debug(m18n.n("ssowat_conf_generated"))


def app_change_label(app, new_label):
    from yunohost.permission import user_permission_update

    installed = _is_installed(app)
    if not installed:
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )
    logger.warning(m18n.n("app_label_deprecated"))
    user_permission_update(app + ".main", label=new_label)


# actions todo list:
# * docstring


def app_action_list(app):
    AppConfigPanel = _get_AppConfigPanel()
    return AppConfigPanel(app).list_actions()


@is_unit_operation()
def app_action_run(operation_logger, app, action, args=None, args_file=None):
    AppConfigPanel = _get_AppConfigPanel()
    return AppConfigPanel(app).run_action(
        action, args=args, args_file=args_file, operation_logger=operation_logger
    )


def app_config_get(app, key="", full=False, export=False):
    """
    Display an app configuration in classic, full or export mode
    """
    if full and export:
        raise YunohostValidationError(
            "You can't use --full and --export together.", raw_msg=True
        )

    if full:
        mode = "full"
    elif export:
        mode = "export"
    else:
        mode = "classic"

    AppConfigPanel = _get_AppConfigPanel()
    try:
        config_ = AppConfigPanel(app)
        return config_.get(key, mode)
    except YunohostValidationError as e:
        if Moulinette.interface.type == "api" and e.key == "config_no_panel":
            # Be more permissive when no config panel found
            return {}
        else:
            raise


@is_unit_operation()
def app_config_set(
    operation_logger, app, key=None, value=None, args=None, args_file=None
):
    """
    Apply a new app configuration
    """

    AppConfigPanel = _get_AppConfigPanel()
    config_ = AppConfigPanel(app)

    return config_.set(key, value, args, args_file, operation_logger=operation_logger)


def _get_AppConfigPanel():
    from yunohost.utils.configpanel import ConfigPanel

    class AppConfigPanel(ConfigPanel):
        entity_type = "app"
        save_path_tpl = os.path.join(APPS_SETTING_PATH, "{entity}/settings.yml")
        config_path_tpl = os.path.join(APPS_SETTING_PATH, "{entity}/config_panel.toml")
        settings_must_be_defined: bool = True

        def _get_raw_settings(self) -> "RawSettings":
            return self._call_config_script("show")

        def _apply(
            self,
            form: "FormModel",
            config: "ConfigPanelModel",
            previous_settings: dict[str, Any],
            exclude: Union["AbstractSetIntStr", "MappingIntStrAny", None] = None,
        ) -> None:
            env = {key: str(value) for key, value in form.model_dump().items()}
            return_content = self._call_config_script("apply", env=env)

            # If the script returned validation error
            # raise a ValidationError exception using
            # the first key
            errors = return_content.get("validation_errors")
            if errors:
                for key, message in errors.items():
                    raise YunohostValidationError(
                        "app_argument_invalid",
                        name=key,
                        error=message,
                    )

        def _run_action(self, form: "FormModel", action_id: str) -> None:
            env = {key: str(value) for key, value in form.model_dump().items()}
            self._call_config_script(action_id, env=env)

        def _call_config_script(
            self, action: str, env: dict[str, Any] | None = None
        ) -> dict[str, Any]:
            from yunohost.hook import hook_exec

            if env is None:
                env = {}

            # Add default config script if needed
            config_script = os.path.join(
                APPS_SETTING_PATH, self.entity, "scripts", "config"
            )
            if not os.path.exists(config_script):
                logger.debug("Adding a default config script")
                default_script = """#!/bin/bash
source /usr/share/yunohost/helpers
ynh_abort_if_errors
ynh_app_config_run $1
"""
                write_to_file(config_script, default_script)

            # Call config script to extract current values
            logger.debug(f"Calling '{action}' action from config script")
            app = self.entity
            app_setting_path = os.path.join(APPS_SETTING_PATH, self.entity)
            app_script_env = _make_environment_for_app_script(
                app, workdir=app_setting_path
            )
            app_script_env.update(env)
            app_script_env["YNH_APP_CONFIG_PANEL_OPTIONS_TYPES_AND_BINDS"] = (
                self._dump_options_types_and_binds()
            )

            ret, values = hook_exec(config_script, args=[action], env=app_script_env)
            if ret != 0:
                if action == "show":
                    raise YunohostError("app_config_unable_to_read")
                elif action == "apply":
                    raise YunohostError("app_config_unable_to_apply")
                else:
                    raise YunohostError("app_action_failed", action=action, app=app)
            return values

        def _get_partial_raw_config(self):

            raw_config = super()._get_partial_raw_config()

            self._compute_binds(raw_config)

            return raw_config

        def _compute_binds(self, raw_config):
            """
            This compute the 'bind' statement for every option
            In particular to handle __FOOBAR__ syntax
            and to handle the fact that bind statements may be defined panel-wide or section-wide
            """

            settings = _get_app_settings(self.entity)

            for panel_id, panel in raw_config.items():
                if not isinstance(panel, dict):
                    continue
                bind_panel = panel.get("bind")
                for section_id, section in panel.items():
                    if not isinstance(section, dict):
                        continue
                    bind_section = section.get("bind")
                    if not bind_section:
                        bind_section = bind_panel
                    elif bind_section[-1] == ":" and bind_panel and ":" in bind_panel:
                        selector, bind_panel_file = bind_panel.split(":")
                        if ">" in bind_section:
                            bind_section = bind_section + bind_panel_file
                        else:
                            bind_section = selector + bind_section + bind_panel_file
                    for option_id, option in section.items():
                        if not isinstance(option, dict):
                            continue
                        bind = option.get("bind")
                        if not bind:
                            if bind_section:
                                bind = bind_section
                            else:
                                bind = "settings"
                        elif bind[-1] == ":" and bind_section and ":" in bind_section:
                            selector, bind_file = bind_section.split(":")
                            if ">" in bind:
                                bind = bind + bind_file
                            else:
                                bind = selector + bind + bind_file
                        if (
                            bind == "settings"
                            and option.get("type", "string") == "file"
                        ):
                            bind = "null"
                        if option.get("type", "string") == "button":
                            bind = "null"

                        option["bind"] = _hydrate_app_template(bind, settings)

        def _dump_options_types_and_binds(self):
            raw_config = self._get_partial_raw_config()
            lines = []
            for panel_id, panel in raw_config.items():
                if not isinstance(panel, dict):
                    continue
                for section_id, section in panel.items():
                    if not isinstance(section, dict):
                        continue
                    for option_id, option in section.items():
                        if not isinstance(option, dict):
                            continue
                        lines.append(
                            "|".join(
                                [
                                    option_id,
                                    option.get("type", "string"),
                                    option["bind"],
                                ]
                            )
                        )
            return "\n".join(lines)

    return AppConfigPanel


app_settings_cache: Dict[str, Dict[str, Any]] = {}
app_settings_cache_timestamp: Dict[str, float] = {}


def _get_app_settings(app: str) -> Dict[str, Any]:
    """
    Get settings of an installed app

    Keyword arguments:
        app -- The app id (like nextcloud__2)

    """
    _assert_is_installed(app)

    global app_settings_cache
    global app_settings_cache_timestamp

    app_setting_path = os.path.join(APPS_SETTING_PATH, app, "settings.yml")
    app_setting_timestamp = os.path.getmtime(app_setting_path)

    # perf: app settings are cached using the settings.yml's modification date,
    # such that we don't have to worry too much about calling this function
    # too many times (because ultimately parsing yml is not free)
    if app_settings_cache_timestamp.get(app) == app_setting_timestamp:
        return app_settings_cache[app].copy()

    try:
        with open(app_setting_path) as f:
            settings = yaml.safe_load(f) or {}
        # If label contains unicode char, this may later trigger issues when building strings...
        # FIXME: this should be propagated to read_yaml so that this fix applies everywhere I think...
        settings = {k: v for k, v in settings.items()}

        # App settings should never be empty, there should always be at least some standard, internal keys like id, install_time etc.
        # Otherwise, this probably means that the app settings disappeared somehow...
        if not settings:
            logger.error(
                f"It looks like settings.yml for {app} is empty ... This should not happen ..."
            )
            logger.error(m18n.n("app_not_correctly_installed", app=app))
            return {}

        # Make the app id available as $app too
        settings["app"] = app

        # FIXME: it's not clear why this code exists... Shouldn't we hard-define 'id' as $app ...?
        if app != settings["id"]:
            return {}

        # Cache the settings
        app_settings_cache[app] = settings.copy()
        app_settings_cache_timestamp[app] = app_setting_timestamp

        return settings
    except (IOError, TypeError, KeyError):
        logger.error(m18n.n("app_not_correctly_installed", app=app))
    return {}


def _set_app_settings(app, settings):
    """
    Set settings of an app

    Keyword arguments:
        app_id -- The app id (like nextcloud__2)
        settings -- Dict with app settings

    """
    with open(os.path.join(APPS_SETTING_PATH, app, "settings.yml"), "w") as f:
        yaml.safe_dump(settings, f, default_flow_style=False)

    if app in app_settings_cache_timestamp:
        del app_settings_cache_timestamp[app]
    if app in app_settings_cache:
        del app_settings_cache[app]


def _parse_app_version(v):

    if v in ["?", "-"]:
        return (0, 0)

    try:
        if "~" in v:
            return (
                version.parse(v.split("~")[0]),
                int(v.split("~")[1].replace("ynh", "")),
            )
        else:
            return (version.parse(v), 0)
    except Exception as e:
        raise YunohostError(f"Failed to parse app version '{v}' : {e}", raw_msg=True)


def _get_manifest_of_app(path):
    "Get app manifest stored in json or in toml"

    # sample data to get an idea of what is going on
    # this toml extract:
    #
    # license = "free"
    # url = "https://example.com"
    # multi_instance = true
    # version = "1.0~ynh1"
    # packaging_format = 1
    # services = ["nginx", "php7.0-fpm", "mysql"]
    # id = "ynhexample"
    # name = "YunoHost example app"
    #
    # [requirements]
    # yunohost = ">= 3.5"
    #
    # [maintainer]
    # url = "http://example.com"
    # name = "John doe"
    # email = "john.doe@example.com"
    #
    # [description]
    # fr = "Exemple de package d'application pour YunoHost."
    # en = "Example package for YunoHost application."
    #
    # [arguments]
    #     [arguments.install.domain]
    #     type = "domain"
    #     example = "example.com"
    #         [arguments.install.domain.ask]
    #         fr = "Choisissez un nom de domaine pour ynhexample"
    #         en = "Choose a domain name for ynhexample"
    #
    # will be parsed into this:
    #
    # OrderedDict([(u'license', u'free'),
    #              (u'url', u'https://example.com'),
    #              (u'multi_instance', True),
    #              (u'version', u'1.0~ynh1'),
    #              (u'packaging_format', 1),
    #              (u'services', [u'nginx', u'php7.0-fpm', u'mysql']),
    #              (u'id', u'ynhexample'),
    #              (u'name', u'YunoHost example app'),
    #              (u'requirements', OrderedDict([(u'yunohost', u'>= 3.5')])),
    #              (u'maintainer',
    #               OrderedDict([(u'url', u'http://example.com'),
    #                            (u'name', u'John doe'),
    #                            (u'email', u'john.doe@example.com')])),
    #              (u'description',
    #               OrderedDict([(u'fr',
    #                             u"Exemple de package d'application pour YunoHost."),
    #                            (u'en',
    #                             u'Example package for YunoHost application.')])),
    #              (u'arguments',
    #               OrderedDict([(u'install',
    #                             OrderedDict([(u'domain',
    #                                           OrderedDict([(u'type', u'domain'),
    #                                                        (u'example',
    #                                                         u'example.com'),
    #                                                        (u'ask',
    #                                                         OrderedDict([(u'fr',
    #                                                                       u'Choisissez un nom de domaine pour ynhexample'),
    #                                                                      (u'en',
    #                                                                       u'Choose a domain name for ynhexample')]))])),
    #
    # and needs to be converted into this:
    #
    # {
    #     "name": "YunoHost example app",
    #     "id": "ynhexample",
    #     "packaging_format": 1,
    #     "description": {
    #     ¦   "en": "Example package for YunoHost application.",
    #     ¦   "fr": "Exemple de package d’application pour YunoHost."
    #     },
    #     "version": "1.0~ynh1",
    #     "url": "https://example.com",
    #     "license": "free",
    #     "maintainer": {
    #     ¦   "name": "John doe",
    #     ¦   "email": "john.doe@example.com",
    #     ¦   "url": "http://example.com"
    #     },
    #     "requirements": {
    #     ¦   "yunohost": ">= 3.5"
    #     },
    #     "multi_instance": true,
    #     "services": [
    #     ¦   "nginx",
    #     ¦   "php7.0-fpm",
    #     ¦   "mysql"
    #     ],
    #     "arguments": {
    #     ¦   "install" : [
    #     ¦   ¦   {
    #     ¦   ¦   ¦   "name": "domain",
    #     ¦   ¦   ¦   "type": "domain",
    #     ¦   ¦   ¦   "ask": {
    #     ¦   ¦   ¦   ¦   "en": "Choose a domain name for ynhexample",
    #     ¦   ¦   ¦   ¦   "fr": "Choisissez un nom de domaine pour ynhexample"
    #     ¦   ¦   ¦   },
    #     ¦   ¦   ¦   "example": "example.com"
    #     ¦   ¦   },

    if os.path.exists(os.path.join(path, "manifest.toml")):
        manifest = read_toml(os.path.join(path, "manifest.toml"))
    elif os.path.exists(os.path.join(path, "manifest.json")):
        manifest = read_json(os.path.join(path, "manifest.json"))
    else:
        raise YunohostError(
            f"There doesn't seem to be any manifest file in {path} ... It looks like an app was not correctly installed/removed.",
            raw_msg=True,
        )

    manifest["packaging_format"] = float(
        str(manifest.get("packaging_format", "")).strip() or "0"
    )

    manifest["install"] = _set_default_ask_questions(manifest.get("install", {}))
    manifest["doc"], manifest["notifications"] = _parse_app_doc_and_notifications(path)

    return manifest


def _parse_app_doc_and_notifications(path):
    doc = {}
    notification_names = ["PRE_INSTALL", "POST_INSTALL", "PRE_UPGRADE", "POST_UPGRADE"]

    for filepath in glob.glob(os.path.join(path, "doc") + "/*.md"):
        # to be improved : [a-z]{2,3} is a clumsy way of parsing the
        # lang code ... some lang code are more complex that this é_è
        m = re.match("([A-Z]*)(_[a-z]{2,3})?.md", filepath.split("/")[-1])

        if not m:
            # FIXME: shall we display a warning ? idk
            continue

        pagename, lang = m.groups()

        if pagename in notification_names:
            continue

        lang = lang.strip("_") if lang else "en"

        if pagename not in doc:
            doc[pagename] = {}

        try:
            doc[pagename][lang] = read_file(filepath).strip()
        except Exception as e:
            logger.error(e)
            continue

    notifications = {}

    for step in notification_names:
        notifications[step] = {}
        for filepath in glob.glob(os.path.join(path, "doc", f"{step}*.md")):
            m = re.match(step + "(_[a-z]{2,3})?.md", filepath.split("/")[-1])
            if not m:
                continue
            pagename = "main"
            lang = m.groups()[0].strip("_") if m.groups()[0] else "en"
            if pagename not in notifications[step]:
                notifications[step][pagename] = {}
            try:
                notifications[step][pagename][lang] = read_file(filepath).strip()
            except Exception as e:
                logger.error(e)
                continue

        for filepath in glob.glob(os.path.join(path, "doc", f"{step}.d") + "/*.md"):
            m = re.match(
                r"([A-Za-z0-9\.\~]*)(_[a-z]{2,3})?.md", filepath.split("/")[-1]
            )
            if not m:
                continue
            pagename, lang = m.groups()
            lang = lang.strip("_") if lang else "en"
            if pagename not in notifications[step]:
                notifications[step][pagename] = {}

            try:
                notifications[step][pagename][lang] = read_file(filepath).strip()
            except Exception as e:
                logger.error(e)
                continue

    return doc, notifications


def _hydrate_app_template(template, data):
    # Apply jinja for stuff like {% if .. %} blocks,
    # but only if there's indeed an if block (to try to reduce overhead or idk)
    if "{%" in template:
        from jinja2 import Template

        template = Template(template).render(**data)

    stuff_to_replace = set(re.findall(r"__[A-Z0-9]+?[A-Z0-9_]*?[A-Z0-9]*?__", template))

    for stuff in stuff_to_replace:
        varname = stuff.strip("_").lower()

        if varname in data:
            template = template.replace(stuff, str(data[varname]))

    return template.strip()


def _set_default_ask_questions(questions, script_name="install"):
    # arguments is something like
    # { "domain":
    #       {
    #         "type": "domain",
    #         ....
    #       },
    #    "path": {
    #         "type": "path",
    #         ...
    #       },
    #       ...
    # }

    # We set a default for any question with these matching (type, name)
    #                           type       namei
    # N.B. : this is only for install script ... should be reworked for other
    # scripts if we supports args for other scripts in the future...
    questions_with_default = [
        ("domain", "domain"),  # i18n: app_manifest_install_ask_domain
        ("path", "path"),  # i18n: app_manifest_install_ask_path
        ("password", "password"),  # i18n: app_manifest_install_ask_password
        ("user", "admin"),  # i18n: app_manifest_install_ask_admin
        ("boolean", "is_public"),  # i18n: app_manifest_install_ask_is_public
        (
            "group",
            "init_main_permission",
        ),  # i18n: app_manifest_install_ask_init_main_permission
        (
            "group",
            "init_admin_permission",
        ),  # i18n: app_manifest_install_ask_init_admin_permission
    ]

    for question_id, question in questions.items():
        question["id"] = question_id

        # If this question corresponds to a question with default ask message...
        if any(
            (question.get("type"), question["id"]) == question_with_default
            for question_with_default in questions_with_default
        ):
            # The key is for example "app_manifest_install_ask_domain"
            question["ask"] = m18n.n(f"app_manifest_{script_name}_ask_{question['id']}")

            # Also it in fact doesn't make sense for any of those questions to have an example value nor a default value...
            if question.get("type") in ["domain", "user", "password"]:
                if "example" in question:
                    del question["example"]
                if "default" in question:
                    del question["default"]

    return questions


def _is_app_repo_url(string: str) -> bool:
    string = string.strip()

    # Dummy test for ssh-based stuff ... should probably be improved somehow
    if "@" in string:
        return True

    return bool(APP_REPO_URL.match(string))


def _app_quality(src: str) -> str:
    """
    app may in fact be an app name, an url, or a path
    """

    raw_app_catalog = _load_apps_catalog()["apps"]
    if src in raw_app_catalog or _is_app_repo_url(src):
        # If we got an app name directly (e.g. just "wordpress"), we gonna test this name
        if src in raw_app_catalog:
            app_name_to_test = src
        # If we got an url like "https://github.com/foo/bar_ynh, we want to
        # extract "bar" and test if we know this app
        elif ("http://" in src) or ("https://" in src):
            app_name_to_test = src.strip("/").split("/")[-1].replace("_ynh", "")
        else:
            # FIXME : watdo if '@' in app ?
            return "thirdparty"

        if app_name_to_test in raw_app_catalog:
            state = raw_app_catalog[app_name_to_test].get("state", "notworking")
            level = raw_app_catalog[app_name_to_test].get("level", None)
            if state in ["working", "validated"]:
                if isinstance(level, int) and level >= 5:
                    return "success"
                elif isinstance(level, int) and level > 0:
                    return "warning"
            return "danger"
        else:
            return "thirdparty"

    elif os.path.exists(src):
        return "thirdparty"
    else:
        if "http://" in src or "https://" in src:
            logger.error(
                f"{src} is not a valid app url: app url are expected to look like https://domain.tld/path/to/repo_ynh"
            )
        raise YunohostValidationError("app_unknown")


def _extract_app(src: str) -> Tuple[Dict, str]:
    """
    src may be an app name, an url, or a path
    """

    raw_app_catalog = _load_apps_catalog()["apps"]

    # App is an appname in the catalog
    if src in raw_app_catalog:
        if "git" not in raw_app_catalog[src]:
            raise YunohostValidationError("app_unsupported_remote_type")

        app_info = raw_app_catalog[src]
        url = app_info["git"]["url"]
        branch = app_info["git"]["branch"]
        revision = str(app_info["git"]["revision"])
        return _extract_app_from_gitrepo(
            url, branch=branch, revision=revision, app_info=app_info
        )
    # App is a git repo url
    elif _is_app_repo_url(src):
        url = src.strip().strip("/")
        # gitlab urls may look like 'https://domain/org/group/repo/-/tree/testing'
        # compated to github urls looking like 'https://domain/org/repo/tree/testing'
        if "/-/" in url:
            url = url.replace("/-/", "/")
        if "/tree/" in url:
            url, branch = url.split("/tree/", 1)
        else:
            branch = None
        return _extract_app_from_gitrepo(url, branch=branch)
    # App is a local folder
    elif os.path.exists(src):
        return _extract_app_from_folder(src)
    else:
        if "http://" in src or "https://" in src:
            logger.error(
                f"{src} is not a valid app url: app url are expected to look like https://domain.tld/path/to/repo_ynh"
            )
        raise YunohostValidationError("app_unknown")


def _extract_app_from_folder(path: str) -> Tuple[Dict, str]:
    """
    Unzip / untar / copy application tarball or directory to a tmp work directory

    Keyword arguments:
        path -- Path of the tarball or directory
    """
    logger.debug(m18n.n("extracting"))

    path = os.path.abspath(path)

    extracted_app_folder = _make_tmp_workdir_for_app()

    if os.path.isdir(path):
        shutil.rmtree(extracted_app_folder)
        if path[-1] != "/":
            path = path + "/"
        cp(path, extracted_app_folder, recursive=True)
        # Change the last edit time which is used in _make_tmp_workdir_for_app
        # to cleanup old dir ... otherwise it may end up being incorrectly removed
        # at the end of the safety-backup-before-upgrade :/
        os.system(f"touch {extracted_app_folder}")
    else:
        try:
            shutil.unpack_archive(path, extracted_app_folder)
        except Exception:
            raise YunohostError("app_extraction_failed")

    try:
        if len(os.listdir(extracted_app_folder)) == 1:
            for folder in os.listdir(extracted_app_folder):
                extracted_app_folder = extracted_app_folder + "/" + folder
    except IOError:
        raise YunohostError("app_install_files_invalid")

    manifest = _get_manifest_of_app(extracted_app_folder)
    manifest["lastUpdate"] = int(time.time())

    logger.debug(m18n.n("done"))

    manifest["remote"] = {"type": "file", "path": path}
    manifest["quality"] = {"level": -1, "state": "thirdparty"}
    manifest["antifeatures"] = []
    manifest["potential_alternative_to"] = []

    return manifest, extracted_app_folder


def _extract_app_from_gitrepo(
    url: str, branch: Optional[str] = None, revision: str = "HEAD", app_info: Dict = {}
) -> Tuple[Dict, str]:
    logger.debug("Checking default branch")

    try:
        git_ls_remote = check_output(
            ["git", "ls-remote", "--symref", url, "HEAD"],
            env={"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"},
            shell=False,
        )
    except Exception as e:
        logger.error(str(e))
        raise YunohostError("app_sources_fetch_failed")

    if not branch:
        default_branch = None
        try:
            for line in git_ls_remote.split("\n"):
                # Look for the line formated like :
                # ref: refs/heads/master	HEAD
                if "ref: refs/heads/" in line:
                    line = line.replace("/", " ").replace("\t", " ")
                    default_branch = line.split()[3]
        except Exception:
            pass

        if not default_branch:
            logger.warning("Failed to parse default branch, trying 'main'")
            branch = "main"
        else:
            if default_branch in ["testing", "dev"]:
                logger.warning(
                    f"Trying 'master' branch instead of default '{default_branch}'"
                )
                branch = "master"
            else:
                branch = default_branch

    logger.debug(m18n.n("downloading"))

    extracted_app_folder = _make_tmp_workdir_for_app()

    # Download only this commit
    try:
        # We don't use git clone because, git clone can't download
        # a specific revision only
        ref = branch if revision == "HEAD" else revision
        run_commands([["git", "init", extracted_app_folder]], shell=False)
        run_commands(
            [
                ["git", "remote", "add", "origin", url],
                ["git", "fetch", "--depth=1", "origin", ref],
                ["git", "reset", "--hard", "FETCH_HEAD"],
            ],
            cwd=extracted_app_folder,
            shell=False,
        )
    except subprocess.CalledProcessError:
        raise YunohostError("app_sources_fetch_failed")
    else:
        logger.debug(m18n.n("done"))

    manifest = _get_manifest_of_app(extracted_app_folder)

    # Store remote repository info into the returned manifest
    manifest["remote"] = {"type": "git", "url": url, "branch": branch}
    if revision == "HEAD":
        try:
            # Get git last commit hash
            cmd = f"git ls-remote --exit-code {url} {branch} | awk '{{print $1}}'"
            manifest["remote"]["revision"] = check_output(cmd)
        except Exception as e:
            logger.warning(f"cannot get last commit hash because: {e}")
    else:
        manifest["remote"]["revision"] = revision
        manifest["lastUpdate"] = app_info.get("lastUpdate")

    manifest["quality"] = {
        "level": app_info.get("level", -1),
        "state": app_info.get("state", "thirdparty"),
    }
    manifest["antifeatures"] = app_info.get("antifeatures", [])
    manifest["potential_alternative_to"] = app_info.get("potential_alternative_to", [])

    return manifest, extracted_app_folder


def _list_upgradable_apps():
    upgradable_apps = list(app_list(upgradable=True)["apps"])

    # Retrieve next manifest pre_upgrade notifications
    for app in upgradable_apps:
        absolute_app_name, _ = _parse_app_instance_name(app["id"])
        manifest, extracted_app_folder = _extract_app(absolute_app_name)
        app["notifications"] = {}
        if manifest["notifications"]["PRE_UPGRADE"]:
            app["notifications"]["PRE_UPGRADE"] = _filter_and_hydrate_notifications(
                manifest["notifications"]["PRE_UPGRADE"],
                app["current_version"],
                app["settings"],
            )
        del app["settings"]
        shutil.rmtree(extracted_app_folder)

    return upgradable_apps


#
# ############################### #
#        Small utilities          #
# ############################### #
#


def _is_installed(app: str) -> bool:
    return os.path.isdir(APPS_SETTING_PATH + app)


def _assert_is_installed(app: str) -> None:
    if not _is_installed(app):
        raise YunohostValidationError(
            "app_not_installed", app=app, all_apps=_get_all_installed_apps_id()
        )


def _installed_apps() -> List[str]:
    return os.listdir(APPS_SETTING_PATH)


def _get_all_installed_apps_id():
    """
    Return something like:
       ' * app1
         * app2
         * ...'
    """

    all_apps_ids = sorted(_installed_apps())

    all_apps_ids_formatted = "\n * ".join(all_apps_ids)
    all_apps_ids_formatted = "\n * " + all_apps_ids_formatted

    return all_apps_ids_formatted


def _check_manifest_requirements(
    manifest: Dict, action: str = ""
) -> Iterator[Tuple[str, bool, object, str]]:
    """Check if required packages are met from the manifest"""

    app_id = manifest["id"]
    logger.debug(m18n.n("app_requirements_checking", app=app_id))

    # Packaging format
    if manifest["packaging_format"] not in [2]:
        raise YunohostValidationError("app_packaging_format_not_supported")

    # Yunohost version
    required_yunohost_version = (
        manifest["integration"].get("yunohost", "4.3").strip(">= ")
    )
    current_yunohost_version = get_ynh_package_version("yunohost")["version"]

    yield (
        "required_yunohost_version",
        version.parse(required_yunohost_version)
        <= version.parse(current_yunohost_version),
        {"current": current_yunohost_version, "required": required_yunohost_version},
        "app_yunohost_version_not_supported",  # i18n: app_yunohost_version_not_supported
    )

    # Architectures
    arch_requirement = manifest["integration"]["architectures"]
    arch = system_arch()

    yield (
        "arch",
        arch_requirement in ["all", "?"] or arch in arch_requirement,
        {"current": arch, "required": ", ".join(arch_requirement)},
        "app_arch_not_supported",  # i18n: app_arch_not_supported
    )

    # Multi-instance
    if action == "install":
        multi_instance = manifest["integration"]["multi_instance"] is True
        if not multi_instance:
            apps = _installed_apps()
            sibling_apps = [
                a for a in apps if a == app_id or a.startswith(f"{app_id}__")
            ]
            multi_instance = len(sibling_apps) == 0

        yield (
            "install",
            multi_instance,
            {"app": app_id},
            "app_already_installed",  # i18n: app_already_installed
        )

    # Disk
    if action == "install":
        root_free_space = free_space_in_directory("/")
        var_free_space = free_space_in_directory("/var")
        if manifest["integration"]["disk"] == "?":
            has_enough_disk = True
        else:
            disk_req_bin = human_to_binary(manifest["integration"]["disk"])
            has_enough_disk = (
                root_free_space > disk_req_bin and var_free_space > disk_req_bin
            )
        free_space = binary_to_human(min(root_free_space, var_free_space))

        yield (
            "disk",
            has_enough_disk,
            {"current": free_space, "required": manifest["integration"]["disk"]},
            "app_not_enough_disk",  # i18n: app_not_enough_disk
        )

    # Ram
    ram_requirement = manifest["integration"]["ram"]
    ram, swap = ram_available()
    # Is "include_swap" really useful ? We should probably decide wether to always include it or not instead
    if ram_requirement.get("include_swap", False):
        ram += swap
    can_build = ram_requirement["build"] == "?" or ram > human_to_binary(
        ram_requirement["build"]
    )
    can_run = ram_requirement["runtime"] == "?" or ram > human_to_binary(
        ram_requirement["runtime"]
    )

    # Some apps have a higher runtime value than build ...
    if ram_requirement["build"] != "?" and ram_requirement["runtime"] != "?":
        max_build_runtime = (
            ram_requirement["build"]
            if human_to_binary(ram_requirement["build"])
            > human_to_binary(ram_requirement["runtime"])
            else ram_requirement["runtime"]
        )
    else:
        max_build_runtime = ram_requirement["build"]

    yield (
        "ram",
        can_build and can_run,
        {"current": binary_to_human(ram), "required": max_build_runtime},
        "app_not_enough_ram",  # i18n: app_not_enough_ram
    )


def _guess_webapp_path_requirement(app_folder: str) -> str:
    # If there's only one "domain" and "path", validate that domain/path
    # is an available url and normalize the path.

    manifest = _get_manifest_of_app(app_folder)
    raw_questions = manifest["install"]

    domain_questions = [
        question
        for question in raw_questions.values()
        if question.get("type") == "domain"
    ]
    path_questions = [
        question
        for question in raw_questions.values()
        if question.get("type") == "path"
    ]

    if len(domain_questions) == 0 and len(path_questions) == 0:
        return ""
    if len(domain_questions) == 1 and len(path_questions) == 1:
        return "domain_and_path"
    if len(domain_questions) == 1 and len(path_questions) == 0:
        # Check if there's a permission with url being a string
        perm_resource = manifest.get("resources", {}).get("permissions")
        if perm_resource is not None and isinstance(
            perm_resource.get("main", {}).get("url"), str
        ):
            return "full_domain"

    return "?"


def _validate_webpath_requirement(
    args: Dict[str, Any], path_requirement: str, ignore_app=None
) -> None:
    domain = args.get("domain")
    path = args.get("path")

    if path_requirement == "domain_and_path":
        _assert_no_conflicting_apps(domain, path, ignore_app=ignore_app)

    elif path_requirement == "full_domain":
        _assert_no_conflicting_apps(
            domain, "/", full_domain=True, ignore_app=ignore_app
        )


def _get_conflicting_apps(domain, path, ignore_app=None):
    """
    Return a list of all conflicting apps with a domain/path (it can be empty)

    Keyword argument:
        domain -- The domain for the web path (e.g. your.domain.tld)
        path -- The path to check (e.g. /coffee)
        ignore_app -- An optional app id to ignore (c.f. the change_url usecase)
    """

    from yunohost.domain import _assert_domain_exists
    from yunohost.utils.form import DomainOption, WebPathOption

    domain = DomainOption.normalize(domain)
    path = WebPathOption.normalize(path)

    # Abort if domain is unknown
    _assert_domain_exists(domain)

    # Fetch apps map
    apps_map = app_map(raw=True)

    # Loop through all apps to check if path is taken by one of them
    conflicts = []
    if domain in apps_map:
        # Loop through apps
        for p, a in apps_map[domain].items():
            if a["id"] == ignore_app:
                continue
            if path == p or (
                not path.startswith("/.well-known/") and (path == "/" or p == "/")
            ):
                conflicts.append((p, a["id"], a["label"]))

    return conflicts


def _assert_no_conflicting_apps(domain, path, ignore_app=None, full_domain=False):
    conflicts = _get_conflicting_apps(domain, path, ignore_app)

    if conflicts:
        apps = []
        for path, app_id, app_label in conflicts:
            apps.append(f" * {domain}{path} → {app_label} ({app_id})")

        if full_domain:
            raise YunohostValidationError("app_full_domain_unavailable", domain=domain)
        else:
            raise YunohostValidationError(
                "app_location_unavailable", apps="\n".join(apps)
            )


def _make_environment_for_app_script(
    app,
    args={},
    args_prefix="APP_ARG_",
    workdir=None,
    action=None,
):
    app_setting_path = os.path.join(APPS_SETTING_PATH, app)

    manifest = _get_manifest_of_app(workdir if workdir else app_setting_path)

    app_id, app_instance_nb = _parse_app_instance_name(app)

    env_dict = {
        "YNH_DEFAULT_PHP_VERSION": "8.2",
        "YNH_APP_ID": app_id,
        "YNH_APP_INSTANCE_NAME": app,
        "YNH_APP_INSTANCE_NUMBER": str(app_instance_nb),
        "YNH_APP_MANIFEST_VERSION": manifest.get("version", "?"),
        "YNH_APP_PACKAGING_FORMAT": str(manifest["packaging_format"]),
        "YNH_HELPERS_VERSION": str(
            manifest.get("integration", {}).get("helpers_version")
            or manifest["packaging_format"]
        ).replace(".0", ""),
        "YNH_ARCH": system_arch(),
        "YNH_DEBIAN_VERSION": debian_version(),
    }

    if workdir:
        env_dict["YNH_APP_BASEDIR"] = workdir

    if action:
        env_dict["YNH_APP_ACTION"] = action

    for arg_name, arg_value in args.items():
        arg_name_upper = arg_name.upper()
        env_dict[f"YNH_{args_prefix}{arg_name_upper}"] = str(arg_value)

    # Load all settings
    env_dict["app"] = app
    data_to_redact = []
    prefixes_or_suffixes_to_redact = [
        "pwd",
        "pass",
        "passwd",
        "password",
        "passphrase",
        "secret",
        "key",
        "token",
    ]

    for setting_name, setting_value in _get_app_settings(app).items():
        # Ignore special internal settings like checksum__
        # (not a huge deal to load them but idk...)
        if setting_name.startswith("checksum__"):
            continue

        setting_value = str(setting_value)
        env_dict[setting_name] = setting_value

        # Check if we should redact this setting value
        # (the check on the setting length exists to prevent stupid stuff like redacting empty string or something which is actually just 0/1, true/false, ...
        if len(setting_value) > 6 and any(
            setting_name.startswith(p) or setting_name.endswith(p)
            for p in prefixes_or_suffixes_to_redact
        ):
            data_to_redact.append(setting_value)

    # Special weird case for backward compatibility...
    # 'path' was loaded into 'path_url' .....
    if "path" in env_dict:
        env_dict["path_url"] = env_dict["path"]

    for operation_logger in OperationLogger._instances:
        operation_logger.data_to_redact.extend(data_to_redact)

    return env_dict


def _parse_app_instance_name(app_instance_name: str) -> Tuple[str, int]:
    """
    Parse a Yunohost app instance name and extracts the original appid
    and the application instance number

    'yolo'      -> ('yolo', 1)
    'yolo1'     -> ('yolo1', 1)
    'yolo__0'   -> ('yolo__0', 1)
    'yolo__1'   -> ('yolo', 1)
    'yolo__23'  -> ('yolo', 23)
    'yolo__42__72'    -> ('yolo__42', 72)
    'yolo__23qdqsd'   -> ('yolo__23qdqsd', 1)
    'yolo__23qdqsd56' -> ('yolo__23qdqsd56', 1)
    """
    match = re_app_instance_name.match(app_instance_name)
    assert match, f"Could not parse app instance name : {app_instance_name}"
    appid = match.groupdict().get("appid")
    app_instance_nb_ = match.groupdict().get("appinstancenb") or "1"
    if not appid:
        raise Exception(f"Could not parse app instance name : {app_instance_name}")
    if not str(app_instance_nb_).isdigit():
        raise Exception(f"Could not parse app instance name : {app_instance_name}")
    else:
        app_instance_nb = int(str(app_instance_nb_))

    return (appid, app_instance_nb)


def _next_instance_number_for_app(app):
    # Get list of sibling apps, such as {app}, {app}__2, {app}__4
    apps = _installed_apps()
    sibling_app_ids = [a for a in apps if a == app or a.startswith(f"{app}__")]

    # Find the list of ids, such as [1, 2, 4]
    sibling_ids = [_parse_app_instance_name(a)[1] for a in sibling_app_ids]

    # Find the first 'i' that's not in the sibling_ids list already
    i = 1
    while True:
        if i not in sibling_ids:
            return i
        else:
            i += 1


def _make_tmp_workdir_for_app(app=None):
    # Create parent dir if it doesn't exists yet
    if not os.path.exists(APP_TMP_WORKDIRS):
        os.makedirs(APP_TMP_WORKDIRS)

    now = int(time.time())

    # Cleanup old dirs (if any)
    for dir_ in os.listdir(APP_TMP_WORKDIRS):
        path = os.path.join(APP_TMP_WORKDIRS, dir_)
        # We only delete folders older than an arbitary 12 hours
        # This is to cover the stupid case of upgrades
        # Where many app will call 'yunohost backup create'
        # from the upgrade script itself,
        # which will also call this function while the upgrade
        # script itself is running in one of those dir...
        # It could be that there are other edge cases
        # such as app-install-during-app-install
        if os.stat(path).st_mtime < now - 12 * 3600:
            shutil.rmtree(path)
    tmpdir = tempfile.mkdtemp(prefix="app_", dir=APP_TMP_WORKDIRS)

    # Copy existing app scripts, conf, ... if an app arg was provided
    if app:
        os.system(f"cp -a {APPS_SETTING_PATH}/{app}/* {tmpdir}")

    return tmpdir


def unstable_apps():
    output = []
    deprecated_apps = ["mailman", "ffsync"]

    for infos in app_list(full=True)["apps"]:
        if (
            not infos.get("from_catalog")
            or infos.get("from_catalog").get("state")
            in [
                "inprogress",
                "notworking",
            ]
            or infos["id"] in deprecated_apps
        ):
            output.append(infos["id"])

    return output


def _assert_system_is_sane_for_app(manifest, when):
    from yunohost.service import service_status

    logger.debug("Checking that required services are up and running...")

    # FIXME: in the past we had more elaborate checks about mariadb/php/postfix
    # though they werent very formalized. Ideally we should rework this in the
    # context of packaging v2, which implies deriving what services are
    # relevant to check from the manifst

    services = ["nginx", "fail2ban"]

    # Wait if a service is reloading
    test_nb = 0

    while test_nb < 16:
        if not any(s for s in services if service_status(s)["status"] == "reloading"):
            break
        time.sleep(0.5)
        test_nb += 1

    # List services currently down and raise an exception if any are found
    services_status = {s: service_status(s) for s in services}
    faulty_services = [
        f"{s} ({status['status']})"
        for s, status in services_status.items()
        if status["status"] != "running"
    ]

    if faulty_services:
        if when == "pre":
            raise YunohostValidationError(
                "app_action_cannot_be_ran_because_required_services_down",
                services=", ".join(faulty_services),
            )
        elif when == "post":
            raise YunohostError(
                "app_action_broke_system", services=", ".join(faulty_services)
            )

    if dpkg_is_broken():
        if when == "pre":
            raise YunohostValidationError("dpkg_is_broken")
        elif when == "post":
            raise YunohostError("this_action_broke_dpkg")


def app_dismiss_notification(app, name):
    assert isinstance(name, str)
    name = name.lower()
    assert name in ["post_install", "post_upgrade"]
    _assert_is_installed(app)

    app_setting(app, f"_dismiss_notification_{name}", value="1")


def _notification_is_dismissed(name, settings):
    # Check for _dismiss_notiication_$name setting and also auto-dismiss
    # notifications after one week (otherwise people using mostly CLI would
    # never really dismiss the notification and it would be displayed forever)

    if name == "POST_INSTALL":
        return (
            settings.get("_dismiss_notification_post_install")
            or (int(time.time()) - settings.get("install_time", 0)) / (24 * 3600) > 7
        )
    elif name == "POST_UPGRADE":
        # Check on update_time also implicitly prevent the post_upgrade notification
        # from being displayed after install, because update_time is only set during upgrade
        return (
            settings.get("_dismiss_notification_post_upgrade")
            or (int(time.time()) - settings.get("update_time", 0)) / (24 * 3600) > 7
        )
    else:
        return False


def _filter_and_hydrate_notifications(notifications, current_version=None, data={}):
    def is_version_more_recent_than_current_version(name, current_version):
        current_version = str(current_version)
        return _parse_app_version(name) > _parse_app_version(current_version)

    out = {
        # Should we render the markdown maybe? idk
        name: _hydrate_app_template(_value_for_locale(content_per_lang), data)
        for name, content_per_lang in notifications.items()
        if current_version is None
        or name == "main"
        or is_version_more_recent_than_current_version(name, current_version)
    }

    # Filter out empty notifications (notifications may be empty because of if blocks)
    return {
        name: content for name, content in out.items() if content and content.strip()
    }


def _display_notifications(notifications, force=False):
    if not notifications:
        return

    for name, content in notifications.items():
        print("==========")
        print(content)
    print("==========")

    # i18n: confirm_notifications_read
    _ask_confirmation("confirm_notifications_read", kind="simple", force=force)


# FIXME: move this to Moulinette
def _ask_confirmation(
    question: str,
    params: dict = {},
    kind: str = "hard",
    force: bool = False,
):
    """
    Ask confirmation

    Keyword argument:
        question -- m18n key or string
        params -- dict of values passed to the string formating
        kind -- "hard": ask with "Yes, I understand", "soft": "Y/N", "simple": "press enter"
        force -- Will not ask for confirmation

    """
    if force or Moulinette.interface.type == "api":
        return

    # If ran from the CLI in a non-interactive context,
    # skip confirmation (except in hard mode)
    if not os.isatty(1) and kind in ["simple", "soft"]:
        return
    if kind == "simple":
        answer = Moulinette.prompt(
            m18n.n(question, answers="Press enter to continue", **params),
            color="yellow",
        )
        answer = True
    elif kind == "soft":
        answer = Moulinette.prompt(
            m18n.n(question, answers="Y/N", **params), color="yellow"
        )
        answer = answer.upper() == "Y"
    else:
        answer = Moulinette.prompt(
            m18n.n(question, answers="Yes, I understand", **params), color="red"
        )
        answer = answer == "Yes, I understand"

    if not answer:
        raise YunohostError("aborting")


def regen_mail_app_user_config_for_dovecot_and_postfix(only=None):
    dovecot = True if only in [None, "dovecot"] else False
    postfix = True if only in [None, "postfix"] else False

    from yunohost.utils.password import _hash_user_password

    postfix_map = []
    dovecot_passwd = []
    for app in _installed_apps():
        settings = _get_app_settings(app)

        if "domain" not in settings or "mail_pwd" not in settings:
            continue

        mail_user = settings.get("mail_user", app)
        mail_domain = settings.get("mail_domain", settings["domain"])

        if dovecot:
            hashed_password = _hash_user_password(settings["mail_pwd"])
            dovecot_passwd.append(
                f"{app}:{hashed_password}::::::allow_nets=::1,127.0.0.1/24,local,mail={mail_user}@{mail_domain}"
            )
        if postfix:
            postfix_map.append(f"{mail_user}@{mail_domain} {app}")

    if dovecot:
        app_senders_passwd = "/etc/dovecot/app-senders-passwd"
        content = "# This file is regenerated automatically.\n# Please DO NOT edit manually ... changes will be overwritten!"
        content += "\n" + "\n".join(dovecot_passwd)
        write_to_file(app_senders_passwd, content)
        chmod(app_senders_passwd, 0o440)
        chown(app_senders_passwd, "root", "dovecot")

    if postfix:
        app_senders_map = "/etc/postfix/app_senders_login_maps"
        content = "# This file is regenerated automatically.\n# Please DO NOT edit manually ... changes will be overwritten!"
        content += "\n" + "\n".join(postfix_map)
        write_to_file(app_senders_map, content)
        chmod(app_senders_map, 0o440)
        chown(app_senders_map, "postfix", "root")
        os.system(f"postmap {app_senders_map} 2>/dev/null")
        chmod(app_senders_map + ".db", 0o640)
        chown(app_senders_map + ".db", "postfix", "root")
