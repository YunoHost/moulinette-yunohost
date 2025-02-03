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

import os
import subprocess
from logging import getLogger
from typing import TYPE_CHECKING, Any, Union

from moulinette import m18n

from yunohost.firewall import firewall_reload
from yunohost.log import is_unit_operation
from yunohost.regenconf import regen_conf
from yunohost.utils.configpanel import ConfigPanel, parse_filter_key
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.form import BaseOption

if TYPE_CHECKING:
    from typing import cast

    from moulinette.utils.log import MoulinetteLogger
    from pydantic.typing import AbstractSetIntStr, MappingIntStrAny

    from yunohost.log import OperationLogger
    from yunohost.utils.configpanel import (
        ConfigPanelGetMode,
        ConfigPanelModel,
        RawSettings,
    )
    from yunohost.utils.form import FormModel

    logger = cast(MoulinetteLogger, getLogger("yunohost.settings"))
else:
    logger = getLogger("yunohost.settings")

SETTINGS_PATH = "/etc/yunohost/settings.yml"


def settings_get(key="", full=False, export=False):
    """
    Get an entry value in the settings

    Keyword argument:
        key -- Settings key

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

    settings = SettingsConfigPanel()
    return settings.get(key, mode)


def settings_list(full=False):
    settings = settings_get(full=full)

    if full:
        return settings
    else:
        return {
            k: v
            for k, v in settings.items()
            if not k.startswith("security.root_access")
        }


@is_unit_operation()
def settings_set(operation_logger, key=None, value=None, args=None, args_file=None):
    """
    Set an entry value in the settings

    Keyword argument:
        key -- Settings key
        value -- New value

    """
    BaseOption.operation_logger = operation_logger
    settings = SettingsConfigPanel()
    return settings.set(key, value, args, args_file, operation_logger=operation_logger)


@is_unit_operation()
def settings_reset(operation_logger, key):
    """
    Set an entry value to its default one

    Keyword argument:
        key -- Settings key

    """

    settings = SettingsConfigPanel()
    return settings.reset(key, operation_logger=operation_logger)


@is_unit_operation()
def settings_reset_all(operation_logger):
    """
    Reset all settings to their default value

    Keyword argument:
        yes -- Yes I'm sure I want to do that

    """
    settings = SettingsConfigPanel()
    return settings.reset(operation_logger=operation_logger)


class SettingsConfigPanel(ConfigPanel):
    entity_type = "global"
    save_path_tpl = SETTINGS_PATH
    save_mode = "diff"
    virtual_settings = {"root_password", "root_password_confirm", "passwordless_sudo"}

    def __init__(self, config_path=None, save_path=None, creation=False) -> None:
        super().__init__("settings")

    def get(
        self, key: str | None = None, mode: "ConfigPanelGetMode" = "classic"
    ) -> Any:
        result = super().get(key=key, mode=mode)

        # Dirty hack to let settings_get() to work from a python script
        if isinstance(result, str) and result in ["True", "False"]:
            result = bool(result == "True")

        return result

    def reset(
        self,
        key: str | None = None,
        operation_logger: Union["OperationLogger", None] = None,
    ) -> None:
        self.filter_key = parse_filter_key(key)

        # Read config panel toml
        self.config, self.form = self._get_config_panel(prevalidate=True)

        # FIXME find a better way to exclude previous settings
        previous_settings = self.form.dict()

        for option in self.config.options:
            if not option.readonly and (
                option.optional or option.default not in {None, ""}
            ):
                # FIXME Mypy complains about option.default not being a valid type for normalize but this should be ok
                self.form[option.id] = option.normalize(option.default, option)  # type: ignore

        # FIXME Not sure if this is need (redact call to operation logger does it on all the instances)
        # BaseOption.operation_logger = operation_logger

        if operation_logger:
            operation_logger.start()
        try:
            self._apply(self.form, self.config, previous_settings)
        except YunohostError:
            raise
        # Script got manually interrupted ...
        # N.B. : KeyboardInterrupt does not inherit from Exception
        except (KeyboardInterrupt, EOFError):
            error = m18n.n("operation_interrupted")
            logger.error(m18n.n("config_apply_failed", error=error))
            raise
        # Something wrong happened in Yunohost's code (most probably hook_exec)
        except Exception:
            import traceback

            error = m18n.n("unexpected_error", error="\n" + traceback.format_exc())
            logger.error(m18n.n("config_apply_failed", error=error))
            raise

        logger.success(m18n.n("global_settings_reset_success"))

        if operation_logger:
            operation_logger.success()

    def _get_raw_settings(self) -> "RawSettings":
        raw_settings = super()._get_raw_settings()

        # Specific logic for those settings who are "virtual" settings
        # and only meant to have a custom setter mapped to tools_rootpw
        raw_settings["root_password"] = ""
        raw_settings["root_password_confirm"] = ""

        # Specific logic for virtual setting "passwordless_sudo"
        try:
            from yunohost.utils.ldap import _get_ldap_interface

            ldap = _get_ldap_interface()
            raw_settings["passwordless_sudo"] = "!authenticate" in ldap.search(
                "ou=sudo", "cn=admins", ["sudoOption"]
            )[0].get("sudoOption", [])
        except Exception:
            raw_settings["passwordless_sudo"] = False

        return raw_settings

    def _apply(
        self,
        form: "FormModel",
        config: "ConfigPanelModel",
        previous_settings: dict[str, Any],
        exclude: Union["AbstractSetIntStr", "MappingIntStrAny", None] = None,
    ) -> None:
        root_password = form.get("root_password", None)
        root_password_confirm = form.get("root_password_confirm", None)
        passwordless_sudo = form.get("passwordless_sudo", None)

        if root_password and root_password.strip():
            if root_password != root_password_confirm:
                raise YunohostValidationError("password_confirmation_not_the_same")

            from yunohost.tools import tools_rootpw

            tools_rootpw(root_password, check_strength=True)

        if passwordless_sudo is not None:
            from yunohost.utils.ldap import _get_ldap_interface

            ldap = _get_ldap_interface()
            ldap.update(
                "cn=admins,ou=sudo",
                {"sudoOption": "!authenticate" if passwordless_sudo else set()},
            )

        # First save settings except virtual + default ones
        super()._apply(form, config, previous_settings, exclude=self.virtual_settings)
        next_settings = {
            k: v
            for k, v in form.dict(exclude=self.virtual_settings).items()
            if previous_settings.get(k) != v
        }

        for setting_name, value in next_settings.items():
            try:
                # FIXME not sure to understand why we need the previous value if
                # updated_settings has already been filtered
                trigger_post_change_hook(
                    setting_name, previous_settings.get(setting_name), value
                )
            except Exception as e:
                logger.error(f"Post-change hook for setting failed : {e}")
                raise


# Meant to be a dict of setting_name -> function to call
post_change_hooks = {}


def post_change_hook(setting_name):
    # TODO: Check that setting_name exists
    def decorator(func):
        post_change_hooks[setting_name] = func
        return func

    return decorator


def trigger_post_change_hook(setting_name, old_value, new_value):
    if setting_name not in post_change_hooks:
        logger.debug(f"Nothing to do after changing setting {setting_name}")
        return

    f = post_change_hooks[setting_name]
    f(setting_name, old_value, new_value)


# ===========================================
#
# Actions to trigger when changing a setting
# You can define such an action with :
#
# @post_change_hook("your.setting.name")
# def some_function_name(setting_name, old_value, new_value):
#     # Do some stuff
#
# ===========================================


@post_change_hook("portal_theme")
def regen_ssowatconf(setting_name, old_value, new_value):
    if old_value != new_value:
        from yunohost.app import app_ssowatconf

        app_ssowatconf()


@post_change_hook("tls_passthrough_enabled")
@post_change_hook("tls_passthrough_list")
@post_change_hook("nginx_redirect_to_https")
@post_change_hook("nginx_compatibility")
@post_change_hook("webadmin_allowlist_enabled")
@post_change_hook("webadmin_allowlist")
def reconfigure_nginx(setting_name, old_value, new_value):
    if old_value != new_value:
        regen_conf(names=["nginx"])


@post_change_hook("security_experimental_enabled")
def reconfigure_nginx_and_yunohost(setting_name, old_value, new_value):
    if old_value != new_value:
        regen_conf(names=["nginx", "yunohost"])


@post_change_hook("ssh_compatibility")
@post_change_hook("ssh_password_authentication")
def reconfigure_ssh(setting_name, old_value, new_value):
    if old_value != new_value:
        regen_conf(names=["ssh"])


@post_change_hook("ssh_port")
def reconfigure_ssh_and_fail2ban(setting_name, old_value, new_value):
    if old_value != new_value:
        regen_conf(names=["ssh", "fail2ban"])
        firewall_reload()


@post_change_hook("smtp_allow_ipv6")
@post_change_hook("smtp_relay_host")
@post_change_hook("smtp_relay_port")
@post_change_hook("smtp_relay_user")
@post_change_hook("smtp_relay_password")
@post_change_hook("smtp_backup_mx_domains")
@post_change_hook("smtp_backup_mx_emails_whitelisted")
@post_change_hook("postfix_compatibility")
def reconfigure_postfix(setting_name, old_value, new_value):
    if old_value != new_value:
        regen_conf(names=["postfix"])


@post_change_hook("pop3_enabled")
def reconfigure_dovecot(setting_name, old_value, new_value):

    environment = os.environ.copy()
    environment.update({"DEBIAN_FRONTEND": "noninteractive"})

    # Depending on how consistent the config panel is, it may spit 1 or True or ..? ...
    if new_value:
        command = [
            "apt-get",
            "-y",
            "--no-remove",
            "-o Dpkg::Options::=--force-confdef",
            "-o Dpkg::Options::=--force-confold",
            "install",
            "dovecot-pop3d",
        ]
        subprocess.call(command, env=environment)
        if old_value != new_value:
            regen_conf(names=["dovecot"])
    else:
        if old_value != new_value:
            regen_conf(names=["dovecot"])
        command = ["apt-get", "-y", "remove", "dovecot-pop3d"]
        subprocess.call(command, env=environment)
