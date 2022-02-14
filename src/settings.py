import os
import json
import subprocess

from datetime import datetime
from collections import OrderedDict

from moulinette import m18n
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.config import ConfigPanel, Question
from moulinette.utils.log import getActionLogger
from yunohost.regenconf import regen_conf
from yunohost.firewall import firewall_reload
from yunohost.log import is_unit_operation
from yunohost.utils.legacy import translate_legacy_settings_to_configpanel_settings

logger = getActionLogger("yunohost.settings")

SETTINGS_PATH = "/etc/yunohost/settings.yaml"
SETTINGS_PATH_OTHER_LOCATION = "/etc/yunohost/settings-%s.yaml"


def is_boolean(value):
    TRUE = ["true", "on", "yes", "y", "1"]
    FALSE = ["false", "off", "no", "n", "0"]

    """
    Ensure a string value is intended as a boolean

    Keyword arguments:
        arg -- The string to check

    Returns:
        (is_boolean, boolean_value)

    """
    if isinstance(value, bool):
        return True, value
    if value in [0, 1]:
        return True, bool(value)
    elif isinstance(value, str):
        if str(value).lower() in TRUE + FALSE:
            return True, str(value).lower() in TRUE
        else:
            return False, None
    else:
        return False, None


# a settings entry is in the form of:
# namespace.subnamespace.name: {type, value, default, description, [choices]}
# choices is only for enum
# the keyname can have as many subnamespace as needed but should have at least
# one level of namespace

# description is implied from the translated strings
# the key is "global_settings_setting_%s" % key.replace(".", "_")

# type can be:
# * bool
# * int
# * string
# * enum (in the form of a python list)

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

    if mode == "classic" and key == "":
        raise YunohostValidationError(
            "Missing key"
        )

    settings = SettingsConfigPanel()
    key = translate_legacy_settings_to_configpanel_settings(key)
    return settings.get(key, mode)


def settings_list(full=False, export=True):
    """
    List all entries of the settings

    """
    
    if full:
        export = False

    return settings_get(full=full, export=export)


@is_unit_operation()
def settings_set(operation_logger, key=None, value=None, args=None, args_file=None):
    """
    Set an entry value in the settings

    Keyword argument:
        key -- Settings key
        value -- New value

    """
    Question.operation_logger = operation_logger
    settings = SettingsConfigPanel()
    key = translate_legacy_settings_to_configpanel_settings(key)
    return settings.set(key, value, args, args_file, operation_logger=operation_logger)


@is_unit_operation()
def settings_reset(operation_logger, key):
    """
    Set an entry value to its default one

    Keyword argument:
        key -- Settings key

    """

    settings = SettingsConfigPanel()
    key = translate_legacy_settings_to_configpanel_settings(key)
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
    entity_type = "settings"
    save_path_tpl = SETTINGS_PATH
    save_mode = "diff"

    def __init__(
        self, config_path=None, save_path=None, creation=False
    ):
        super().__init__("settings")

    def _apply(self):
        super()._apply()

        settings = { k: v for k, v in self.future_values.items() if self.values.get(k) != v }
        for setting_name, value in settings.items():
            try:
                trigger_post_change_hook(setting_name, self.values.get(setting_name), value)
            except Exception as e:
                logger.error(f"Post-change hook for setting failed : {e}")
                raise

    def get(self, key="", mode="classic"):
        result = super().get(key=key, mode=mode)

        if mode == "full":
            for panel, section, option in self._iterate():
                if m18n.key_exists(self.config["i18n"] + "_" + option["id"] + "_help"):
                    option["help"] = m18n.n(self.config["i18n"] + "_" + option["id"] + "_help")
            return self.config

        return result

    def reset(self, key = "", operation_logger=None):
        self.filter_key = key

        # Read config panel toml
        self._get_config_panel()

        if not self.config:
            raise YunohostValidationError("config_no_panel")

        # Replace all values with default values
        self.values = self._get_default_values()

        Question.operation_logger = operation_logger

        if operation_logger:
            operation_logger.start()

        try:
            self._apply()
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

        logger.success("Config updated as expected")
        operation_logger.success()


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


@post_change_hook("ssowat_panel_overlay_enabled")
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
@post_change_hook("postfix_compatibility")
def reconfigure_postfix(setting_name, old_value, new_value):
    if old_value != new_value:
        regen_conf(names=["postfix"])


@post_change_hook("pop3_enabled")
def reconfigure_dovecot(setting_name, old_value, new_value):
    dovecot_package = "dovecot-pop3d"

    environment = os.environ.copy()
    environment.update({"DEBIAN_FRONTEND": "noninteractive"})

    if new_value == "True":
        command = [
            "apt-get",
            "-y",
            "--no-remove",
            "-o Dpkg::Options::=--force-confdef",
            "-o Dpkg::Options::=--force-confold",
            "install",
            dovecot_package,
        ]
        subprocess.call(command, env=environment)
        if old_value != new_value:
            regen_conf(names=["dovecot"])
    else:
        if old_value != new_value:
            regen_conf(names=["dovecot"])
        command = ["apt-get", "-y", "remove", dovecot_package]
        subprocess.call(command, env=environment)
