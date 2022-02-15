import subprocess
import time
import urllib
import os
import json

from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.tools import Migration
from yunohost.settings import settings_set
from yunohost.utils.legacy import translate_legacy_settings_to_configpanel_settings

logger = getActionLogger("yunohost.migration")

OLD_SETTINGS_PATH = "/etc/yunohost/settings.json"

class MyMigration(Migration):

    "Migrate old global settings to the new ConfigPanel global settings"

    dependencies = ["migrate_to_bullseye"]

    def run(self):
        if not os.path.exists(OLD_SETTINGS_PATH):
            return

        try:
            old_settings = json.load(open(OLD_SETTINGS_PATH))
        except Exception as e:
            raise YunohostError("global_settings_cant_open_settings", reason=e)

        settings = { translate_legacy_settings_to_configpanel_settings(k): v['value'] for k,v in old_settings.items() }

        if settings.get('email.smtp.smtp_relay_host') != "":
            settings['email.smtp.smtp_relay_enabled'] = "True"

        args = urllib.parse.urlencode(settings)
        settings_set(args=args)
