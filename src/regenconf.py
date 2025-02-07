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

import hashlib
import json
import os
import shutil
from datetime import datetime
from difflib import unified_diff
from logging import getLogger

import yaml
from moulinette import m18n
from moulinette.utils.filesystem import mkdir
from moulinette.utils.process import check_output

from yunohost.hook import hook_callback, hook_list
from yunohost.log import is_unit_operation
from yunohost.utils.error import YunohostError

BASE_CONF_PATH = "/var/cache/yunohost/regenconf"
BACKUP_CONF_DIR = os.path.join(BASE_CONF_PATH, "backup")
PENDING_CONF_DIR = os.path.join(BASE_CONF_PATH, "pending")
REGEN_CONF_FILE = "/etc/yunohost/regenconf.yml"

logger = getLogger("yunohost.regenconf")


# FIXME : those ain't just services anymore ... what are we supposed to do with this ...
# FIXME : check for all reference of 'service' close to operation_logger stuff
@is_unit_operation([("names", "configuration")])
def regen_conf(
    operation_logger,
    names=None,
    with_diff=False,
    force=False,
    dry_run=False,
    list_pending=False,
):
    """
    Regenerate the configuration file(s)

    Keyword argument:
        names -- Categories to regenerate configuration of
        with_diff -- Show differences in case of configuration changes
        force -- Override all manual modifications in configuration files
        dry_run -- Show what would have been regenerated
        list_pending -- List pending configuration files and exit

    """

    from yunohost.settings import settings_get

    if names is None:
        names = []

    result = {}

    # Return the list of pending conf
    if list_pending:
        pending_conf = _get_pending_conf(names)

        if not with_diff:
            return pending_conf

        for category, conf_files in pending_conf.items():
            for system_path, pending_path in conf_files.items():
                pending_conf[category][system_path] = {
                    "pending_conf": pending_path,
                    "diff": _get_files_diff(system_path, pending_path, True),
                }

        return pending_conf

    if not dry_run:
        operation_logger.related_to = [("configuration", x) for x in names]
        if not names:
            operation_logger.name_parameter_override = "all"
        elif len(names) != 1:
            operation_logger.name_parameter_override = (
                str(len(operation_logger.related_to)) + "_categories"
            )
        operation_logger.start()

    # Clean pending conf directory
    if os.path.isdir(PENDING_CONF_DIR):
        if not names:
            shutil.rmtree(PENDING_CONF_DIR, ignore_errors=True)
        else:
            for name in names:
                shutil.rmtree(os.path.join(PENDING_CONF_DIR, name), ignore_errors=True)
    else:
        mkdir(PENDING_CONF_DIR, 0o755, True)

    # Execute hooks for pre-regen
    # element 2 and 3 with empty string is because of legacy...
    pre_args = ["pre", "", ""]

    def _pre_call(name, priority, path, args):
        # create the pending conf directory for the category
        category_pending_path = os.path.join(PENDING_CONF_DIR, name)
        mkdir(category_pending_path, 0o755, True, uid="root")

        # return the arguments to pass to the script
        return pre_args + [
            category_pending_path,
        ]

    ssh_explicitly_specified = isinstance(names, list) and "ssh" in names

    # By default, we regen everything
    if not names:
        names = hook_list("conf_regen", list_by="name", show_info=False)["hooks"]

    # [Optimization] We compute and feed the domain list to the conf regen
    # hooks to avoid having to call "yunohost domain list" so many times which
    # ends up in wasted time (about 3~5 seconds per call on a RPi2)
    from yunohost.domain import domain_list

    env = {}
    # Well we can only do domain_list() if postinstall is done ...
    # ... but hooks that effectively need the domain list are only
    # called only after the 'installed' flag is set so that's all good,
    # though kinda tight-coupled to the postinstall logic :s
    if os.path.exists("/etc/yunohost/installed"):
        env["YNH_DOMAINS"] = " ".join(domain_list()["domains"])
        env["YNH_MAIN_DOMAINS"] = " ".join(
            domain_list(exclude_subdomains=True)["domains"]
        )
    env["YNH_CONTEXT"] = "regenconf"
    # perf: Export all global settings as a environment variable
    # so that scripts dont have to call 'yunohost settings get' manually
    # which is painful performance-wise
    env["YNH_SETTINGS"] = json.dumps(settings_get("", export=True))
    env["FORCE"] = "true" if force else "false"

    pre_result = hook_callback("conf_regen", names, pre_callback=_pre_call, env=env)

    # Keep only the hook names with at least one success
    names = [
        hook
        for hook, infos in pre_result.items()
        if any(result["state"] == "succeed" for result in infos.values())
    ]

    # FIXME : what do in case of partial success/failure ...
    if not names:
        ret_failed = [
            hook
            for hook, infos in pre_result.items()
            if any(result["state"] == "failed" for result in infos.values())
        ]
        raise YunohostError("regenconf_failed", categories=", ".join(ret_failed))

    # Set the processing method
    _regen = _process_regen_conf if not dry_run else lambda *a, **k: True

    operation_logger.related_to = []

    # Iterate over categories and process pending conf
    for category, conf_files in _get_pending_conf(names).items():
        if not dry_run:
            operation_logger.related_to.append(("configuration", category))

        if dry_run:
            logger.debug(m18n.n("regenconf_pending_applying", category=category))
        else:
            logger.debug(m18n.n("regenconf_dry_pending_applying", category=category))

        conf_hashes = _get_conf_hashes(category)
        succeed_regen = {}
        failed_regen = {}

        # Here we are doing some weird legacy shit
        # The thing is, on some very old or specific setup, the sshd_config file
        # was absolutely not managed by the regenconf ...
        # But we now want to make sure that this file is managed.
        # However, we don't want to overwrite a specific custom sshd_config
        # which may make the admin unhappy ...
        # So : if the hash for this file does not exists, we set the hash as the
        # hash of the pending configuration ...
        # That way, the file will later appear as manually modified.
        sshd_config = "/etc/ssh/sshd_config"
        if (
            category == "ssh"
            and sshd_config not in conf_hashes
            and sshd_config in conf_files
        ):
            conf_hashes[sshd_config] = _calculate_hash(conf_files[sshd_config])
            _update_conf_hashes(category, conf_hashes)

        # Consider the following scenario:
        # - you add a domain foo.bar
        # - the regen-conf creates file /etc/dnsmasq.d/foo.bar
        # - the admin manually *deletes* /etc/dnsmasq.d/foo.bar
        # - the file is now understood as manually deleted because there's the old file hash in regenconf.yml
        #
        # ... so far so good, that's the expected behavior.
        #
        # But then:
        # - the admin remove domain foo.bar entirely
        # - but now the hash for /etc/dnsmasq.d/foo.bar is *still* in
        # regenconf.yml and and the file is still flagged as manually
        # modified/deleted... And the user cannot even do anything about it
        # except removing the hash in regenconf.yml...
        #
        # Expected behavior: it should forget about that
        # hash because dnsmasq's regen-conf doesn't say anything about what's
        # the state of that file so it should assume that it should be deleted.
        #
        # - then the admin tries to *re-add* foo.bar !
        # - ... but because the file is still flagged as manually modified
        # the regen-conf refuses to re-create the file.
        #
        # Excepted behavior : the regen-conf should have forgot about the hash
        # from earlier and this wouldnt happen.
        # ------
        # conf_files contain files explicitly set by the current regen conf run
        # conf_hashes contain all files known from the past runs
        # we compare these to get the list of stale hashes and flag the file as
        # "should be removed"
        stale_files = set(conf_hashes.keys()) - set(conf_files.keys())
        stale_files_with_non_empty_hash = [f for f in stale_files if conf_hashes.get(f)]
        for f in stale_files_with_non_empty_hash:
            conf_files[f] = None
        # </> End discussion about stale file hashes

        force_update_hashes_for_this_category = False

        for system_path, pending_path in conf_files.items():
            logger.debug(
                "processing pending conf '%s' to system conf '%s'",
                pending_path,
                system_path,
            )
            conf_status = None
            regenerated = False

            # Get the diff between files
            conf_diff = (
                _get_files_diff(system_path, pending_path, True) if with_diff else None
            )

            # Check if the conf must be removed
            to_remove = (
                True if pending_path and os.path.getsize(pending_path) == 0 else False
            )

            # Retrieve and calculate hashes
            system_hash = _calculate_hash(system_path)
            saved_hash = conf_hashes.get(system_path, None)
            new_hash = None if to_remove else _calculate_hash(pending_path)

            # -> configuration was previously managed by yunohost but should now
            # be removed / unmanaged
            if system_path in stale_files_with_non_empty_hash:
                # File is already deleted, so let's just silently forget about this hash entirely
                if not system_hash:
                    logger.debug("> forgetting about stale file/hash")
                    conf_hashes[system_path] = None
                    conf_status = "forget-about-it"
                    regenerated = True
                # Otherwise there's still a file on the system but it's not managed by
                # Yunohost anymore... But if user requested --force we shall
                # force-erase it
                elif force:
                    logger.debug("> force-remove stale file")
                    regenerated = _regen(system_path)
                    conf_status = "force-removed"
                # Otherwise, flag the file as manually modified
                else:
                    logger.warning(
                        m18n.n("regenconf_file_manually_modified", conf=system_path)
                    )
                    conf_status = "modified"

            # -> system conf does not exists
            elif not system_hash:
                if to_remove:
                    logger.debug("> system conf is already removed")
                    os.remove(pending_path)
                    conf_hashes[system_path] = None
                    conf_status = "forget-about-it"
                    force_update_hashes_for_this_category = True
                    continue
                elif not saved_hash or force:
                    if force:
                        logger.debug("> system conf has been manually removed")
                        conf_status = "force-created"
                    else:
                        logger.debug("> system conf does not exist yet")
                        conf_status = "created"
                    regenerated = _regen(system_path, pending_path, save=False)
                else:
                    logger.info(
                        m18n.n("regenconf_file_manually_removed", conf=system_path)
                    )
                    conf_status = "removed"

            # -> system conf is not managed yet
            elif not saved_hash:
                logger.debug("> system conf is not managed yet")
                if system_hash == new_hash:
                    logger.debug("> no changes to system conf has been made")
                    conf_status = "managed"
                    regenerated = True
                elif not to_remove:
                    # If the conf exist but is not managed yet, and is not to be removed,
                    # we assume that it is safe to regen it, since the file is backuped
                    # anyway (by default in _regen), as long as we warn the user
                    # appropriately.
                    logger.info(
                        m18n.n(
                            "regenconf_now_managed_by_yunohost",
                            conf=system_path,
                            category=category,
                        )
                    )
                    regenerated = _regen(system_path, pending_path)
                    conf_status = "new"
                elif force:
                    regenerated = _regen(system_path)
                    conf_status = "force-removed"
                else:
                    logger.info(
                        m18n.n(
                            "regenconf_file_kept_back",
                            conf=system_path,
                            category=category,
                        )
                    )
                    conf_status = "unmanaged"

            # -> system conf has not been manually modified
            elif system_hash == saved_hash:
                if to_remove:
                    regenerated = _regen(system_path)
                    conf_status = "removed"
                elif system_hash != new_hash:
                    regenerated = _regen(system_path, pending_path)
                    conf_status = "updated"
                else:
                    logger.debug("> system conf is already up-to-date")
                    os.remove(pending_path)
                    continue

            else:
                logger.debug("> system conf has been manually modified")
                if system_hash == new_hash:
                    logger.debug("> new conf is as current system conf")
                    conf_status = "managed"
                    regenerated = True
                elif (
                    force
                    and system_path == sshd_config
                    and not ssh_explicitly_specified
                ):
                    logger.warning(m18n.n("regenconf_need_to_explicitly_specify_ssh"))
                    conf_status = "modified"
                elif force:
                    regenerated = _regen(system_path, pending_path)
                    conf_status = "force-updated"
                else:
                    logger.warning(
                        m18n.n("regenconf_file_manually_modified", conf=system_path)
                    )
                    conf_status = "modified"

            # Store the result
            conf_result = {"status": conf_status}
            if conf_diff is not None:
                conf_result["diff"] = conf_diff
            if regenerated:
                succeed_regen[system_path] = conf_result
                conf_hashes[system_path] = new_hash
                if pending_path and os.path.isfile(pending_path):
                    os.remove(pending_path)
            else:
                failed_regen[system_path] = conf_result

        # Check for category conf changes
        if not succeed_regen and not failed_regen:
            logger.debug(m18n.n("regenconf_up_to_date", category=category))
            continue
        elif not failed_regen:
            if not dry_run:
                logger.success(m18n.n("regenconf_updated", category=category))
            else:
                logger.success(m18n.n("regenconf_would_be_updated", category=category))

        if (succeed_regen or force_update_hashes_for_this_category) and not dry_run:
            _update_conf_hashes(category, conf_hashes)

        # Append the category results
        result[category] = {"applied": succeed_regen, "pending": failed_regen}

    # Return in case of dry run
    if dry_run:
        return result

    # Execute hooks for post-regen
    # element 2 and 3 with empty string is because of legacy...
    post_args = ["post", "", ""]

    def _pre_call(name, priority, path, args):
        # append coma-separated applied changes for the category
        if name in result and result[name]["applied"]:
            regen_conf_files = ",".join(result[name]["applied"].keys())
        else:
            regen_conf_files = ""
        return post_args + [
            regen_conf_files,
        ]

    hook_callback("conf_regen", names, pre_callback=_pre_call, env=env)

    operation_logger.success()

    return result


def _get_regenconf_infos():
    """
    Get a dict of regen conf informations
    """
    try:
        with open(REGEN_CONF_FILE, "r") as f:
            data = yaml.safe_load(f)
        # Cleanup legacy
        if "metronome" in data:
            del data["metronome"]
        if "rspamd" in data:
            del data["rspamd"]
        return data
    except Exception:
        return {}


def _save_regenconf_infos(infos):
    """
    Save the regen conf informations
    Keyword argument:
        categories -- A dict containing the regenconf infos
    """

    try:
        with open(REGEN_CONF_FILE, "w") as f:
            yaml.safe_dump(infos, f, default_flow_style=False)
    except Exception as e:
        logger.warning(
            f"Error while saving regenconf infos, exception: {e}", exc_info=1
        )
        raise


def _get_files_diff(orig_file, new_file, as_string=False, skip_header=True):
    """Compare two files and return the differences

    Read and compare two files. The differences are returned either as a delta
    in unified diff format or a formatted string if as_string is True. The
    header can also be removed if skip_header is True.

    """

    if orig_file and os.path.exists(orig_file):
        with open(orig_file, "r") as orig_file:
            orig_file = orig_file.readlines()
    else:
        orig_file = []

    if new_file and os.path.exists(new_file):
        with open(new_file, "r") as new_file:
            new_file = new_file.readlines()
    else:
        new_file = []

    # Compare files and format output
    diff = unified_diff(orig_file, new_file)

    if skip_header:
        try:
            next(diff)
            next(diff)
        except Exception:
            pass

    if as_string:
        return "".join(diff).rstrip()

    return diff


def _calculate_hash(path):
    """Calculate the MD5 hash of a file"""

    if not path or not os.path.exists(path):
        return None

    hasher = hashlib.md5()

    try:
        with open(path, "rb") as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    except IOError as e:
        logger.warning(f"Error while calculating file '{path}' hash: {e}", exc_info=1)
        return None


def _get_pending_conf(categories=[]):
    """Get pending configuration for categories

    Iterate over the pending configuration directory for given categories - or
    all if empty - and look for files inside. Each file is considered as a
    pending configuration file and therefore must be in the same directory
    tree than the system file that it replaces.
    The result is returned as a dict of categories with pending configuration as
    key and a dict of `system_conf_path` => `pending_conf_path` as value.

    """
    result = {}

    if not os.path.isdir(PENDING_CONF_DIR):
        return result

    if not categories:
        categories = os.listdir(PENDING_CONF_DIR)

    for name in categories:
        category_pending_path = os.path.join(PENDING_CONF_DIR, name)

        if not os.path.isdir(category_pending_path):
            continue

        path_index = len(category_pending_path)
        category_conf = {}

        for root, dirs, files in os.walk(category_pending_path):
            for filename in files:
                pending_path = os.path.join(root, filename)
                category_conf[pending_path[path_index:]] = pending_path

        if category_conf:
            result[name] = category_conf
        else:
            # remove empty directory
            shutil.rmtree(category_pending_path, ignore_errors=True)

    return result


def _get_conf_hashes(category):
    """Get the registered conf hashes for a category"""

    categories = _get_regenconf_infos()

    if category not in categories:
        logger.debug(f"category {category} is not in categories.yml yet.")
        return {}

    elif categories[category] is None or "conffiles" not in categories[category]:
        logger.debug(f"No configuration files for category {category}.")
        return {}

    else:
        return categories[category]["conffiles"]


def _update_conf_hashes(category, hashes):
    """Update the registered conf hashes for a category"""
    logger.debug(f"updating conf hashes for '{category}' with: {hashes}")

    categories = _get_regenconf_infos()
    category_conf = categories.get(category, {})

    # Handle the case where categories[category] is set to null in the yaml
    if category_conf is None:
        category_conf = {}

    # If a file shall be removed and is indeed removed, forget entirely about
    # that path.
    # It avoid keeping weird old entries like
    # /etc/nginx/conf.d/some.domain.that.got.removed.conf
    hashes = {
        path: hash_
        for path, hash_ in hashes.items()
        if hash_ is not None or os.path.exists(path)
    }

    category_conf["conffiles"] = hashes
    categories[category] = category_conf
    _save_regenconf_infos(categories)


def _force_clear_hashes(paths):
    categories = _get_regenconf_infos()
    for path in paths:
        for category in categories.keys():
            if path in categories[category]["conffiles"]:
                logger.debug(
                    f"force-clearing old conf hash for {path} in category {category}"
                )
                del categories[category]["conffiles"][path]

    _save_regenconf_infos(categories)


def _process_regen_conf(system_conf, new_conf=None, save=True):
    """Regenerate a given system configuration file

    Replace a given system configuration file by a new one or delete it if
    new_conf is None. A backup of the file - keeping its directory tree - will
    be done in the backup conf directory before any operation if save is True.

    """
    if save:
        system_conf_ = system_conf.lstrip("/")
        now_ = datetime.utcnow().strftime("%Y%m%d.%H%M%S")
        backup_path = os.path.join(BACKUP_CONF_DIR, f"{system_conf_}-{now_}")
        backup_dir = os.path.dirname(backup_path)

        if not os.path.isdir(backup_dir):
            mkdir(backup_dir, 0o755, True)

        shutil.copy2(system_conf, backup_path)
        logger.debug(
            m18n.n("regenconf_file_backed_up", conf=system_conf, backup=backup_path)
        )

    try:
        if not new_conf:
            os.remove(system_conf)
            logger.debug(m18n.n("regenconf_file_removed", conf=system_conf))
        else:
            system_dir = os.path.dirname(system_conf)

            if not os.path.isdir(system_dir):
                mkdir(system_dir, 0o755, True)

            shutil.copyfile(new_conf, system_conf)
            logger.debug(m18n.n("regenconf_file_updated", conf=system_conf))
    except Exception as e:
        logger.warning(
            f"Exception while trying to regenerate conf '{system_conf}': {e}",
            exc_info=1,
        )
        if not new_conf and os.path.exists(system_conf):
            logger.warning(
                m18n.n("regenconf_file_remove_failed", conf=system_conf), exc_info=1
            )
            return False

        elif new_conf:
            try:
                # From documentation:
                # Raise an exception if an os.stat() call on either pathname fails.
                # (os.stats returns a series of information from a file like type, size...)
                copy_succeed = os.path.samefile(system_conf, new_conf)
            except Exception:
                copy_succeed = False
            finally:
                if not copy_succeed:
                    logger.warning(
                        m18n.n(
                            "regenconf_file_copy_failed", conf=system_conf, new=new_conf
                        ),
                        exc_info=1,
                    )
                    return False

    return True


def manually_modified_files():
    output = []
    regenconf_categories = _get_regenconf_infos()
    for category, infos in regenconf_categories.items():
        conffiles = infos["conffiles"]
        for path, hash_ in conffiles.items():
            if hash_ != _calculate_hash(path):
                output.append(path)

    return output


def manually_modified_files_compared_to_debian_default(
    ignore_handled_by_regenconf=False,
):
    # from https://serverfault.com/a/90401
    files = check_output(
        "dpkg-query -W -f='${Conffiles}\n' '*' \
                        | awk 'OFS=\"  \"{print $2,$1}' \
                        | md5sum -c 2>/dev/null \
                        | awk -F': ' '$2 !~ /OK/{print $1}'"
    )
    files = files.strip().split("\n")

    if ignore_handled_by_regenconf:
        regenconf_categories = _get_regenconf_infos()
        regenconf_files = []
        for infos in regenconf_categories.values():
            regenconf_files.extend(infos["conffiles"].keys())

        files = [f for f in files if f not in regenconf_files]

    return files
