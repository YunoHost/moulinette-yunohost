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
import glob
import os
import re
import time
from datetime import datetime, timedelta
from logging import FileHandler, getLogger, Formatter, INFO
from io import IOBase
from typing import List

import psutil
import yaml
from moulinette import Moulinette, m18n
from moulinette.core import MoulinetteError
from moulinette.utils.filesystem import read_file, read_yaml
from moulinette.utils.log import SUCCESS

from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.system import get_ynh_package_version

logger = getLogger("yunohost.log")

OPERATIONS_PATH = "/var/log/yunohost/operations/"

BORING_LOG_LINES = [
    r"set [+-]x$",
    r"set [+-]o xtrace$",
    r"\+ set \+o$",
    r"\+ grep xtrace$",
    r"local 'xtrace_enable=",
    r"set [+-]o errexit$",
    r"set [+-]o nounset$",
    r"trap '' EXIT",
    r"local \w+$",
    r"local exit_code=(1|0)$",
    r"local legacy_args=.*$",
    r"local _globalapp=.*$",
    r"local checksum_setting_name=.*$",
    r"ynh_app_setting ",  # (note the trailing space to match the "low level" one called by other setting helpers)
    r"local -A args_array$",
    r"args_array=.*$",
    r"ret_code=1",
    r".*Helper used in legacy mode.*",
    r"ynh_handle_getopts_args",
    r"ynh_script_progression",
    r"sleep 0.5",
    r"'\[' (1|0) -eq (1|0) '\]'$",
    r"\[?\['? -n '' '?\]\]?$",
    r"rm -rf /var/cache/yunohost/download/$",
    r"type -t ynh_clean_setup$",
    r"DEBUG - \+ unset \S+$",
    r"DEBUG - \+ echo '",
    r"DEBUG - \+ LC_ALL=C$",
    r"DEBUG - \+ DEBIAN_FRONTEND=noninteractive$",
    r"DEBUG - \+ exit (1|0)$",
    r"DEBUG - \+ app=\S+$",
    r"DEBUG - \+\+ app=\S+$",
    r"DEBUG - \+\+ jq -r .\S+$",
    r"DEBUG - \+\+ sed 's/\^null\$//'$",
    "DEBUG - \\+ sed --in-place \\$'s\\\\001",
    "DEBUG - \\+ sed --in-place 's\u0001.*$",
]


def _update_log_cache_symlinks():

    one_year_ago = time.time() - 365 * 24 * 3600

    logs = glob.iglob(OPERATIONS_PATH + "*.yml")
    for log_md in logs:
        if os.path.getctime(log_md) < one_year_ago:
            # Let's ignore files older than one year because hmpf reading a shitload of yml is not free
            continue

        name = log_md.split("/")[-1][: -len(".yml")]
        parent_symlink = os.path.join(OPERATIONS_PATH, f".{name}.parent.yml")
        success_symlink = os.path.join(OPERATIONS_PATH, f".{name}.success")
        if os.path.islink(parent_symlink) and (
            os.path.islink(success_symlink)
            and os.path.getmtime(success_symlink) < os.path.getmtime(log_md)
        ):
            continue

        try:
            metadata = (
                read_yaml(log_md) or {}
            )  # Making sure this is a dict and not  None..?
        except Exception as e:
            # If we can't read the yaml for some reason, report an error and ignore this entry...
            logger.error(m18n.n("log_corrupted_md_file", md_file=log_md, error=e))
            continue

        if not os.path.islink(success_symlink) or os.path.getctime(
            success_symlink
        ) > os.path.getctime(log_md):
            success = metadata.get("success", "?")
            if success is True:
                success_target = "/usr/bin/true"
            elif success is False:
                success_target = "/usr/bin/false"
            else:
                success_target = "/dev/null"
            try:
                os.symlink(success_target, success_symlink)
            except Exception as e:
                logger.warning(f"Failed to create symlink {parent_symlink} ? {e}")

        if not os.path.islink(parent_symlink):
            parent = metadata.get("parent")
            parent = parent + ".yml" if parent else "/dev/null"
            try:
                os.symlink(parent, parent_symlink)
            except Exception as e:
                logger.warning(f"Failed to create symlink {parent_symlink} ? {e}")


def log_list(
    limit=None, with_details=False, with_suboperations=False, since_days_ago=365
):
    """
    List available logs

    Keyword argument:
        limit -- Maximum number of logs
        with_details -- Include details (e.g. if the operation was a success).
        Likely to increase the command time as it needs to open and parse the
        metadata file for each log...
        with_suboperations -- Include operations that are not the "main"
        operation but are sub-operations triggered by another ongoing operation
        ... (e.g. initializing groups/permissions when installing an app)
    """

    operations = {}

    _update_log_cache_symlinks()

    since = time.time() - since_days_ago * 24 * 3600
    logs = [
        x.split("/")[-1]
        for x in glob.iglob(OPERATIONS_PATH + "*.yml")
        if os.path.getctime(x) > since
    ]
    logs = list(reversed(sorted(logs)))

    if not with_suboperations:

        def parent_symlink_points_to_dev_null(log):
            name = log[: -len(".yml")]
            parent_symlink = os.path.join(OPERATIONS_PATH, f".{name}.parent.yml")
            return (
                os.path.islink(parent_symlink)
                and os.path.realpath(parent_symlink) == "/dev/null"
            )

        logs = [log for log in logs if parent_symlink_points_to_dev_null(log)]

    if limit is not None:
        logs = logs[:limit]

    for log in logs:
        name = log[: -len(".yml")]
        md_path = os.path.join(OPERATIONS_PATH, log)

        entry = {
            "name": name,
            "path": md_path,
            "description": _get_description_from_name(name),
        }

        success_symlink = os.path.join(OPERATIONS_PATH, f".{name}.success")
        entry["success"] = "?"
        if os.path.islink(success_symlink):
            success_target = os.path.realpath(success_symlink)
            if success_target == "/usr/bin/false":
                entry["success"] = False
            elif success_target == "/usr/bin/true":
                entry["success"] = True

        try:
            entry["started_at"] = _get_datetime_from_name(name)
        except ValueError:
            pass

        if with_details or with_suboperations:
            if (
                name in log_list.cache
                and os.path.getmtime(md_path) == log_list.cache[name]["time"]
            ):
                metadata = log_list.cache[name]["metadata"]
            else:
                try:
                    metadata = (
                        read_yaml(md_path) or {}
                    )  # Making sure this is a dict and not  None..?
                except Exception as e:
                    # If we can't read the yaml for some reason, report an error and ignore this entry...
                    logger.error(
                        m18n.n("log_corrupted_md_file", md_file=md_path, error=e)
                    )
                    continue
                else:
                    log_list.cache[name] = {
                        "time": os.path.getmtime(md_path),
                        "metadata": metadata,
                    }

        if with_details:
            entry["success"] = metadata.get("success", "?")
            entry["parent"] = metadata.get("parent")
            entry["started_by"] = metadata.get("started_by")

        if with_suboperations:
            entry["parent"] = metadata.get("parent")
            entry["suboperations"] = []

        operations[name] = entry

    # When displaying suboperations, we build a tree-like structure where
    # "suboperations" is a list of suboperations (each of them may also have a list of
    # "suboperations" suboperations etc...
    if with_suboperations:
        suboperations = [o for o in operations.values() if o["parent"] is not None]
        for suboperation in suboperations:
            parent = operations.get(suboperation["parent"])
            if not parent:
                continue
            parent["suboperations"].append(suboperation)
        operations = [o for o in operations.values() if o["parent"] is None]
    else:
        operations = [o for o in operations.values()]

    if limit:
        operations = operations[:limit]

    operations = list(reversed(sorted(operations, key=lambda o: o["name"])))
    # Reverse the order of log when in cli, more comfortable to read (avoid
    # unecessary scrolling)
    is_api = Moulinette.interface.type == "api"
    if not is_api:
        operations = list(reversed(operations))

    return {"operation": operations}


log_list.cache = {}  # type: ignore


def log_show(
    path, number=None, share=False, filter_irrelevant=False, with_suboperations=False
):
    """
    Display a log file enriched with metadata if any.

    If the file_name is not an absolute path, it will try to search the file in
    the unit operations log path (see OPERATIONS_PATH).

    Argument:
        file_name
        number
        share
    """

    # Set up path with correct value if 'last' or 'last-X' magic keywords are used
    last = re.match(r"last(?:-(?P<position>[0-9]{1,6}))?$", path)
    if last:
        position = 1
        if last.group("position") is not None:
            position += int(last.group("position"))

        logs = list(log_list()["operation"])

        if position > len(logs):
            raise YunohostValidationError("There isn't that many logs", raw_msg=True)

        path = logs[-position]["path"]

    if share:
        filter_irrelevant = True

    if filter_irrelevant:

        def _filter(lines):
            filters = [re.compile(f) for f in BORING_LOG_LINES]
            return [
                line
                for line in lines
                if not any(f.search(line.strip()) for f in filters)
            ]

    else:

        def _filter(lines):
            return lines

    # Normalize log/metadata paths and filenames
    abs_path = path
    log_path = None
    if not path.startswith("/"):
        abs_path = os.path.join(OPERATIONS_PATH, path)

    if os.path.exists(abs_path) and not path.endswith(".yml"):
        log_path = abs_path

    if abs_path.endswith(".yml") or abs_path.endswith(".log"):
        base_path = "".join(os.path.splitext(abs_path)[:-1])
    else:
        base_path = abs_path
    base_filename = os.path.basename(base_path)
    md_path = base_path + ".yml"
    if log_path is None:
        log_path = base_path + ".log"

    if not os.path.exists(md_path) and not os.path.exists(log_path):
        raise YunohostValidationError("log_does_exists", log=path)

    infos = {}

    # If it's a unit operation, display the name and the description
    if base_path.startswith(OPERATIONS_PATH):
        infos["description"] = _get_description_from_name(base_filename)
        infos["name"] = base_filename

    if share:
        from yunohost.utils.yunopaste import yunopaste

        content = ""
        if os.path.exists(md_path):
            content += read_file(md_path)
            content += "\n============\n\n"
        if os.path.exists(log_path):
            actual_log = read_file(log_path)
            content += "\n".join(_filter(actual_log.split("\n")))

        url = yunopaste(content)

        logger.success(m18n.n("log_available_on_yunopaste", url=url))
        if Moulinette.interface.type == "api":
            return {"url": url}
        else:
            return

    # Display metadata if exist
    if os.path.exists(md_path):
        try:
            metadata = read_yaml(md_path) or {}
        except MoulinetteError as e:
            error = m18n.n("log_corrupted_md_file", md_file=md_path, error=e)
            if os.path.exists(log_path):
                logger.warning(error)
            else:
                raise YunohostError(error)
        else:
            infos["metadata_path"] = md_path
            infos["metadata"] = metadata

            if "log_path" in metadata:
                log_path = metadata["log_path"]

            if with_suboperations:

                def suboperations():
                    try:
                        log_start = _get_datetime_from_name(base_filename)
                    except ValueError:
                        return

                    for filename in os.listdir(OPERATIONS_PATH):
                        if not filename.endswith(".yml"):
                            continue

                        # We first retrict search to a ~48h time window to limit the number
                        # of .yml we look into
                        try:
                            date = _get_datetime_from_name(base_filename)
                        except ValueError:
                            continue
                        if (date < log_start) or (
                            date > log_start + timedelta(hours=48)
                        ):
                            continue

                        try:
                            submetadata = read_yaml(
                                os.path.join(OPERATIONS_PATH, filename)
                            )
                        except Exception:
                            continue

                        if submetadata and submetadata.get("parent") == base_filename:
                            name = filename[: -len(".yml")]
                            yield {
                                "name": name,
                                "description": _get_description_from_name(name),
                                "success": submetadata.get("success", "?"),
                            }

                metadata["suboperations"] = list(suboperations())

    # Display logs if exist
    if os.path.exists(log_path):
        from yunohost.service import _tail

        if number and filter_irrelevant:
            logs = _tail(log_path, int(number * 6))
        elif number:
            logs = _tail(log_path, int(number))
        else:
            logs = read_file(log_path)
        logs = list(_filter(logs))
        if number:
            logs = logs[-number:]
        infos["log_path"] = log_path
        infos["logs"] = logs

    return infos


from typing import Callable, Concatenate, ParamSpec, TypeVar

# FuncT = TypeVar("FuncT", bound=Callable[..., Any])
Param = ParamSpec("Param")
RetType = TypeVar("RetType")


def is_unit_operation(
    entities=["app", "domain", "group", "service", "user"],
    exclude=["password"],
    sse_only=False,
    flash=False,
) -> Callable[
    [Callable[Concatenate["OperationLogger", Param], RetType]], Callable[Param, RetType]
]:
    """
    Configure quickly a unit operation

    This decorator help you to configure the record of a unit operations.

    Argument:
    entities   A list of entity types related to the unit operation. The entity
    type is searched inside argument's names of the decorated function. If
    something match, the argument value is added as related entity. If the
    argument name is different you can specify it with a tuple
    (argname, entity_type) instead of just put the entity type.

    exclude    Remove some arguments from the context. By default, arguments
    called 'password' are removed. If an argument is an object, you need to
    exclude it or create manually the unit operation without this decorator.

    """

    def decorate(
        func: Callable[Concatenate["OperationLogger", Param], RetType]
    ) -> Callable[Param, RetType]:
        def func_wrapper(*args, **kwargs):

            # If the function is called directly from an other part of the code
            # and not by the moulinette framework, we need to complete kwargs
            # dictionnary with the args list.
            # Indeed, we use convention naming in this decorator and we need to
            # know name of each args (so we need to use kwargs instead of args)
            if len(args) > 0:
                from inspect import signature

                keys = list(signature(func).parameters.keys())
                if "operation_logger" in keys:
                    keys.remove("operation_logger")
                for k, arg in enumerate(args):
                    kwargs[keys[k]] = arg
                args = ()

            # Search related entity in arguments of the decorated function
            related_to = []
            for entity in entities:
                if isinstance(entity, tuple):
                    entity_type = entity[1]
                    entity = entity[0]
                else:
                    entity_type = entity

                if entity in kwargs and kwargs[entity] is not None:
                    if isinstance(kwargs[entity], str):
                        related_to.append((entity_type, kwargs[entity]))
                    else:
                        for x in kwargs[entity]:
                            related_to.append((entity_type, x))

            context = kwargs.copy()

            # Exclude unappropriate data from the context
            for field in exclude:
                if field in context:
                    context.pop(field, None)

            # Context is made from args given to main function by argparse
            # This context will be added in extra parameters in yml file, so this context should
            # be serializable and short enough (it will be displayed in webadmin)
            # Argparse can provide some File or Stream, so here we display the filename or
            # the IOBase, if we have no name.
            for field, value in context.items():
                if isinstance(value, IOBase):
                    try:
                        context[field] = value.name
                    except Exception:
                        context[field] = "IOBase"
            operation_logger = OperationLogger(
                func.__name__, related_to, sse_only, flash, args=context
            )

            try:
                # Start the actual function, and give the unit operation
                # in argument to let the developper start the record itself
                if not flash:
                    args = (operation_logger,) + args
                result = func(*args, **kwargs)
            except Exception as e:
                operation_logger.error(e)
                raise
            else:
                operation_logger.success()
            return result

        return func_wrapper

    return decorate


class RedactingFormatter(Formatter):
    def __init__(self, format_string, data_to_redact):
        super(RedactingFormatter, self).__init__(format_string)
        self.data_to_redact = data_to_redact

    def format(self, record):
        msg = super(RedactingFormatter, self).format(record)
        self.identify_data_to_redact(msg)
        for data in self.data_to_redact:
            # we check that data is not empty string,
            # otherwise this may lead to super epic stuff
            # (try to run "foo".replace("", "bar"))
            if data:
                msg = msg.replace(data, "**********")
        return msg

    def identify_data_to_redact(self, record):
        # Wrapping this in a try/except because we don't want this to
        # break everything in case it fails miserably for some reason :s
        try:
            # This matches stuff like db_pwd=the_secret or admin_password=other_secret
            # (the secret part being at least 3 chars to avoid catching some lines like just "db_pwd=")
            # Some names like "key" or "manifest_key" are ignored, used in helpers like ynh_app_setting_set or ynh_read_manifest
            match = re.search(
                r"(pwd|pass|passwd|password|passphrase|secret\w*|\w+key|token|PASSPHRASE)=(\S{3,})$",
                record.strip(),
            )
            if (
                match
                and match.group(2) not in self.data_to_redact
                and match.group(1) not in ["key", "manifest_key"]
            ):
                self.data_to_redact.append(match.group(2))
        except Exception as e:
            logger.warning(
                "Failed to parse line to try to identify data to redact ... : %s" % e
            )


class OperationLogger:
    """
    Instances of this class represents unit operation done on the ynh instance.

    Each time an action of the yunohost cli/api change the system, one or
    several unit operations should be registered.

    This class record logs and metadata like context or  time/end time.
    """

    _instances: List["OperationLogger"] = []

    def __init__(
        self, operation, related_to=None, sse_only=False, flash=False, **kwargs
    ):
        # TODO add a way to not save password on app installation
        self.operation = operation
        self.related_to = related_to
        self.extra = kwargs
        self.started_at = None
        self.ended_at = None
        self.logger = None
        self.file_handler = None
        self.sse_handler = None
        self._name = None
        self.sse_only = sse_only
        self.flash = flash
        self.data_to_redact = []
        self.parent = self.parent_logger()
        self._instances.append(self)

        for filename in ["/etc/yunohost/mysql", "/etc/yunohost/psql"]:
            if os.path.exists(filename):
                self.data_to_redact.append(read_file(filename).strip())

        self.started_by = None
        if not self.parent:
            if Moulinette.interface.type == "api":
                try:
                    from yunohost.authenticators.ldap_admin import Authenticator as Auth

                    auth = Auth().get_session_cookie()
                    self.started_by = auth["user"]
                except Exception:
                    # During postinstall, we're not actually authenticated so eeeh what happens exactly?
                    self.started_by = "root"
            elif "SUDO_USER" in os.environ:
                self.started_by = os.environ["SUDO_USER"]
            elif not os.isatty(1):
                self.started_by = "noninteractive"
            else:
                self.started_by = "root"

        if not os.path.exists(OPERATIONS_PATH):
            os.makedirs(OPERATIONS_PATH)

        # Autostart the logger for flash operations ?
        if self.flash:
            self.start()

    def parent_logger(self):
        # If there are other operation logger instances
        for instance in reversed(self._instances):
            # Is one of these operation logger started but not yet done ?
            if instance.started_at is not None and instance.ended_at is None:
                # We are a child of the first one we found
                return instance.name

        # If no lock exists, we are probably in tests or yunohost is used as a
        # lib ... let's not really care about that case and assume we're the
        # root logger then.
        if not os.path.exists("/var/run/moulinette_yunohost.lock"):
            return None

        locks = read_file("/var/run/moulinette_yunohost.lock").strip().split("\n")
        # If we're the process with the lock, we're the root logger
        if locks == [] or str(os.getpid()) in locks:
            return None

        # If we get here, we are in a yunohost command called by a yunohost
        # (maybe indirectly from an app script for example...)
        #
        # The strategy is :
        # 1. list 20 most recent log files
        # 2. iterate over the PID of parent processes
        # 3. see if parent process has some log file open (being actively
        # written in)
        # 4. if among those file, there's an operation log file, we use the id
        # of the most recent file

        recent_operation_logs = sorted(
            glob.iglob(OPERATIONS_PATH + "*.log"), key=os.path.getctime, reverse=True
        )[:20]

        proc = psutil.Process().parent()
        while proc is not None:
            # We use proc.open_files() to list files opened / actively used by this proc
            # We only keep files matching a recent yunohost operation log
            active_logs = sorted(
                (f.path for f in proc.open_files() if f.path in recent_operation_logs),
                key=os.path.getctime,
                reverse=True,
            )
            if active_logs != []:
                # extra the log if from the full path
                return os.path.basename(active_logs[0])[:-4]
            else:
                proc = proc.parent()
                continue

        # If nothing found, assume we're the root operation logger
        return None

    def start(self):
        """
        Start to record logs that change the system
        Until this start method is run, no unit operation will be registered.
        """

        if self.started_at is None:
            self.started_at = datetime.utcnow()
            self.flush()
            self._register_log()
            if self.sse_handler is not None and not self.flash:
                self.sse_handler.emit_operation_start(
                    self.started_at,
                    _get_description_from_name(self.name),
                    self.started_by,
                )

    @property
    def md_path(self):
        """
        Metadata path file
        """
        return f"{OPERATIONS_PATH}/{self.name}.yml"

    @property
    def log_path(self):
        """
        Log path file
        """
        return f"{OPERATIONS_PATH}/{self.name}.log"

    def _register_log(self):
        """
        Register log with a handler connected on log system
        """

        if not self.sse_only and not self.flash:
            self.file_handler = FileHandler(self.log_path)
            # We use a custom formatter that's able to redact all stuff in self.data_to_redact
            # N.B. : the subtle thing here is that the class will remember a pointer to the list,
            # so we can directly append stuff to self.data_to_redact and that'll be automatically
            # propagated to the RedactingFormatter
            self.file_handler.formatter = RedactingFormatter(
                "%(asctime)s: %(levelname)s - %(message)s", self.data_to_redact
            )

        # Only do this one for the main parent operation
        if not self.parent:
            from yunohost.utils.sse import SSELogStreamingHandler

            self.sse_handler = SSELogStreamingHandler(self.name, flash=self.flash)
            self.sse_handler.level = INFO if not self.flash else SUCCESS
            self.sse_handler.formatter = RedactingFormatter(
                "%(message)s", self.data_to_redact
            )

        # Listen to the root logger
        self.logger = getLogger("yunohost")
        if self.file_handler is not None:
            self.logger.addHandler(self.file_handler)

        if self.sse_handler is not None:
            self.logger.addHandler(self.sse_handler)

    def flush(self):
        """
        Write or rewrite the metadata file with all metadata known
        """
        if self.sse_only or self.flash:
            return

        metadata = copy.copy(self.metadata)

        # Remove lower-case keys ... this is because with the new v2 app packaging,
        # all settings are included in the env but we probably don't want to dump all of these
        # which may contain various secret/private data ...
        if "env" in metadata:
            metadata["env"] = {
                k: v for k, v in metadata["env"].items() if k == k.upper()
            }

        dump = yaml.safe_dump(metadata, default_flow_style=False)
        for data in self.data_to_redact:
            # N.B. : we need quotes here, otherwise yaml isn't happy about loading the yml later
            dump = dump.replace(data, "'**********'")
        with open(self.md_path, "w") as outfile:
            outfile.write(dump)

    @property
    def name(self):
        """
        Name of the operation
        This name is used as filename, so don't use space
        """
        if self._name is not None:
            return self._name

        name = [self.started_at.strftime("%Y%m%d-%H%M%S")]
        name += [self.operation]

        if hasattr(self, "name_parameter_override"):
            # This is for special cases where the operation is not really
            # unitary. For instance, the regen conf cannot be logged "per
            # service" because of the way it's built
            name.append(self.name_parameter_override)
        elif self.related_to:
            # We use the name of the first related thing
            name.append(self.related_to[0][1])

        self._name = "-".join(name)
        return self._name

    @property
    def metadata(self):
        """
        Dictionnary of all metadata collected
        """

        data = {
            "started_at": self.started_at,
            "operation": self.operation,
            "parent": self.parent,
            "yunohost_version": get_ynh_package_version("yunohost")["version"],
            "interface": Moulinette.interface.type,
        }
        if self.related_to is not None:
            data["related_to"] = self.related_to
        if self.ended_at is not None:
            data["ended_at"] = self.ended_at
            data["success"] = self._success
            if self.error is not None:
                data["error"] = self._error
        if self.started_by is not None:
            data["started_by"] = self.started_by
        # TODO: detect if 'extra' erase some key of 'data'
        data.update(self.extra)
        # Remove the 'args' arg from args (yodawg). It corresponds to url-encoded args for app install, config panel set, etc
        # Because the data are url encoded, it's hell to properly redact secrets inside it,
        # and the useful info is usually already available in `env` too
        if "args" in data and isinstance(data["args"], dict) and "args" in data["args"]:
            data["args"].pop("args")
        return data

    def success(self):
        """
        Declare the success end of the unit operation
        """
        self.close()

    def error(self, error):
        """
        Declare the failure of the unit operation
        """
        return self.close(error)

    def close(self, error=None):
        """
        Close properly the unit operation
        """

        # When the error happen's in the is_unit_operation try/except,
        # we want to inject the log ref in the exception, such that it may be
        # transmitted to the webadmin which can then redirect to the appropriate
        # log page
        if (
            self.started_at
            and isinstance(error, Exception)
            and not isinstance(error, YunohostValidationError)
        ):
            error.log_ref = self.name

        if self.ended_at is not None or self.started_at is None:
            return
        if error is not None and not isinstance(error, str):
            error = str(error)

        self.ended_at = datetime.utcnow()
        self._error = error
        self._success = error is None

        if self.sse_handler is not None:
            if not self.flash:
                self.sse_handler.emit_operation_end(
                    self.ended_at, self._success, self._error
                )
            elif self._error:
                self.sse_handler.emit_error_toast(self._error)

        if self.file_handler is not None:
            self.logger.removeHandler(self.file_handler)
            self.file_handler.close()
        if self.sse_handler is not None:
            self.logger.removeHandler(self.sse_handler)
            self.sse_handler.close()

        if not self.flash:
            is_api = Moulinette.interface.type == "api"
            desc = _get_description_from_name(self.name)
            if error is None:
                if is_api:
                    msg = m18n.n("log_link_to_log", name=self.name, desc=desc)
                else:
                    msg = m18n.n("log_help_to_get_log", name=self.name, desc=desc)
                logger.debug(msg)
            else:
                if is_api:
                    msg = (
                        "<strong>"
                        + m18n.n("log_link_to_failed_log", name=self.name, desc=desc)
                        + "</strong>"
                    )
                else:
                    msg = m18n.n(
                        "log_help_to_get_failed_log", name=self.name, desc=desc
                    )
                logger.info(msg)
        else:
            msg = None
        self.flush()
        return msg

    def __del__(self):
        """
        Try to close the unit operation, if it's missing.
        The missing of the message below could help to see an electrical
        shortage.
        """
        if self.ended_at is not None or self.started_at is None:
            return
        else:
            self.error(m18n.n("log_operation_unit_unclosed_properly"))

    def dump_script_log_extract_for_debugging(self):
        with open(self.log_path, "r") as f:
            lines = f.readlines()

        # A line typically looks like
        # 2019-10-19 16:10:27,611: DEBUG - + mysql -u piwigo --password=********** -B piwigo
        # And we just want the part starting by "DEBUG - "
        lines = [line for line in lines if ":" in line.strip()]
        lines = [line.strip().split(": ", 1)[-1] for line in lines]
        # And we ignore boring/irrelevant lines
        # Annnnnnd we also ignore lines matching [number] + such as
        # 72971 [37m[1mDEBUG [m29739 + ynh_exit_properly
        # which are lines from backup-before-upgrade or restore-after-failed-upgrade ...
        filters = [re.compile(f_) for f_ in BORING_LOG_LINES]
        filters.append(re.compile(r"\d+ \+ "))
        lines = [
            line
            for line in lines
            if not any(filter_.search(line) for filter_ in filters)
        ]

        lines_to_display = []

        # Get the 20 lines before the last 'ynh_exit_properly'
        rev_lines = list(reversed(lines))
        for i, line in enumerate(rev_lines[:50]):
            if line.endswith("+ ynh_exit_properly"):
                lines_to_display = reversed(rev_lines[i : i + 20])
                break

        # If didnt find anything, just get the last 20 lines
        if not lines_to_display:
            lines_to_display = lines[-20:]

        logger.warning(
            "Here's an extract of the logs before the crash. It might help debugging the error:"
        )
        for line in lines_to_display:
            logger.info(line)


def _get_datetime_from_name(name):
    # Filenames are expected to follow the format:
    # 20200831-170740-short_description-and-stuff

    raw_datetime = " ".join(name.split("-")[:2])
    return datetime.strptime(raw_datetime, "%Y%m%d %H%M%S")


def _get_description_from_name(name):
    """
    Return the translated description from the filename
    """

    parts = name.split("-", 3)
    try:
        try:
            datetime.strptime(" ".join(parts[:2]), "%Y%m%d %H%M%S")
        except ValueError:
            key = "log_" + parts[0]
            args = parts[1:]
        else:
            key = "log_" + parts[2]
            args = parts[3:]
        return m18n.n(key, *args)
    except IndexError:
        return name


@is_unit_operation(flash=True)
def log_share(path):
    return log_show(path, share=True)
