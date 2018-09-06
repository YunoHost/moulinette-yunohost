# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2018 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_log.py

    Manage debug logs
"""

import os
import yaml
import errno
import collections

from datetime import datetime
from logging import FileHandler, getLogger, Formatter
from sys import exc_info

from moulinette import m18n, msettings
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file

CATEGORIES_PATH = '/var/log/yunohost/categories/'
OPERATIONS_PATH = '/var/log/yunohost/categories/operation/'
CATEGORIES = ['operation', 'history', 'package', 'system', 'access', 'service',
              'app']
METADATA_FILE_EXT = '.yml'
LOG_FILE_EXT = '.log'
RELATED_CATEGORIES = ['app', 'domain', 'service', 'user']

logger = getActionLogger('yunohost.log')


def log_list(category=[], limit=None):
    """
    List available logs

    Keyword argument:
        limit -- Maximum number of logs
    """

    categories = category
    is_api = msettings.get('interface') == 'api'

    # In cli we just display `operation` logs by default
    if not categories:
        categories = ["operation"] if not is_api else CATEGORIES

    result = collections.OrderedDict()
    for category in categories:
        result[category] = []

        category_path = os.path.join(CATEGORIES_PATH, category)
        if not os.path.exists(category_path):
            logger.debug(m18n.n('log_category_404', category=category))

            continue

        logs = filter(lambda x: x.endswith(METADATA_FILE_EXT),
                      os.listdir(category_path))
        logs = reversed(sorted(logs))

        if limit is not None:
            logs = logs[:limit]

        for log in logs:

            base_filename = log[:-len(METADATA_FILE_EXT)]
            md_filename = log
            md_path = os.path.join(category_path, md_filename)

            log = base_filename.split("-")

            entry = {
                "name": base_filename,
                "path": md_path,
            }
            entry["description"] = _get_description_from_name(base_filename)
            try:
                log_datetime = datetime.strptime(" ".join(log[:2]),
                                                 "%Y%m%d %H%M%S")
            except ValueError:
                pass
            else:
                entry["started_at"] = log_datetime

            result[category].append(entry)

    # Reverse the order of log when in cli, more comfortable to read (avoid
    # unecessary scrolling)
    if not is_api:
        for category in result:
            result[category] = list(reversed(result[category]))

    return result


def log_display(path, number=50, share=False):
    """
    Display a log file enriched with metadata if any.

    If the file_name is not an absolute path, it will try to search the file in
    the unit operations log path (see OPERATIONS_PATH).

    Argument:
        file_name
        number
        share
    """

    # Normalize log/metadata paths and filenames
    abs_path = path
    log_path = None
    if not path.startswith('/'):
        for category in CATEGORIES:
            abs_path = os.path.join(CATEGORIES_PATH, category, path)
            if os.path.exists(abs_path) or os.path.exists(abs_path + METADATA_FILE_EXT):
                break

    if os.path.exists(abs_path) and not path.endswith(METADATA_FILE_EXT):
        log_path = abs_path

    if abs_path.endswith(METADATA_FILE_EXT) or abs_path.endswith(LOG_FILE_EXT):
        base_path = ''.join(os.path.splitext(abs_path)[:-1])
    else:
        base_path = abs_path
    base_filename = os.path.basename(base_path)
    md_path = base_path + METADATA_FILE_EXT
    if log_path is None:
        log_path = base_path + LOG_FILE_EXT

    if not os.path.exists(md_path) and not os.path.exists(log_path):
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('log_does_exists', log=path))

    infos = {}

    # If it's a unit operation, display the name and the description
    if base_path.startswith(CATEGORIES_PATH):
        infos["description"] = _get_description_from_name(base_filename)
        infos['name'] = base_filename

    if share:
        from yunohost.utils.yunopaste import yunopaste
        content = ""
        if os.path.exists(md_path):
            content += read_file(md_path)
            content += "\n============\n\n"
        if os.path.exists(log_path):
            content += read_file(log_path)

        url = yunopaste(content)

        logger.info(m18n.n("log_available_on_yunopaste", url=url))
        if msettings.get('interface') == 'api':
            return {"url": url}
        else:
            return

    # Display metadata if exist
    if os.path.exists(md_path):
        with open(md_path, "r") as md_file:
            try:
                metadata = yaml.safe_load(md_file)
                infos['metadata_path'] = md_path
                infos['metadata'] = metadata
                if 'log_path' in metadata:
                    log_path = metadata['log_path']
            except yaml.YAMLError:
                error = m18n.n('log_corrupted_md_file', file=md_path)
                if os.path.exists(log_path):
                    logger.warning(error)
                else:
                    raise MoulinetteError(errno.EINVAL, error)

    # Display logs if exist
    if os.path.exists(log_path):
        from yunohost.service import _tail
        logs = _tail(log_path, int(number))
        infos['log_path'] = log_path
        infos['logs'] = logs

    return infos


def is_unit_operation(entities=['app', 'domain', 'service', 'user'],
                      exclude=['auth', 'password'], operation_key=None):
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
    called 'password' and 'auth' are removed. If an argument is an object, you
    need to exclude it or create manually the unit operation without this
    decorator.

    operation_key   A key to describe the unit operation log used to create the
    filename and search a translation. Please ensure that this key prefixed by
    'log_' is present in locales/en.json otherwise it won't be translatable.

    """
    def decorate(func):
        def func_wrapper(*args, **kwargs):
            op_key = operation_key
            if op_key is None:
                op_key = func.__name__

            # If the function is called directly from an other part of the code
            # and not by the moulinette framework, we need to complete kwargs
            # dictionnary with the args list.
            # Indeed, we use convention naming in this decorator and we need to
            # know name of each args (so we need to use kwargs instead of args)
            if len(args) > 0:
                from inspect import getargspec
                keys = getargspec(func).args
                if 'operation_logger' in keys:
                    keys.remove('operation_logger')
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
                    if isinstance(kwargs[entity], basestring):
                        related_to.append((entity_type, kwargs[entity]))
                    else:
                        for x in kwargs[entity]:
                            related_to.append((entity_type, x))

            context = kwargs.copy()

            # Exclude unappropriate data from the context
            for field in exclude:
                if field in context:
                    context.pop(field, None)
            operation_logger = OperationLogger(op_key, related_to, args=context)

            try:
                # Start the actual function, and give the unit operation
                # in argument to let the developper start the record itself
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


class OperationLogger(object):
    """
    Instances of this class represents unit operation done on the ynh instance.

    Each time an action of the yunohost cli/api change the system, one or
    several unit operations should be registered.

    This class record logs and metadata like context or start time/end time.
    """

    def __init__(self, operation, related_to=None, **kwargs):
        # TODO add a way to not save password on app installation
        self.operation = operation
        self.related_to = related_to
        self.extra = kwargs
        self.started_at = None
        self.ended_at = None
        self.logger = None
        self._name = None

        self.path = OPERATIONS_PATH

        if not os.path.exists(self.path):
            os.makedirs(self.path)

    def start(self):
        """
        Start to record logs that change the system
        Until this start method is run, no unit operation will be registered.
        """

        if self.started_at is None:
            self.started_at = datetime.now()
            self.flush()
            self._register_log()

    def _register_log(self):
        """
        Register log with a handler connected on log system
        """

        # TODO add a way to not save password on app installation
        filename = os.path.join(self.path, self.name + LOG_FILE_EXT)
        self.file_handler = FileHandler(filename)
        self.file_handler.formatter = Formatter('%(asctime)s: %(levelname)s - %(message)s')

        # Listen to the root logger
        self.logger = getLogger('yunohost')
        self.logger.addHandler(self.file_handler)

    def flush(self):
        """
        Write or rewrite the metadata file with all metadata known
        """

        filename = os.path.join(self.path, self.name + METADATA_FILE_EXT)
        with open(filename, 'w') as outfile:
            yaml.safe_dump(self.metadata, outfile, default_flow_style=False)

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

        self._name = '-'.join(name)
        return self._name

    @property
    def metadata(self):
        """
        Dictionnary of all metadata collected
        """

        data = {
            'started_at': self.started_at,
            'operation': self.operation,
        }
        if self.related_to is not None:
            data['related_to'] = self.related_to
        if self.ended_at is not None:
            data['ended_at'] = self.ended_at
            data['success'] = self._success
            if self.error is not None:
                data['error'] = self._error
        # TODO: detect if 'extra' erase some key of 'data'
        data.update(self.extra)
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
        if self.ended_at is not None or self.started_at is None:
            return
        if error is not None and not isinstance(error, basestring):
            error = str(error)
        self.ended_at = datetime.now()
        self._error = error
        self._success = error is None
        if self.logger is not None:
            self.logger.removeHandler(self.file_handler)

        is_api = msettings.get('interface') == 'api'
        desc = _get_description_from_name(self.name)
        if error is None:
            if is_api:
                msg = m18n.n('log_link_to_log', name=self.name, desc=desc)
            else:
                msg = m18n.n('log_help_to_get_log', name=self.name, desc=desc)
            logger.debug(msg)
        else:
            if is_api:
                msg = "<strong>" + m18n.n('log_link_to_failed_log',
                                    name=self.name, desc=desc) + "</strong>"
            else:
                msg = m18n.n('log_help_to_get_failed_log', name=self.name,
                             desc=desc)
            logger.info(msg)
        self.flush()
        return msg

    def __del__(self):
        """
        Try to close the unit operation, if it's missing.
        The missing of the message below could help to see an electrical
        shortage.
        """
        self.error(m18n.n('log_operation_unit_unclosed_properly'))


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
