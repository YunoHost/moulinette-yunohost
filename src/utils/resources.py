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
import copy
import shutil
import random
import tempfile
import subprocess
from typing import Dict, Any, List, Union, Callable
from logging import getLogger

from moulinette import m18n
from moulinette.utils.text import random_ascii
from moulinette.utils.process import check_output
from moulinette.utils.filesystem import mkdir, chown, chmod, write_to_file
from moulinette.utils.filesystem import (
    rm,
)
from yunohost.utils.system import system_arch, debian_version, debian_version_id
from yunohost.utils.error import YunohostError, YunohostValidationError

logger = getLogger("yunohost.utils.resources")


class AppResourceManager:
    def __init__(self, app: str, current: Dict, wanted: Dict, workdir=None):
        self.app = app
        self.current = current
        self.wanted = wanted
        self.workdir = workdir

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
                    logger.info(f"Deprovisioning {name}...")
                    old.deprovision(context=context)
                elif todo == "provision":
                    logger.info(f"Provisioning {name}...")
                    new.provision_or_update(context=context)
                elif todo == "update":
                    logger.info(f"Updating {name}...")
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
                        logger.info(f"Reprovisioning {name}...")
                        old.provision_or_update(context=context)
                    elif todo == "provision":
                        logger.info(f"Deprovisioning {name}...")
                        new.deprovision(context=context)
                    elif todo == "update":
                        logger.info(f"Reverting {name}...")
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
        properties = self.default_properties | properties

        # It's not guaranteed that this info will be defined, e.g. during unit tests, only small resource snippets are used, not proper manifests
        app_upstream_version = ""
        if manager and manager.wanted and "version" in manager.wanted:
            app_upstream_version = manager.wanted["version"].split("~")[0]
        elif manager and manager.current and "version" in manager.current:
            app_upstream_version = manager.current["version"].split("~")[0]

        # FIXME : should use packaging.version to properly parse / compare versions >_>
        self.helpers_version: float = 0
        if (
            manager
            and manager.wanted
            and manager.wanted.get("integration", {}).get("helpers_version")
        ):
            self.helpers_version = float(
                manager.wanted.get("integration", {}).get("helpers_version")
            )
        elif (
            manager
            and manager.current
            and manager.current.get("integration", {}).get("helpers_version")
        ):
            self.helpers_version = float(
                manager.current.get("integration", {}).get("helpers_version")
            )
        elif manager and manager.wanted and manager.wanted.get("packaging_format"):
            self.helpers_version = float(manager.wanted.get("packaging_format"))
        elif manager and manager.current and manager.current.get("packaging_format"):
            self.helpers_version = float(manager.current.get("packaging_format"))
        if not self.helpers_version:
            self.helpers_version = 1.0

        replacements: dict[str, str] = {
            "__APP__": self.app,
            "__YNH_ARCH__": system_arch(),
            "__YNH_DEBIAN_VERSION__": debian_version(),
            "__YNH_DEBIAN_VERSION_ID__": debian_version_id(),
            "__YNH_APP_UPSTREAM_VERSION__": app_upstream_version,
        }

        def recursive_apply(function: Callable, data: Any) -> Any:
            if isinstance(data, dict):  # FIXME: hashable?
                return {
                    key: recursive_apply(function, value) for key, value in data.items()
                }

            if isinstance(data, list):  # FIXME: iterable?
                return [recursive_apply(function, value) for value in data]

            return function(data)

        def replace_tokens_in_strings(data: Any):
            if not isinstance(data, str):
                return data
            for token, replacement in replacements.items():
                data = data.replace(token, replacement)

            return data

        properties = recursive_apply(replace_tokens_in_strings, properties)

        for key, value in properties.items():
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

    def check_output_bash_snippet(self, snippet, env={}):
        from yunohost.app import (
            _make_environment_for_app_script,
        )

        env_ = _make_environment_for_app_script(
            self.app,
        )
        env_.update(env)

        with tempfile.NamedTemporaryFile(prefix="ynh_") as fp:
            fp.write(snippet.encode())
            fp.seek(0)
            with tempfile.TemporaryFile() as stderr:
                out = check_output(f"bash {fp.name}", env=env_, stderr=stderr)

                stderr.seek(0)
                err = stderr.read().decode()

        return out, err

    def _run_script(self, action, script, env={}):
        from yunohost.app import (
            _make_tmp_workdir_for_app,
            _make_environment_for_app_script,
        )
        from yunohost.hook import hook_exec_with_script_debug_if_failure

        workdir = (
            self.manager.workdir
            if self.manager and self.manager.workdir
            else _make_tmp_workdir_for_app(app=self.app)
        )

        env_ = _make_environment_for_app_script(
            self.app,
            workdir=workdir,
            action=f"{action}_{self.type}",
        )
        env_.update(env)

        script_path = f"{workdir}/{action}_{self.type}"
        script = f"""
source /usr/share/yunohost/helpers
ynh_abort_if_errors

{script}
"""

        write_to_file(script_path, script)

        from yunohost.log import OperationLogger

        # FIXME ? : this is an ugly hack :(
        active_operation_loggers = [
            o for o in OperationLogger._instances if o.ended_at is None
        ]
        if active_operation_loggers:
            operation_logger = active_operation_loggers[-1]
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
                # more sophisticated code checking if this broke something on the system etc.
                # dunno if we want to do this here or manage it elsewhere
                pass

        # print(ret)


class SourcesResource(AppResource):
    """
    Declare what are the sources / assets used by this app. Typically, this corresponds to some tarball published by the upstream project, that needs to be downloaded and extracted in the install dir using the ynh_setup_source helper.

    This resource is intended both to declare the assets, which will be parsed by ynh_setup_source during the app script runtime, AND to prefetch and validate the sha256sum of those asset before actually running the script, to be able to report an error early when the asset turns out to not be available for some reason.

    Various options are available to accomodate the behavior according to the asset structure

    ### Example

    ```toml
    [resources.sources]

        [resources.sources.main]
        url = "https://github.com/foo/bar/archive/refs/tags/v1.2.3.tar.gz"
        sha256 = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

        autoupdate.strategy = "latest_github_tag"
    ```

    Or more complex examples with several element, including one with asset that depends on the arch

    ```toml
    [resources.sources]

        [resources.sources.main]
        in_subdir = false
        amd64.url = "https://github.com/foo/bar/archive/refs/tags/v1.2.3.amd64.tar.gz"
        amd64.sha256 = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
        i386.url = "https://github.com/foo/bar/archive/refs/tags/v1.2.3.386.tar.gz"
        i386.sha256 = "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"
        armhf.url = "https://github.com/foo/bar/archive/refs/tags/v1.2.3.arm.tar.gz"
        armhf.sha256 = "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"

        autoupdate.strategy = "latest_github_release"
        autoupdate.asset.amd64 = ".*\\\\.amd64.tar.gz"
        autoupdate.asset.i386 = ".*\\\\.386.tar.gz"
        autoupdate.asset.armhf = ".*\\\\.arm.tar.gz"

        [resources.sources.zblerg]
        url = "https://zblerg.com/download/zblerg"
        sha256 = "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"
        format = "script"
        rename = "zblerg.sh"

    ```

    ### Properties (for each source)

    - `prefetch` : `true` (default) or `false`, wether or not to pre-fetch this asset during the provisioning phase of the resource. If several arch-dependent url are provided, YunoHost will only prefetch the one for the current system architecture.
    - `url` : the asset's URL
        - If the asset's URL depend on the architecture, you may instead provide `amd64.url`, `i386.url`, `armhf.url` and `arm64.url` (depending on what architectures are supported), using the same `dpkg --print-architecture` nomenclature as for the supported architecture key in the manifest
    - `sha256` : the asset's sha256sum. This is used both as an integrity check, and as a layer of security to protect against malicious actors which could have injected malicious code inside the asset...
        - Same as `url` : if the asset's URL depend on the architecture, you may instead provide `amd64.sha256`, `i386.sha256`, ...
    - `format` : The "format" of the asset. It is typically automatically guessed from the extension of the URL (or the mention of "tarball", "zipball" in the URL), but can be set explicitly:
        - `tar.gz`, `tar.xz`, `tar.bz2` : will use `tar` to extract the archive
        - `zip` : will use `unzip` to extract the archive
        - `docker` : useful to extract files from an already-built docker image (instead of rebuilding them locally). Will use `docker-image-extract`
        - `whatever`: whatever arbitrary value, not really meaningful except to imply that the file won't be extracted (eg because it's a .deb to be manually installed with dpkg/apt, or a script, or ...)
    - `in_subdir`: `true` (default) or `false`, depending on if there's an intermediate subdir in the archive before accessing the actual files. Can also be `N` (an integer) to handle special cases where there's `N` level of subdir to get rid of to actually access the files
    - `extract` : `true` or `false`. Defaults to `true` for archives such as `zip`, `tar.gz`, `tar.bz2`, ... Or defaults to `false` when `format` is not something that should be extracted. When `extract = false`, the file will only be `mv`ed to the location, possibly renamed using the `rename` value
    - `rename`: some string like `whatever_your_want`, to be used for convenience when `extract` is `false` and the default name of the file is not practical
    - `platform`: for example `linux/amd64` (defaults to `linux/$YNH_ARCH`) to be used in conjonction with `format = "docker"` to specify which architecture to extract for

    #### Regarding `autoupdate`

    Strictly speaking, this has nothing to do with the actual app install. `autoupdate` is expected to contain metadata for automatic maintenance / update of the app sources info in the manifest. It is meant to be a simpler replacement for "autoupdate" Github workflow mechanism.

    The infos are used by this script : <https://github.com/YunoHost/apps_tools/blob/main/autoupdate_app_sources/autoupdate_app_sources.py> which is ran by the YunoHost infrastructure periodically and will create the corresponding pull request automatically.

    The script will rely on the code repo specified in `code` in the upstream section of the manifest.

    The `autoupdate.strategy` is expected to be constructed like this: `latest_<gitforge>_<strategy>`

    You need to replace the `<gitforge>` in the strategy name by either `github`, `gitlab`, `gitea` or `forgejo`, as the autoupdater supports:

    - GitHub
    - GitLab (official and self-hosted instances)
    - Gitea & Forgejo instances

    And choose one strategy in the following ones:

    - `latest_<gitforge>_release` : similar to `latest_<gitforge>_tag`, but starting from the list of releases. Note that it's the only strategy that provides the changelog link in the PR message. Pre- or draft releases are ignored. Releases may have assets attached to them, in which case you can define:
      - `autoupdate.asset = "some regex"` (when there's only one asset to use). The regex is used to find the appropriate asset among the list of all assets
      - or several `autoupdate.asset.$arch = "some_regex"` (when the asset is arch-specific). The regex is used to find the appropriate asset for the specific arch among the list of assets
    - `latest_<gitforge>_tag` : look for the latest tag (by sorting tags and finding the "largest" version). Then using the corresponding tar.gz url. Tags containing `rc`, `beta`, `alpha`, `start` are ignored, and actually any tag which doesn't look like `x.y.z` or `vx.y.z`
    - `latest_<gitforge>_commit` : will use the latest commit on github, and the corresponding tarball. If this is used for the 'main' source, it will also assume that the version is YYYY.MM.DD corresponding to the date of the commit.

    It is also possible to define `autoupdate.upstream` to use a different Git repository instead of the code repository from the upstream section of the manifest. This can be useful when, for example, the app uses other assets such as plugin from a different repository.

    If the upstream project provides non-standard tag or release names, you can fix this, with a regex with a matching group.

    For example, if tags look like `release-v4.1`, put:

    ```toml
    autoupdate.version_regex = "^release-v(.*)$"
    ```

    And the autoupdater will use the matched group (here: `4.1`) as the version.

    You can make sure that your autoupdate strategy is working well immediately (without waiting for the next check on the infra) by doing the following:
    1. Clone this repo: https://github.com/YunoHost/apps_tools
    2. In `apps_tools` open a terminal to run the following commands:
        ```sh
        # Create test branch
        git checkout -b localtest

        # Create a Python virtual environment
        python -m venv venv
        source venv/bin/activate

        # Install dependencies (if you don't have pip already installed on your system, check https://pip.pypa.io/en/stable/installation)
        pip install -r requirements.txt

        # Run autoupdate script - replace '/path/to/myapp_ynh' with your actual local app path
        ./autoupdate_app_sources/autoupdate_app_sources.py '/path/to/myapp_ynh'
        ```
    3. If the return output includes:
    - `Apps udpated`, it ran successfully. Note that it will automatically make local changes in your app's `manifest.toml` (which can be discarded as they will be made automatically later online by the YNH infra);
    - `Apps failed`, the autoupdate stragegy is not working properly - check the debug info;
    - none of the above but `apps -> Autoupdater just ran, here are the results:`, it ran successfully but the app was already up to date.

    ### Provision/Update
    - For elements with `prefetch = true`, will download the asset (for the appropriate architecture) and store them in `/var/cache/yunohost/download/$app/$source_id`, to be later picked up by `ynh_setup_source`. (NB: this only happens during install and upgrade, not restore)

    ### Deprovision
    - Nothing (just cleanup the cache)
    """

    type = "sources"
    priority = 10

    default_sources_properties: Dict[str, Any] = {
        "prefetch": True,
        "url": None,
        "sha256": None,
    }

    sources: Dict[str, Dict[str, Any]] = {}

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):
        for source_id, infos in properties.items():
            properties[source_id] = copy.copy(self.default_sources_properties)
            properties[source_id].update(infos)

        super().__init__({"sources": properties}, *args, **kwargs)

    def deprovision(self, context: Dict = {}):
        if os.path.isdir(f"/var/cache/yunohost/download/{self.app}/"):
            rm(f"/var/cache/yunohost/download/{self.app}/", recursive=True)

    def provision_or_update(self, context: Dict = {}):
        # Don't prefetch stuff during restore
        if context.get("action") == "restore":
            return

        for source_id, infos in self.sources.items():
            if not infos["prefetch"]:
                continue

            if infos["url"] is None:
                arch = system_arch()
                if (
                    arch in infos
                    and isinstance(infos[arch], dict)
                    and isinstance(infos[arch].get("url"), str)
                    and isinstance(infos[arch].get("sha256"), str)
                ):
                    self.prefetch(source_id, infos[arch]["url"], infos[arch]["sha256"])
                else:
                    raise YunohostError(
                        f"In resources.sources: it looks like you forgot to define url/sha256 or {arch}.url/{arch}.sha256",
                        raw_msg=True,
                    )
            else:
                if infos["sha256"] is None:
                    raise YunohostError(
                        f"In resources.sources: it looks like the sha256 is missing for {source_id}",
                        raw_msg=True,
                    )
                self.prefetch(source_id, infos["url"], infos["sha256"])

    def prefetch(self, source_id, url, expected_sha256):
        logger.debug(f"Prefetching asset {source_id}: {url} ...")

        if not os.path.isdir(f"/var/cache/yunohost/download/{self.app}/"):
            mkdir(f"/var/cache/yunohost/download/{self.app}/", parents=True)
        filename = f"/var/cache/yunohost/download/{self.app}/{source_id}"

        # NB: we use wget and not requests.get() because we want to output to a file (ie avoid ending up with the full archive in RAM)
        # AND the nice --tries, --no-dns-cache, --timeout options ...
        p = subprocess.Popen(
            [
                "/usr/bin/wget",
                "--tries=3",
                "--no-dns-cache",
                "--timeout=900",
                "--no-verbose",
                "--output-document=" + filename,
                url,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out, _ = p.communicate()
        returncode = p.returncode
        if returncode != 0:
            if os.path.exists(filename):
                rm(filename)
            raise YunohostError(
                "app_failed_to_download_asset",
                source_id=source_id,
                url=url,
                app=self.app,
                out=out.decode(),
            )

        assert os.path.exists(
            filename
        ), f"For some reason, wget worked but {filename} doesnt exists?"

        computed_sha256 = check_output(f"sha256sum {filename}").split()[0]
        if computed_sha256 != expected_sha256:
            size = check_output(f"du -hs {filename}").split()[0]
            rm(filename)
            raise YunohostError(
                "app_corrupt_source",
                source_id=source_id,
                url=url,
                app=self.app,
                expected_sha256=expected_sha256,
                computed_sha256=computed_sha256,
                size=size,
            )


class PermissionsResource(AppResource):
    """
    Configure the SSO permissions/tiles. Typically, webapps are expected to have a 'main' permission mapped to '/', meaning that a tile pointing to the `$domain/$path` will be available in the SSO for users allowed to access that app.

    Additional permissions can be created, typically to have a specific tile and/or access rules for the admin part of a webapp.

    The list of allowed user/groups may be initialized using the content of the `init_{perm}_permission` question from the manifest, hence `init_main_permission` replaces the `is_public` question and shall contain a group name (typically, `all_users` or `visitors`).

    ### Example
    ```toml
    [resources.permissions]
    main.url = "/"
    # (these two previous lines should be enough in the majority of cases)

    admin.url = "/admin"
    admin.show_tile = false
    admin.allowed = "admins"   # Assuming the "admins" group exists (cf future developments ;))
    ```

    ### Properties (for each perm name)
    - `url`: The relative URI corresponding to this permission. Typically `/` or `/something`. This property may be omitted for non-web permissions.
    - `show_tile`: (default: `true` if `url` is defined) Wether or not a tile should be displayed for that permission in the user portal
    - `allowed`: (default: nobody) The group initially allowed to access this perm, if `init_{perm}_permission` is not defined in the manifest questions. Note that the admin may tweak who is allowed/unallowed on that permission later on, this is only meant to **initialize** the permission.
    - `auth_header`: (default: `true`) Define for the URL of this permission, if SSOwat pass the authentication header to the application. Default is true
    - `protected`: (default: `false`) Define if this permission is protected. If it is protected the administrator won't be able to add or remove the visitors group of this permission. Defaults to 'false'.
    - `additional_urls`: (default: none) List of additional URL for which access will be allowed/forbidden

    ### Provision/Update
    - Delete any permissions that may exist and be related to this app yet is not declared anymore
    - Loop over the declared permissions and create them if needed or update them with the new values

    ### Deprovision
    - Delete all permission related to this app

    ### Legacy management
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

        # Validate packager-provided infos
        for perm, infos in properties.items():
            if "auth_header" in infos and not isinstance(
                infos.get("auth_header"), bool
            ):
                raise YunohostError(
                    f"In manifest, for permission '{perm}', 'auth_header' should be a boolean",
                    raw_msg=True,
                )
            if "show_tile" in infos and not isinstance(infos.get("show_tile"), bool):
                raise YunohostError(
                    f"In manifest, for permission '{perm}', 'show_tile' should be a boolean",
                    raw_msg=True,
                )
            if "protected" in infos and not isinstance(infos.get("protected"), bool):
                raise YunohostError(
                    f"In manifest, for permission '{perm}', 'protected' should be a boolean",
                    raw_msg=True,
                )
            if "additional_urls" in infos and not isinstance(
                infos.get("additional_urls"), list
            ):
                raise YunohostError(
                    f"In manifest, for permission '{perm}', 'additional_urls' should be a list",
                    raw_msg=True,
                )

        if "main" not in properties:
            properties["main"] = copy.copy(self.default_perm_properties)

        for perm, infos in properties.items():
            properties[perm] = copy.copy(self.default_perm_properties)
            properties[perm].update(infos)
            if properties[perm]["show_tile"] is None:
                properties[perm]["show_tile"] = bool(properties[perm]["url"])

        if properties["main"]["url"] is not None and (
            not isinstance(properties["main"].get("url"), str)
            or properties["main"]["url"] != "/"
        ):
            raise YunohostError(
                "URL for the 'main' permission should be '/' for webapps (or left undefined for non-webapps). Note that / refers to the install url of the app, i.e $domain.tld/$path/",
                raw_msg=True,
            )

        super().__init__({"permissions": properties}, *args, **kwargs)

        from yunohost.app import _get_app_settings, _hydrate_app_template

        settings = _get_app_settings(self.app)
        for perm, infos in self.permissions.items():
            if infos.get("url") and "__" in infos.get("url"):
                infos["url"] = _hydrate_app_template(infos["url"], settings)

            if infos.get("additional_urls"):
                infos["additional_urls"] = [
                    _hydrate_app_template(url, settings)
                    for url in infos["additional_urls"]
                ]

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

        # Detect that we're using a full-domain app,
        # in which case we probably need to automagically
        # define the "path" setting with "/"
        if (
            isinstance(self.permissions["main"]["url"], str)
            and self.get_setting("domain")
            and not self.get_setting("path")
        ):
            self.set_setting("path", "/")

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

                # If we're choosing 'visitors' from the init_{perm}_permission question, add all_users too
                if not infos["allowed"] and init_allowed == "visitors":
                    init_allowed = ["visitors", "all_users"]

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

    ### Example
    ```toml
    [resources.system_user]
    # (empty - defaults are usually okay)
    ```

    ### Properties
    - `allow_ssh`: (default: False) Adds the user to the ssh.app group, allowing SSH connection via this user
    - `allow_sftp`: (default: False) Adds the user to the sftp.app group, allowing SFTP connection via this user
    - `allow_email`: (default: False) Enable authentication on the mail stack for the system user and send mail using `__APP__@__DOMAIN__`. A `mail_pwd` setting is automatically defined (similar to `db_pwd` for databases). You can then configure the app to use `__APP__` and `__MAIL_PWD__` as SMTP credentials (with host 127.0.0.1). You can also tweak the user-part of the domain-part of the email used by manually defining a custom setting `mail_user` or `mail_domain`
    - `home`: (default: `/var/www/__APP__`) Defines the home property for this user. NB: unfortunately you can't simply use `__INSTALL_DIR__` or `__DATA_DIR__` for now

    ### Provision/Update
    - will create the system user if it doesn't exists yet
    - will add/remove the ssh/sftp.app groups

    ### Deprovision
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

    default_properties: Dict[str, Any] = {
        "allow_ssh": False,
        "allow_sftp": False,
        "allow_email": False,
        "home": "/var/www/__APP__",
    }

    # FIXME : wat do regarding ssl-cert, multimedia, and other groups

    allow_ssh: bool = False
    allow_sftp: bool = False
    allow_email: bool = False
    home: str = ""

    def provision_or_update(self, context: Dict = {}):
        from yunohost.app import regen_mail_app_user_config_for_dovecot_and_postfix

        # FIXME : validate that no yunohost user exists with that name?
        # and/or that no system user exists during install ?

        if os.system(f"getent passwd {self.app} >/dev/null 2>/dev/null") != 0:
            # FIXME: improve logging ? os.system wont log stdout / stderr
            cmd = f"useradd --system --user-group {self.app} --home-dir {self.home} --no-create-home"
            ret = os.system(cmd)
            assert ret == 0, f"useradd command failed with exit code {ret}"

        if os.system(f"getent passwd {self.app} >/dev/null 2>/dev/null") != 0:
            raise YunohostError(
                f"Failed to create system user for {self.app}", raw_msg=True
            )

        # Update groups
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

        # Update home dir
        raw_user_line_in_etc_passwd = check_output(f"getent passwd {self.app}").strip()
        user_infos = raw_user_line_in_etc_passwd.split(":")
        current_home = user_infos[5]
        if current_home != self.home:
            ret = os.system(f"usermod --home {self.home} {self.app} 2>/dev/null")
            # Most of the time this won't work because apparently we can't change the home dir while being logged-in -_-
            # So we gotta brute force by replacing the line in /etc/passwd T_T
            if ret != 0:
                user_infos[5] = self.home
                new_raw_user_line_in_etc_passwd = ":".join(user_infos)
                os.system(
                    f"sed -i 's@{raw_user_line_in_etc_passwd}@{new_raw_user_line_in_etc_passwd}@g' /etc/passwd"
                )

        # Update mail-related stuff
        if self.allow_email:
            mail_pwd = self.get_setting("mail_pwd")
            if not mail_pwd:
                mail_pwd = random_ascii(24)
                self.set_setting("mail_pwd", mail_pwd)

            regen_mail_app_user_config_for_dovecot_and_postfix()
        else:
            self.delete_setting("mail_pwd")
            if (
                os.system(
                    f"grep --quiet ' {self.app}$' /etc/postfix/app_senders_login_maps"
                )
                == 0
                or os.system(
                    f"grep --quiet '^{self.app}:' /etc/dovecot/app-senders-passwd"
                )
                == 0
            ):
                regen_mail_app_user_config_for_dovecot_and_postfix()

    def deprovision(self, context: Dict = {}):
        from yunohost.app import regen_mail_app_user_config_for_dovecot_and_postfix

        if os.system(f"getent passwd {self.app} >/dev/null 2>/dev/null") == 0:
            os.system(f"deluser {self.app} >/dev/null")
        if os.system(f"getent passwd {self.app} >/dev/null 2>/dev/null") == 0:
            raise YunohostError(
                f"Failed to delete system user for {self.app}", raw_msg=True
            )

        if os.system(f"getent group {self.app} >/dev/null 2>/dev/null") == 0:
            os.system(f"delgroup {self.app} >/dev/null")
        if os.system(f"getent group {self.app} >/dev/null 2>/dev/null") == 0:
            raise YunohostError(
                f"Failed to delete system user for {self.app}", raw_msg=True
            )

        self.delete_setting("mail_pwd")
        if (
            os.system(
                f"grep --quiet ' {self.app}$' /etc/postfix/app_senders_login_maps"
            )
            == 0
            or os.system(f"grep --quiet '^{self.app}:' /etc/dovecot/app-senders-passwd")
            == 0
        ):
            regen_mail_app_user_config_for_dovecot_and_postfix()

        # FIXME : better logging and error handling, add stdout/stderr from the deluser/delgroup commands...


class InstalldirAppResource(AppResource):
    """
    Creates a directory to be used by the app as the installation directory, typically where the app sources and assets are located. The corresponding path is stored in the settings as `install_dir`

    ### Example
    ```toml
    [resources.install_dir]
    # (empty - defaults are usually okay)
    ```

    ### Properties
    - `dir`: (default: `/var/www/__APP__`) The full path of the install dir
    - `owner`: (default: `__APP__:rwx`) The owner (and owner permissions) for the install dir
    - `group`: (default: `__APP__:rx`) The group (and group permissions) for the install dir

    ### Provision/Update
    - during install, the folder will be deleted if it already exists (FIXME: is this what we want?)
    - if the dir path changed and a folder exists at the old location, the folder will be `mv`'ed to the new location
    - otherwise, creates the directory if it doesn't exists yet
    - (re-)apply permissions (only on the folder itself, not recursively)
    - save the value of `dir` as `install_dir` in the app's settings, which can be then used by the app scripts (`$install_dir`) and conf templates (`__INSTALL_DIR__`)

    ### Deprovision
    - recursively deletes the directory if it exists

    ### Legacy management
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
        "owner": "__APP__:rwx",
        "group": "__APP__:rx",
    }

    dir: str = ""
    owner: str = ""
    group: str = ""

    # FIXME: change default dir to /opt/stuff if app ain't a webapp...

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
                    f"Moving {current_install_dir} to {self.dir}... (this may take a while)"
                )
                shutil.move(current_install_dir, self.dir)
            else:
                mkdir(self.dir, parents=True)

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

    ### Example
    ```toml
    [resources.data_dir]
    # (empty - defaults are usually okay)
    ```

    ### Properties
    - `dir`: (default: `/home/yunohost.app/__APP__`) The full path of the data dir
    - `subdirs`: (default: empty list) A list of subdirs to initialize inside the data dir. For example, `['foo', 'bar']`
    - `owner`: (default: `__APP__:rwx`) The owner (and owner permissions) for the data dir
    - `group`: (default: `__APP__:rx`) The group (and group permissions) for the data dir

    ### Provision/Update
    - if the dir path changed and a folder exists at the old location, the folder will be `mv`'ed to the new location
    - otherwise, creates the directory if it doesn't exists yet
    - create each subdir declared and which do not exist already
    - (re-)apply permissions (only on the folder itself and declared subdirs, not recursively)
    - save the value of `dir` as `data_dir` in the app's settings, which can be then used by the app scripts (`$data_dir`) and conf templates (`__DATA_DIR__`)

    ### Deprovision
    - (only if the purge option is chosen by the user) recursively deletes the directory if it exists
    - also delete the corresponding setting

    ### Legacy management
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
        "subdirs": [],
        "owner": "__APP__:rwx",
        "group": "__APP__:rx",
    }

    dir: str = ""
    subdirs: list = []
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
                    f"Moving {current_data_dir} to {self.dir}... (this may take a while)"
                )
                shutil.move(current_data_dir, self.dir)
            else:
                mkdir(self.dir, parents=True)

        for subdir in self.subdirs:
            full_path = os.path.join(self.dir, subdir)
            if not os.path.isdir(full_path):
                mkdir(full_path, parents=True)

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
        for subdir in self.subdirs:
            full_path = os.path.join(self.dir, subdir)
            chmod(os.path.realpath(full_path), perm_octal)
            chown(os.path.realpath(full_path), owner, group)

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

    ### Example
    ```toml
    [resources.apt]
    packages = ["nyancat", "lolcat", "sl"]

    # (this part is optional and corresponds to the legacy ynh_install_extra_app_dependencies helper)
    extras.yarn.repo = "deb https://dl.yarnpkg.com/debian/ stable main"
    extras.yarn.key = "https://dl.yarnpkg.com/debian/pubkey.gpg"
    extras.yarn.packages = ["yarn"]
    ```

    ### Properties
    - `packages`: List of packages to be installed via `apt`
    - `packages_from_raw_bash`: A multi-line bash snippet (using triple quotes as open/close) which should echo additional packages to be installed. Meant to be used for packages to be conditionally installed depending on architecture, debian version, install questions, or other logic.
    - `extras`: A dict of (repo, key, packages) corresponding to "extra" repositories to fetch dependencies from

    ### Provision/Update
    - The code literally calls the bash helpers `ynh_install_app_dependencies` and `ynh_install_extra_app_dependencies`, similar to what happens in v1.
    - Note that when `packages` contains some phpX.Y-foobar dependencies, this will automagically define a `phpversion` setting equal to `X.Y` which can therefore be used in app scripts ($phpversion) or templates (`__PHPVERSION__`)

    ### Deprovision
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
    packages_from_raw_bash: str = ""
    extras: Dict[str, Dict[str, Union[str, List]]] = {}

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):
        super().__init__(properties, *args, **kwargs)

        if isinstance(self.packages, str):
            if self.packages.strip() == "":
                self.packages = []
            else:
                self.packages = [value.strip() for value in self.packages.split(",")]

        if self.packages_from_raw_bash:
            out, err = self.check_output_bash_snippet(self.packages_from_raw_bash)
            if err:
                logger.error(
                    "Error while running apt resource packages_from_raw_bash snippet:"
                )
                logger.error(err)
            self.packages += out.split("\n")

        for key, values in self.extras.items():
            if isinstance(values.get("packages"), str):
                values["packages"] = [value.strip() for value in values["packages"].split(",")]  # type: ignore

            if isinstance(values.get("packages_from_raw_bash"), str):
                out, err = self.check_output_bash_snippet(
                    values.get("packages_from_raw_bash")
                )
                if err:
                    logger.error(
                        f"Error while running apt resource packages_from_raw_bash snippet for '{key}' extras:"
                    )
                    logger.error(err)
                values["packages"] = values.get("packages", []) + [value.strip() for value in out.split("\n") if value.strip()]  # type: ignore

            if (
                not isinstance(values.get("repo"), str)
                or not isinstance(values.get("key"), str)
                or not isinstance(values.get("packages"), list)
            ):
                raise YunohostError(
                    "In apt resource in the manifest: 'extras' repo should have the keys 'repo', 'key' defined as strings, 'packages' defined as list or 'packages_from_raw_bash' defined as string",
                    raw_msg=True,
                )

        # Drop 'extras' entries associated to no packages
        self.extras = {
            key: values for key, values in self.extras.items() if values["packages"]
        }

        # Yarn repository is now provided by the core.
        # Let's "move" any extra apt resources depending on yarn to the standard packages list.
        for key in list(self.extras.keys()):
            if self.extras[key][
                "repo"
            ] == "deb https://dl.yarnpkg.com/debian/ stable main" and self.extras[key][
                "packages"
            ] == [
                "yarn"
            ]:
                self.packages.append("yarn")
                del self.extras[key]

    def provision_or_update(self, context: Dict = {}):

        if self.helpers_version >= 2.1:
            ynh_apt_install_dependencies = "ynh_apt_install_dependencies"
            ynh_apt_install_dependencies_from_extra_repository = (
                "ynh_apt_install_dependencies_from_extra_repository"
            )
        else:
            ynh_apt_install_dependencies = "ynh_install_app_dependencies"
            ynh_apt_install_dependencies_from_extra_repository = (
                "ynh_install_extra_app_dependencies"
            )

        script = ""
        if self.packages:
            script += " ".join([ynh_apt_install_dependencies, *self.packages])
        for repo, values in self.extras.items():
            script += "\n" + " ".join(
                [
                    ynh_apt_install_dependencies_from_extra_repository,
                    f"--repo='{values['repo']}'",
                    f"--key='{values['key']}'",
                    f"--package='{' '.join(values['packages'])}'",
                ]
            )
            # FIXME : we're feeding the raw value of values['packages'] to the helper .. if we want to be consistent, may they should be comma-separated, though in the majority of cases, only a single package is installed from an extra repo..

        self._run_script("provision_or_update", script)

    def deprovision(self, context: Dict = {}):
        if self.helpers_version >= 2.1:
            ynh_apt_remove_dependencies = "ynh_apt_remove_dependencies"
        else:
            ynh_apt_remove_dependencies = "ynh_remove_app_dependencies"

        self._run_script("deprovision", ynh_apt_remove_dependencies)


class PortsResource(AppResource):
    """
    Book port(s) to be used by the app, typically to be used to the internal reverse-proxy between nginx and the app process.

    Note that because multiple ports can be booked, each properties is prefixed by the name of the port. `main` is a special name and will correspond to the setting `$port`, whereas for example `xmpp_client` will correspond to the setting `$port_xmpp_client`.

    ### Example
    ```toml
    [resources.ports]
    # (empty should be fine for most apps... though you can customize stuff if absolutely needed)


    main.default = 12345    # if you really want to specify a prefered value .. but shouldnt matter in the majority of cases

    xmpp_client.default = 5222  # if you need another port, pick a name for it (here, "xmpp_client")
    xmpp_client.exposed = "TCP" # here, we're telling that the port needs to be publicly exposed on TCP on the firewall
    ```

    ### Properties (for every port name)
    - `default`: The prefered value for the port. If this port is already being used by another process right now, or is booked in another app's setting, the code will increment the value until it finds a free port and store that value as the setting. If no value is specified, a random value between 10000 and 60000 is used.
    - `exposed`: (default: `false`) Wether this port should be opened on the firewall and be publicly reachable. This should be kept to `false` for the majority of apps than only need a port for internal reverse-proxying! Possible values: `false`, `true`(=`Both`), `Both`, `TCP`, `UDP`. This will result in the port being opened on the firewall, and the diagnosis checking that a program answers on that port.
    - `fixed`: (default: `false`) Tells that the app absolutely needs the specific value provided in `default`, typically because it's needed for a specific protocol

    ### Provision/Update (for every port name)
    - If not already booked, look for a free port, starting with the `default` value (or a random value between 10000 and 60000 if no `default` set)
    - If `exposed` is not `false`, open the port in the firewall accordingly - otherwise make sure it's closed.
    - The value of the port is stored in the `$port` setting for the `main` port, or `$port_NAME` for other `NAME`s

    ### Deprovision
    - Close the ports on the firewall if relevant
    - Deletes all the port settings

    ### Legacy management
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

        # This is to prevent using twice the same port during provisionning.
        self.ports_used_by_self: list[int] = []

        super().__init__({"ports": properties}, *args, **kwargs)

    def _port_is_used(self, port):
        # FIXME : this could be less brutal than two os.system...
        used_by_process = (
            os.system(
                "ss --numeric --listening --tcp --udp | awk '{print$5}' | grep --quiet --extended-regexp ':%s$'"
                % port
            )
            == 0
        )
        # This second command is mean to cover (most) case where an app is using a port yet ain't currently using it for some reason (typically service ain't up)
        used_by_app = (
            os.system(
                f"grep --quiet --extended-regexp \"port: '?{port}'?\" /etc/yunohost/apps/*/settings.yml"
            )
            == 0
        )
        used_by_self_provisioning = port in self.ports_used_by_self

        return used_by_process or used_by_app or used_by_self_provisioning

    def provision_or_update(self, context: Dict = {}):
        from yunohost.firewall import firewall_allow, firewall_disallow

        for name, infos in self.ports.items():
            setting_name = f"port_{name}" if name != "main" else "port"
            port_value = self.get_setting(setting_name)
            if not port_value and name != "main":
                # Automigrate from legacy setting foobar_port (instead of port_foobar)
                legacy_setting_name = f"{name}_port"
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
                            f"Port {port_value} is already used by another process or app.",
                            raw_msg=True,
                        )
                else:
                    while self._port_is_used(port_value):
                        port_value += 1

            self.ports_used_by_self.append(port_value)
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

    ### Example
    ```toml
    [resources.database]
    type = "mysql"   # or : "postgresql". Only these two values are supported
    ```

    ### Properties
    - `type`: The database type, either `mysql` or `postgresql`

    ### Provision/Update
    - (Re)set the `$db_name` and `$db_user` settings with the sanitized app name (replacing `-` and `.` with `_`)
    - If `$db_pwd` doesn't already exists, pick a random database password and store it in that setting
    - If the database doesn't exists yet, create the SQL user and DB using `ynh_mysql_create_db` or `ynh_psql_create_db`.

    ### Deprovision
    - Drop the DB using `ynh_mysql_remove_db` or `ynh_psql_remove_db`
    - Deletes the `db_name`, `db_user` and `db_pwd` settings

    ### Legacy management
    - In the past, the sql passwords may have been named `mysqlpwd` or `psqlpwd`, in which case it will automatically be renamed as `db_pwd`
    """

    # Notes for future?
    # deep_clean  -> ... idk look into any db name that would not be related to any app...
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
        # to avoid conflicting with the generic self.type of the resource object...
        # dunno if that's really a good idea :|
        properties = {"dbtype": properties["type"]}

        super().__init__(properties, *args, **kwargs)

    def db_exists(self, db_name):
        if self.dbtype == "mysql":
            return os.system(f"mariadb-show | grep -q -w '{db_name}' 2>/dev/null") == 0
        elif self.dbtype == "postgresql":
            return (
                os.system(
                    f"sudo --login --user=postgres psql '{db_name}' -c ';' >/dev/null 2>/dev/null"
                )
                == 0
            )
        else:
            return False

    def provision_or_update(self, context: Dict = {}):
        # This is equivalent to ynh_sanitize_dbid
        db_user = self.app.replace("-", "_").replace(".", "_")
        db_name = self.get_setting("db_name") or db_user
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
        db_user = self.app.replace("-", "_").replace(".", "_")
        db_name = self.get_setting("db_name") or db_user

        if self.dbtype == "mysql":
            db_helper_name = "mysql"
        elif self.dbtype == "postgresql":
            db_helper_name = "psql"
        else:
            raise RuntimeError(f"Invalid dbtype {self.dbtype}")

        self._run_script(
            "deprovision",
            f"""
ynh_{db_helper_name}_database_exists "{db_name}" && ynh_{db_helper_name}_drop_db "{db_name}" || true
ynh_{db_helper_name}_user_exists "{db_user}" && ynh_{db_helper_name}_drop_user "{db_user}" || true
""",
        )

        self.delete_setting("db_name")
        self.delete_setting("db_user")
        self.delete_setting("db_pwd")


AppResourceClassesByType = {c.type: c for c in AppResource.__subclasses__()}
