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
import glob
import os
import re
from collections import OrderedDict
from logging import getLogger
from typing import TYPE_CHECKING, Any, Iterator, Literal, Sequence, Type, Union, cast

from pydantic import BaseModel, ConfigDict, field_validator

from moulinette import Moulinette, m18n
from moulinette.interfaces.cli import colorize
from moulinette.utils.filesystem import mkdir, read_toml, read_yaml, write_to_yaml
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.form import (
    AnyOption,
    BaseInputOption,
    BaseReadonlyOption,
    FileOption,
    OptionsModel,
    OptionType,
    Translation,
    build_form,
    evaluate_simple_js_expression,
    parse_prefilled_values,
    prompt_or_validate_form,
)
from yunohost.utils.i18n import _value_for_locale

if TYPE_CHECKING:
    from pydantic import GetJsonSchemaHandler
    from pydantic.fields import ValidationInfo
    from pydantic.json_schema import JsonSchemaValue
    from pydantic.typing import AbstractSetIntStr, MappingIntStrAny
    from pydantic_core.core_schema import CoreSchema

    from yunohost.utils.form import FormModel, Hooks
    from yunohost.log import OperationLogger

if TYPE_CHECKING:
    from moulinette.utils.log import MoulinetteLogger

    logger = cast(MoulinetteLogger, getLogger("yunohost.configpanel"))
else:
    logger = getLogger("yunohost.configpanel")


# ╭───────────────────────────────────────────────────────╮
# │  ╭╮╮╭─╮┌─╮┌─╴╷  ╭─╴                                   │
# │  ││││ ││ │├─╴│  ╰─╮                                   │
# │  ╵╵╵╰─╯└─╯╰─╴╰─╴╶─╯                                   │
# ╰───────────────────────────────────────────────────────╯

CONFIG_PANEL_VERSION_SUPPORTED = 1.0


class ContainerModel(BaseModel):
    id: str
    name: Translation | None = None
    services: list[str] = []
    help: Translation | None = None

    def translate(self, i18n_key: str | None = None) -> None:
        """
        Translate `ask` and `name` attributes of panels and section.
        This is in place mutation.
        """

        for key in ("help", "name"):
            value = getattr(self, key)
            if value:
                setattr(self, key, _value_for_locale(value))
            elif m18n.key_exists(f"{i18n_key}_{self.id}_{key}"):
                setattr(self, key, m18n.n(f"{i18n_key}_{self.id}_{key}"))


class SectionModel(ContainerModel, OptionsModel):
    """
    Sections are, basically, options grouped together. Sections are `dict`s defined inside a Panel and require a unique id (in the below example, the id is `customization` prepended by the panel's id `main`). Keep in mind that this combined id will be used in CLI to refer to the section, so choose something short and meaningfull. Also make sure to not make a typo in the panel id, which would implicitly create an other entire panel.

    If at least one `button` is present it then become an action section.
    Options in action sections are not considered settings and therefor are not saved, they are more like parameters that exists only during the execution of an action.
    FIXME i'm not sure we have this in code.

    #### Examples
    ```toml
    [main]

        [main.customization]
        name.en = "Advanced configuration"
        name.fr = "Configuration avancée"
        help = "Every form items in this section are not saved."
        services = ["__APP__", "nginx"]

            [main.customization.option_id]
            type = "string"
            # …refer to Options doc
    ```

    #### Properties
    - `name` (optional): `Translation` or `str`, displayed as the section's title if any
    - `help`: `Translation` or `str`, text to display before the first option
    - `services` (optional): `list` of services names to `reload-or-restart` when any option's value contained in the section changes
        - `"__APP__` will refer to the app instance name
    - `optional`: `bool` (default: `true`), set the default `optional` prop of all Options in the section
    - `visible`: `bool` or `JSExpression` (default: `true`), allow to conditionally display a section depending on user's answers to previous questions.
        - Be careful that the `visible` property should only refer to **previous** options's value. Hence, it should not make sense to have a `visible` property on the very first section.
    """

    visible: bool | str = True
    optional: bool = True
    is_action_section: bool = False
    bind: str | None = None

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        id: str,
        name: Translation | None = None,
        services: list[str] = [],
        help: Translation | None = None,
        visible: bool | str = True,
        optional: bool = True,
        bind: str | None = None,
        **kwargs,
    ) -> None:
        options = self.options_dict_to_list(kwargs, optional=optional)
        is_action_section = any(
            [option["type"] == OptionType.button for option in options]
        )
        ContainerModel.__init__(  # type: ignore
            self,
            id=id,
            name=name,
            services=services,
            help=help,
            visible=visible,
            bind=bind,
            options=options,
            is_action_section=is_action_section,
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: "CoreSchema", handler: "GetJsonSchemaHandler"
    ) -> "JsonSchemaValue":
        schema = handler(core_schema)
        del schema["properties"]["id"]
        options = schema["properties"].pop("options")
        del schema["required"]
        schema["additionalProperties"] = options["items"]

        return schema

    def is_visible(self, context: dict[str, Any]) -> bool:
        if isinstance(self.visible, bool):
            return self.visible

        return evaluate_simple_js_expression(self.visible, context=context)

    def translate(self, i18n_key: str | None = None) -> None:
        """
        Call to `Container`'s `translate` for self translation
        + Call to `OptionsContainer`'s `translate_options` for options translation
        """
        super().translate(i18n_key)
        self.translate_options(i18n_key)


class PanelModel(ContainerModel):
    """
    Panels are, basically, sections grouped together. Panels are `dict`s defined inside a ConfigPanel file and require a unique id (in the below example, the id is `main`). Keep in mind that this id will be used in CLI to refer to the panel, so choose something short and meaningfull.

    #### Examples
    ```toml
    [main]
    name.en = "Main configuration"
    name.fr = "Configuration principale"
    help = ""
    services = ["__APP__", "nginx"]

        [main.customization]
        # …refer to Sections doc
    ```
    #### Properties
    - `name`: `Translation` or `str`, displayed as the panel title
    - `help` (optional): `Translation` or `str`, text to display before the first section
    - `services` (optional): `list` of services names to `reload-or-restart` when any option's value contained in the panel changes
        - `"__APP__` will refer to the app instance name
    - `actions`: FIXME not sure what this does
    """

    # FIXME what to do with `actions?
    actions: dict[str, Translation] = {"apply": {"en": "Apply"}}
    bind: str | None = None
    sections: list[SectionModel]

    model_config = ConfigDict(
        extra="allow",
    )

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        id: str,
        name: Translation | None = None,
        services: list[str] = [],
        help: Translation | None = None,
        bind: str | None = None,
        **kwargs,
    ) -> None:
        sections = [data | {"id": name} for name, data in kwargs.items()]
        super().__init__(  # type: ignore
            id=id, name=name, services=services, help=help, bind=bind, sections=sections
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: "CoreSchema", handler: "GetJsonSchemaHandler"
    ) -> "JsonSchemaValue":
        schema = handler(core_schema)
        del schema["properties"]["id"]
        del schema["properties"]["sections"]
        del schema["required"]
        schema["additionalProperties"] = {"$ref": "#/definitions/SectionModel"}

        return schema

    def translate(self, i18n_key: str | None = None) -> None:
        """
        Recursivly mutate translatable attributes to their translation
        """
        super().translate(i18n_key)

        for section in self.sections:
            section.translate(i18n_key)


class ConfigPanelModel(BaseModel):
    """
    This is the 'root' level of the config panel toml file

    #### Examples

    ```toml
    version = 1.0

    [config]
    # …refer to Panels doc
    ```

    #### Properties

    - `version`: `float` (default: `1.0`), version that the config panel supports in terms of features.
    - `i18n` (optional): `str`, an i18n property that let you internationalize options text.
        - However this feature is only available in core configuration panel (like `yunohost domain config`), prefer the use `Translation` in `name`, `help`, etc.

    """

    version: float = CONFIG_PANEL_VERSION_SUPPORTED
    i18n: str | None = None
    panels: list[PanelModel]

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
    )

    # Don't forget to pass arguments to super init
    def __init__(
        self,
        version: float,
        i18n: str | None = None,
        **kwargs,
    ) -> None:
        panels = [data | {"id": name} for name, data in kwargs.items()]
        super().__init__(version=version, i18n=i18n, panels=panels)

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: "CoreSchema", handler: "GetJsonSchemaHandler"
    ) -> "JsonSchemaValue":
        """Update the schema to the expected input
        In actual TOML definition, schema is like:
        ```toml
        [panel_1]
            [panel_1.section_1]
                [panel_1.section_1.option_1]
        ```
        Which is equivalent to `{"panel_1": {"section_1": {"option_1": {}}}}`
        so `section_id` (and `option_id`) are additional property of `panel_id`,
        which is convinient to write but not ideal to iterate.
        In ConfigPanelModel we gather additional properties of panels, sections
        and options as lists so that structure looks like:
        `{"panels`: [{"id": "panel_1", "sections": [{"id": "section_1", "options": [{"id": "option_1"}]}]}]
        """
        schema = handler(core_schema)
        del schema["properties"]["panels"]
        del schema["required"]
        schema["additionalProperties"] = {"$ref": "#/definitions/PanelModel"}

        return schema

    @property
    def sections(self) -> Iterator[SectionModel]:
        """Convinient prop to iter on all sections"""
        for panel in self.panels:
            for section in panel.sections:
                yield section

    @property
    def options(self) -> Iterator[AnyOption]:
        """Convinient prop to iter on all options"""
        for section in self.sections:
            for option in section.options:
                yield option

    def get_panel(self, panel_id: str) -> PanelModel | None:
        for panel in self.panels:
            if panel.id == panel_id:
                return panel
        return None

    def get_section(self, section_id: str) -> SectionModel | None:
        for section in self.sections:
            if section.id == section_id:
                return section
        return None

    def get_option(self, option_id: str) -> AnyOption | None:
        for option in self.options:
            if option.id == option_id:
                return option
        # FIXME raise error?
        return None

    @property
    def services(self) -> list[str]:
        services = set()
        for panel in self.panels:
            services |= set(panel.services)
            for section in panel.sections:
                services |= set(section.services)

        services_ = list(services)
        services_.sort(key="nginx".__eq__)
        return services_

    def iter_children(
        self,
        trigger: list[Literal["panel", "section", "option", "action"]] = ["option"],
    ):
        for panel in self.panels:
            if "panel" in trigger:
                yield (panel, None, None)
            for section in panel.sections:
                if "section" in trigger:
                    yield (panel, section, None)
                if "action" in trigger:
                    for option in section.options:
                        if option.type is OptionType.button:
                            yield (panel, section, option)
                if "option" in trigger:
                    for option in section.options:
                        yield (panel, section, option)

    def translate(self) -> None:
        """
        Recursivly mutate translatable attributes to their translation
        """
        for panel in self.panels:
            panel.translate(self.i18n)

    @field_validator("version")
    @classmethod
    def check_version(cls, value: float, info: "ValidationInfo") -> float:
        if value < CONFIG_PANEL_VERSION_SUPPORTED:
            raise ValueError(
                f"Config panels version '{value}' are no longer supported."
            )

        return value


# ╭───────────────────────────────────────────────────────╮
# │  ╭─╴╭─╮╭╮╷┌─╴╶┬╴╭─╮   ╶┬╴╭╮╮┌─╮╷                      │
# │  │  │ ││││├─╴ │ │╶╮    │ │││├─╯│                      │
# │  ╰─╴╰─╯╵╰╯╵  ╶┴╴╰─╯   ╶┴╴╵╵╵╵  ╰─╴                    │
# ╰───────────────────────────────────────────────────────╯

if TYPE_CHECKING:
    FilterKey = Sequence[str | None]
    RawConfig = OrderedDict[str, Any]
    RawSettings = dict[str, Any]
    ConfigPanelGetMode = Literal["classic", "full", "export"]


def parse_filter_key(key: str | None = None) -> "FilterKey":
    if key and key.count(".") > 2:
        raise YunohostError(
            f"The filter key {key} has too many sub-levels, the max is 3.",
            raw_msg=True,
        )

    if not key:
        return (None, None, None)
    keys = key.split(".")
    return tuple(keys[i] if len(keys) > i else None for i in range(3))


class ConfigPanel:
    entity_type = "config"
    save_path_tpl: str | None = None
    config_path_tpl = "/usr/share/yunohost/config_{entity_type}.toml"
    save_mode = "full"
    settings_must_be_defined: bool = False
    filter_key: "FilterKey" = (None, None, None)
    config: ConfigPanelModel | None = None
    form: Union["FormModel", None] = None
    raw_settings: "RawSettings" = {}
    hooks: "Hooks" = {}

    @classmethod
    def list(cls):
        """
        List available config panel
        """
        try:
            entities = [
                re.match(
                    "^" + cls.save_path_tpl.format(entity="(?p<entity>)") + "$", f
                ).group("entity")
                for f in glob.glob(cls.save_path_tpl.format(entity="*"))
                if os.path.isfile(f)
            ]
        except FileNotFoundError:
            entities = []
        return entities

    def __init__(
        self, entity, config_path=None, save_path=None, creation=False
    ) -> None:
        self.entity = entity
        self.config_path = config_path
        if not config_path:
            self.config_path = self.config_path_tpl.format(
                entity=entity, entity_type=self.entity_type
            )
        self.save_path = save_path
        if not save_path and self.save_path_tpl:
            self.save_path = self.save_path_tpl.format(entity=entity)

        if (
            self.save_path
            and self.save_mode != "diff"
            and not creation
            and not os.path.exists(self.save_path)
        ):
            raise YunohostValidationError(
                f"{self.entity_type}_unknown", **{self.entity_type: entity}
            )
        if self.save_path and creation and os.path.exists(self.save_path):
            raise YunohostValidationError(
                f"{self.entity_type}_exists", **{self.entity_type: entity}
            )

        # Search for hooks in the config panel
        self.hooks = {
            func: getattr(self, func)
            for func in dir(self)
            if callable(getattr(self, func))
            and re.match("^(validate|post_ask)__", func)
        }

    def get(
        self, key: str | None = None, mode: "ConfigPanelGetMode" = "classic"
    ) -> Any:
        self.filter_key = parse_filter_key(key)
        self.config, self.form = self._get_config_panel(prevalidate=False)

        panel_id, section_id, option_id = self.filter_key

        # In 'classic' mode, we display the current value if key refer to an option
        if option_id and mode == "classic":
            option = self.config.get_option(option_id)

            if option is None:
                # FIXME i18n
                raise YunohostValidationError(
                    f"Couldn't find any option with id {option_id}", raw_msg=True
                )

            if isinstance(option, BaseReadonlyOption):
                return None

            return option.normalize(self.form[option_id], option)

        # Format result in 'classic' or 'export' mode
        self.config.translate()
        logger.debug(f"Formating result in '{mode}' mode")

        if mode == "full":
            result = self.config.model_dump(exclude_none=True)

            for panel in result["panels"]:
                for section in panel["sections"]:
                    for opt in section["options"]:
                        instance = self.config.get_option(opt["id"])
                        if isinstance(instance, BaseInputOption):
                            opt["value"] = instance.normalize(
                                self.form[opt["id"]], instance
                            )
            return result

        result = OrderedDict()

        for panel in self.config.panels:
            for section in panel.sections:
                if section.is_action_section and mode != "full":
                    continue

                for option in section.options:
                    # FIXME not sure why option resolves as possibly `None`
                    option = cast(AnyOption, option)

                    if mode == "export":
                        if isinstance(option, BaseInputOption):
                            result[option.id] = self.form[option.id]
                        continue

                    if mode == "classic":
                        key = f"{panel.id}.{section.id}.{option.id}"
                        result[key] = {"ask": option.ask}

                        if isinstance(option, BaseInputOption):
                            result[key]["value"] = option.humanize(
                                self.form[option.id], option
                            )
                            if option.type is OptionType.password:
                                result[key][
                                    "value"
                                ] = "**************"  # Prevent displaying password in `config get`

        return result

    def set(
        self,
        key: str | None = None,
        value: Any = None,
        args: str | None = None,
        args_file: str | None = None,
        operation_logger: Union["OperationLogger", None] = None,
    ) -> None:
        self.filter_key = parse_filter_key(key)
        panel_id, section_id, option_id = self.filter_key

        if (args is not None or args_file is not None) and value is not None:
            raise YunohostValidationError(
                "You should either provide a value, or a serie of args/args_file, but not both at the same time",
                raw_msg=True,
            )

        if not option_id and value is not None:
            raise YunohostValidationError("config_cant_set_value_on_section")

        # Import and parse pre-answered options
        logger.debug("Import and parse pre-answered options")
        if option_id and value is not None:
            prefilled_answers = {option_id: value}
        else:
            prefilled_answers = parse_prefilled_values(args, args_file)

        self.config, self.form = self._get_config_panel()
        # FIXME find a better way to exclude previous settings
        previous_settings = self.form.model_dump()

        # FIXME Not sure if this is need (redact call to operation logger does it on all the instances)
        # BaseOption.operation_logger = operation_logger

        self.form = self._ask(
            self.config,
            self.form,
            prefilled_answers=prefilled_answers,
            hooks=self.hooks,
        )

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
        finally:
            # Delete files uploaded from API
            # FIXME : this is currently done in the context of config panels,
            # but could also happen in the context of app install ... (or anywhere else
            # where we may parse args etc...)
            FileOption.clean_upload_dirs()

        self._reload_services()

        logger.success("Config updated as expected")

        if operation_logger:
            operation_logger.success()

    def list_actions(self) -> dict[str, str]:
        actions = {}

        # FIXME : meh, loading the entire config panel is again going to cause
        # stupid issues for domain (e.g loading registrar stuff when willing to just list available actions ...)
        self.config, self.form = self._get_config_panel()

        for panel, section, option in self.config.iter_children():
            if option.type == OptionType.button:
                key = f"{panel.id}.{section.id}.{option.id}"
                actions[key] = _value_for_locale(option.ask)

        return actions

    def run_action(
        self,
        key: str | None = None,
        args: str | None = None,
        args_file: str | None = None,
        operation_logger: Union["OperationLogger", None] = None,
    ) -> None:
        #
        # FIXME : this stuff looks a lot like set() ...
        #
        panel_id, section_id, action_id = parse_filter_key(key)
        # since an action may require some options from its section,
        # remove the action_id from the filter
        self.filter_key = (panel_id, section_id, None)

        self.config, self.form = self._get_config_panel()

        # FIXME: should also check that there's indeed a key called action
        if not action_id or not self.config.get_option(action_id):
            raise YunohostValidationError(f"No action named {action_id}", raw_msg=True)

        # Import and parse pre-answered options
        logger.debug("Import and parse pre-answered options")
        prefilled_answers = parse_prefilled_values(args, args_file)

        self.form = self._ask(
            self.config,
            self.form,
            prefilled_answers=prefilled_answers,
            action_id=action_id,
            hooks=self.hooks,
        )

        # FIXME Not sure if this is need (redact call to operation logger does it on all the instances)
        # BaseOption.operation_logger = operation_logger

        # FIXME: here, we could want to check constrains on
        # the action's visibility / requirements wrt to the answer to questions ...

        if operation_logger:
            operation_logger.start()

        try:
            self._run_action(self.form, action_id)
        except YunohostError:
            raise
        # Script got manually interrupted ...
        # N.B. : KeyboardInterrupt does not inherit from Exception
        except (KeyboardInterrupt, EOFError):
            error = m18n.n("operation_interrupted")
            logger.error(m18n.n("config_action_failed", action=key, error=error))
            raise
        # Something wrong happened in Yunohost's code (most probably hook_exec)
        except Exception:
            import traceback

            error = m18n.n("unexpected_error", error="\n" + traceback.format_exc())
            logger.error(m18n.n("config_action_failed", action=key, error=error))
            raise
        finally:
            # Delete files uploaded from API
            # FIXME : this is currently done in the context of config panels,
            # but could also happen in the context of app install ... (or anywhere else
            # where we may parse args etc...)
            FileOption.clean_upload_dirs()

        # FIXME: i18n
        logger.success(f"Action {action_id} successful")

        if operation_logger:
            operation_logger.success()

    def _get_raw_config(self) -> "RawConfig":
        if not os.path.exists(self.config_path):
            raise YunohostValidationError("config_no_panel")

        return read_toml(self.config_path)

    def _get_raw_settings(self) -> "RawSettings":
        if not self.save_path or not os.path.exists(self.save_path):
            return {}

        return read_yaml(self.save_path) or {}

    def _get_partial_raw_config(self) -> "RawConfig":
        def filter_keys(
            data: "RawConfig",
            key: str,
            model: Type[ConfigPanelModel] | Type[PanelModel] | Type[SectionModel],
        ) -> "RawConfig":
            # filter in keys defined in model, filter out panels/sections/options that aren't `key`
            return OrderedDict(
                {k: v for k, v in data.items() if k in model.model_fields or k == key}
            )

        raw_config = self._get_raw_config()

        panel_id, section_id, option_id = self.filter_key

        try:
            if panel_id:
                raw_config = filter_keys(raw_config, panel_id, ConfigPanelModel)

                if section_id:
                    raw_config[panel_id] = filter_keys(
                        raw_config[panel_id], section_id, PanelModel
                    )

                    if option_id:
                        raw_config[panel_id][section_id] = filter_keys(
                            raw_config[panel_id][section_id], option_id, SectionModel
                        )
        except KeyError:
            raise YunohostValidationError(
                "config_unknown_filter_key",
                filter_key=".".join([k for k in self.filter_key if k]),
            )

        return raw_config

    def _get_partial_raw_settings_and_mutate_config(
        self, config: ConfigPanelModel
    ) -> tuple[ConfigPanelModel, "RawSettings"]:
        raw_settings = self._get_raw_settings()
        # Save `raw_settings` for diff at `_apply`
        self.raw_settings = raw_settings
        values = {}

        for _, section, option in config.iter_children():
            value = data = raw_settings.get(option.id, getattr(option, "default", None))

            if isinstance(option, BaseInputOption) and option.id not in raw_settings:
                if option.default is not None:
                    value = option.default
                elif option.type is OptionType.file or option.bind == "null":
                    continue
                elif self.settings_must_be_defined:
                    raise YunohostError(
                        f"Config panel question '{option.id}' should be initialized with a value during install or upgrade.",
                        raw_msg=True,
                    )

            if isinstance(data, dict):
                # Settings data if gathered from bash "ynh_app_config_show"
                # may be a custom getter that returns a dict with `value` or `current_value`
                # and other attributes meant to override those of the option.

                if "value" in data:
                    value = data.pop("value")

                # Allow to use value instead of current_value in app config script.
                # e.g. apps may write `echo 'value: "foobar"'` in the config file (which is more intuitive that `echo 'current_value: "foobar"'`
                # For example hotspot used it...
                # See https://github.com/YunoHost/yunohost/pull/1546
                # FIXME do we still need the `current_value`?
                if "current_value" in data:
                    value = data.pop("current_value")

                # Mutate other possible option attributes
                for k, v in data.items():
                    setattr(option, k, v)

            if isinstance(option, BaseInputOption):  # or option.bind == "null":
                values[option.id] = value

        return (config, values)

    def _get_config_panel(
        self, prevalidate: bool = False
    ) -> tuple[ConfigPanelModel, "FormModel"]:
        raw_config = self._get_partial_raw_config()
        config = ConfigPanelModel(**raw_config)
        config, raw_settings = self._get_partial_raw_settings_and_mutate_config(config)
        config.translate()
        Settings = build_form(config.options)
        settings = (
            Settings(**raw_settings)
            if prevalidate
            else Settings.model_construct(**raw_settings)
        )

        try:
            config.panels[0].sections[0].options[0]
        except (KeyError, IndexError):
            raise YunohostValidationError(
                "config_unknown_filter_key", filter_key=self.filter_key
            )

        return (config, settings)

    def _ask(
        self,
        config: ConfigPanelModel,
        form: "FormModel",
        prefilled_answers: dict[str, Any] = {},
        action_id: str | None = None,
        hooks: "Hooks" = {},
    ) -> "FormModel":
        # FIXME could be turned into a staticmethod
        logger.debug("Ask unanswered question and prevalidate data")

        interactive = Moulinette.interface.type == "cli" and os.isatty(1)
        verbose = action_id is None or len(list(config.options)) > 1

        if interactive:
            config.translate()

        for panel in config.panels:
            if interactive and verbose:
                Moulinette.display(
                    colorize(f"\n{'=' * 40}\n>>>> {panel.name}\n{'=' * 40}", "purple")
                )

            # A section or option may only evaluate its conditions (`visible`
            # and `enabled`) with its panel's local context that is built
            # prompt after prompt.
            # That means that a condition can only reference options of its
            # own panel and options that are previously defined.
            context: dict[str, Any] = {}

            for section in panel.sections:
                if (
                    action_id is None and section.is_action_section
                ) or not section.is_visible(context):
                    continue

                if interactive and verbose and section.name:
                    Moulinette.display(colorize(f"\n# {section.name}", "purple"))

                # filter action section options in case of multiple buttons
                options = [
                    option
                    for option in section.options
                    if option.type is not OptionType.button or option.id == action_id
                ]

                form = prompt_or_validate_form(
                    options,
                    form,
                    prefilled_answers=prefilled_answers,
                    context=context,
                    hooks=hooks,
                )

        return form

    def _apply(
        self,
        form: "FormModel",
        config: ConfigPanelModel,
        previous_settings: dict[str, Any],
        exclude: Union["AbstractSetIntStr", "MappingIntStrAny", None] = None,
    ) -> None:
        """
        Save settings in yaml file.
        If `save_mode` is `"diff"` (which is the default), only values that are
        different from their default value will be saved.
        """
        logger.info("Saving the new configuration...")

        dir_path = os.path.dirname(os.path.realpath(self.save_path))
        if not os.path.exists(dir_path):
            mkdir(dir_path, mode=0o700)

        exclude_defaults = self.save_mode == "diff"
        # get settings keys filtered by filter_key
        partial_settings_keys = form.model_fields.keys()
        # get filtered settings
        partial_settings = form.model_dump(exclude_defaults=exclude_defaults, exclude=exclude)  # type: ignore
        # get previous settings that we will updated with new settings
        current_settings = self.raw_settings.copy()

        if exclude:
            current_settings = {
                key: value
                for key, value in current_settings.items()
                if key not in exclude
            }

        for key in partial_settings_keys:
            if (
                exclude_defaults
                and key not in partial_settings
                and key in current_settings
            ):
                del current_settings[key]
            elif key in partial_settings:
                current_settings[key] = partial_settings[key]

        # Save the settings to the .yaml file
        write_to_yaml(self.save_path, current_settings)

    def _run_action(self, form: "FormModel", action_id: str) -> None:
        raise NotImplementedError()

    def _reload_services(self) -> None:
        from yunohost.service import service_reload_or_restart

        services_to_reload = self.config.services if self.config else []

        if services_to_reload:
            logger.info("Reloading services...")
        for service in services_to_reload:
            if hasattr(self, "entity"):
                service = service.replace("__APP__", self.entity)
            service_reload_or_restart(service)
