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
import ast
import datetime
import operator as op
import os
import re
import shutil
import tempfile
import urllib.parse
from enum import Enum
from logging import getLogger
from typing import (
    TYPE_CHECKING,
    cast,
    overload,
    Annotated,
    Any,
    Callable,
    ClassVar,
    Iterable,
    Literal,
    Mapping,
    Type,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    create_model,
    field_validator,
    model_validator,
)
from pydantic.fields import Field
from pydantic.networks import EmailStr, HttpUrl, Url
from pydantic.types import constr
from pydantic_extra_types.color import Color

from moulinette import Moulinette, m18n
from moulinette.interfaces.cli import colorize
from moulinette.utils.filesystem import read_yaml, write_to_file
from yunohost.log import OperationLogger
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.i18n import _value_for_locale

if TYPE_CHECKING:
    from pydantic import GetJsonSchemaHandler
    from pydantic.fields import ValidationInfo, FieldInfo
    from pydantic.json_schema import JsonSchemaValue
    from pydantic_core.core_schema import CoreSchema

logger = getLogger("yunohost.form")


# ╭───────────────────────────────────────────────────────╮
# │  ┌─╴╷ ╷╭─┐╷                                           │
# │  ├─╴│╭╯├─┤│                                           │
# │  ╰─╴╰╯ ╵ ╵╰─╴                                         │
# ╰───────────────────────────────────────────────────────╯


# Those js-like evaluate functions are used to eval safely visible attributes
# The goal is to evaluate in the same way than js simple-evaluate
# https://github.com/shepherdwind/simple-evaluate
def evaluate_simple_ast(node, context=None):
    if context is None:
        context = {}

    operators = {
        ast.Not: op.not_,
        ast.Mult: op.mul,
        ast.Div: op.truediv,  # number
        ast.Mod: op.mod,  # number
        ast.Add: op.add,  # str
        ast.Sub: op.sub,  # number
        ast.USub: op.neg,  # Negative number
        ast.Gt: op.gt,
        ast.Lt: op.lt,
        ast.GtE: op.ge,
        ast.LtE: op.le,
        ast.Eq: op.eq,
        ast.NotEq: op.ne,
    }
    context["true"] = True
    context["false"] = False
    context["null"] = None

    # Variable
    if isinstance(node, ast.Name):  # Variable
        return context[node.id]

    # Python <=3.7 String
    elif isinstance(node, ast.Str):
        return node.s

    # Python <=3.7 Number
    elif isinstance(node, ast.Num):
        return node.n

    # Boolean, None and Python 3.8 for Number, Boolean, String and None
    elif isinstance(node, (ast.Constant, ast.NameConstant)):
        return node.value

    # + - * / %
    elif (
        isinstance(node, ast.BinOp) and type(node.op) in operators
    ):  # <left> <operator> <right>
        left = evaluate_simple_ast(node.left, context)
        right = evaluate_simple_ast(node.right, context)
        if type(node.op) is ast.Add:
            if isinstance(left, str) or isinstance(right, str):  # support 'I am ' + 42
                left = str(left)
                right = str(right)
        elif type(left) is type(right):  # support "111" - "1" -> 110
            left = float(left)
            right = float(right)

        return operators[type(node.op)](left, right)

    # Comparison
    # JS and Python don't give the same result for multi operators
    # like True == 10 > 2.
    elif (
        isinstance(node, ast.Compare) and len(node.comparators) == 1
    ):  # <left> <ops> <comparators>
        left = evaluate_simple_ast(node.left, context)
        right = evaluate_simple_ast(node.comparators[0], context)
        operator = node.ops[0]
        if isinstance(left, (int, float)) or isinstance(right, (int, float)):
            try:
                left = float(left)
                right = float(right)
            except ValueError:
                return type(operator) is ast.NotEq
        try:
            return operators[type(operator)](left, right)
        except TypeError:  # support "e" > 1 -> False like in JS
            return False

    # and / or
    elif isinstance(node, ast.BoolOp):  # <op> <values>
        for value in node.values:
            value = evaluate_simple_ast(value, context)
            if isinstance(node.op, ast.And) and not value:
                return False
            elif isinstance(node.op, ast.Or) and value:
                return True
        return isinstance(node.op, ast.And)

    # not / USub (it's negation number -\d)
    elif isinstance(node, ast.UnaryOp):  # <operator> <operand> e.g., -1
        return operators[type(node.op)](evaluate_simple_ast(node.operand, context))

    # match function call
    elif isinstance(node, ast.Call) and node.func.__dict__.get("id") == "match":
        return re.match(
            evaluate_simple_ast(node.args[1], context), context[node.args[0].id]
        )

    # Unauthorized opcode
    else:
        opcode = str(type(node))
        raise YunohostError(
            f"Unauthorize opcode '{opcode}' in visible attribute", raw_msg=True
        )


def js_to_python(expr):
    in_string = None
    py_expr = ""
    i = 0
    escaped = False
    for char in expr:
        if char in r"\"'":
            # Start a string
            if not in_string:
                in_string = char

            # Finish a string
            elif in_string == char and not escaped:
                in_string = None

        # If we are not in a string, replace operators
        elif not in_string:
            if char == "!" and expr[i + 1] != "=":
                char = "not "
            elif char in "|&" and py_expr[-1:] == char:
                py_expr = py_expr[:-1]
                char = " and " if char == "&" else " or "

        # Determine if next loop will be in escaped mode
        escaped = char == "\\" and not escaped
        py_expr += char
        i += 1
    return py_expr


def evaluate_simple_js_expression(expr: str, context: dict[str, Any] = {}) -> bool:
    if not expr.strip():
        return False
    node = ast.parse(js_to_python(expr), mode="eval").body
    return evaluate_simple_ast(node, context)


# ╭───────────────────────────────────────────────────────╮
# │  ╭─╮┌─╮╶┬╴╶┬╴╭─╮╭╮╷╭─╴                                │
# │  │ │├─╯ │  │ │ ││││╰─╮                                │
# │  ╰─╯╵   ╵ ╶┴╴╰─╯╵╰╯╶─╯                                │
# ╰───────────────────────────────────────────────────────╯


class OptionType(str, Enum):
    # display
    display_text = "display_text"
    markdown = "markdown"
    alert = "alert"
    # action
    button = "button"
    # text
    string = "string"
    text = "text"
    password = "password"
    color = "color"
    # numeric
    number = "number"
    range = "range"
    # boolean
    boolean = "boolean"
    # time
    date = "date"
    time = "time"
    # location
    email = "email"
    path = "path"
    url = "url"
    # file
    file = "file"
    # choice
    select = "select"
    tags = "tags"
    # entity
    domain = "domain"
    app = "app"
    user = "user"
    group = "group"


READONLY_TYPES = {
    OptionType.display_text,
    OptionType.markdown,
    OptionType.alert,
    OptionType.button,
}
FORBIDDEN_READONLY_TYPES = {
    OptionType.password,
    OptionType.app,
    OptionType.domain,
    OptionType.user,
    OptionType.group,
}

# To simplify AppConfigPanel bash scripts, we've chosen to use question
# short_ids as global variables. The consequence is that there is a risk
# of collision with other variables, notably different global variables
# used to expose old values or the type of a question...
# In addition to conflicts with bash variables, there is a direct
# conflict with the TOML properties of sections, so the keywords `name`,
# `visible`, `services`, `optional` and `help` cannot be used either.
FORBIDDEN_KEYWORDS = {
    "old",
    "app",
    "changed",
    "file_hash",
    "binds",
    "types",
    "formats",
    "getter",
    "setter",
    "short_setting",
    "type",
    "bind",
    "nothing_changed",
    "changes_validated",
    "result",
    "max_progression",
    "name",
    "visible",
    "services",
    "optional",
    "help",
}

Context = dict[str, Any]
Translation = dict[str, str] | str
JSExpression = str
Values = dict[str, Any]
Mode = Literal["python", "bash"]


class Pattern(BaseModel):
    regexp: str
    error: Translation = "pydantic.value_error.str.regex"  # FIXME add generic i18n key


class BaseOption(BaseModel):
    """
    Options are fields declaration that renders as form items, button, alert or text in the web-admin and printed or prompted in CLI.
    They are used in app manifests to declare the before installation form and in config panels.

    [Have a look at the app config panel doc](/packaging_apps_config_panels) for details about Panels and Sections.

    ! IMPORTANT: as for Panels and Sections you have to choose an id, but this one should be unique in all this document, even if the question is in an other panel.

    #### Example

    ```toml
    [section.my_option_id]
    type = "string"
    # ask as `str`
    ask = "The text in english"
    # ask as `dict`
    ask.en = "The text in english"
    ask.fr = "Le texte en français"
    # advanced props
    visible = "my_other_option_id != 'success'"
    readonly = true
    # much advanced: config panel only?
    bind = "null"
    ```

    #### Properties

    - `type`: the actual type of the option, such as 'markdown', 'password', 'number', 'email', ...
    - `ask`: `Translation` (default to the option's `id` if not defined):
        - text to display as the option's label for inputs or text to display for readonly options
        - in config panels, questions are displayed on the left side and therefore have not much space to be rendered. Therefore, it is better to use a short question, and use the `help` property to provide additional details if necessary.
    - `visible` (optional): `bool` or `JSExpression` (default: `true`)
        - define if the option is diplayed/asked
        - if `false` and used alongside `readonly = true`, you get a context only value that can still be used in `JSExpression`s
    - `readonly` (optional): `bool` (default: `false`, forced to `true` for readonly types):
        - If `true` for input types: forbid mutation of its value
    - `bind` (optional): `Binding`, config panels only! A powerful feature that let you configure how and where the setting will be read, validated and written
        - if not specified, the value will be read/written in the app `settings.yml`
        - if `"null"`:
            - the value will not be stored at all (can still be used in context evaluations)
            - if in `scripts/config` there's a function named:
                - `get__my_option_id`: the value will be gathered from this custom getter
                - `set__my_option_id`: the value will be passed to this custom setter where you can do whatever you want with the value
                - `validate__my_option_id`: the value will be passed to this custom validator before any custom setter
        - if `bind` is a file path:
            - if the path starts with `:`, the value be saved as its id's variable/property counterpart
                - this only works for first level variables/properties and simple types (no array)
            - else the value will be stored as the whole content of the file
            - you can use `__FINALPATH__` or `__INSTALL_DIR__` in your path to point to dynamic install paths
                - FIXME are other global variables accessible?
        - [refer to `bind` doc for explaination and examples](#read-and-write-values-the)
    """

    type: OptionType
    id: str
    mode: Mode = (
        "bash"  # TODO use "python" as default mode with AppConfigPanel setuping it to "bash"
    )
    ask: Translation | None = None
    readonly: bool = False
    visible: JSExpression | bool = True
    bind: str | None = None
    name: str | None = None  # LEGACY (replaced by `id`)

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        use_enum_values=True,
        validate_assignment=True,
        extra="forbid",
    )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: "CoreSchema", handler: "GetJsonSchemaHandler"
    ) -> "JsonSchemaValue":
        schema = handler(core_schema)
        del schema["properties"]["id"]
        del schema["properties"]["name"]
        schema["required"] = [
            required for required in schema.get("required", []) if required != "id"
        ]
        if not schema["required"]:
            del schema["required"]

        return schema

    @field_validator("id", mode="before")
    @classmethod
    def check_id_is_not_forbidden(cls, value: str) -> str:
        if value in FORBIDDEN_KEYWORDS:
            raise ValueError(m18n.n("config_forbidden_keyword", keyword=value))
        return value

    # FIXME Legacy, is `name` still needed?
    @field_validator("name")
    @classmethod
    def apply_legacy_name(cls, value: str | None, info: "ValidationInfo") -> str:
        if value is None:
            return info.data["id"]
        return value

    @field_validator("readonly", mode="before")
    @classmethod
    def can_be_readonly(cls, value: bool, info: "ValidationInfo") -> bool:
        if value is True and info.data["type"] in FORBIDDEN_READONLY_TYPES:
            raise ValueError(
                m18n.n(
                    "config_forbidden_readonly_type",
                    type=info.data["type"],
                    id=info.data["id"],
                )
            )
        return value

    def is_visible(self, context: Context) -> bool:
        if isinstance(self.visible, bool):
            return self.visible

        return evaluate_simple_js_expression(self.visible, context=context)

    def _get_prompt_message(self, value: None) -> str:
        # force type to str
        # `OptionsModel.translate_options()` should have been called before calling this method
        return cast(str, self.ask)


# ╭───────────────────────────────────────────────────────╮
# │ DISPLAY OPTIONS                                       │
# ╰───────────────────────────────────────────────────────╯


class BaseReadonlyOption(BaseOption):
    readonly: Literal[True] = True


class DisplayTextOption(BaseReadonlyOption):
    """
    Display simple multi-line content.

    #### Example

    ```toml
    [section.my_option_id]
    type = "display_text"
    ask = "Simple text rendered as is."
    ```
    """

    type: Literal[OptionType.display_text] = OptionType.display_text


class MarkdownOption(BaseReadonlyOption):
    """
    Display markdown multi-line content.
    Markdown is currently only rendered in the web-admin

    #### Example
    ```toml
    [section.my_option_id]
    type = "display_text"
    ask = "Text **rendered** in markdown."
    ```
    """

    type: Literal[OptionType.markdown] = OptionType.markdown


class State(str, Enum):
    success = "success"
    info = "info"
    warning = "warning"
    danger = "danger"


class AlertOption(BaseReadonlyOption):
    """
    Alerts displays a important message with a level of severity.
    You can use markdown in `ask` but will only be rendered in the web-admin.

    #### Example

    ```toml
    [section.my_option_id]
    type = "alert"
    ask = "The configuration seems to be manually modified..."
    style = "warning"
    icon = "warning"
    ```
    #### Properties

    - [common properties](#common-properties)
    - `style`: any of `"success|info|warning|danger"` (default: `"info"`)
    - `icon` (optional): any icon name from [Fork Awesome](https://forkaweso.me/Fork-Awesome/icons/)
        - Currently only displayed in the web-admin
    """

    type: Literal[OptionType.alert] = OptionType.alert
    style: State = State.info
    icon: str | None = None

    def _get_prompt_message(self, value: None) -> str:
        colors = {
            State.success: "green",
            State.info: "cyan",
            State.warning: "yellow",
            State.danger: "red",
        }
        message = m18n.g(self.style) if self.style != State.danger else m18n.n("danger")
        return f"{colorize(message, colors[self.style])} {self.ask}"


class ButtonOption(BaseReadonlyOption):
    """
    Triggers actions.
    Available only in config panels.
    Renders as a `button` in the web-admin and can be called with `yunohost [app|domain|settings] action run <action_id>` in CLI.

    Every options defined in an action section (a config panel section with at least one `button`) is guaranted to be shown/asked to the user and available in `scripts/config`'s scope.
    [check examples in advanced use cases](#actions).

    #### Example

    ```toml
    [section.my_option_id]
    type = "button"
    ask = "Break the system"
    style = "danger"
    icon = "bug"
    # enabled only if another option's value (a `boolean` for example) is positive
    enabled = "aknowledged"
    ```

    To be able to trigger an action we have to add a bash function starting with `run__` in your `scripts/config`

    ```bash
    run__my_action_id() {
        ynh_print_info "Running 'my_action_id' action"
    }
    ```

    #### Properties

    - [common properties](#common-properties)
        - `bind`: forced to `"null"`
    - `style`: any of `"success|info|warning|danger"` (default: `"success"`)
    - `enabled`: `JSExpression` or `bool` (default: `true`)
        - when used with `JSExpression` you can enable/disable the button depending on context
    - `icon` (optional): any icon name from [Fork Awesome](https://forkaweso.me/Fork-Awesome/icons/)
        - Currently only displayed in the web-admin
    """

    type: Literal[OptionType.button] = OptionType.button
    bind: Literal["null"] = "null"
    help: Translation | None = None
    style: State = State.success
    icon: str | None = None
    enabled: JSExpression | bool = True

    def is_enabled(self, context: Context) -> bool:
        if isinstance(self.enabled, bool):
            return self.enabled

        return evaluate_simple_js_expression(self.enabled, context=context)


# ╭───────────────────────────────────────────────────────╮
# │ INPUT OPTIONS                                         │
# ╰───────────────────────────────────────────────────────╯


class BaseInputOption(BaseOption):
    """
    Rest of the option types available are considered `inputs`.

    #### Example

    ```toml
    [section.my_option_id]
    type = "string"
    # …any common props… +
    optional = false
    redact = false
    default = "some default string"
    help = "You can enter almost anything!"
    example = "an example string"
    placeholder = "write something…"
    ```

    #### Properties

    - [common properties](#common-properties)
    - `optional`: `bool` (default: `false`, but `true` in config panels)
    - `redact`: `bool` (default: `false`), to redact the value in the logs when the value contain private information
    - `default`: depends on `type`, the default value to assign to the option
        - in case of readonly values, you can use this `default` to assign a value (or return a dynamic `default` from a custom getter)
    - `help` (optional): `Translation`, to display a short help message in cli and web-admin
    - `example` (optional): `str`, to display an example value in web-admin only
    - `placeholder` (optional): `str`, shown in the web-admin fields only
    """

    help: Translation | None = None
    example: str | None = None
    placeholder: str | None = None
    redact: bool = False
    optional: bool = False  # FIXME keep required as default?
    default: Any = None
    _annotation: Any = Any
    _none_as_empty_str: ClassVar[bool] = True

    @field_validator("default", mode="before")
    @classmethod
    def check_empty_default(cls, value: Any) -> Any:
        if value == "":
            return None
        return value

    @staticmethod
    def humanize(value: Any, option={}) -> str:
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def normalize(value, option={}):
        if isinstance(value, str):
            value = value.strip()
        return value

    @property
    def _dynamic_annotation(self) -> Any:
        """
        Returns the expected type of an Option's value.
        This may be dynamic based on constraints.
        """
        return self._annotation

    @property
    def _validators(self) -> dict[str, Callable]:
        return {
            "pre": self._value_pre_validator,
            "post": self._value_post_validator,
        }

    def _get_field_attrs(self) -> dict[str, Any]:
        """
        Returns attributes to build a `pydantic.Field`.
        Extra can be used as constraints in custom validators and ends up
        in the JSON Schema.
        """
        # TODO
        # - help
        # - placeholder
        attrs: dict[str, Any] = {}
        attrs["json_schema_extra"] = {
            "redact": self.redact,  # extra
            "none_as_empty_str": self._none_as_empty_str,
        }

        if self.readonly:
            attrs["frozen"] = True

        if self.example:
            attrs["examples"] = [self.example]

        if self.default is not None:
            attrs["default"] = self.default
            attrs["validate_default"] = True
        else:
            attrs["default"] = ... if not self.optional else None

        return attrs

    def _as_dynamic_model_field(self) -> tuple[Any, "FieldInfo"]:
        """
        Return a tuple of a type and a Field instance to be injected in a
        custom form declaration.
        """
        attrs = self._get_field_attrs()
        anno = (
            self._dynamic_annotation
            if not self.optional
            else self._dynamic_annotation | None
        )
        field = Field(default=attrs.pop("default", None), **attrs)

        return (anno, field)

    def _get_prompt_message(self, value: Any) -> str:
        message = super()._get_prompt_message(value)

        if self.readonly:
            message = colorize(message, "purple")
            return f"{message} {self.humanize(value, self)}"

        return message

    @staticmethod
    def _value_pre_validator(cls, value: Any, info: "ValidationInfo") -> Any:
        if value == "":
            return None

        return value

    @staticmethod
    def _value_post_validator(cls, value: Any, info: "ValidationInfo") -> Any:
        extras = cls.model_fields[info.field_name].json_schema_extra

        if value is None and extras["none_as_empty_str"]:
            value = ""

        if not extras.get("redact"):
            return value

        # Tell the operation_logger to redact all password-type / secret args
        # Also redact the % escaped version of the password that might appear in
        # the 'args' section of metadata (relevant for password with non-alphanumeric char)
        data_to_redact = []
        if value and isinstance(value, str):
            data_to_redact.append(value)

        data_to_redact += [
            urllib.parse.quote(data)
            for data in data_to_redact
            if urllib.parse.quote(data) != data
        ]

        for operation_logger in OperationLogger._instances:
            operation_logger.data_to_redact.extend(data_to_redact)

        return value


# ─ STRINGS ───────────────────────────────────────────────


class BaseStringOption(BaseInputOption):
    default: str | None = None
    pattern: Pattern | None = None
    _annotation = str

    @property
    def _dynamic_annotation(self) -> Type[str]:
        if self.pattern:
            return constr(pattern=self.pattern.regexp)

        return self._annotation

    def _get_field_attrs(self) -> dict[str, Any]:
        attrs = super()._get_field_attrs()

        if self.pattern:
            attrs["json_schema_extra"]["regex_error"] = self.pattern.error  # extra

        return attrs


class StringOption(BaseStringOption):
    r"""
    Ask for a simple string.

    #### Example
    ```toml
    [section.my_option_id]
    type = "string"
    default = "E10"
    pattern.regexp = '^[A-F]\d\d$'
    pattern.error = "Provide a room like F12 : one uppercase and 2 numbers"
    ```

    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    - `pattern` (optional): `Pattern`, a regex to match the value against
    """

    type: Literal[OptionType.string] = OptionType.string


class TextOption(BaseStringOption):
    """
    Ask for a multiline string.
    Renders as a `textarea` in the web-admin and by opening a text editor on the CLI.

    #### Example
    ```toml
    [section.my_option_id]
    type = "text"
    default = "multi\\nline\\ncontent"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    - `pattern` (optional): `Pattern`, a regex to match the value against
    """

    type: Literal[OptionType.text] = OptionType.text


FORBIDDEN_PASSWORD_CHARS = r"{}"


class PasswordOption(BaseInputOption):
    """
    Ask for a password.
    The password is tested as a regular user password (at least 8 chars)

    #### Example
    ```toml
    [section.my_option_id]
    type = "password"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: forced to `""`
        - `redact`: forced to `true`
        - `example`: forbidden
    """

    type: Literal[OptionType.password] = OptionType.password
    example: Literal[None] = None
    default: Literal[None] = None
    redact: Literal[True] = True
    _annotation = str
    _forbidden_chars: ClassVar[str] = FORBIDDEN_PASSWORD_CHARS

    def _get_field_attrs(self) -> dict[str, Any]:
        attrs = super()._get_field_attrs()

        attrs["json_schema_extra"]["forbidden_chars"] = self._forbidden_chars  # extra

        return attrs

    @staticmethod
    def _value_pre_validator(
        cls, value: str | None, info: "ValidationInfo"
    ) -> str | None:
        value = super(PasswordOption, PasswordOption)._value_pre_validator(
            cls, value, info
        )

        if value is not None and value != "":
            value = str(value)
            forbidden_chars: str = cls.model_fields[info.field_name].json_schema_extra[
                "forbidden_chars"
            ]
            if any(char in value for char in forbidden_chars):
                raise YunohostValidationError(
                    "pattern_password_app", forbidden_chars=forbidden_chars
                )

            # If it's an optional argument the value should be empty or strong enough
            from yunohost.utils.password import assert_password_is_strong_enough

            assert_password_is_strong_enough("user", value)

        return value


class ColorOption(BaseInputOption):
    """
    Ask for a color represented as a hex value (with possibly an alpha channel).
    Renders as color picker in the web-admin and as a prompt that accept named color like `yellow` in CLI.

    #### Example
    ```toml
    [section.my_option_id]
    type = "color"
    default = "#ff0"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    """

    type: Literal[OptionType.color] = OptionType.color
    default: str | None = None
    _annotation = Color

    @staticmethod
    def humanize(value: Color | str | None, option={}) -> str:
        if isinstance(value, Color):
            value.as_named(fallback=True)

        return super(ColorOption, ColorOption).humanize(value, option)

    @staticmethod
    def normalize(value: Color | str | None, option={}) -> str:
        if isinstance(value, Color):
            return value.as_hex()

        return super(ColorOption, ColorOption).normalize(value, option)

    @staticmethod
    def _value_post_validator(
        cls, value: Color | None, info: "ValidationInfo"
    ) -> str | None:
        if isinstance(value, Color):
            return value.as_hex()

        return super(ColorOption, ColorOption)._value_post_validator(cls, value, info)


# ─ NUMERIC ───────────────────────────────────────────────


class NumberOption(BaseInputOption):
    """
    Ask for a number (an integer).

    #### Example
    ```toml
    [section.my_option_id]
    type = "number"
    default = 100
    min = 50
    max = 200
    step = 5
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `type`: `number` or `range` (input or slider in the web-admin)
    - `min` (optional): minimal int value inclusive
    - `max` (optional): maximal int value inclusive
    - `step` (optional): currently only used in the webadmin as the `<input/>` step jump
    """

    # `number` and `range` are exactly the same, but `range` does render as a slider in web-admin
    type: Literal[OptionType.number, OptionType.range] = OptionType.number
    default: int | None = None
    min: int | None = None
    max: int | None = None
    step: int | None = None
    _annotation = int
    _none_as_empty_str = False

    @staticmethod
    def normalize(value, option={}) -> int | None:
        if isinstance(value, int):
            return value

        if isinstance(value, str):
            value = value.strip()

        if isinstance(value, str) and value.isdigit():
            return int(value)

        if value in [None, ""]:
            return None

        option = option.model_dump() if isinstance(option, BaseOption) else option
        raise YunohostValidationError(
            "app_argument_invalid",
            name=option.get("id"),
            error=m18n.n("invalid_number"),
        )

    def _get_field_attrs(self) -> dict[str, Any]:
        attrs = super()._get_field_attrs()
        attrs["ge"] = self.min
        attrs["le"] = self.max
        attrs["json_schema_extra"]["step"] = self.step  # extra

        return attrs

    @staticmethod
    def _value_pre_validator(
        cls, value: int | None, info: "ValidationInfo"
    ) -> int | None:
        value = super(NumberOption, NumberOption)._value_pre_validator(cls, value, info)

        if value is None:
            return None

        return value


# ─ BOOLEAN ───────────────────────────────────────────────


class BooleanOption(BaseInputOption):
    """
    Ask for a boolean.
    Renders as a switch in the web-admin and a yes/no prompt in CLI.

    #### Example
    ```toml
    [section.my_option_id]
    type = "boolean"
    default = 1
    yes = "agree"
    no = "disagree"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `0`
    - `yes` (optional): (default: `1`) define as what the thruthy value should output
        - can be `true`, `True`, `"yes"`, etc.
    - `no` (optional): (default: `0`) define as what the thruthy value should output
        - can be `0`, `"false"`, `"n"`, etc.
    """

    type: Literal[OptionType.boolean] = OptionType.boolean
    yes: Any = 1
    no: Any = 0
    default: bool | int | str | None = 0
    _annotation = bool | int | str
    _yes_answers: ClassVar[set[str]] = {"1", "yes", "y", "true", "t", "on"}
    _no_answers: ClassVar[set[str]] = {"0", "no", "n", "false", "f", "off"}
    _none_as_empty_str = False

    @staticmethod
    def humanize(value, option={}) -> str:
        option = option.model_dump() if isinstance(option, BaseOption) else option

        yes = option.get("yes", 1)
        no = option.get("no", 0)

        value = BooleanOption.normalize(value, option)

        if value == yes:
            return "yes"
        if value == no:
            return "no"
        if value is None:
            return ""

        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=option.get("id"),
            value=value,
            choices="yes/no",
        )

    @staticmethod
    def normalize(value, option={}) -> Any:
        option = option.model_dump() if isinstance(option, BaseOption) else option

        if isinstance(value, str):
            value = value.strip()

        technical_yes = option.get("yes", 1)
        technical_no = option.get("no", 0)

        no_answers = BooleanOption._no_answers
        yes_answers = BooleanOption._yes_answers

        assert (
            str(technical_yes).lower() not in no_answers
        ), f"'yes' value can't be in {no_answers}"
        assert (
            str(technical_no).lower() not in yes_answers
        ), f"'no' value can't be in {yes_answers}"

        no_answers.add(str(technical_no).lower())
        yes_answers.add(str(technical_yes).lower())

        strvalue = str(value).lower()

        if strvalue in yes_answers:
            return technical_yes
        if strvalue in no_answers:
            return technical_no

        if strvalue in ["none", ""]:
            return None

        raise YunohostValidationError(
            "app_argument_choice_invalid",
            name=option.get("id"),
            value=strvalue,
            choices="yes/no",
        )

    def get(self, key, default=None):
        return getattr(self, key, default)

    def _get_field_attrs(self) -> dict[str, Any]:
        attrs = super()._get_field_attrs()
        attrs["json_schema_extra"]["parse"] = {  # extra
            True: self.yes,
            False: self.no,
        }
        return attrs

    def _get_prompt_message(self, value: bool | None) -> str:
        message = super()._get_prompt_message(value)

        if not self.readonly:
            message += " [yes | no]"

        return message

    @staticmethod
    def _value_post_validator(cls, value: bool | None, info: "ValidationInfo") -> Any:
        if isinstance(value, bool):
            return cls.model_fields[info.field_name].json_schema_extra["parse"][value]

        return super(BooleanOption, BooleanOption)._value_post_validator(
            cls, value, info
        )


# ─ TIME ──────────────────────────────────────────────────


class DateOption(BaseInputOption):
    """
    Ask for a date in the form `"2025-06-14"`.
    Renders as a date-picker in the web-admin and a regular prompt in CLI.

    Can also take a timestamp as value that will output as an ISO date string.

    #### Example
    ```toml
    [section.my_option_id]
    type = "date"
    default = "2070-12-31"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    """

    type: Literal[OptionType.date] = OptionType.date
    default: str | None = None
    _annotation = datetime.date

    @staticmethod
    def _value_pre_validator(
        cls, v: datetime.date | str | None, info: "ValidationInfo"
    ) -> datetime.date | str | None:
        v = super(DateOption, DateOption)._value_pre_validator(cls, v, info)
        if isinstance(v, int | float) or (
            isinstance(v, str) and v.replace(".", "").replace("-", "", 1).isdigit()
        ):
            # FIXME use datetime.timezone.utc? or use local timezone
            return datetime.date.fromtimestamp(float(v))

        return v

    @staticmethod
    def _value_post_validator(
        cls, value: datetime.date | None, info: "ValidationInfo"
    ) -> str | None:
        if isinstance(value, datetime.date):
            return value.isoformat()

        return super(DateOption, DateOption)._value_post_validator(cls, value, info)


class TimeOption(BaseInputOption):
    """
    Ask for an hour in the form `"22:35"`.
    Renders as a date-picker in the web-admin and a regular prompt in CLI.

    #### Example
    ```toml
    [section.my_option_id]
    type = "time"
    default = "12:26"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    """

    type: Literal[OptionType.time] = OptionType.time
    default: str | int | None = None
    _annotation = datetime.time

    @staticmethod
    def _value_pre_validator(
        cls, v: Any, info: "ValidationInfo"
    ) -> datetime.time | datetime.datetime | None:
        v = super(TimeOption, TimeOption)._value_pre_validator(cls, v, info)
        if isinstance(v, int | float) or (
            isinstance(v, str) and v.replace(".", "").replace("-", "", 1).isdigit()
        ):
            value = float(v)
            if value >= 0:
                return datetime.datetime.fromtimestamp(float(v)).time()

        return v

    @staticmethod
    def _value_post_validator(
        cls, value: datetime.date | None, info: "ValidationInfo"
    ) -> str | None:
        if isinstance(value, datetime.time):
            # FIXME could use `value.isoformat()` to get `%H:%M:%S`
            return value.strftime("%H:%M")

        return super(TimeOption, TimeOption)._value_post_validator(cls, value, info)


# ─ LOCATIONS ─────────────────────────────────────────────


class EmailOption(BaseInputOption):
    """
    Ask for an email. Validation made with [python-email-validator](https://github.com/JoshData/python-email-validator)

    #### Example
    ```toml
    [section.my_option_id]
    type = "email"
    default = "Abc.123@test-example.com"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    """

    type: Literal[OptionType.email] = OptionType.email
    default: EmailStr | None = None
    _annotation = EmailStr


class WebPathOption(BaseStringOption):
    """
    Ask for an web path (the part of an url after the domain). Used by default in app install to define from where the app will be accessible.

    #### Example
    ```toml
    [section.my_option_id]
    type = "path"
    default = "/"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    - `pattern` (optional): `Pattern`, a regex to match the value against
    """

    type: Literal[OptionType.path] = OptionType.path

    @staticmethod
    def normalize(value, option={}) -> str:
        option = option.model_dump() if isinstance(option, BaseOption) else option

        if value is None:
            value = ""

        if not isinstance(value, str):
            raise YunohostValidationError(
                "app_argument_invalid",
                name=option.get("id"),
                error="Argument for path should be a string.",
            )

        if not value.strip():
            if option.get("optional"):
                return ""
            # Hmpf here we could just have a "else" case
            # but we also want WebPathOption.normalize("") to return "/"
            # (i.e. if no option is provided, hence .get("optional") is None
            elif option.get("optional") is False:
                raise YunohostValidationError(
                    "app_argument_invalid",
                    name=option.get("id"),
                    error="Option is mandatory",
                )

        return "/" + value.strip().strip(" /")


class URLOption(BaseStringOption):
    """
    Ask for any url.

    #### Example
    ```toml
    [section.my_option_id]
    type = "url"
    default = "https://example.xn--zfr164b/@handle/"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    - `pattern` (optional): `Pattern`, a regex to match the value against
    """

    type: Literal[OptionType.url] = OptionType.url
    _annotation = HttpUrl

    @staticmethod
    def _value_post_validator(
        cls, value: HttpUrl | None, info: "ValidationInfo"
    ) -> str | None:
        if isinstance(value, Url):
            return str(value)

        return super(URLOption, URLOption)._value_post_validator(cls, value, info)


# ─ FILE ──────────────────────────────────────────────────


def _base_value_post_validator(
    cls, value: Any, info: "ValidationInfo"
) -> tuple[bytes, str | None]:
    import mimetypes
    from pathlib import Path
    from magic import Magic
    from base64 import b64decode

    if Moulinette.interface.type != "api":
        path = Path(value)
        if not (path.exists() and path.is_absolute() and path.is_file()):
            raise YunohostValidationError("File doesn't exists", raw_msg=True)
        content = path.read_bytes()
    else:
        content = b64decode(value)

    accept_list = cls.model_fields[info.field_name].json_schema_extra.get("accept")
    mimetype = Magic(mime=True).from_buffer(content)

    if accept_list and mimetype not in accept_list:
        raise YunohostValidationError(
            f"Unsupported file type '{mimetype}', expected a type among '{', '.join(accept_list)}'.",
            raw_msg=True,
        )

    ext = mimetypes.guess_extension(mimetype)

    return content, ext


class FileOption(BaseInputOption):
    r"""
    Ask for file.
    Renders a file prompt in the web-admin and ask for a path in CLI.

    #### Example
    ```toml
    [section.my_option_id]
    type = "file"
    accept = ".json"
    # bind the file to a location to save the file there
    bind = "/tmp/my_file.json"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    - `accept`: a comma separated list of extension to accept like `".conf, .ini`
        - /!\ currently only work on the web-admin
    """

    type: Literal[OptionType.file] = OptionType.file
    # `FilePath` for CLI (path must exists and must be a file)
    # `bytes` for API (a base64 encoded file actually)
    accept: list[str] | None = None  # currently only used by the web-admin
    default: str | None = None
    _annotation = str  # TODO could be Path at some point
    _upload_dirs: ClassVar[set[str]] = set()

    @property
    def _validators(self) -> dict[str, Callable]:
        return {
            "pre": self._value_pre_validator,
            "post": (
                self._bash_value_post_validator
                if self.mode == "bash"
                else self._python_value_post_validator
            ),
        }

    def _get_field_attrs(self) -> dict[str, Any]:
        attrs = super()._get_field_attrs()

        if self.accept:
            attrs["json_schema_extra"]["accept"] = self.accept  # extra

        attrs["json_schema_extra"]["bind"] = self.bind

        return attrs

    @classmethod
    def clean_upload_dirs(cls) -> None:
        # Delete files uploaded from API
        for upload_dir in cls._upload_dirs:
            if os.path.exists(upload_dir):
                shutil.rmtree(upload_dir)

    @staticmethod
    def _bash_value_post_validator(cls, value: Any, info: "ValidationInfo") -> str:
        """File handling for "bash" config panels (app)"""
        if not value:
            return ""

        content, _ = _base_value_post_validator(cls, value, info)

        upload_dir = tempfile.mkdtemp(prefix="ynh_filequestion_")
        _, file_path = tempfile.mkstemp(dir=upload_dir)

        FileOption._upload_dirs.add(upload_dir)

        logger.debug(
            f"Saving file {info.field_name} for file question into {file_path}"
        )

        write_to_file(file_path, content, file_mode="wb")

        return file_path

    @staticmethod
    def _python_value_post_validator(cls, value: Any, info: "ValidationInfo") -> str:
        """File handling for "python" config panels"""

        from pathlib import Path
        import hashlib

        if not value:
            return ""

        bind = cls.model_fields[info.field_name].json_schema_extra["bind"]

        # to avoid "filename too long" with b64 content
        if len(value.encode("utf-8")) < 255:
            # Check if value is an already hashed and saved filepath
            path = Path(value)
            if path.exists() and value == bind.format(
                filename=path.stem, ext=path.suffix
            ):
                return value

        content, ext = _base_value_post_validator(cls, value, info)

        m = hashlib.sha256()
        m.update(content)
        sha256sum = m.hexdigest()
        filename = Path(bind.format(filename=sha256sum, ext=ext))
        filename.write_bytes(content)

        return str(filename)


# ─ CHOICES ───────────────────────────────────────────────


class BaseChoicesOption(BaseInputOption):
    # FIXME probably forbid choices to be None?
    filter: JSExpression | None = None  # filter before choices
    # We do not declare `choices` here to be able to declare other fields before `choices` and acces their values in `choices` validators
    # choices: dict[str, Any] | list[Any] | None

    @field_validator("choices", mode="before", check_fields=False)
    @classmethod
    def parse_comalist_choices(cls, value: Any) -> dict[str, Any] | list[Any] | None:
        if isinstance(value, str):
            values = [value.strip() for value in value.split(",")]
            return [value for value in values if value]
        return value

    @property
    def _dynamic_annotation(self) -> object | Type[str]:
        if self.choices:
            choices = (
                self.choices if isinstance(self.choices, list) else self.choices.keys()
            )
            return Literal[tuple(choices)]

        return self._annotation

    def _get_prompt_message(self, value: Any) -> str:
        message = super()._get_prompt_message(value)

        if self.readonly:
            if isinstance(self.choices, dict) and value is not None:
                value = self.choices[value]

            return f"{colorize(message, 'purple')} {value}"

        if self.choices:
            # Prevent displaying a shitload of choices
            # (e.g. 100+ available users when choosing an app admin...)
            choices = (
                list(self.choices.keys())
                if isinstance(self.choices, dict)
                else self.choices
            )
            splitted_choices = choices[:20]
            remaining_choices = len(choices[20:])

            if remaining_choices > 0:
                splitted_choices += [
                    m18n.n("other_available_options", n=remaining_choices)
                ]

            choices_to_display = " | ".join(str(choice) for choice in splitted_choices)

            return f"{message} [{choices_to_display}]"

        return message


class SelectOption(BaseChoicesOption):
    """
    Ask for value from a limited set of values.
    Renders as a regular `<select/>` in the web-admin and as a regular prompt in CLI with autocompletion of `choices`.

    #### Example
    ```toml
    [section.my_option_id]
    type = "select"
    choices = ["one", "two", "three"]
    choices = "one,two,three"
    default = "two"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`, obviously the default has to be empty or an available `choices` item.
    - `choices`: a (coma separated) list of values
    """

    type: Literal[OptionType.select] = OptionType.select
    filter: Literal[None] = None
    choices: list[Any] | dict[Any, Any] | None = None
    default: str | None = None
    _annotation = str


class TagsOption(BaseChoicesOption):
    """
    Ask for series of values. Optionally from a limited set of values.
    Renders as a multi select in the web-admin and as a regular prompt in CLI without autocompletion of `choices`.

    This output as a coma separated list of strings `"one,two,three"`

    #### Example
    ```toml
    [section.my_option_id]
    type = "tags"
    default = "word,another word"

    [my_other_option_id]
    type = "tags"
    choices = ["one", "two", "three"]
    # choices = "one,two,three"
    default = "two,three"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`, obviously the default has to be empty or an available `choices` item.
    - `pattern` (optional): `Pattern`, a regex to match all the values against
    - `choices` (optional): a (coma separated) list of values
    - `icon` (optional): any icon name from [Fork Awesome](https://forkaweso.me/Fork-Awesome/icons/)
        - Currently only displayed in the web-admin
    """

    type: Literal[OptionType.tags] = OptionType.tags
    filter: Literal[None] = None
    choices: list[str] | None = None
    pattern: Pattern | None = None
    icon: str | None = None
    default: str | list[str] | None = None
    _annotation = str

    @staticmethod
    def humanize(value, option={}) -> str:
        if isinstance(value, list):
            return ",".join(str(v) for v in value)
        if not value:
            return ""
        return value

    @staticmethod
    def normalize(value, option={}) -> str:
        if isinstance(value, list):
            return ",".join(str(v) for v in value)
        if isinstance(value, str):
            value = value.strip().strip(",")
        if value is None or value == "":
            return ""
        return value

    @property
    def _dynamic_annotation(self) -> Type[str]:
        # TODO use Literal when serialization is seperated from validation
        # if self.choices is not None:
        #     return Literal[tuple(self.choices)]

        # Repeat pattern stuff since we can't call the bare class `_dynamic_annotation` prop without instantiating it
        if self.pattern:
            return constr(pattern=self.pattern.regexp)

        return self._annotation

    def _get_field_attrs(self) -> dict[str, Any]:
        attrs = super()._get_field_attrs()

        if self.choices:
            attrs["json_schema_extra"]["choices"] = self.choices  # extra

        return attrs

    @staticmethod
    def _value_pre_validator(
        cls, value: list | str | None, info: "ValidationInfo"
    ) -> str | None:
        if value is None or value == "":
            return None

        if not isinstance(value, (list, str, type(None))):
            raise YunohostValidationError(
                "app_argument_invalid",
                name=info.field_name,
                error=f"'{str(value)}' is not a list",
            )

        if isinstance(value, str):
            value = [v.strip() for v in value.split(",")]
            value = [v for v in value if v]

        if isinstance(value, list):
            choices = cls.model_fields[info.field_name].json_schema_extra.get("choices")
            if choices:
                if not all(v in choices for v in value):
                    raise YunohostValidationError(
                        "app_argument_choice_invalid",
                        name=info.field_name,
                        value=value,
                        choices=", ".join(str(choice) for choice in choices),
                    )

            return ",".join(str(v) for v in value)
        return value


# ─ ENTITIES ──────────────────────────────────────────────


class DomainOption(BaseChoicesOption):
    """
    Ask for a user domain.
    Renders as a select in the web-admin and as a regular prompt in CLI with autocompletion of registered domains.

    #### Example
    ```toml
    [section.my_option_id]
    type = "domain"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: forced to the instance main domain
    """

    type: Literal[OptionType.domain] = OptionType.domain
    filter: Literal[None] = None
    choices: dict[str, str] | None = None

    @model_validator(mode="before")
    @classmethod
    def inject_domains_choices(cls, values: Values) -> Values:
        # TODO remove calls to resources in validators (pydantic V2 should adress this)
        from yunohost.domain import domain_list

        data = domain_list()
        values["choices"] = {
            domain: domain + " ★" if domain == data["main"] else domain
            for domain in data["domains"]
        }

        return values

    @model_validator(mode="before")
    @classmethod
    def inject_default(cls, values: Values) -> Values:
        # TODO remove calls to resources in validators (pydantic V2 should adress this)
        from yunohost.domain import _get_maindomain

        values["default"] = _get_maindomain()
        return values

    @staticmethod
    def normalize(value, option={}) -> str:
        if value.startswith("https://"):
            value = value[len("https://") :]
        elif value.startswith("http://"):
            value = value[len("http://") :]

        # Remove trailing slashes
        value = value.rstrip("/").lower()

        return value


class AppOption(BaseChoicesOption):
    """
    Ask for a user app.
    Renders as a select in the web-admin and as a regular prompt in CLI with autocompletion of installed apps.

    #### Example
    ```toml
    [section.my_option_id]
    type = "app"
    filter = "is_webapp"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `""`
    - `filter` (optional): `JSExpression` with what `yunohost app info <app_id> --full` returns as context (only first level keys)
    """

    type: Literal[OptionType.app] = OptionType.app
    filter: JSExpression | None = None
    choices: dict[str, str] | None = None

    @model_validator(mode="before")
    @classmethod
    def inject_apps_choices(cls, values: Values) -> Values:
        # TODO remove calls to resources in validators (pydantic V2 should adress this)
        from yunohost.app import app_list

        apps = app_list(full=True)["apps"]

        if values.get("filter", None):
            apps = [
                app
                for app in apps
                if evaluate_simple_js_expression(values["filter"], context=app)
            ]

        value = {"_none": "---"}
        value.update(
            {
                app["id"]: f"{app['label']} ({app.get('domain_path', app['id'])})"
                for app in apps
            }
        )

        values["choices"] = value

        return values


class UserOption(BaseChoicesOption):
    """
    Ask for a user.
    Renders as a select in the web-admin and as a regular prompt in CLI with autocompletion of available usernames.

    #### Example
    ```toml
    [section.my_option_id]
    type = "user"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: the first admin user found
    """

    type: Literal[OptionType.user] = OptionType.user
    filter: Literal[None] = None
    choices: dict[str, str] | None = None

    @model_validator(mode="before")
    def inject_users_choices_and_default(cls, values: Values) -> Values:
        # TODO remove calls to resources in validators (pydantic V2 should adress this)
        from yunohost.user import user_list

        users = user_list(fields=["username", "fullname", "mail", "groups"])["users"]

        values["choices"] = {
            username: f"{infos['fullname']} ({infos['mail']})"
            for username, infos in users.items()
        }

        # FIXME keep this to test if any user, do not raise error if no admin?
        if not values["choices"]:
            raise YunohostValidationError(
                "app_argument_invalid",
                name=values["id"],
                error="You should create a YunoHost user first.",
            )

        if not values.get("default"):
            values["default"] = next(
                username
                for username, infos in users.items()
                if "admins" in infos["groups"]
            )

        return values


class GroupOption(BaseChoicesOption):
    """
    Ask for a group.
    Renders as a select in the web-admin and as a regular prompt in CLI with autocompletion of available groups.

    #### Example
    ```toml
    [section.my_option_id]
    type = "group"
    default = "visitors"
    ```
    #### Properties
    - [common inputs properties](#common-inputs-properties)
        - `default`: `"all_users"`, `"visitors"` or `"admins"` (default: `"all_users"`)
    """

    type: Literal[OptionType.group] = OptionType.group
    filter: Literal[None] = None
    choices: dict[str, str] | None = None
    default: Literal["visitors", "all_users", "admins"] | None = "all_users"

    @model_validator(mode="before")
    @classmethod
    def inject_groups_choices(cls, values: Values) -> Values:
        # TODO remove calls to resources in validators (pydantic V2 should adress this)
        from yunohost.user import user_group_list

        groups = list(user_group_list(include_primary_groups=False)["groups"].keys())

        def _human_readable_group(groupname):
            # i18n: visitors
            # i18n: all_users
            # i18n: admins
            return (
                m18n.n(groupname)
                if groupname in ["visitors", "all_users", "admins"]
                else groupname
            )

        values["choices"] = {
            groupname: _human_readable_group(groupname) for groupname in groups
        }

        return values

    @model_validator(mode="before")
    @classmethod
    def inject_default(cls, values: Values) -> Values:
        # FIXME do we really want to default to something all the time?
        if values.get("default") in ("", None):
            values["default"] = "all_users"
        return values


OPTIONS = {
    OptionType.display_text: DisplayTextOption,
    OptionType.markdown: MarkdownOption,
    OptionType.alert: AlertOption,
    OptionType.button: ButtonOption,
    OptionType.string: StringOption,
    OptionType.text: TextOption,
    OptionType.password: PasswordOption,
    OptionType.color: ColorOption,
    OptionType.number: NumberOption,
    OptionType.range: NumberOption,
    OptionType.boolean: BooleanOption,
    OptionType.date: DateOption,
    OptionType.time: TimeOption,
    OptionType.email: EmailOption,
    OptionType.path: WebPathOption,
    OptionType.url: URLOption,
    OptionType.file: FileOption,
    OptionType.select: SelectOption,
    OptionType.tags: TagsOption,
    OptionType.domain: DomainOption,
    OptionType.app: AppOption,
    OptionType.user: UserOption,
    OptionType.group: GroupOption,
}

AnyOption = (
    DisplayTextOption
    | MarkdownOption
    | AlertOption
    | ButtonOption
    | StringOption
    | TextOption
    | PasswordOption
    | ColorOption
    | NumberOption
    | BooleanOption
    | DateOption
    | TimeOption
    | EmailOption
    | WebPathOption
    | URLOption
    | FileOption
    | SelectOption
    | TagsOption
    | DomainOption
    | AppOption
    | UserOption
    | GroupOption
)


# ╭───────────────────────────────────────────────────────╮
# │  ┌─╴╭─╮┌─╮╭╮╮                                         │
# │  ├─╴│ │├┬╯│││                                         │
# │  ╵  ╰─╯╵ ╰╵╵╵                                         │
# ╰───────────────────────────────────────────────────────╯


class OptionsModel(BaseModel):
    # Pydantic will match option types to their models class based on the "type" attribute
    options: list[Annotated[AnyOption, Field(discriminator="type")]]

    @staticmethod
    def options_dict_to_list(
        options: dict[str, Any], optional: bool = False
    ) -> list[dict[str, Any]]:
        options_list = []

        for id_, data in options.items():
            option = data | {
                "id": data.get("id", id_),
                "type": data.get(
                    "type",
                    OptionType.select if "choices" in data else OptionType.string,
                ),
            }

            if option["type"] not in READONLY_TYPES:
                option["optional"] = option.get("optional", optional)

            # LEGACY (`choices` in option `string` used to be valid)
            if "choices" in option and option["type"] == OptionType.string:
                logger.warning(
                    f"Packagers: option {id_} has 'choices' but has type 'string', use 'select' instead to remove this warning."
                )
                option["type"] = OptionType.select

            options_list.append(option)

        return options_list

    def __init__(self, **kwargs) -> None:
        super().__init__(options=self.options_dict_to_list(kwargs))

    def translate_options(self, i18n_key: str | None = None) -> None:
        """
        Mutate in place translatable attributes of options to their translations
        """
        for option in self.options:
            for key in ("ask", "help"):
                if not hasattr(option, key):
                    continue

                value = getattr(option, key)
                if value:
                    setattr(option, key, _value_for_locale(value))
                elif key == "ask" and m18n.key_exists(f"{i18n_key}_{option.id}"):
                    setattr(option, key, m18n.n(f"{i18n_key}_{option.id}"))
                elif key == "help" and m18n.key_exists(f"{i18n_key}_{option.id}_help"):
                    setattr(option, key, m18n.n(f"{i18n_key}_{option.id}_help"))
                elif key == "ask":
                    # FIXME warn?
                    option.ask = option.id


class FormModel(BaseModel):
    """
    Base form on which dynamic forms are built upon Options.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="ignore",
        coerce_numbers_to_str=True,
    )

    def __getitem__(self, name: str) -> Any:
        # FIXME
        # if a FormModel's required field is not instancied with a value, it is
        # not available as an attr and therefor triggers an `AttributeError`
        # Also since `BaseReadonlyOption`s do not end up in form,
        # `form[AlertOption.id]` would also triggers an error
        # For convinience in those 2 cases, we return `None`
        if not hasattr(self, name):
            # Return None to trigger a validation error instead for required fields
            return None

        return getattr(self, name)

    def __setitem__(self, name: str, value: Any) -> None:
        setattr(self, name, value)

    def get(self, attr: str, default: Any = None) -> Any:
        try:
            return getattr(self, attr)
        except AttributeError:
            return default


def build_form(
    options: Iterable[AnyOption], name: str = "DynamicForm"
) -> Type[FormModel]:
    """
    Returns a dynamic pydantic model class that can be used as a form.
    Parsing/validation occurs at instanciation and assignements.
    To avoid validation at instanciation, use `my_form.model_construct(**values)`
    """
    options_as_fields: Any = {}
    validators: dict[str, Any] = {}

    for option in options:
        if not isinstance(option, BaseInputOption):
            continue  # filter out non input options

        options_as_fields[option.id] = option._as_dynamic_model_field()
        option_validators = option._validators

        for step in ("pre", "post"):
            validators[f"{option.id}_{step}_validator"] = field_validator(
                option.id, mode="before" if step == "pre" else "after"
            )(option_validators[step])

    return cast(
        Type[FormModel],
        create_model(
            name,
            __base__=FormModel,
            __validators__=validators,
            **options_as_fields,
        ),
    )


# ╭───────────────────────────────────────────────────────╮
# │  ╷ ╷╶┬╴╶┬╴╷  ╭─╴                                      │
# │  │ │ │  │ │  ╰─╮                                      │
# │  ╰─╯ ╵ ╶┴╴╰─╴╶─╯                                      │
# ╰───────────────────────────────────────────────────────╯


Hooks = dict[str, Callable[[BaseInputOption], Any]]


def parse_prefilled_values(
    args: str | None = None,
    args_file: str | None = None,
    method: Literal["parse_qs", "parse_qsl"] = "parse_qs",
) -> dict[str, Any]:
    """
    Retrieve form values from yaml file or query string.
    """
    values: Values = {}
    if args_file:
        # Import YAML / JSON file
        values |= read_yaml(args_file)
    if args:
        # FIXME See `ask_questions_and_parse_answers`
        parsed = getattr(urllib.parse, method)(args, keep_blank_values=True)
        if isinstance(parsed, dict):  # parse_qs
            # FIXME could do the following to get a list directly?
            # k: None if not len(v) else (v if len(v) > 1 else v[0])
            values |= {k: ",".join(v) for k, v in parsed.items()}
        else:
            values |= dict(parsed)

    return values


# i18n: pydantic_type_error
# i18n: pydantic_type_error_none_not_allowed
# i18n: pydantic_type_error_str
# i18n: pydantic_value_error_color
# i18n: pydantic_value_error_const
# i18n: pydantic_value_error_date
# i18n: pydantic_value_error_email
# i18n: pydantic_value_error_number_not_ge
# i18n: pydantic_value_error_number_not_le
# i18n: pydantic_value_error_str_regex
# i18n: pydantic_value_error_time
# i18n: pydantic_value_error_url_extra
# i18n: pydantic_value_error_url_host
# i18n: pydantic_value_error_url_port
# i18n: pydantic_value_error_url_scheme

MAX_RETRIES = 4


def prompt_or_validate_form(
    options: Iterable[AnyOption],
    form: FormModel,
    prefilled_answers: dict[str, Any] = {},
    context: Context = {},
    hooks: Hooks = {},
) -> FormModel:
    for option in options:
        interactive = Moulinette.interface.type == "cli" and os.isatty(1)

        if isinstance(option, ButtonOption):
            if option.is_visible(context) and option.is_enabled(context):
                continue
            else:
                raise YunohostValidationError(
                    "config_action_disabled",
                    action=option.id,
                    help=option.help,
                )

        if not option.is_visible(context):
            if isinstance(option, BaseInputOption):
                # FIXME There could be several use case if the question is not displayed:
                # - we doesn't want to give a specific value
                # - we want to keep the previous value
                # - we want the default value
                context[option.id] = None

            continue

        # if we try to get a `BaseReadonlyOption` value, which doesn't exists in the form,
        # we get `None`
        value = form[option.id]

        if isinstance(option, BaseReadonlyOption) or option.readonly:
            if isinstance(option, BaseInputOption):
                # only update the context with the value
                context[option.id] = option.normalize(form[option.id])

                # FIXME here we could error out
                if option.id in prefilled_answers:
                    logger.warning(
                        f"'{option.id}' is readonly, value '{prefilled_answers[option.id]}' is then ignored."
                    )

            if interactive:
                Moulinette.display(option._get_prompt_message(value))

            continue

        for i in range(5):
            if option.id in prefilled_answers:
                value = prefilled_answers[option.id]
            elif interactive:
                value = option.humanize(value, option)
                choices = (
                    option.choices if isinstance(option, BaseChoicesOption) else []
                )
                value = Moulinette.prompt(
                    message=option._get_prompt_message(value),
                    is_password=isinstance(option, PasswordOption),
                    confirm=False,
                    prefill=value,
                    is_multiline=isinstance(option, TextOption),
                    autocomplete=choices,
                    help=option.help,
                )

            # Apply default value if none
            if value is None or value == "" and option.default is not None:
                value = option.default

            try:
                # Normalize and validate
                form[option.id] = option.normalize(value, option)
                context[option.id] = form[option.id]
                # In case of boolean option, yes/no may be custom, set a true boolean as context
                if isinstance(option, BooleanOption) and form[option.id] is not None:
                    context[option.id] = form[option.id] == option.yes

            except (ValidationError, YunohostValidationError) as e:
                if isinstance(e, ValidationError):
                    # TODO: handle multiple errors
                    err = e.errors()[0]
                    ctx = err.get("ctx", {})

                    if "permitted" in ctx:
                        ctx["permitted"] = ", ".join(
                            f"'{choice}'" for choice in ctx["permitted"]
                        )
                    if (
                        isinstance(option, (BaseStringOption, TagsOption))
                        and "pattern" in err["type"]
                        and option.pattern is not None
                    ):
                        err_text = option.pattern.error
                    else:
                        i18n_key = f"pydantic.{err['type']}".replace(".", "_")
                        err_text = (
                            m18n.n(i18n_key, **ctx)
                            if m18n.key_exists(i18n_key)
                            else err["msg"]
                        )
                else:
                    err_text = str(e)

                # If in interactive cli, re-ask the current question
                if i < MAX_RETRIES and interactive:
                    logger.error(err_text)
                    value = None
                    continue

                if isinstance(e, ValidationError):
                    if not interactive:
                        err_text = m18n.n(
                            "app_argument_invalid", name=option.id, error=err_text
                        )

                    raise YunohostValidationError(err_text, raw_msg=True)

                # Otherwise raise the ValidationError
                raise e

            break

        # Search for post actions in hooks
        post_hook = f"post_ask__{option.id}"
        if post_hook in hooks:
            # Hooks looks like they can return multiple values, validate those
            values = hooks[post_hook](option)
            for option_id, value in values.items():
                option = next(opt for opt in options if option.id == option_id)
                if option and isinstance(option, BaseInputOption):
                    form[option.id] = option.normalize(value, option)
                    context[option.id] = form[option.id]

    return form


def ask_questions_and_parse_answers(
    raw_options: dict[str, Any],
    prefilled_answers: str | Mapping[str, Any] = {},
    current_values: Mapping[str, Any] = {},
    hooks: Hooks = {},
) -> tuple[list[AnyOption], FormModel]:
    """Parse arguments store in either manifest.json or actions.json or from a
    config panel against the user answers when they are present.

    Keyword arguments:
        raw_questions     -- the arguments description store in yunohost
                             format from actions.json/toml, manifest.json/toml
                             or config_panel.json/toml
        prefilled_answers -- a url "query-string" such as "domain=yolo.test&path=/foobar&admin=sam"
                             or a dict such as {"domain": "yolo.test", "path": "/foobar", "admin": "sam"}
    """

    if isinstance(prefilled_answers, str):
        # FIXME FIXME : this is not uniform with config_set() which uses parse.qs (no l)
        # parse_qsl parse single values
        # whereas parse.qs return list of values (which is useful for tags, etc)
        # For now, let's not migrate this piece of code to parse_qs
        # Because Aleks believes some bits of the app CI rely on overriding values (e.g. foo=foo&...&foo=bar)
        answers = parse_prefilled_values(prefilled_answers, method="parse_qsl")
    elif isinstance(prefilled_answers, Mapping):
        answers = {**prefilled_answers}
    else:
        answers = {}

    context = {**current_values, **answers}

    model_options = parse_raw_options(raw_options, serialize=False)
    # Build the form from those questions and instantiate it without
    # parsing/validation (construct) since it may contains required questions.
    form = build_form(model_options).model_construct()
    form = prompt_or_validate_form(
        model_options, form, prefilled_answers=answers, context=context, hooks=hooks
    )
    return (model_options, form)


@overload
def parse_raw_options(
    raw_options: dict[str, Any], serialize: Literal[True]
) -> list[dict[str, Any]]:
    ...


@overload
def parse_raw_options(
    raw_options: dict[str, Any], serialize: Literal[False] = False
) -> list[AnyOption]:
    ...


def parse_raw_options(
    raw_options: dict[str, Any], serialize: bool = False
) -> list[dict[str, Any]] | list[AnyOption]:
    # Validate/parse the options attributes
    try:
        model = OptionsModel(**raw_options)
    except ValidationError as e:
        raise YunohostError("While parsing manifest: " + str(e), raw_msg=True)

    model.translate_options()

    if serialize:
        return model.model_dump()["options"]

    return model.options
