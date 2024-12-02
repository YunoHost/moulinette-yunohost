import inspect
import sys
import pytest
import os
import tempfile

from contextlib import contextmanager
from mock import patch
from io import StringIO
from typing import Any, Literal, Sequence, TypedDict, Union

from _pytest.mark.structures import ParameterSet

from moulinette import Moulinette
from yunohost import app, domain, user
from yunohost.utils.form import (
    OPTIONS,
    FORBIDDEN_PASSWORD_CHARS,
    READONLY_TYPES,
    ask_questions_and_parse_answers,
    BaseChoicesOption,
    BaseInputOption,
    BaseReadonlyOption,
    DomainOption,
    WebPathOption,
    BooleanOption,
    FileOption,
    evaluate_simple_js_expression,
)
from yunohost.utils import form
from yunohost.utils.error import YunohostError, YunohostValidationError


"""
Argument default format:
{
    "the_id": {
        "type": "one_of_the_available_type",  // "sting" is not specified
        "ask": {
            "en": "the question in english",
            "fr": "the question in french"
        },
        "help": {
            "en": "some help text in english",
            "fr": "some help text in french"
        },
        "example": "an example value", // optional
        "default", "some stuff", // optional, not available for all types
        "optional": true // optional, will skip if not answered
    }
}

User answers:
{"the_id": "value", ...}
"""


# ╭───────────────────────────────────────────────────────╮
# │  ┌─╮╭─┐╶┬╴╭─╴╷ ╷╶┬╴╭╮╷╭─╮                             │
# │  ├─╯├─┤ │ │  ├─┤ │ ││││╶╮                             │
# │  ╵  ╵ ╵ ╵ ╰─╴╵ ╵╶┴╴╵╰╯╰─╯                             │
# ╰───────────────────────────────────────────────────────╯


@contextmanager
def patch_isatty(isatty):
    with patch.object(os, "isatty", return_value=isatty):
        yield


@contextmanager
def patch_interface(interface: Literal["api", "cli"] = "api"):
    with patch.object(Moulinette.interface, "type", interface), patch_isatty(
        interface == "cli"
    ):
        yield


@contextmanager
def patch_prompt(return_value):
    with patch_interface("cli"), patch.object(
        Moulinette, "prompt", return_value=return_value
    ) as prompt:
        yield prompt


@pytest.fixture
def patch_no_tty():
    with patch_isatty(False):
        yield


@pytest.fixture
def patch_with_tty():
    with patch_isatty(True):
        yield


@pytest.fixture
def patch_cli_retries():
    with patch.object(form, "MAX_RETRIES", 0):
        yield


# ╭───────────────────────────────────────────────────────╮
# │  ╭─╴╭─╴┌─╴╭╮╷╭─┐┌─╮╶┬╴╭─╮╭─╴                          │
# │  ╰─╮│  ├─╴│││├─┤├┬╯ │ │ │╰─╮                          │
# │  ╶─╯╰─╴╰─╴╵╰╯╵ ╵╵ ╰╶┴╴╰─╯╶─╯                          │
# ╰───────────────────────────────────────────────────────╯


MinScenario = tuple[Any, Union[Literal["FAIL"], Any]]
PartialScenario = tuple[Any, Union[Literal["FAIL"], Any], dict[str, Any]]
FullScenario = tuple[Any, Union[Literal["FAIL"], Any], dict[str, Any], dict[str, Any]]

Scenario = Union[
    MinScenario,
    PartialScenario,
    FullScenario,
    "InnerScenario",
]


class InnerScenario(TypedDict, total=False):
    scenarios: Sequence[Scenario]
    raw_options: Sequence[dict[str, Any]]
    data: Sequence[dict[str, Any]]


# ╭───────────────────────────────────────────────────────╮
# │ Scenario generators/helpers                           │
# ╰───────────────────────────────────────────────────────╯


def get_hydrated_scenarios(raw_options, scenarios, data=[{}]):
    """
    Normalize and hydrate a mixed list of scenarios to proper tuple/pytest.param flattened list values.

    Example::
        scenarios = [
            {
                "raw_options": [{}, {"optional": True}],
                "scenarios": [
                    ("", "value", {"default": "value"}),
                    *unchanged("value", "other"),
                ]
            },
            *all_fails(-1, 0, 1, raw_options={"optional": True}),
            *xfail(scenarios=[(True, "True"), (False, "False)], reason="..."),
        ]
        # Is exactly the same as
        scenarios = [
            ("", "value", {"default": "value"}),
            ("", "value", {"optional": True, "default": "value"}),
            ("value", "value", {}),
            ("value", "value", {"optional": True}),
            ("other", "other", {}),
            ("other", "other", {"optional": True}),
            (-1, FAIL, {"optional": True}),
            (0, FAIL, {"optional": True}),
            (1, FAIL, {"optional": True}),
            pytest.param(True, "True", {}, marks=pytest.mark.xfail(reason="...")),
            pytest.param(False, "False", {}, marks=pytest.mark.xfail(reason="...")),
        ]
    """
    hydrated_scenarios = []
    for raw_option in raw_options:
        for mocked_data in data:
            for scenario in scenarios:
                if isinstance(scenario, dict):
                    merged_raw_options = [
                        {**raw_option, **raw_opt}
                        for raw_opt in scenario.get("raw_options", [{}])
                    ]
                    hydrated_scenarios += get_hydrated_scenarios(
                        merged_raw_options,
                        scenario["scenarios"],
                        scenario.get("data", [mocked_data]),
                    )
                elif isinstance(scenario, ParameterSet):
                    intake, output, custom_raw_option = (
                        scenario.values
                        if len(scenario.values) == 3
                        else (*scenario.values, {})
                    )
                    merged_raw_option = {**raw_option, **custom_raw_option}
                    hydrated_scenarios.append(
                        pytest.param(
                            intake,
                            output,
                            merged_raw_option,
                            mocked_data,
                            marks=scenario.marks,
                        )
                    )
                elif isinstance(scenario, tuple):
                    intake, output, custom_raw_option = (
                        scenario if len(scenario) == 3 else (*scenario, {})
                    )
                    merged_raw_option = {**raw_option, **custom_raw_option}
                    hydrated_scenarios.append(
                        (intake, output, merged_raw_option, mocked_data)
                    )
                else:
                    raise Exception(
                        "Test scenario should be tuple(intake, output, raw_option), pytest.param(intake, output, raw_option) or dict(raw_options, scenarios, data)"
                    )

    return hydrated_scenarios


def generate_test_name(intake, output, raw_option, data):
    values_as_str = []
    for value in (intake, output):
        if isinstance(value, str) and value != FAIL:
            values_as_str.append(f"'{value}'")
        elif inspect.isclass(value) and issubclass(value, Exception):
            values_as_str.append(value.__name__)
        else:
            values_as_str.append(value)
    name = f"{values_as_str[0]} -> {values_as_str[1]}"

    keys = [
        "=".join(
            [
                key,
                (
                    str(raw_option[key])
                    if not isinstance(raw_option[key], str)
                    else f"'{raw_option[key]}'"
                ),
            ]
        )
        for key in raw_option.keys()
        if key not in ("id", "type")
    ]
    if keys:
        name += " (" + ",".join(keys) + ")"
    return name


def pytest_generate_tests(metafunc):
    """
    Pytest test factory that, for each `BaseTest` subclasses, parametrize its
    methods if it requires it by checking the method's parameters.
    For those and based on their `cls.scenarios`, a series of `pytest.param` are
    automaticly injected as test values.
    """
    if metafunc.cls and issubclass(metafunc.cls, BaseTest):
        argnames = []
        argvalues = []
        ids = []
        fn_params = inspect.signature(metafunc.function).parameters

        for params in [
            ["intake", "expected_output", "raw_option", "data"],
            ["intake", "expected_normalized", "raw_option", "data"],
            ["intake", "expected_humanized", "raw_option", "data"],
        ]:
            if all(param in fn_params for param in params):
                argnames += params
                if params[1] == "expected_output":
                    # Hydrate scenarios with generic raw_option data
                    argvalues += get_hydrated_scenarios(
                        [metafunc.cls.raw_option], metafunc.cls.scenarios
                    )
                    ids += [
                        (
                            generate_test_name(*args.values)
                            if isinstance(args, ParameterSet)
                            else generate_test_name(*args)
                        )
                        for args in argvalues
                    ]
                elif params[1] == "expected_normalized":
                    argvalues += metafunc.cls.normalized
                    ids += [
                        f"{metafunc.cls.raw_option['type']}-normalize-{scenario[0]}"
                        for scenario in metafunc.cls.normalized
                    ]
                elif params[1] == "expected_humanized":
                    argvalues += metafunc.cls.humanized
                    ids += [
                        f"{metafunc.cls.raw_option['type']}-normalize-{scenario[0]}"
                        for scenario in metafunc.cls.humanized
                    ]

                metafunc.parametrize(argnames, argvalues, ids=ids)


# ╭───────────────────────────────────────────────────────╮
# │ Scenario helpers                                      │
# ╰───────────────────────────────────────────────────────╯

FAIL = YunohostValidationError


def nones(
    *nones, output, raw_option: dict[str, Any] = {}, fail_if_required: bool = True
) -> list[PartialScenario]:
    """
    Returns common scenarios for ~None values.
    - required and required + as default -> `FAIL`
    - optional and optional + as default -> `expected_output=None`
    """
    return [
        (none, FAIL if fail_if_required else output, base_raw_option | raw_option)  # type: ignore
        for none in nones
        for base_raw_option in ({}, {"default": none})
    ] + [
        (none, output, base_raw_option | raw_option)
        for none in nones
        for base_raw_option in ({"optional": True}, {"optional": True, "default": none})
    ]


def unchanged(*args, raw_option: dict[str, Any] = {}) -> list[PartialScenario]:
    """
    Returns a series of params for which output is expected to be the same as its intake

    Example::
        # expect `"value"` to output as `"value"`, etc.
        unchanged("value", "yes", "none")

    """
    return [(arg, arg, raw_option.copy()) for arg in args]


def all_as(*args, output, raw_option: dict[str, Any] = {}) -> list[PartialScenario]:
    """
    Returns a series of params for which output is expected to be the same single value

    Example::
        # expect all values to output as `True`
        all_as("y", "yes", 1, True, output=True)
    """
    return [(arg, output, raw_option.copy()) for arg in args]


def all_fails(
    *args, raw_option: dict[str, Any] = {}, error=FAIL
) -> list[PartialScenario]:
    """
    Returns a series of params for which output is expected to be failing with validation error
    """
    return [(arg, error, raw_option.copy()) for arg in args]


def xpass(*, scenarios: list[Scenario], reason="unknown") -> list[Scenario]:
    """
    Return a pytest param for which test should have fail but currently passes.
    """
    return [
        pytest.param(
            *scenario,
            marks=pytest.mark.xfail(
                reason=f"Currently valid but probably shouldn't. details: {reason}."
            ),
        )
        for scenario in scenarios
    ]


def xfail(*, scenarios: list[Scenario], reason="unknown") -> list[Scenario]:
    """
    Return a pytest param for which test should have passed but currently fails.
    """
    return [
        pytest.param(
            *scenario,
            marks=pytest.mark.xfail(
                reason=f"Currently invalid but should probably pass. details: {reason}."
            ),
        )
        for scenario in scenarios
    ]


# ╭───────────────────────────────────────────────────────╮
# │  ╶┬╴┌─╴╭─╴╶┬╴╭─╴                                      │
# │   │ ├─╴╰─╮ │ ╰─╮                                      │
# │   ╵ ╰─╴╶─╯ ╵ ╶─╯                                      │
# ╰───────────────────────────────────────────────────────╯


def _fill_or_prompt_one_option(raw_option, intake):
    raw_option = raw_option.copy()
    id_ = raw_option.pop("id")
    options = {id_: raw_option}
    answers = {id_: intake} if intake is not None else {}

    options, form = ask_questions_and_parse_answers(options, answers)
    return (options[0], form[id_] if isinstance(options[0], BaseInputOption) else None)


def _test_value_is_expected_output(value, expected_output):
    """
    Properly compares bools and None
    """
    if isinstance(expected_output, bool) or expected_output is None:
        assert value is expected_output
    else:
        assert value == expected_output


def _test_intake(raw_option, intake, expected_output):
    option, value = _fill_or_prompt_one_option(raw_option, intake)

    _test_value_is_expected_output(value, expected_output)


def _test_intake_may_fail(raw_option, intake, expected_output):
    if inspect.isclass(expected_output) and issubclass(expected_output, Exception):
        with pytest.raises(expected_output):
            _fill_or_prompt_one_option(raw_option, intake)
    else:
        _test_intake(raw_option, intake, expected_output)


@pytest.mark.usefixtures("patch_cli_retries")  # To avoid chain error logging
class BaseTest:
    raw_option: dict[str, Any] = {}
    prefill: dict[Literal["raw_option", "prefill", "intake"], Any]
    scenarios: list[Scenario]

    # fmt: off
    # scenarios = [
    #     *all_fails(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),
    #     *all_fails("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),
    #     *nones(None, "", output=""),
    # ]
    # fmt: on
    # TODO
    # - pattern (also on Date for example to see if it override the default pattern)
    # - example
    # - visible
    # - redact
    # - regex
    # - hooks

    @classmethod
    def get_raw_option(cls, raw_option={}, **kwargs):
        base_raw_option = cls.raw_option.copy()
        base_raw_option.update(**raw_option)
        base_raw_option.update(**kwargs)
        return base_raw_option

    @classmethod
    def _test_basic_attrs(self):
        raw_option = self.get_raw_option(optional=True)

        if raw_option["type"] in READONLY_TYPES:
            del raw_option["optional"]

        if raw_option["type"] == "select":
            raw_option["choices"] = ["one"]

        id_ = raw_option["id"]
        option, value = _fill_or_prompt_one_option(raw_option, None)

        is_special_readonly_option = isinstance(option, BaseReadonlyOption)

        assert isinstance(option, OPTIONS[raw_option["type"]])
        assert option.type == raw_option["type"]
        assert option.id == id_
        assert option.ask == id_
        assert option.readonly is (True if is_special_readonly_option else False)
        assert option.visible is True
        # assert option.bind is None

        if is_special_readonly_option:
            assert value is None

        return (raw_option, option, value)

    @pytest.mark.usefixtures("patch_no_tty")
    def test_basic_attrs(self):
        """
        Test basic options factories and BaseOption default attributes values.
        """
        # Intermediate method since pytest doesn't like tests that returns something.
        # This allow a test class to call `_test_basic_attrs` then do additional checks
        self._test_basic_attrs()

    def test_options_prompted_with_ask_help(self, prefill_data=None):
        """
        Test that assert that moulinette prompt is called with:
        - `message` with translated string and possible choices list
        -  help` with translated string
        - `prefill` is the expected string value from a custom default
        - `is_password` is true for `password`s only
        - `is_multiline` is true for `text`s only
        - `autocomplete` is option choices

        Ran only once with `cls.prefill` data
        """
        if prefill_data is None:
            prefill_data = self.prefill

        base_raw_option = prefill_data["raw_option"]
        prefill = prefill_data["prefill"]

        # FIXME could patch prompt with prefill if we switch to "do not apply default if value is None|''"
        with patch_prompt("") as prompt:
            raw_option = self.get_raw_option(
                raw_option=base_raw_option,
                ask={"en": "Can i haz question?"},
                help={"en": "Here's help!"},
            )
            option, value = _fill_or_prompt_one_option(raw_option, None)

            expected_message = option.ask
            choices = []

            if isinstance(option, BaseChoicesOption):
                choices = option.choices
                if choices:
                    expected_message += f" [{' | '.join(choices)}]"
            if option.type == "boolean":
                expected_message += " [yes | no]"

            prompt.assert_called_with(
                message=expected_message,
                is_password=option.type == "password",
                confirm=False,  # FIXME no confirm?
                prefill=prefill,
                is_multiline=option.type == "text",
                autocomplete=choices,
                help=option.help,
            )

    def test_scenarios(self, intake, expected_output, raw_option, data):
        with patch_interface("api"):
            _test_intake_may_fail(
                raw_option,
                intake,
                expected_output,
            )


# ╭───────────────────────────────────────────────────────╮
# │ DISPLAY_TEXT                                          │
# ╰───────────────────────────────────────────────────────╯


class TestDisplayText(BaseTest):
    raw_option = {"type": "display_text", "id": "display_text_id"}
    prefill = {
        "raw_option": {},
        "prefill": " custom default",
    }
    # fmt: off
    scenarios = [
        (None, None, {"ask": "Some text\na new line"}),
        (None, None, {"ask": {"en": "Some text\na new line", "fr": "Un peu de texte\nune nouvelle ligne"}}),
    ]
    # fmt: on

    def test_options_prompted_with_ask_help(self, prefill_data=None):
        pytest.skip(reason="no prompt for display types")

    def test_scenarios(self, intake, expected_output, raw_option, data):
        _id = raw_option.pop("id")
        answers = {_id: intake} if intake is not None else {}
        options = None
        with patch_interface("cli"):
            if inspect.isclass(expected_output) and issubclass(
                expected_output, Exception
            ):
                with pytest.raises(expected_output):
                    ask_questions_and_parse_answers({_id: raw_option}, answers)
            else:
                with patch.object(sys, "stdout", new_callable=StringIO) as stdout:
                    options, form = ask_questions_and_parse_answers(
                        {_id: raw_option}, answers
                    )
                    assert stdout.getvalue() == f"{options[0].ask}\n"


# ╭───────────────────────────────────────────────────────╮
# │ MARKDOWN                                              │
# ╰───────────────────────────────────────────────────────╯


class TestMarkdown(TestDisplayText):
    raw_option = {"type": "markdown", "id": "markdown_id"}
    # in cli this option is exactly the same as "display_text", no markdown support for now


# ╭───────────────────────────────────────────────────────╮
# │ ALERT                                                 │
# ╰───────────────────────────────────────────────────────╯


class TestAlert(TestDisplayText):
    raw_option = {"type": "alert", "id": "alert_id"}
    prefill = {
        "raw_option": {"ask": " Custom info message"},
        "prefill": " custom default",
    }
    # fmt: off
    scenarios = [
        (None, None, {"ask": "Some text\na new line"}),
        (None, None, {"ask": {"en": "Some text\na new line", "fr": "Un peu de texte\nune nouvelle ligne"}}),
        *[(None, None, {"ask": "question", "style": style}) for style in ("success", "info", "warning", "danger")],
        (None, YunohostError, {"ask": "question", "style": "nimp"}),
    ]
    # fmt: on

    def test_scenarios(self, intake, expected_output, raw_option, data):
        style = raw_option.get("style", "info")
        colors = {"danger": "31", "warning": "33", "info": "36", "success": "32"}
        answers = {"alert_id": intake} if intake is not None else {}

        with patch_interface("cli"):
            if inspect.isclass(expected_output) and issubclass(
                expected_output, Exception
            ):
                with pytest.raises(expected_output):
                    ask_questions_and_parse_answers(
                        {"display_text_id": raw_option}, answers
                    )
            else:
                with patch.object(sys, "stdout", new_callable=StringIO) as stdout:
                    options, form = ask_questions_and_parse_answers(
                        {"display_text_id": raw_option}, answers
                    )
                    ask = options[0].ask
                    if style in colors:
                        color = colors[style]
                        title = style.title() + (":" if style != "success" else "!")
                        assert (
                            stdout.getvalue()
                            == f"\x1b[{color}m\x1b[1m{title}\x1b[m {ask}\n"
                        )
                    else:
                        # FIXME should fail
                        stdout.getvalue() == f"{ask}\n"


# ╭───────────────────────────────────────────────────────╮
# │ BUTTON                                                │
# ╰───────────────────────────────────────────────────────╯


# TODO


# ╭───────────────────────────────────────────────────────╮
# │ STRING                                                │
# ╰───────────────────────────────────────────────────────╯


class TestString(BaseTest):
    raw_option = {"type": "string", "id": "string_id"}
    prefill = {
        "raw_option": {"default": " custom default"},
        "prefill": " custom default",
    }
    # fmt: off
    scenarios = [
        *nones(None, "", output=""),
        # basic typed values
        (False, FAIL),
        (True, FAIL),
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (1337, "1337"),
        (13.37, "13.37"),
        *all_fails([], ["one"], {}),
        *unchanged("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", raw_option={"optional": True}),
        # test strip
        ("value", "value"),
        ("value\n", "value"),
        ("  \n value\n", "value"),
        ("  \\n value\\n", "\\n value\\n"),
        ("  \tvalue\t", "value"),
        (r" ##value \n \tvalue\n  ", r"##value \n \tvalue\n"),
        *xpass(scenarios=[
            ("value\nvalue", "value\nvalue"),
            (" ##value \n \tvalue\n  ", "##value \n \tvalue"),
        ], reason=r"should fail or without `\n`?"),
        # readonly
        ("overwrite", "expected value", {"readonly": True, "default": "expected value"}),  # FIXME do we want to fail instead?
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ TEXT                                                  │
# ╰───────────────────────────────────────────────────────╯


class TestText(BaseTest):
    raw_option = {"type": "text", "id": "text_id"}
    prefill = {
        "raw_option": {"default": "some value\nanother line "},
        "prefill": "some value\nanother line ",
    }
    # fmt: off
    scenarios = [
        *nones(None, "", output=""),
        # basic typed values
        (False, FAIL),
        (True, FAIL),
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (1337, "1337"),
        (13.37, "13.37"),
        *all_fails([], ["one"], {}),
        *unchanged("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", raw_option={"optional": True}),
        ("value", "value"),
        ("value\n value", "value\n value"),
        ("value", FAIL, {"pattern": {"regexp": r'^[A-F]\d\d$', "error": "Provide a room like F12 : one uppercase and 2 numbers"}}),
        ("F12", "F12", {"pattern": {"regexp": r'^[A-F]\d\d$', "error": "Provide a room like F12 : one uppercase and 2 numbers"}}),
        # test no strip
        *xpass(scenarios=[
            ("value\n", "value"),
            ("  \n value\n", "value"),
            ("  \\n value\\n", "\\n value\\n"),
            ("  \tvalue\t", "value"),
            (" ##value \n \tvalue\n  ", "##value \n \tvalue"),
            (r" ##value \n \tvalue\n  ", r"##value \n \tvalue\n"),
        ], reason="Should not be stripped"),
        # readonly
        ("overwrite", "expected value", {"readonly": True, "default": "expected value"}),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ PASSWORD                                              │
# ╰───────────────────────────────────────────────────────╯


class TestPassword(BaseTest):
    raw_option = {"type": "password", "id": "password_id"}
    prefill = {
        "raw_option": {"default": None, "optional": True},
        "prefill": "",
    }
    # fmt: off
    scenarios = [
        *all_fails(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),
        *all_fails("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),
        *nones(None, "", output=""),
        ("s3cr3t!!", YunohostError, {"default": "SUPAs3cr3t!!"}),  # default is forbidden
        ("s3cr3t!!", YunohostError, {"example": "SUPAs3cr3t!!"}),  # example is forbidden
        *xpass(scenarios=[
            (" value \n moarc0mpl1cat3d\n  ", "value \n moarc0mpl1cat3d"),
            (" some_ value", "some_ value"),
        ], reason="Should output exactly the same"),
        ("s3cr3t!!", "s3cr3t!!"),
        ("secret", FAIL),
        *[("supersecret" + char, FAIL) for char in FORBIDDEN_PASSWORD_CHARS],  # FIXME maybe add ` \n` to the list?
        # readonly
        ("s3cr3t!!", YunohostError, {"readonly": True}),  # readonly is forbidden
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ COLOR                                                 │
# ╰───────────────────────────────────────────────────────╯


class TestColor(BaseTest):
    raw_option = {"type": "color", "id": "color_id"}
    prefill = {
        "raw_option": {"default": "red"},
        "prefill": "red",
    }
    # fmt: off
    scenarios = [
        *all_fails(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),
        *all_fails("none", "_none", "False", "True", "0", "1", "-1", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),
        *nones(None, "", output=""),
        # custom valid
        (" #fe1  ", "#fe1"),
        ("#000000", "#000"),
        ("#000", "#000"),
        ("#ABCDEF", "#abcdef"),
        ('1337', "#1337"),  # rgba=(17, 51, 51, 0.47)
        ("000000", "#000"),
        ("#feaf", "#fea"),  # `#feaf` is `#fea` with alpha at `f|100%` -> equivalent to `#fea`
        # named
        ("red", "#f00"),
        ("yellow", "#ff0"),
        # custom fail
        ("#12", FAIL),
        ("#gggggg", FAIL),
        ("#01010101af", FAIL),
        # readonly
        ("#ffff00", "#000", {"readonly": True, "default": "#000"}),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ NUMBER | RANGE                                        │
# ╰───────────────────────────────────────────────────────╯
# Testing only number since "range" is only for webadmin (slider instead of classic intake).


class TestNumber(BaseTest):
    raw_option = {"type": "number", "id": "number_id"}
    prefill = {
        "raw_option": {"default": 10},
        "prefill": "10",
    }
    # fmt: off
    scenarios = [
        *all_fails([], ["one"], {}),
        *all_fails("none", "_none", "False", "True", "[]", ",", "['one']", "one,two", r"{}", "value"),

        *nones(None, "", output=None),
        *unchanged(0, 1, -1, 1337),
        *all_as(False, "0", 0, output=0),  # FIXME should `False` fail instead?
        *all_as(True, "1", 1, output=1),  # FIXME should `True` fail instead?
        *all_as("1337", 1337, output=1337),
        *xfail(scenarios=[
            ("-1", -1)
        ], reason="should output as `-1` instead of failing"),
        *all_fails(13.37, "13.37"),

        *unchanged(10, 5000, 10000, raw_option={"min": 10, "max": 10000}),
        *all_fails(9, 10001, raw_option={"min": 10, "max": 10000}),

        *all_as(None, "", output=0, raw_option={"default": 0}),
        *all_as(None, "", output=0, raw_option={"default": 0, "optional": True}),
        (-10, -10, {"default": 10}),
        (-10, -10, {"default": 10, "optional": True}),
        # readonly
        (1337, 10000, {"readonly": True, "default": "10000"}),
    ]
    # fmt: on
    # FIXME should `step` be some kind of "multiple of"?


# ╭───────────────────────────────────────────────────────╮
# │ BOOLEAN                                               │
# ╰───────────────────────────────────────────────────────╯


class TestBoolean(BaseTest):
    raw_option = {"type": "boolean", "id": "boolean_id"}
    prefill = {
        "raw_option": {"default": True},
        "prefill": "yes",
    }
    # fmt: off
    truthy_values = (True, 1, "1", "True", "true", "Yes", "yes", "y", "on")
    falsy_values = (False, 0, "0", "False", "false", "No", "no", "n", "off")
    scenarios = [
        *all_as(None, "", output=0),
        *all_fails("none", "None"),  # FIXME should output as `0` (default) like other none values when required?
        *all_as(None, "", output=0, raw_option={"optional": True}),  # FIXME should output as `None`?
        *all_as("none", "None", output=None, raw_option={"optional": True}),
        {
            "raw_options": [
                {"default": None},
                {"default": ""},
                {"default": "none"},
                {"default": "None"}
            ],
            "scenarios": [
                # All none values fails if default is overriden
                *all_fails(None, "", "none", "None"),
                # All none values ends up as None if default is overriden
                *all_as(None, "", "none", "None", output=None, raw_option={"optional": True}),
            ]
        },
        # Unhandled types should fail
        *all_fails(1337, "1337", "string", [], "[]", ",", "one,two"),
        *all_fails(1337, "1337", "string", [], "[]", ",", "one,two", {"optional": True}),
        # Required
        *all_as(*truthy_values, output=1),
        *all_as(*falsy_values, output=0),
        # Optional
        *all_as(*truthy_values, output=1, raw_option={"optional": True}),
        *all_as(*falsy_values, output=0, raw_option={"optional": True}),
        # test values as default, as required option without intake
        *[(None, 1, {"default": true for true in truthy_values})],
        *[(None, 0, {"default": false for false in falsy_values})],
        # custom boolean output
        ("", "disallow", {"yes": "allow", "no": "disallow"}),  # required -> default to False -> `"disallow"`
        ("n", "disallow", {"yes": "allow", "no": "disallow"}),
        ("y", "allow", {"yes": "allow", "no": "disallow"}),
        ("", False, {"yes": True, "no": False}),  # required -> default to False -> `False`
        ("n", False, {"yes": True, "no": False}),
        ("y", True, {"yes": True, "no": False}),
        ("", -1, {"yes": 1, "no": -1}),  # required -> default to False -> `-1`
        ("n", -1, {"yes": 1, "no": -1}),
        ("y", 1, {"yes": 1, "no": -1}),
        {
            "raw_options": [
                {"yes": "no", "no": "yes", "optional": True},
                {"yes": False, "no": True, "optional": True},
                {"yes": "0", "no": "1", "optional": True},
            ],
            # "no" for "yes" and "yes" for "no" should fail
            "scenarios": all_fails("", "y", "n", error=AssertionError),
        },
        # readonly
        (1, 0, {"readonly": True, "default": 0}),
    ]


# ╭───────────────────────────────────────────────────────╮
# │ DATE                                                  │
# ╰───────────────────────────────────────────────────────╯


class TestDate(BaseTest):
    raw_option = {"type": "date", "id": "date_id"}
    prefill = {
        "raw_option": {"default": "2024-12-29"},
        "prefill": "2024-12-29",
    }
    # fmt: off
    scenarios = [
        # Those passes since False|True are parsed as 0|1 then int|float are considered a timestamp in seconds which ends up as default Unix date
        *all_as(False, True, 0, 1, 1337, 13.37, "0", "1", "1337", "13.37", output="1970-01-01"),
        # Those are negative one second timestamp ending up as Unix date - 1 sec (so day change)
        *all_as(-1, "-1", output="1969-12-31"),
        *all_fails([], ["one"], {}, raw_option={"optional": True}),
        *all_fails("none", "_none", "False", "True", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),
        *nones(None, "", output=""),
        # custom valid
        ("2070-12-31", "2070-12-31"),
        ("2024-02-29", "2024-02-29"),
        *xfail(scenarios=[
            ("2025-06-15T13:45:30", "2025-06-15"),
            ("2025-06-15 13:45:30", "2025-06-15")
        ], reason="iso date repr should be valid and extra data striped"),
        (1749938400, "2025-06-14"),
        (1749938400.0, "2025-06-14"),
        ("1749938400", "2025-06-14"),
        ("1749938400.0", "2025-06-14"),
        # custom invalid
        ("29-12-2070", FAIL),
        ("12-01-10", FAIL),
        ("2022-02-29", FAIL),
        # readonly
        ("2070-12-31", "2024-02-29", {"readonly": True, "default": "2024-02-29"}),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ TIME                                                  │
# ╰───────────────────────────────────────────────────────╯


class TestTime(BaseTest):
    raw_option = {"type": "time", "id": "time_id"}
    prefill = {
        "raw_option": {"default": "12:26"},
        "prefill": "12:26",
    }
    # fmt: off
    scenarios = [
        # Those passes since False|True are parsed as 0|1 then int|float are considered a timestamp in seconds but we don't take seconds into account so -> 00:00
        *all_as(False, True, 0, 1, 13.37, "0", "1", "13.37", output="00:00"),
        # 1337 seconds == 22 minutes
        *all_as(1337, "1337", output="00:22"),
        # Negative timestamp fails
        *all_fails(-1, "-1"),
        # *all_fails(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),
        *all_fails("none", "_none", "False", "True", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),
        *nones(None, "", output=""),
        # custom valid
        *unchanged("00:00", "08:00", "12:19", "20:59", "23:59"),
        ("22:35:05", "22:35"),
        ("22:35:03.514", "22:35"),
        # custom invalid
        ("3:00", FAIL),
        ("23:1", FAIL),
        ("24:00", FAIL),
        ("23:005", FAIL),
        # readonly
        ("00:00", "08:00", {"readonly": True, "default": "08:00"}),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ EMAIL                                                 │
# ╰───────────────────────────────────────────────────────╯


class TestEmail(BaseTest):
    raw_option = {"type": "email", "id": "email_id"}
    prefill = {
        "raw_option": {"default": "Abc@example.tld"},
        "prefill": "Abc@example.tld",
    }
    # fmt: off
    scenarios = [
        *all_fails(False, True, 0, 1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),
        *all_fails("none", "_none", "False", "True", "0", "1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),

        *nones(None, "", output=""),
        ("\n Abc@example.tld  ", "Abc@example.tld"),
        *xfail(scenarios=[("admin@ynh.local", "admin@ynh.local")], reason="Should this pass?"),
        # readonly
        ("Abc@example.tld", "admin@ynh.org", {"readonly": True, "default": "admin@ynh.org"}),

        # Next examples are from https://github.com/JoshData/python-email-validator/blob/main/tests/test_syntax.py
        # valid email values
        *unchanged(
            "Abc@example.tld",
            "Abc.123@test-example.com",
            "user+mailbox/department=shipping@example.tld",
            "伊昭傑@郵件.商務",
            "राम@मोहन.ईन्फो",
            "юзер@екзампл.ком",
            "θσερ@εχαμπλε.ψομ",
            "jeff@臺網中心.tw",
            "ñoñó@example.tld",
            "甲斐黒川日本@example.tld",
            "чебурашкаящик-с-апельсинами.рф@example.tld",
            "उदाहरण.परीक्ष@domain.with.idn.tld",
            "ιωάννης@εεττ.gr",
        ),
        ("葉士豪@臺網中心.tw", "葉士豪@臺網中心.tw"),
        ("jeff葉@臺網中心.tw", "jeff葉@臺網中心.tw"),
        ("葉士豪@臺網中心.台灣", "葉士豪@臺網中心.台灣"),
        # invalid email (Hiding because our current regex is very permissive)
        *all_fails(
            "my@localhost",
            "my@.leadingdot.com",
            "my@．leadingfwdot.com",
            "my@twodots..com",
            "my@twofwdots．．.com",
            "my@trailingdot.com.",
            "my@trailingfwdot.com．",
            "me@-leadingdash",
            "me@－leadingdashfw",
            "me@trailingdash-",
            "me@trailingdashfw－",
            "my@baddash.-.com",
            "my@baddash.-a.com",
            "my@baddash.b-.com",
            "my@baddashfw.－.com",
            "my@baddashfw.－a.com",
            "my@baddashfw.b－.com",
            "my@example\n.com",
            "me@x!",
            "me@x ",
            ".leadingdot@domain.com",
            "twodots..here@domain.com",
            "trailingdot.@domain.email",
            "me@⒈wouldbeinvalid.com",
            "@example.com",
            "m\ny@example.com",
            "my\n@example.com",
            "11111111112222222222333333333344444444445555555555666666666677777@example.com",
            "111111111122222222223333333333444444444455555555556666666666777777@example.com",
            "me@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.111111111122222222223333333333444444444455555555556.com",
            "me@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555566.com",
            "me@中1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555566.com",
            "my.long.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333333344444.info",
            "my.long.address@λ111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.11111111112222222222333333.info",
            "my.long.address@λ111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
            "my.λong.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.111111111122222222223333333333444.info",
            "my.λong.address@1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444444444555555555.6666666666777777777788888888889999999999000000000.1111111111222222222233333333334444.info",
            "me@bad-tld-1",
            "me@bad.tld-2",
            "me@xn--0.tld",
            "me@yy--0.tld",
            "me@yy－－0.tld",
        )
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ PATH                                                  │
# ╰───────────────────────────────────────────────────────╯


class TestWebPath(BaseTest):
    raw_option = {"type": "path", "id": "path_id"}
    prefill = {
        "raw_option": {"default": "some_path"},
        "prefill": "some_path",
    }
    # fmt: off
    scenarios = [
        *all_fails(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),

        *nones(None, "", output=""),
        # custom valid
        ("/", "/"),
        ("/one/two", "/one/two"),
        *[
            (v, "/" + v)
            for v in ("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value")
        ],
        ("value\n", "/value"),
        ("//value", "/value"),
        ("///value///", "/value"),
        *xpass(scenarios=[
            ("value\nvalue", "/value\nvalue"),
            ("value value", "/value value"),
            ("value//value", "/value//value"),
        ], reason="Should fail"),
        *xpass(scenarios=[
            ("./here", "/./here"),
            ("../here", "/../here"),
            ("/somewhere/../here", "/somewhere/../here"),
        ], reason="Should fail or flattened"),

        *xpass(scenarios=[
            ("/one?withquery=ah", "/one?withquery=ah"),
        ], reason="Should fail or query string removed"),
        *xpass(scenarios=[
            ("https://example.com/folder", "/https://example.com/folder")
        ], reason="Should fail or scheme+domain removed"),
        # readonly
        ("/overwrite", "/value", {"readonly": True, "default": "/value"}),
        # FIXME should path have forbidden_chars?
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ URL                                                   │
# ╰───────────────────────────────────────────────────────╯


class TestUrl(BaseTest):
    raw_option = {"type": "url", "id": "url_id"}
    prefill = {
        "raw_option": {"default": "https://domain.tld"},
        "prefill": "https://domain.tld",
    }
    # fmt: off
    scenarios = [
        *all_fails(False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {}, raw_option={"optional": True}),
        *all_fails("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n", raw_option={"optional": True}),

        *nones(None, "", output=""),
        ("http://some.org/folder/file.txt", "http://some.org/folder/file.txt"),
        ('  https://www.example.com \n', 'https://www.example.com/'),
        # readonly
        ("https://overwrite.org", "https://example.org", {"readonly": True, "default": "https://example.org"}),
        # rest is taken from https://github.com/pydantic/pydantic/blob/main/tests/test_networks.py
        # valid
        *unchanged(
            # Those are valid but not sure how they will output with pydantic
            'https://example.org/whatever/next/',
            'https://foo_bar.example.com/',
            'http://www.example.com/a%C2%B1b',
            'http://www.example.com/~username/',
            'http://info.example.com/?fred',
            'http://xn--mgbh0fb.xn--kgbechtv/',
            'http://example.com/blue/red%3Fand+green',
            'http://www.example.com/?array%5Bkey%5D=value',
            'http://xn--rsum-bpad.example.org/',
            'http://123.45.67.8/',
            'http://123.45.67.8:8329/',
            'http://[2001:db8::1]/',
            'http://www.example.com:8000/foo',
            'https://exam_ple.com/',
            'http://twitter.com/@handle/',
            'http://11.11.11.11.example.com/action',
            'http://abc.11.11.11.11.example.com/action',
            'http://example.org/path#',
            'http://example.org/path#fragment',
            'http://example.org/path?query#',
            'http://example.org/path?query#fragment',
            'https://foo_bar.example.com/',
            'https://exam_ple.com/',
            'http://localhost/',
            'http://localhost:8000/',
            'http://example/#',
            'http://example/#fragment',
            'http://example/?#',
        ),
        *[
            (url, url + '/')
            for url in [
                'http://example.org',
                'https://example.org',
                'http://example.co.jp',
                'http://[2001:db8::ff00:42]:8329',
                'http://[2001::1]:8329',
                'https://example.xn--p1ai',
                'https://example.xn--vermgensberatung-pwb',
                'https://example.xn--zfr164b',
                'http://test',
                'http://localhost',
                'http://localhost:8000'
            ]
        ],
        ('http://info.example.com?fred', 'http://info.example.com/?fred'),
        ('http://example#', 'http://example/#'),
        ('HTTP://EXAMPLE.ORG', 'http://example.org/'),
        ('https://example.org?a=1&b=2', 'https://example.org/?a=1&b=2'),
        ('https://example.org#a=3;b=3', 'https://example.org/#a=3;b=3'),
        ('http://www.cwi.nl:80/%7Eguido/Python.html', 'http://www.cwi.nl/%7Eguido/Python.html'),
        ('https://www.python.org/путь', 'https://www.python.org/%D0%BF%D1%83%D1%82%D1%8C'),
        ('http://андрей@example.com', 'http://%D0%B0%D0%BD%D0%B4%D1%80%D0%B5%D0%B9@example.com/'),
        # invalid
        *all_fails(
            'ftp://example.com/',
            "$https://example.org",
            "../icons/logo.gif",
            "abc",
            "..",
            "/",
            "+http://example.com/",
            "ht*tp://example.com/",
            "http:///",
            "http://??",
            "https://example.org more",
            "http://2001:db8::ff00:42:8329",
            "http://[192.168.1.1]:8329",
            "http://example.com:99999",
        ),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ FILE                                                  │
# ╰───────────────────────────────────────────────────────╯


@pytest.fixture
def file_clean():
    FileOption.clean_upload_dirs()
    yield
    FileOption.clean_upload_dirs()


@contextmanager
def patch_file_cli(intake):
    upload_dir = tempfile.mkdtemp(prefix="ynh_test_option_file")
    _, filename = tempfile.mkstemp(dir=upload_dir)
    with open(filename, "w") as f:
        f.write(intake)

    yield filename
    os.system(f"rm -f {filename}")


@contextmanager
def patch_file_api(intake):
    from base64 import b64encode

    with patch_interface("api"):
        yield b64encode(intake.encode())


def _test_file_intake_may_fail(raw_option, intake, expected_output):
    if inspect.isclass(expected_output) and issubclass(expected_output, Exception):
        with pytest.raises(expected_output):
            _fill_or_prompt_one_option(raw_option, intake)

    option, value = _fill_or_prompt_one_option(raw_option, intake)

    # The file is supposed to be copied somewhere else
    assert value != intake
    assert value.startswith("/tmp/ynh_filequestion_")
    assert os.path.exists(value)
    with open(value) as f:
        assert f.read() == expected_output

    FileOption.clean_upload_dirs()

    assert not os.path.exists(value)


file_content1 = "helloworld"
file_content2 = """
{
    "testy": true,
    "test": ["one"]
}
"""


class TestFile(BaseTest):
    raw_option = {"type": "file", "id": "file_id"}
    # Prefill data is generated in `cls.test_options_prompted_with_ask_help`
    # fmt: off
    scenarios = [
        *nones(None, "", output=""),
        *unchanged(file_content1, file_content2),
        # other type checks are done in `test_wrong_intake`
    ]
    # fmt: on
    # TODO test readonly
    # TODO test accept

    @pytest.mark.usefixtures("patch_no_tty")
    def test_basic_attrs(self):
        raw_option, option, value = self._test_basic_attrs()

        accept = raw_option.get("accept", None)  # accept default
        assert option.accept == accept

    def test_options_prompted_with_ask_help(self):
        with patch_file_cli(file_content1) as default_filename:
            super().test_options_prompted_with_ask_help(
                prefill_data={
                    "raw_option": {
                        "default": default_filename,
                    },
                    "prefill": default_filename,
                }
            )

    @pytest.mark.usefixtures("file_clean")
    def test_scenarios(self, intake, expected_output, raw_option, data):
        if intake in (None, ""):
            with patch_prompt(intake):
                _test_intake_may_fail(raw_option, None, expected_output)
            with patch_isatty(False):
                _test_intake_may_fail(raw_option, intake, expected_output)
        else:
            with patch_file_cli(intake) as filename:
                with patch_prompt(filename):
                    _test_file_intake_may_fail(raw_option, None, expected_output)
            with patch_file_api(intake) as b64content:
                with patch_isatty(False):
                    _test_file_intake_may_fail(raw_option, b64content, expected_output)

    @pytest.mark.parametrize(
        "path",
        [
            "/tmp/inexistant_file.txt",
            "/tmp",
            "/tmp/",
        ],
    )
    def test_wrong_cli_filename(self, path):
        with patch_prompt(path):
            with pytest.raises(YunohostValidationError):
                _fill_or_prompt_one_option(self.raw_option, None)

    @pytest.mark.parametrize(
        "intake",
        [
            # fmt: off
            False, True, 0, 1, -1, 1337, 13.37, [], ["one"], {},
            "none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", ",", "['one']", "one,two", r"{}", "value", "value\n"
            # fmt: on
        ],
    )
    def test_wrong_intake(self, intake):
        with pytest.raises(YunohostValidationError):
            with patch_prompt(intake):
                _fill_or_prompt_one_option(self.raw_option, None)
            with patch_isatty(False):
                _fill_or_prompt_one_option(self.raw_option, intake)


# ╭───────────────────────────────────────────────────────╮
# │ SELECT                                                │
# ╰───────────────────────────────────────────────────────╯


class TestSelect(BaseTest):
    raw_option = {"type": "select", "id": "select_id"}
    prefill = {
        "raw_option": {"default": "one", "choices": ["one", "two"]},
        "prefill": "one",
    }
    # fmt: off
    scenarios = [
        {
            # ["one", "two"]
            "raw_options": [
                {"choices": ["one", "two"]},
                {"choices": {"one": "verbose one", "two": "verbose two"}},
            ],
            "scenarios": [
                *nones(None, "", output=""),
                *unchanged("one", "two"),
                ("three", FAIL),
            ]
        },
        # custom bash style list as choices (only strings for now)
        ("one", "one", {"choices": "one,two"}),
        {
            # [-1, 0, 1]
            "raw_options": [
                {"choices": [-1, 0, 1, 10]},
            ],
            "scenarios": [
                *nones(None, "", output=""),
                *unchanged(-1, 0, 1, 10),
                *xfail(scenarios=[
                    ("-1", -1),
                    ("0", 0),
                    ("1", 1),
                    ("10", 10),
                ], reason="str -> int not handled"),
                *all_fails("100", 100),
            ]
        },
        {
            "raw_options": [
                {"choices": {"-1": "verbose -one", "0": "verbose zero", "1": "verbose one", "10": "verbose ten"}},
            ],
            "scenarios": [
                *nones(None, "", output=""),
                *all_fails(-1, 0, 1, 10),  # Should pass? converted to str?
                *unchanged("-1", "0", "1", "10"),
                *all_fails("100", 100),
            ]
        },
        {
            "raw_options": [
                {"choices": {-1: "verbose -one", 0: "verbose zero", 1: "verbose one", 10: "verbose ten"}},
            ],
            "scenarios": [
                *nones(None, "", output=""),
                *unchanged(-1, 0, 1, 10), 
                *all_fails("-1", "0", "1", "10"),
                *all_fails("100", 100),
            ]
        },
        # [True, False, None]
        *unchanged(True, False, raw_option={"choices": [True, False, None]}),  # FIXME we should probably forbid None in choices
        (None, "", {"choices": [True, False, None]}),
        {
            # mixed types
            "raw_options": [{"choices": ["one", 2, True]}],
            "scenarios": [
                *xpass(scenarios=[
                    ("one", "one"),
                    (2, 2),
                    (True, True),
                ], reason="mixed choices, should fail"),
                *all_fails("2", "True", "y"),
            ]
        },
        {
            "raw_options": [{"choices": ""}, {"choices": []}],
            "scenarios": [
                # FIXME those should fail at option level (wrong default, dev error)
                *all_fails(None, "", error=YunohostError),
                *xpass(scenarios=[
                    ("", "", {"optional": True}),
                    (None, "", {"optional": True}),
                ], reason="empty choices, should fail at option instantiation"),
            ]
        },
        # readonly
        ("one", "two", {"readonly": True, "choices": ["one", "two"], "default": "two"}),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ TAGS                                                  │
# ╰───────────────────────────────────────────────────────╯


#  [], ["one"], {}
class TestTags(BaseTest):
    raw_option = {"type": "tags", "id": "tags_id"}
    prefill = {
        "raw_option": {"default": ["one", "two"]},
        "prefill": "one,two",
    }
    # fmt: off
    scenarios = [
        *nones(None, [], "", ",", output=""),
        {
            "raw_options": [
                {},
                {"choices": ["one", "two"]}
            ],
            "scenarios": [
                *unchanged("one", "one,two"),
                (["one"], "one"),
                (["one", "two"], "one,two"),
            ]
        },
        ("three", FAIL, {"choices": ["one", "two"]}),
        *unchanged("none", "_none", "False", "True", "0", "1", "-1", "1337", "13.37", "[]", "['one']", "one,two", r"{}", "value"),
        (" value\n", "value"),
        ([False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {}], "False,True,-1,0,1,1337,13.37,[],['one'],{}"),
        *(([t], str(t)) for t in (False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {})),
        # basic types (not in a list) should fail
        *all_fails(True, False, -1, 0, 1, 1337, 13.37, {}),
        # Mixed choices should fail
        ([False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {}], YunohostError, {"choices": [False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {}]}),
        ("False,True,-1,0,1,1337,13.37,[],['one'],{}", YunohostError, {"choices": [False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {}]}),
        *all_fails(*([t] for t in [False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {}]), raw_option={"choices": [False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {}]}, error=YunohostError),
        *all_fails(*([str(t)] for t in [False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {}]), raw_option={"choices": [False, True, -1, 0, 1, 1337, 13.37, [], ["one"], {}]}, error=YunohostError),
        # readonly
        ("one", "one,two", {"readonly": True, "choices": ["one", "two"], "default": "one,two"}),
    ]
    # fmt: on


# ╭───────────────────────────────────────────────────────╮
# │ DOMAIN                                                │
# ╰───────────────────────────────────────────────────────╯

main_domain = "ynh.local"
domains1 = ["ynh.local"]
domains2 = ["another.org", "ynh.local", "yet.another.org"]


@contextmanager
def patch_domains(*, domains, main_domain):
    """
    Data mocking for DomainOption:
    - yunohost.domain.domain_list
    """
    with patch.object(
        domain,
        "domain_list",
        return_value={"domains": domains, "main": main_domain},
    ), patch.object(domain, "_get_maindomain", return_value=main_domain):
        yield


class TestDomain(BaseTest):
    raw_option = {"type": "domain", "id": "domain_id"}
    prefill = {
        "raw_option": {
            "default": None,
        },
        "prefill": main_domain,
    }
    # fmt: off
    scenarios = [
        # Probably not needed to test common types since those are not available as choices
        # Also no scenarios with no domains since it should not be possible
        {
            "data": [{"main_domain": domains1[0], "domains": domains1}],
            "scenarios": [
                *nones(None, "", output=domains1[0], fail_if_required=False),
                (domains1[0], domains1[0], {}),
                ("doesnt_exist.pouet", FAIL, {}),
                ("fake.com", FAIL, {"choices": ["fake.com"]}),
                # readonly
                (domains1[0], YunohostError, {"readonly": True}),  # readonly is forbidden
            ]
        },
        {
            "data": [{"main_domain": domains2[1], "domains": domains2}],
            "scenarios": [
                *nones(None, "", output=domains2[1], fail_if_required=False),
                (domains2[1], domains2[1], {}),
                (domains2[0], domains2[0], {}),
                ("doesnt_exist.pouet", FAIL, {}),
                ("fake.com", FAIL, {"choices": ["fake.com"]}),
            ]
        },

    ]
    # fmt: on

    def test_options_prompted_with_ask_help(self, prefill_data=None):
        with patch_domains(domains=[main_domain], main_domain=main_domain):
            super().test_options_prompted_with_ask_help(prefill_data=prefill_data)

    def test_scenarios(self, intake, expected_output, raw_option, data):
        with patch_domains(**data):
            super().test_scenarios(intake, expected_output, raw_option, data)


# ╭───────────────────────────────────────────────────────╮
# │ APP                                                   │
# ╰───────────────────────────────────────────────────────╯

installed_webapp = {
    "is_webapp": True,
    "is_default": True,
    "label": "My webapp",
    "id": "my_webapp",
    "domain_path": "/ynh-dev",
}
installed_non_webapp = {
    "is_webapp": False,
    "is_default": False,
    "label": "My non webapp",
    "id": "my_non_webapp",
}


@contextmanager
def patch_apps(*, apps):
    """
    Data mocking for AppOption:
    - yunohost.app.app_list
    """
    with patch.object(app, "app_list", return_value={"apps": apps}):
        yield


class TestApp(BaseTest):
    raw_option = {"type": "app", "id": "app_id"}
    # fmt: off
    scenarios = [
        # Probably not needed to test common types since those are not available as choices
        {
            "data": [
                {"apps": []},
                {"apps": [installed_webapp]},
                {"apps": [installed_webapp, installed_non_webapp]},
            ],
            "scenarios": [
                # FIXME there are currently 3 different nones (`None`, `""` and `_none`), choose one?
                *nones(None, "", output=""),  # FIXME Should return chosen none?
                *xpass(scenarios=[
                    ("_none", "_none"),
                    ("_none", "_none", {"default": "_none"}),
                ], reason="should fail; is required"),
                *xpass(scenarios=[
                    ("_none", "_none", {"optional": True}),
                    ("_none", "_none", {"optional": True, "default": "_none"})
                ], reason="Should output chosen none value"),
                ("fake_app", FAIL),
                ("fake_app", FAIL, {"choices": ["fake_app"]}),
            ]
        },
        {
            "data": [
                {"apps": [installed_webapp]},
                {"apps": [installed_webapp, installed_non_webapp]},
            ],
            "scenarios": [
                (installed_webapp["id"], installed_webapp["id"]),
                (installed_webapp["id"], installed_webapp["id"], {"filter": "is_webapp"}),
                (installed_webapp["id"], FAIL, {"filter": "is_webapp == false"}),
                (installed_webapp["id"], FAIL, {"filter": "id != 'my_webapp'"}),
                (None, "", {"filter": "id == 'fake_app'", "optional": True}),
            ]
        },
        {
            "data": [{"apps": [installed_webapp, installed_non_webapp]}],
            "scenarios": [
                (installed_non_webapp["id"], installed_non_webapp["id"]),
                (installed_non_webapp["id"], FAIL, {"filter": "is_webapp"}),
                # readonly
                (installed_non_webapp["id"], YunohostError, {"readonly": True}),  # readonly is forbidden
            ]
        },
    ]
    # fmt: on

    @pytest.mark.usefixtures("patch_no_tty")
    def test_basic_attrs(self):
        with patch_apps(apps=[]):
            raw_option, option, value = self._test_basic_attrs()

            assert option.choices == {"_none": "---"}
            assert option.filter is None

        with patch_apps(apps=[installed_webapp, installed_non_webapp]):
            raw_option, option, value = self._test_basic_attrs()

            assert option.choices == {
                "_none": "---",
                "my_webapp": "My webapp (/ynh-dev)",
                "my_non_webapp": "My non webapp (my_non_webapp)",
            }
            assert option.filter is None

    def test_options_prompted_with_ask_help(self, prefill_data=None):
        with patch_apps(apps=[installed_webapp, installed_non_webapp]):
            super().test_options_prompted_with_ask_help(
                prefill_data={
                    "raw_option": {"default": installed_webapp["id"]},
                    "prefill": installed_webapp["id"],
                }
            )
            super().test_options_prompted_with_ask_help(
                prefill_data={"raw_option": {"optional": True}, "prefill": ""}
            )

    def test_scenarios(self, intake, expected_output, raw_option, data):
        with patch_apps(**data):
            super().test_scenarios(intake, expected_output, raw_option, data)


# ╭───────────────────────────────────────────────────────╮
# │ USER                                                  │
# ╰───────────────────────────────────────────────────────╯

admin_username = "admin_user"
admin_user = {
    "username": admin_username,
    "mail": "a@ynh.local",
    "fullname": "john doe",
    "groups": ["admins"],
}
regular_username = "normal_user"
regular_user = {
    "username": regular_username,
    "mail": "z@ynh.local",
    "fullname": "john doe",
    "groups": [],
}


@contextmanager
def patch_users(*, users):
    """
    Data mocking for UserOption:
    - yunohost.user.user_list
    - yunohost.user.user_info
    - yunohost.domain._get_maindomain
    """
    with patch.object(user, "user_list", return_value={"users": users}):
        yield


class TestUser(BaseTest):
    raw_option = {"type": "user", "id": "user_id"}
    # fmt: off
    scenarios = [
        # No tests for empty users since it should not happens
        {
            "data": [
                {"users": {admin_username: admin_user}},
                {"users": {admin_username: admin_user, regular_username: regular_user}},
            ],
            "scenarios": [
                # FIXME User option is not really nullable, even if optional
                *nones(None, "", output=admin_username, fail_if_required=False),
                ("fake_user", FAIL),
                ("fake_user", FAIL, {"choices": ["fake_user"]}),
            ]
        },
        {
            "data": [
                {"users": {admin_username: admin_user, regular_username: regular_user}},
            ],
            "scenarios": [
                *xpass(scenarios=[
                    ("", regular_username, {"default": regular_username})
                ], reason="Should throw 'no default allowed'"),
                # readonly
                (admin_username, YunohostError, {"readonly": True}),  # readonly is forbidden
            ]
        },
    ]
    # fmt: on

    @pytest.mark.usefixtures("patch_no_tty")
    def test_basic_attrs(self):
        with patch_users(users={admin_username: admin_user}):
            self._test_basic_attrs()

    def test_options_prompted_with_ask_help(self, prefill_data=None):
        with patch_users(
            users={admin_username: admin_user, regular_username: regular_user}
        ):
            super().test_options_prompted_with_ask_help(
                prefill_data={"raw_option": {}, "prefill": admin_username}
            )
            # FIXME This should fail, not allowed to set a default
            super().test_options_prompted_with_ask_help(
                prefill_data={
                    "raw_option": {"default": regular_username},
                    "prefill": regular_username,
                }
            )

    def test_scenarios(self, intake, expected_output, raw_option, data):
        with patch_users(**data):
            super().test_scenarios(intake, expected_output, raw_option, data)


# ╭───────────────────────────────────────────────────────╮
# │ GROUP                                                 │
# ╰───────────────────────────────────────────────────────╯

groups1 = {"all_users": {}, "visitors": {}, "admins": {}}
groups2 = {"all_users": {}, "visitors": {}, "admins": {}, "custom_group": {}}


@contextmanager
def patch_groups(*, groups):
    """
    Data mocking for GroupOption:
    - yunohost.user.user_group_list
    """
    with patch.object(user, "user_group_list", return_value={"groups": groups}):
        yield


class TestGroup(BaseTest):
    raw_option = {"type": "group", "id": "group_id"}
    # fmt: off
    scenarios = [
        # No tests for empty groups since it should not happens
        {
            "data": [
                {"groups": groups1},
                {"groups": groups2},
            ],
            "scenarios": [
                # FIXME Group option is not really nullable, even if optional
                *nones(None, "", output="all_users", fail_if_required=False),
                ("admins", "admins"),
                ("fake_group", FAIL),
                ("fake_group", FAIL, {"choices": ["fake_group"]}),
            ]
        },
        {
            "data": [
                {"groups": groups2},
            ],
            "scenarios": [
                ("custom_group", "custom_group"),
                *all_as("", None, output="visitors", raw_option={"default": "visitors"}),
                ("", YunohostError, {"default": "custom_group"}),  # Not allowed to set a default which is not a default group
                # readonly
                ("admins", YunohostError, {"readonly": True}),  # readonly is forbidden
            ]
        },
    ]
    # fmt: on

    def test_options_prompted_with_ask_help(self, prefill_data=None):
        with patch_groups(groups=groups2):
            super().test_options_prompted_with_ask_help(
                prefill_data={"raw_option": {}, "prefill": "all_users"}
            )
            super().test_options_prompted_with_ask_help(
                prefill_data={
                    "raw_option": {"default": "admins"},
                    "prefill": "admins",
                }
            )

    def test_scenarios(self, intake, expected_output, raw_option, data):
        with patch_groups(**data):
            super().test_scenarios(intake, expected_output, raw_option, data)


# ╭───────────────────────────────────────────────────────╮
# │ MULTIPLE                                              │
# ╰───────────────────────────────────────────────────────╯


@pytest.fixture
def patch_entities():
    with patch_domains(domains=domains2, main_domain=main_domain), patch_apps(
        apps=[installed_webapp, installed_non_webapp]
    ), patch_users(
        users={admin_username: admin_user, regular_username: regular_user},
    ), patch_groups(
        groups=groups2
    ):
        yield


def test_options_empty():
    ask_questions_and_parse_answers({}, {}) == []


@pytest.mark.usefixtures("patch_entities", "file_clean")
def test_options_query_string():
    raw_options = {
        "string_id": {"type": "string"},
        "text_id": {"type": "text"},
        "password_id": {"type": "password"},
        "color_id": {"type": "color"},
        "number_id": {"type": "number"},
        "boolean_id": {"type": "boolean"},
        "date_id": {"type": "date"},
        "time_id": {"type": "time"},
        "email_id": {"type": "email"},
        "path_id": {"type": "path"},
        "url_id": {"type": "url"},
        "file_id": {"type": "file"},
        "select_id": {"type": "select", "choices": ["one", "two"]},
        "tags_id": {"type": "tags", "choices": ["one", "two"]},
        "domain_id": {"type": "domain"},
        "app_id": {"type": "app"},
        "user_id": {"type": "user"},
        "group_id": {"type": "group"},
    }

    results = {
        "string_id": "string",
        "text_id": "text\ntext",
        "password_id": "sUpRSCRT",
        "color_id": "#ff0",
        "number_id": 10,
        "boolean_id": 1,
        "date_id": "2030-03-06",
        "time_id": "20:55",
        "email_id": "coucou@ynh.org",
        "path_id": "/ynh-dev",
        "url_id": "https://yunohost.org/",
        "file_id": file_content1,
        "select_id": "one",
        "tags_id": "one,two",
        "domain_id": main_domain,
        "app_id": installed_webapp["id"],
        "user_id": regular_username,
        "group_id": "admins",
    }

    @contextmanager
    def patch_query_string(file_repr):
        yield (
            "string_id= string"
            "&text_id=text\ntext"
            "&password_id=sUpRSCRT"
            "&color_id=#ffff00"
            "&number_id=10"
            "&boolean_id=y"
            "&date_id=2030-03-06"
            "&time_id=20:55"
            "&email_id=coucou@ynh.org"
            "&path_id=ynh-dev/"
            "&url_id=https://yunohost.org"
            f"&file_id={file_repr}"
            "&select_id=one"
            "&tags_id=one,two"
            # FIXME We can't test with parse.qs for now, next syntax is available only with config panels
            # "&tags_id=one"
            # "&tags_id=two"
            f"&domain_id={main_domain}"
            f"&app_id={installed_webapp['id']}"
            f"&user_id={regular_username}"
            "&group_id=admins"
            # not defined extra values are silently ignored
            "&fake_id=fake_value"
        )

    def _assert_correct_values(options, form, raw_options):
        for k, v in results.items():
            if k == "file_id":
                assert os.path.exists(form["file_id"]) and os.path.isfile(
                    form["file_id"]
                )
                with open(form["file_id"], "r") as f:
                    assert f.read() == file_content1
            else:
                assert form[k] == results[k]

        assert len(options) == len(raw_options.keys())
        assert "fake_id" not in form

    with patch_interface("api"), patch_file_api(file_content1) as b64content:
        with patch_query_string(b64content.decode("utf-8")) as query_string:
            options, form = ask_questions_and_parse_answers(raw_options, query_string)
            _assert_correct_values(options, form, raw_options)

    with patch_interface("cli"), patch_file_cli(file_content1) as filepath:
        with patch_query_string(filepath) as query_string:
            options, form = ask_questions_and_parse_answers(raw_options, query_string)
            _assert_correct_values(options, form, raw_options)


def test_question_string_default_type():
    questions = {"some_string": {}}
    answers = {"some_string": "some_value"}

    options, form = ask_questions_and_parse_answers(questions, answers)
    option = options[0]
    assert option.id == "some_string"
    assert option.type == "string"
    assert form[option.id] == "some_value"


def test_option_default_type_with_choices_is_select():
    questions = {
        "some_choices": {"choices": ["a", "b"]},
        # LEGACY (`choices` in option `string` used to be valid)
        # make sure this result as a `select` option
        "some_legacy": {"type": "string", "choices": ["a", "b"]},
    }
    answers = {"some_choices": "a", "some_legacy": "a"}

    options, form = ask_questions_and_parse_answers(questions, answers)
    for option in options:
        assert option.type == "select"
        assert form[option.id] == "a"


@pytest.mark.skip  # we should do something with this example
def test_question_string_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = {
        "some_string": {
            "ask": ask_text,
            "example": example_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this example
def test_question_password_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = {
        "some_password": {
            "type": "password",
            "ask": ask_text,
            "example": example_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this example
def test_question_path_input_test_ask_with_example():
    ask_text = "some question"
    example_text = "some example"
    questions = {
        "some_path": {
            "type": "path",
            "ask": ask_text,
            "example": example_text,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="some_value"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_text in prompt.call_args[1]["message"]


@pytest.mark.skip  # we should do something with this example
def test_question_number_input_test_ask_with_example():
    ask_text = "some question"
    example_value = 1337
    questions = {
        "some_number": {
            "type": "number",
            "ask": ask_text,
            "example": example_value,
        }
    }
    answers = {}

    with patch.object(
        Moulinette, "prompt", return_value="1111"
    ) as prompt, patch.object(os, "isatty", return_value=True):
        ask_questions_and_parse_answers(questions, answers)
        assert ask_text in prompt.call_args[1]["message"]
        assert example_value in prompt.call_args[1]["message"]


def test_normalize_boolean_nominal():
    assert BooleanOption.normalize("yes") == 1
    assert BooleanOption.normalize("Yes") == 1
    assert BooleanOption.normalize(" yes  ") == 1
    assert BooleanOption.normalize("y") == 1
    assert BooleanOption.normalize("true") == 1
    assert BooleanOption.normalize("True") == 1
    assert BooleanOption.normalize("on") == 1
    assert BooleanOption.normalize("1") == 1
    assert BooleanOption.normalize(1) == 1

    assert BooleanOption.normalize("no") == 0
    assert BooleanOption.normalize("No") == 0
    assert BooleanOption.normalize(" no  ") == 0
    assert BooleanOption.normalize("n") == 0
    assert BooleanOption.normalize("false") == 0
    assert BooleanOption.normalize("False") == 0
    assert BooleanOption.normalize("off") == 0
    assert BooleanOption.normalize("0") == 0
    assert BooleanOption.normalize(0) == 0

    assert BooleanOption.normalize("") is None
    assert BooleanOption.normalize("   ") is None
    assert BooleanOption.normalize(" none   ") is None
    assert BooleanOption.normalize("None") is None
    assert BooleanOption.normalize("noNe") is None
    assert BooleanOption.normalize(None) is None


def test_normalize_boolean_humanize():
    assert BooleanOption.humanize("yes") == "yes"
    assert BooleanOption.humanize("true") == "yes"
    assert BooleanOption.humanize("on") == "yes"

    assert BooleanOption.humanize("no") == "no"
    assert BooleanOption.humanize("false") == "no"
    assert BooleanOption.humanize("off") == "no"


def test_normalize_boolean_invalid():
    with pytest.raises(YunohostValidationError):
        BooleanOption.normalize("yesno")
    with pytest.raises(YunohostValidationError):
        BooleanOption.normalize("foobar")
    with pytest.raises(YunohostValidationError):
        BooleanOption.normalize("enabled")


def test_normalize_boolean_special_yesno():
    customyesno = {"yes": "enabled", "no": "disabled"}

    assert BooleanOption.normalize("yes", customyesno) == "enabled"
    assert BooleanOption.normalize("true", customyesno) == "enabled"
    assert BooleanOption.normalize("enabled", customyesno) == "enabled"
    assert BooleanOption.humanize("yes", customyesno) == "yes"
    assert BooleanOption.humanize("true", customyesno) == "yes"
    assert BooleanOption.humanize("enabled", customyesno) == "yes"

    assert BooleanOption.normalize("no", customyesno) == "disabled"
    assert BooleanOption.normalize("false", customyesno) == "disabled"
    assert BooleanOption.normalize("disabled", customyesno) == "disabled"
    assert BooleanOption.humanize("no", customyesno) == "no"
    assert BooleanOption.humanize("false", customyesno) == "no"
    assert BooleanOption.humanize("disabled", customyesno) == "no"


def test_normalize_domain():
    assert DomainOption.normalize("https://yolo.swag/") == "yolo.swag"
    assert DomainOption.normalize("http://yolo.swag") == "yolo.swag"
    assert DomainOption.normalize("yolo.swag/") == "yolo.swag"


def test_normalize_path():
    assert WebPathOption.normalize("") == "/"
    assert WebPathOption.normalize("") == "/"
    assert WebPathOption.normalize("macnuggets") == "/macnuggets"
    assert WebPathOption.normalize("/macnuggets") == "/macnuggets"
    assert WebPathOption.normalize("   /macnuggets      ") == "/macnuggets"
    assert WebPathOption.normalize("/macnuggets") == "/macnuggets"
    assert WebPathOption.normalize("mac/nuggets") == "/mac/nuggets"
    assert WebPathOption.normalize("/macnuggets/") == "/macnuggets"
    assert WebPathOption.normalize("macnuggets/") == "/macnuggets"
    assert WebPathOption.normalize("////macnuggets///") == "/macnuggets"


def test_simple_evaluate():
    context = {
        "a1": 1,
        "b2": 2,
        "c10": 10,
        "foo": "bar",
        "comp": "1>2",
        "empty": "",
        "lorem": "Lorem ipsum dolor et si qua met!",
        "warning": "Warning! This sentence will fail!",
        "quote": "Je s'apelle Groot",
        "and_": "&&",
        "object": {"a": "Security risk"},
    }
    supported = {
        "42": 42,
        "9.5": 9.5,
        "'bopbidibopbopbop'": "bopbidibopbopbop",
        "true": True,
        "false": False,
        "null": None,
        # Math
        "1 * (2 + 3 * (4 - 3))": 5,
        "1 * (2 + 3 * (4 - 3)) > 10 - 2 || 3 * 2 > 9 - 2 * 3": True,
        "(9 - 2) * 3 - 10": 11,
        "12 - 2 * -2 + (3 - 4) * 3.1": 12.9,
        "9 / 12 + 12 * 3 - 5": 31.75,
        "9 / 12 + 12 * (3 - 5)": -23.25,
        "12 > 13.1": False,
        "12 < 14": True,
        "12 <= 14": True,
        "12 >= 14": False,
        "12 == 14": False,
        "12 % 5 > 3": False,
        "12 != 14": True,
        "9 - 1 > 10 && 3 * 5 > 10": False,
        "9 - 1 > 10 || 3 * 5 > 10": True,
        "a1 > 0 || a1 < -12": True,
        "a1 > 0 && a1 < -12": False,
        "a1 + 1 > 0 && -a1 > -12": True,
        "-(a1 + 1) < 0 || -(a1 + 2) > -12": True,
        "-a1 * 2": -2,
        "(9 - 2) * 3 - c10": 11,
        "(9 - b2) * 3 - c10": 11,
        "c10 > b2": True,
        # String
        "foo == 'bar'": True,
        "foo != 'bar'": False,
        'foo == "bar" && 1 > 0': True,
        "!!foo": True,
        "!foo": False,
        "foo": "bar",
        '!(foo > "baa") || 1 > 2': False,
        '!(foo > "baa") || 1 < 2': True,
        'empty == ""': True,
        '1 == "1"': True,
        '1.0 == "1"': True,
        '1 == "aaa"': False,
        "'I am ' + b2 + ' years'": "I am 2 years",
        "quote == 'Je s\\'apelle Groot'": True,
        "lorem == 'Lorem ipsum dolor et si qua met!'": True,
        "and_ == '&&'": True,
        "warning == 'Warning! This sentence will fail!'": True,
        # Match
        "match(lorem, '^Lorem [ia]psumE?')": bool,
        "match(foo, '^Lorem [ia]psumE?')": None,
        "match(lorem, '^Lorem [ia]psumE?') && 1 == 1": bool,
        # No code
        "": False,
        " ": False,
    }
    trigger_errors = {
        "object.a": YunohostError,  # Keep unsupported, for security reasons
        "a1 ** b2": YunohostError,  # Keep unsupported, for security reasons
        "().__class__.__bases__[0].__subclasses__()": YunohostError,  # Very dangerous code
        "a1 > 11 ? 1 : 0": SyntaxError,
        "c10 > b2 == false": YunohostError,  # JS and Python doesn't do the same thing for this situation
        "c10 > b2 == true": YunohostError,
    }

    for expression, result in supported.items():
        if result == bool:
            assert bool(evaluate_simple_js_expression(expression, context)), expression
        else:
            assert (
                evaluate_simple_js_expression(expression, context) == result
            ), expression

    for expression, error in trigger_errors.items():
        with pytest.raises(error):
            evaluate_simple_js_expression(expression, context)
