import typing as t
from dataclasses import dataclass


Mode = t.Literal["python", "bash"]
Translation = dict[str, str] | str


@dataclass
class Pattern:
    regexp: str
    error: Translation = "pydantic.value_error.str.regex"
