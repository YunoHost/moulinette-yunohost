import datetime
import email_validator
import typing as t
import urllib
from dataclasses import dataclass
from logging import getLogger
from pathlib import Path
from pydantic import AnyUrl, ValidationError
from pydantic_core import PydanticCustomError, PydanticUseDefault, core_schema as cs

from moulinette import Moulinette
from yunohost.log import OperationLogger

if t.TYPE_CHECKING:
    from pydantic import (
        GetCoreSchemaHandler,
        SerializerFunctionWrapHandler,
        ValidatorFunctionWrapHandler,
        ValidationInfo,
    )
    from pydantic_core import CoreSchema

# Hackish way of allowing some special use tlds
for ext in ("test", "local", "localhost"):
    email_validator.SPECIAL_USE_DOMAIN_NAMES.remove(ext)

logger = getLogger("yunohost.validation")

Mode = t.Literal["normal", "string", "human"]
Translation = dict[str, str] | str


@dataclass
class Pattern:
    regexp: str
    error: Translation = "pydantic.value_error.str.regex"


# TYPE CHECKING
NONISH_VALUES: t.Final = (None, "", "none", "_none")  # null, nil, undefined


def is_nonish(v: t.Any) -> bool:
    v = v.strip().lower() if isinstance(v, str) else v
    return True if v in NONISH_VALUES else False


def is_digit(v: t.Any) -> bool:
    if isinstance(v, str):
        v = v.replace(".", "", 1)
        v = v.replace("-", "", 1) if v.startswith("-") else v
        return v.isdigit()

    return isinstance(v, int | float)


# COERCING/SERIALIZING


def coerce_nonish_to_default(v: t.Any) -> t.Any:
    if is_nonish(v):
        raise PydanticUseDefault()
    return v


def coerce_nonish_to_none(v: t.Any) -> t.Any:
    return None if is_nonish(v) else v


def coerce_comalist_to_list(v: t.Any) -> t.Any:
    if isinstance(v, str):
        values = [coerce_nonish_to_none(value) for value in v.split(",")]
        v = [value.strip() for value in values if value]

    if isinstance(v, list) and len(v) < 1:
        return None

    return v


def serialize_none_to_empty_str(v: t.Any) -> t.Any:
    return "" if v is None else v


# VALIDATORS


def redact(v: t.Any) -> t.Any:
    # FIXME should receive serialized value?
    if not v or not isinstance(v, str):
        return v

    # Tell the operation_logger to redact all password-type / secret args
    # Also redact the % escaped version of the password that might appear in
    # the 'args' section of metadata (relevant for password with non-alphanumeric char)
    data_to_redact = [v]
    data_to_redact += [
        urllib.parse.quote(data)
        for data in data_to_redact
        if urllib.parse.quote(data) != data
    ]

    for operation_logger in OperationLogger._instances:
        operation_logger.data_to_redact.extend(data_to_redact)

    return v


# CORE SCHEMA HELPERS


def find_type_schema(schema: "CoreSchema", type_: str) -> t.Union["CoreSchema", None]:
    if schema["type"] == type_:
        return schema
    if schema["type"] == "nullable":
        return find_type_schema(schema["schema"], type_)
    if schema["type"] == "union":
        return next((s for s in schema["choices"] if s["type"] == type_), None)
    return None


# CONSTRAINTS


@dataclass
class BaseConstraints:
    mode: Mode = "normal"
    has_default: bool = False
    redact: bool = False
    serializer: t.Callable | None = None
    none_value: t.Any = ""

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        return self.apply_base_schema(handler(source_type))

    def apply_base_schema(self, schema: "CoreSchema") -> "CoreSchema":
        return cs.no_info_before_validator_function(
            self.preparse,
            schema,
            serialization=cs.wrap_serializer_function_ser_schema(self.wrap_serializer),
        )

    def preparse(self, v: t.Any) -> t.Any:
        return (
            coerce_nonish_to_default(v)
            if self.has_default
            else coerce_nonish_to_none(v)
        )

    def serialize(self, v: t.Any) -> t.Any:
        return v

    def wrap_serializer(
        self, v: t.Any, handler: "SerializerFunctionWrapHandler"
    ) -> t.Any:
        v = handler(v)

        v = self.serialize(v)

        if self.serializer:
            v = self.serializer(v)

        v = self.none_value if v is None else v

        if self.redact and v not in NONISH_VALUES:
            redact(v)

        return v


@dataclass
class StringConstraints(BaseConstraints):
    pattern: Pattern | None = None
    strip_whitespace: bool = True
    multiline: bool = False

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        schema = handler(source_type)
        str_schema = find_type_schema(schema, "str")

        if str_schema is None:
            return schema

        str_schema.update(
            cs.no_info_after_validator_function(
                self.validate,
                cs.no_info_wrap_validator_function(
                    self.pattern_error_wrapper,
                    cs.str_schema(
                        pattern=self.pattern.regexp if self.pattern else None,
                        strip_whitespace=self.strip_whitespace,
                        coerce_numbers_to_str=True,
                    ),
                ),
            )
        )

        return self.apply_base_schema(schema)

    def pattern_error_wrapper(self, v: str, handler: t.Any):
        """
        Catch "string_pattern_mismatch" validation error to raise another error with
        the custom pattern error message
        """
        if not self.pattern:
            return handler(v)
        try:
            return handler(v)
        except ValidationError as err:
            pattern_error = next(
                (e for e in err.errors() if e["type"] == "string_pattern_mismatch"),
                None,
            )
            if pattern_error:
                raise PydanticCustomError(
                    "string_pattern_mismatch", str(self.pattern.error)
                )
            raise err

    def validate(self, v: str) -> str:
        if not self.multiline and "\n" in v or "\r" in v:
            raise PydanticCustomError(
                "multiline",
                "String contains multiline character",
            )

        return v


FORBIDDEN_PASSWORD_CHARS = r"{}"


@dataclass
class PasswordConstraints(BaseConstraints):
    has_default: t.Literal[False] = False
    redact: t.Literal[True] = True
    forbidden_chars: str = FORBIDDEN_PASSWORD_CHARS

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":

        schema = handler(source_type)
        str_schema = find_type_schema(schema, "str")

        if str_schema is None:
            return schema

        str_schema.update(
            cs.no_info_after_validator_function(
                self.validate,
                cs.str_schema(
                    max_length=127,
                    coerce_numbers_to_str=True,
                ),
                serialization=cs.plain_serializer_function_ser_schema(redact),
            )
        )

        return self.apply_base_schema(schema)

    def validate(self, v: str) -> str:
        if any(char in v for char in (self.forbidden_chars)):
            raise PydanticCustomError(
                "pattern_password_app",
                "forbidden characters in string: {chars}",  # FIXME trad
                {"forbidden_chars": self.forbidden_chars},
            )

        from yunohost.utils.password import PasswordValidator

        validator = PasswordValidator("user")
        status, error_key = validator.validation_summary(v)

        if status == "error":
            raise PydanticCustomError(
                error_key,
                error_key,  # FIXME trad
            )

        return v


@dataclass
class NumberConstraints(BaseConstraints):
    min: int | None = None
    max: int | None = None
    step: int | None = None
    none_value: t.Any = None

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        schema = handler(source_type)
        int_schema = find_type_schema(schema, "int")

        if int_schema is None:
            return schema

        int_schema.update(
            cs.int_schema(
                multiple_of=self.step,
                ge=self.min,
                le=self.max,
            ),
        )

        return self.apply_base_schema(schema)

    def serialize(self, v: int) -> int | str:
        return str(v) if self.mode == "human" else v


@dataclass
class BooleanConstraints(BaseConstraints):
    serialization: tuple[int, int] | tuple[bool, bool] | tuple[str, str] = (True, False)

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        schema = handler(source_type)
        schema = cs.no_info_before_validator_function(
            self.validate,
            schema,
            serialization=cs.plain_serializer_function_ser_schema(
                self.serialize, when_used="unless-none"
            ),
        )

        return schema

    def validate(self, v: t.Any) -> t.Any:
        v = self.preparse(v)
        v = v.strip() if isinstance(v, str) else v
        
        if v == self.serialization[0]:
            return True
        elif v == self.serialization[1]:
            return False

        return v

    def serialize(self, v: bool) -> t.Any:
        if self.mode == "string":
            return self.serialization[0] if v is True else self.serialization[1]
        if self.mode == "human":
            return "yes" if v is True else "no"
            
        return v


@dataclass
class DatetimeConstraints(BaseConstraints):

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        schema = handler(source_type)
        date_schema = find_type_schema(schema, "date")

        schema = cs.no_info_before_validator_function(
            (coerce_nonish_to_default if self.has_default else coerce_nonish_to_none),
            cs.no_info_before_validator_function(
                self.validate_date if date_schema else self.validate_time,
                schema,
                serialization=cs.plain_serializer_function_ser_schema(
                    self.serialize_date if date_schema else self.serialize_time
                ),
            ),
        )

        return schema

    def validate_date(self, v: t.Any) -> t.Any:
        if is_digit(v):
            # FIXME use datetime.timezone.utc? or use local timezone
            return datetime.date.fromtimestamp(float(v))
        if isinstance(v, str):
            if v.find("T") == 10:
                return v.split("T")[0]
            if v.find(" ") == 10:
                return v.split(" ")[0]
        return v

    def validate_time(self, v: t.Any) -> t.Any:
        if is_digit(v):
            value = float(v)
            if value >= 0:
                return datetime.datetime.fromtimestamp(float(v)).time()

        return v

    def serialize_date(self, v: datetime.datetime | None) -> str:
        return "" if v is None else v.isoformat()

    def serialize_time(self, v: datetime.time | None) -> str:
        return "" if v is None else v.strftime("%H:%M")


@dataclass
class PathConstraints(BaseConstraints):
    type: t.Literal["webpath"] = "webpath"

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        schema = handler(source_type)
        schema = cs.no_info_before_validator_function(
            (coerce_nonish_to_default if self.has_default else coerce_nonish_to_none),
            cs.no_info_wrap_validator_function(
                self.validate,
                schema,
                serialization=cs.plain_serializer_function_ser_schema(self.serialize),
            ),
        )

        return schema

    def validate(
        self, v: Path | str | None, handler: "ValidatorFunctionWrapHandler"
    ) -> Path | None:
        if isinstance(v, str):
            if "://" in v:
                v = Path(t.cast(str, AnyUrl(v).path).strip("/"))
            else:
                v = v.strip().strip("/")

                for chars in ("?", "\n", "\t", "\r", " ", "./"):
                    if chars in v:
                        raise PydanticCustomError(
                            "forbidden_chars",
                            "Forbidden characters in string: {chars}",
                            {"chars": chars},
                        )

        path: Path | None = handler(v)

        if path is None:
            return None

        if not path.is_absolute() and str("/" / path).find("../") < 0:
            path = "/" / path

        return path

    def serialize(self, v: Path | None) -> str:
        return "" if v is None else str(v)


UPLOAD_DIRS = set()


@dataclass
class FileConstraints(BaseConstraints):
    bind: str | None = None
    accept: list[str] | None = None

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        schema = handler(source_type)
        type_schema = find_type_schema(schema, "str")
        type_schema.update(
            cs.with_info_after_validator_function(
                self.file_normal if self.mode == "normal" else self.file_string,
                cs.str_schema(),
            )
        )

        return self.apply_base_schema(schema)

    def _base_parse_file(self, v: str) -> tuple[bytes, str | None]:
        import mimetypes
        from magic import Magic
        from base64 import b64decode

        if Moulinette.interface.type != "api":  # isinstance(v, Path):
            path = Path(v)
            if not (path.exists() and path.is_absolute() and path.is_file()):
                # FIXME, search pydantic eq error i18n key
                raise PydanticCustomError("file_not_exists", "File doesn't exists")
            content = path.read_bytes()
        else:
            content = b64decode(v)

        mimetype = Magic(mime=True).from_buffer(content)

        if self.accept and mimetype not in self.accept:
            raise PydanticCustomError(
                "file_unsupported_type",
                "Unsupported file type '{mimetype}', expected a type among '{accept_list}'.",
                {"mimetype": mimetype, "accept_list": ", ".join(self.accept)},
            )

        ext = mimetypes.guess_extension(mimetype)

        return content, ext

    def file_string(self, v: str, info: "ValidationInfo") -> str:
        """File handling for "string" config panels (app)"""
        import tempfile

        content, _ = self._base_parse_file(v)

        upload_dir = tempfile.mkdtemp(prefix="ynh_filequestion_")
        _, file_path = tempfile.mkstemp(dir=upload_dir)

        UPLOAD_DIRS.add(upload_dir)

        logger.debug(
            f"Saving file {info.field_name} for file question into {file_path}"
        )
        Path(file_path).write_bytes(content)

        return file_path

    def file_normal(self, v: str, info: "ValidationInfo") -> str:
        """File handling for "normal" config panels"""
        import hashlib

        assert self.bind is not None, f"File 'bind' is required for {info.field_name}."

        # to avoid "filename too long" with b64 content
        if len(v.encode("utf-8")) < 255:
            # Check if value is an already hashed and saved filepath
            path = Path(v)
            if path.exists() and v == self.bind.format(
                filename=path.stem, ext=path.suffix
            ):
                return v

        content, ext = self._base_parse_file(v)

        m = hashlib.sha256()
        m.update(content)
        sha256sum = m.hexdigest()
        file = Path(self.bind.format(filename=sha256sum, ext=ext))
        file.write_bytes(content)

        return str(file)


@dataclass
class ListConstraints:
    mode: Mode = "normal"
    has_default: bool = False
    none_value: t.Any = ""

    def __get_pydantic_core_schema__(
        self, source_type: t.Any, handler: "GetCoreSchemaHandler"
    ) -> "CoreSchema":
        schema = handler(source_type)
        type_schema = find_type_schema(schema, "list")

        if not type_schema:
            return schema

        schema = cs.no_info_before_validator_function(
            self.validate,
            schema,
            serialization=(
                cs.wrap_serializer_function_ser_schema(
                    self.serialize,
                    schema=type_schema["items_schema"],
                )
            ),
        )

        return schema

    def validate(self, v: t.Any) -> t.Any:
        v = coerce_comalist_to_list(v)

        if v is None:
            if self.has_default:
                raise PydanticUseDefault()
            return None

        return v
    def serialize(
        self, v: list[t.Any] | None, handler: "SerializerFunctionWrapHandler"
    ) -> str:
        if not v:
            return self.none_value

        return ",".join([str(handler(item)) for item in v])
