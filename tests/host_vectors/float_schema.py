"""Pydantic schema for ``ripple.app.HookzFloatVectors`` host-oracle JSON.

Source suite (xahaud worktree ``hookz-test-vectors``):
  ``src/test/app/HookzFloatVectors_test.cpp``

Host APIs under test (see emitter ``host_cites`` and file header):
  xahaud:src/xrpld/app/hook/HookAPI.h:39-42,184-289,291-292
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:986-1005 (float_set),
  1008-1021/2509-2537 (multiply), 1023-1048/2540-2559 (mulratio),
  1060-1099 (compare), 1105-1145 (sum),
  1356-1364 (invert), 1367-1369/2562-2636 (divide)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3375-3392 (invalid-float gate)

Wide integers are never bare JSON numbers. Every leaf is::

    {"type": "u64"|"i64"|"i32"|"error", "val": "<decimal string>"}

so nothing is rounded through IEEE double (Json::UInt is 32-bit on the host
emitter; XFL bit patterns need the full 64 bits).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

_BEGIN = "---HOOKZ_FLOAT_VECTORS_BEGIN---"
_END = "---HOOKZ_FLOAT_VECTORS_END---"
_DECIMAL = re.compile(r"^-?(0|[1-9][0-9]*)$")


def _require_decimal(v: str) -> str:
    if not _DECIMAL.match(v):
        raise ValueError(f"val must be a decimal integer string, got {v!r}")
    return v


class TypedU64(BaseModel):
    """Unsigned 64-bit integer as a decimal string."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["u64"]
    val: str

    @field_validator("val")
    @classmethod
    def _decimal_range(cls, v: str) -> str:
        v = _require_decimal(v)
        n = int(v)
        if n < 0 or n > 0xFFFF_FFFF_FFFF_FFFF:
            raise ValueError(f"u64 out of range: {v}")
        return v

    def as_int(self) -> int:
        return int(self.val)


class TypedI64(BaseModel):
    """Signed 64-bit integer as a decimal string."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["i64"]
    val: str

    @field_validator("val")
    @classmethod
    def _decimal_range(cls, v: str) -> str:
        v = _require_decimal(v)
        n = int(v)
        if n < -(1 << 63) or n > (1 << 63) - 1:
            raise ValueError(f"i64 out of range: {v}")
        return v

    def as_int(self) -> int:
        return int(self.val)


class TypedI32(BaseModel):
    """Signed 32-bit integer as a decimal string."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["i32"]
    val: str

    @field_validator("val")
    @classmethod
    def _decimal_range(cls, v: str) -> str:
        v = _require_decimal(v)
        n = int(v)
        if n < -(1 << 31) or n > (1 << 31) - 1:
            raise ValueError(f"i32 out of range: {v}")
        return v

    def as_int(self) -> int:
        return int(self.val)


class TypedError(BaseModel):
    """HookReturnCode (negative host status) as a decimal string."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["error"]
    val: str

    @field_validator("val")
    @classmethod
    def _decimal(cls, v: str) -> str:
        return _require_decimal(v)

    def as_int(self) -> int:
        return int(self.val)


TypedValue = Annotated[
    TypedU64 | TypedI64 | TypedI32 | TypedError,
    Field(discriminator="type"),
]


class ExpectedU64(BaseModel):
    """Host ``Expected<uint64_t, HookReturnCode>``."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    value: TypedU64 | None = None
    error: TypedError | None = None

    @model_validator(mode="after")
    def _ok_xor_payload(self) -> ExpectedU64:
        if self.ok:
            if self.value is None:
                raise ValueError("ok=true requires value")
            if self.error is not None:
                raise ValueError("ok=true must not set error")
        else:
            if self.error is None:
                raise ValueError("ok=false requires error")
            if self.value is not None:
                raise ValueError("ok=false must not set value")
        return self

    def as_int_or_error(self) -> int:
        """Return the XFL bit pattern, or the negative host error code."""
        if self.ok:
            assert self.value is not None
            return self.value.as_int()
        assert self.error is not None
        return self.error.as_int()


class FloatSetCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exp: TypedI32
    man: TypedI64
    result: ExpectedU64


class FloatSumCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    a: TypedU64
    b: TypedU64
    result: ExpectedU64


class FloatCompareCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    a: TypedU64
    b: TypedU64
    mode: TypedI32
    result: ExpectedU64


class FloatMultiplyCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    a: TypedU64
    b: TypedU64
    result: ExpectedU64


class FloatMulRatioCase(BaseModel):
    """Direct host vector for ``HookAPI::float_mulratio``.

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1023-1048
    xahaud:src/libxrpl/protocol/IOUAmount.cpp:183-315
    """

    model_config = ConfigDict(extra="forbid")

    a: TypedU64
    round_up: TypedI32
    numerator: TypedU64
    denominator: TypedU64
    result: ExpectedU64
    note: str


class FloatDivideCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    a: TypedU64
    b: TypedU64
    result: ExpectedU64
    note: str | None = None


class FloatInvertCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    a: TypedU64
    result: ExpectedU64


class HookzFloatVectors(BaseModel):
    """Root document emitted by ``ripple.app.HookzFloatVectors``.

    Host API anchors (when present) are ``xahaud:path:line`` strings from
    ``HookzFloatVectors_test.cpp`` / the same worktree sources.
    """

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    suite: str
    purpose: str
    value_encoding: str
    # Optional map of API name → xahaud:path:line cite string(s)
    host_cites: dict[str, str] | None = None
    float_one: TypedU64
    float_set: list[FloatSetCase]
    float_sum: list[FloatSumCase]
    float_compare: list[FloatCompareCase]
    float_multiply: list[FloatMultiplyCase]
    float_mulratio: list[FloatMulRatioCase]
    float_divide: list[FloatDivideCase]
    float_invert: list[FloatInvertCase]

    @field_validator("suite")
    @classmethod
    def _suite_name(cls, v: str) -> str:
        if v != "ripple.app.HookzFloatVectors":
            raise ValueError(f"unexpected suite {v!r}")
        return v


def extract_marker_json(text: str) -> str:
    """Slice JSON between BEGIN/END markers from an x-run-tests log."""
    start = text.find(_BEGIN)
    end = text.find(_END)
    if start < 0 or end < 0 or end <= start:
        raise ValueError(
            f"missing {_BEGIN!r} / {_END!r} markers in host vector dump"
        )
    body = text[start + len(_BEGIN) : end].strip()
    if not body:
        raise ValueError("empty vector payload between markers")
    return body


def load_hookz_float_vectors(data: str | bytes | dict) -> HookzFloatVectors:
    """Parse a JSON document, log slice, or already-decoded dict."""
    if isinstance(data, dict):
        return HookzFloatVectors.model_validate(data)
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    text = data
    if _BEGIN in text:
        text = extract_marker_json(text)
    return HookzFloatVectors.model_validate_json(text)


def load_hookz_float_vectors_path(path: str | Path) -> HookzFloatVectors:
    return load_hookz_float_vectors(Path(path).read_text(encoding="utf-8"))


def dump_hookz_float_vectors(doc: HookzFloatVectors, *, indent: int = 2) -> str:
    """Serialize back to JSON (typed vals preserved as strings)."""
    return doc.model_dump_json(indent=indent)


# re-export for callers that want the raw json module
loads = json.loads
