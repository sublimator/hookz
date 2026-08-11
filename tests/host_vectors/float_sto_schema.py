"""Schema + fixtures for float_sto / float_sto_set host vectors.

Primary goldens: xahaud:src/test/app/SetHook_test.cpp:6242+ (test_float_sto).
Host body:       xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1146-1350
Wrapper:         xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3568-3663

Vectors that need a live host dump can be refreshed from
``ripple.app.HookzFloatStoVectors`` (xahaud worktree) once that suite lands;
until then the SetHook constants below are the oracle.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FloatStoCase(BaseModel):
    """One float_sto serialize case."""

    model_config = ConfigDict(extra="forbid")

    id: str
    xfl: int = Field(description="XFL bit pattern as signed/unsigned 64 int")
    field_code: int
    # None = no currency/issuer; 3-char string or 40-char hex for 20 bytes
    currency: str | None = None
    currency_len: Literal[0, 3, 20] = 0
    issuer_hex: str | None = None  # 40 hex chars when present
    expect_rc: int  # returned length or negative HookReturnCode
    # optional expected amount-bytes hex (8 bytes) for non-error successes
    expect_amount_hex: str | None = None
    host_cite: str = (
        "xahaud:src/test/app/SetHook_test.cpp:6242+ / "
        "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1146-1284"
    )


class FloatStoSetCase(BaseModel):
    """One float_sto_set deserialize case."""

    model_config = ConfigDict(extra="forbid")

    id: str
    data_hex: str
    expect_xfl: int
    host_cite: str = (
        "xahaud:src/test/app/SetHook_test.cpp:6242+ / "
        "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1287-1350"
    )


# Known XFL from SetHook_test float_sto (1234567.0)
XFL_1234567 = 6198187654261802496
XFL_NEG_SHORT = 1244912689067196128  # used in short-mode host vector


def set_hook_float_sto_cases() -> list[FloatStoCase]:
    """Hand-ported SetHook_test.cpp:6340+ success/error cases."""
    iss = "01" * 20
    cur20 = "00" * 12 + "555344" + "00" * 5  # "USD" at 12..14 — unused for len=3
    return [
        FloatStoCase(
            id="iou_sfamount_3char",
            xfl=XFL_1234567,
            field_code=0x60001,  # sfAmount: type=6 field=1
            currency="USD",
            currency_len=3,
            issuer_hex=iss,
            expect_rc=49,
        ),
        FloatStoCase(
            id="iou_zero",
            xfl=0,
            field_code=0x60001,
            currency="USD",
            currency_len=3,
            issuer_hex=iss,
            expect_rc=49,
        ),
        FloatStoCase(
            id="iou_sfdeliveredamount",
            xfl=XFL_1234567,
            field_code=0x60012,  # type=6 field=18
            currency="USD",
            currency_len=3,
            issuer_hex=iss,
            expect_rc=50,
        ),
        FloatStoCase(
            id="short_positive",
            xfl=XFL_1234567,
            field_code=0xFFFFFFFF,
            expect_rc=8,
        ),
        FloatStoCase(
            id="short_negative",
            xfl=XFL_NEG_SHORT,
            field_code=0xFFFFFFFF,
            expect_rc=8,
        ),
        FloatStoCase(
            id="short_zero",
            xfl=0,
            field_code=0xFFFFFFFF,
            expect_rc=8,
        ),
        FloatStoCase(
            id="xrp_mode",
            xfl=XFL_1234567,
            field_code=0,
            expect_rc=8,
        ),
        FloatStoCase(
            id="invalid_float",
            xfl=-1,
            field_code=0x60001,
            currency="USD",
            currency_len=3,
            issuer_hex=iss,
            expect_rc=-10024,  # INVALID_FLOAT; filled in test via hookapi
        ),
        FloatStoCase(
            id="issuer_without_currency",
            xfl=XFL_1234567,
            field_code=0x60001,
            currency=None,
            currency_len=0,
            issuer_hex=iss,
            expect_rc=-7,  # INVALID_ARGUMENT; filled in test via hookapi
        ),
    ]


def set_hook_float_sto_set_roundtrips() -> list[FloatStoSetCase]:
    """Round-trip cases: data produced by float_sto under host rules."""
    # Filled at test time from live float_sto output when paired with serialize.
    return []
