"""Schema tests for host float-oracle JSON (typed {type,val} leaves)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from host_vectors.float_schema import (
    ExpectedU64,
    HookzFloatVectors,
    TypedError,
    TypedI32,
    TypedI64,
    TypedU64,
    dump_hookz_float_vectors,
    extract_marker_json,
    load_hookz_float_vectors,
    load_hookz_float_vectors_path,
)

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "host_vectors"
    / "hookz_float_vectors.json"
)
MINIMAL = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "host_vectors"
    / "hookz_float_vectors_minimal.json"
)


def test_host_fixture_validates():
    doc = load_hookz_float_vectors_path(FIXTURE)
    assert doc.version == 1
    assert doc.suite == "ripple.app.HookzFloatVectors"
    assert doc.float_one.as_int() == 6089866696204910592
    assert len(doc.float_set) >= 50  # full HookzFloatVectors dump
    assert len(doc.float_mulratio) >= 12
    assert {
        "rounding_carry_positive",
        "rounding_carry_negative",
        "invalid_float_precedes_division_by_zero",
    } <= {case.note for case in doc.float_mulratio}
    # -97,1 → INVALID_FLOAT (-10024)
    bad = next(c for c in doc.float_set if c.exp.as_int() == -97)
    assert not bad.result.ok
    assert bad.result.error is not None
    assert bad.result.as_int_or_error() == -10024
    # float_one construction via float_set(-15, 1e15)
    one_set = next(
        c
        for c in doc.float_set
        if c.exp.as_int() == -15 and c.man.as_int() == 10**15
    )
    assert one_set.result.ok
    assert one_set.result.as_int_or_error() == doc.float_one.as_int()


def test_minimal_fixture_still_validates():
    doc = load_hookz_float_vectors_path(MINIMAL)
    assert doc.suite == "ripple.app.HookzFloatVectors"
    assert len(doc.float_set) >= 3


def test_marker_extract_and_load():
    body = FIXTURE.read_text(encoding="utf-8")
    wrapped = (
        "noise\n---HOOKZ_FLOAT_VECTORS_BEGIN---\n"
        + body
        + "\n---HOOKZ_FLOAT_VECTORS_END---\nnoise"
    )
    doc = load_hookz_float_vectors(wrapped)
    assert doc.float_one.type == "u64"


def test_u64_preserves_full_width_bits():
    """JSON numbers lose bits above 2^53; typed val must not."""
    # 2^60 + 1 — not exactly representable as IEEE float
    n = (1 << 60) + 1
    t = TypedU64(type="u64", val=str(n))
    assert t.as_int() == n
    # round-trip through model dump/validate
    again = TypedU64.model_validate(t.model_dump())
    assert again.as_int() == n


def test_rejects_json_number_for_typed_val():
    with pytest.raises(ValidationError):
        TypedU64.model_validate({"type": "u64", "val": 123})


def test_rejects_non_decimal_val():
    with pytest.raises(ValidationError):
        TypedU64.model_validate({"type": "u64", "val": "0x10"})
    with pytest.raises(ValidationError):
        TypedI64.model_validate({"type": "i64", "val": "1.5"})


def test_expected_ok_xor_error():
    with pytest.raises(ValidationError):
        ExpectedU64.model_validate(
            {
                "ok": True,
                "error": {"type": "error", "val": "-1"},
            }
        )
    with pytest.raises(ValidationError):
        ExpectedU64.model_validate({"ok": False})
    with pytest.raises(ValidationError):
        ExpectedU64.model_validate(
            {
                "ok": True,
                "value": {"type": "u64", "val": "1"},
                "error": {"type": "error", "val": "-1"},
            }
        )


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        TypedI32.model_validate(
            {"type": "i32", "val": "1", "extra": True}
        )


def test_wrong_suite_rejected():
    raw = load_hookz_float_vectors_path(FIXTURE).model_dump()
    raw["suite"] = "ripple.app.Other"
    with pytest.raises(ValidationError):
        HookzFloatVectors.model_validate(raw)


def test_dump_round_trip_keeps_string_vals():
    doc = load_hookz_float_vectors_path(FIXTURE)
    text = dump_hookz_float_vectors(doc)
    # val fields must appear as JSON strings, not bare numbers
    assert '"val": "6089866696204910592"' in text
    assert '"val": 6089866696204910592' not in text
    again = load_hookz_float_vectors(text)
    assert again.float_one.as_int() == doc.float_one.as_int()


def test_extract_marker_requires_both_markers():
    with pytest.raises(ValueError, match="missing"):
        extract_marker_json("no markers here")


def test_typed_error_and_i32_ranges():
    assert TypedError(type="error", val="-10024").as_int() == -10024
    assert TypedI32(type="i32", val="80").as_int() == 80
    with pytest.raises(ValidationError):
        TypedI32(type="i32", val=str(2**31))
