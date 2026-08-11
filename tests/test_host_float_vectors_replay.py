"""Replay host-vector fixtures against hookz float handlers.

Fixture: tests/fixtures/host_vectors/hookz_float_vectors.json
  Prefer a LIVE dump from ripple.app.HookzFloatVectors (see .host.json).
  scripts/generate_float_vectors.py is a fallback emitter only — do not
  overwrite the host dump with self-oracle output in normal workflows.

Schema: tests/host_vectors/float_schema.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hookz.handlers.float import (
    float_compare,
    float_divide,
    float_invert,
    float_mulratio,
    float_multiply,
    float_one,
    float_set,
    float_sum,
)
from host_vectors.float_schema import (
    HookzFloatVectors,
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


def _as_signed_u64(u: int) -> int:
    """WASM/host pass XFLs as i64 bit patterns."""
    return u if u < (1 << 63) else u - (1 << 64)


@pytest.fixture(scope="module")
def vectors() -> HookzFloatVectors:
    # Do not silently fall back to MINIMAL — that hides a missing host dump.
    if not FIXTURE.exists():
        raise FileNotFoundError(
            f"host float vector fixture missing: {FIXTURE}\n"
            "Dump via: rippled -u ripple.app.HookzFloatVectors\n"
            "or copy hookz_float_vectors.host.json → hookz_float_vectors.json"
        )
    return load_hookz_float_vectors_path(FIXTURE)


def test_fixture_matches_host_sidecar_when_present():
    """If a .host.json sidecar exists, the primary fixture must be identical."""
    host = FIXTURE.with_name("hookz_float_vectors.host.json")
    if not host.exists():
        pytest.skip("no host sidecar")
    assert FIXTURE.read_text(encoding="utf-8") == host.read_text(encoding="utf-8")


def test_fixture_loads_and_names_suite(vectors: HookzFloatVectors):
    assert vectors.suite == "ripple.app.HookzFloatVectors"
    assert vectors.version == 1
    assert vectors.float_one.as_int() == float_one(None) & 0xFFFF_FFFF_FFFF_FFFF


def test_replay_float_set(vectors: HookzFloatVectors):
    for i, case in enumerate(vectors.float_set):
        got = float_set(None, case.exp.as_int(), case.man.as_int())
        exp = case.result.as_int_or_error()
        if case.result.ok:
            assert got == exp, f"float_set[{i}] exp={case.exp.as_int()} man={case.man.as_int()}"
        else:
            assert got == exp, f"float_set[{i}] expected error {exp}, got {got}"


def test_replay_float_sum(vectors: HookzFloatVectors):
    for i, case in enumerate(vectors.float_sum):
        a = _as_signed_u64(case.a.as_int())
        b = _as_signed_u64(case.b.as_int())
        got = float_sum(None, a, b)
        exp = case.result.as_int_or_error()
        if case.result.ok:
            assert (got & 0xFFFF_FFFF_FFFF_FFFF) == (exp & 0xFFFF_FFFF_FFFF_FFFF), (
                f"float_sum[{i}]"
            )
        else:
            assert got == exp, f"float_sum[{i}] error"


def test_replay_float_compare(vectors: HookzFloatVectors):
    for i, case in enumerate(vectors.float_compare):
        a = _as_signed_u64(case.a.as_int())
        b = _as_signed_u64(case.b.as_int())
        got = float_compare(None, a, b, case.mode.as_int())
        exp = case.result.as_int_or_error()
        assert got == exp, f"float_compare[{i}] mode={case.mode.as_int()}"


def test_replay_float_multiply(vectors: HookzFloatVectors):
    for i, case in enumerate(vectors.float_multiply):
        a = _as_signed_u64(case.a.as_int())
        b = _as_signed_u64(case.b.as_int())
        got = float_multiply(None, a, b)
        exp = case.result.as_int_or_error()
        if case.result.ok:
            assert (got & 0xFFFF_FFFF_FFFF_FFFF) == (exp & 0xFFFF_FFFF_FFFF_FFFF)
        else:
            assert got == exp, f"float_multiply[{i}]"


def test_replay_float_mulratio(vectors: HookzFloatVectors):
    """Replay the live decimal-ratio oracle, including mantissa carry cases.

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1023-1048
    xahaud:src/libxrpl/protocol/IOUAmount.cpp:183-315
    """
    for i, case in enumerate(vectors.float_mulratio):
        got = float_mulratio(
            None,
            _as_signed_u64(case.a.as_int()),
            case.round_up.as_int(),
            case.numerator.as_int(),
            case.denominator.as_int(),
        )
        exp = case.result.as_int_or_error()
        if case.result.ok:
            assert (got & 0xFFFF_FFFF_FFFF_FFFF) == (
                exp & 0xFFFF_FFFF_FFFF_FFFF
            ), f"float_mulratio[{i}] note={case.note}"
        else:
            assert got == exp, f"float_mulratio[{i}] note={case.note}"


def test_replay_float_divide(vectors: HookzFloatVectors):
    for i, case in enumerate(vectors.float_divide):
        a = _as_signed_u64(case.a.as_int())
        b = _as_signed_u64(case.b.as_int())
        got = float_divide(None, a, b)
        exp = case.result.as_int_or_error()
        if case.result.ok:
            assert (got & 0xFFFF_FFFF_FFFF_FFFF) == (exp & 0xFFFF_FFFF_FFFF_FFFF)
        else:
            assert got == exp, f"float_divide[{i}] note={case.note}"


def test_replay_float_invert(vectors: HookzFloatVectors):
    for i, case in enumerate(vectors.float_invert):
        a = _as_signed_u64(case.a.as_int())
        got = float_invert(None, a)
        exp = case.result.as_int_or_error()
        if case.result.ok:
            assert (got & 0xFFFF_FFFF_FFFF_FFFF) == (exp & 0xFFFF_FFFF_FFFF_FFFF)
        else:
            assert got == exp, f"float_invert[{i}]"
