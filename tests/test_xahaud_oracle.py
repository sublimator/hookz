"""Optional live differential checks against the Xahau C-ABI oracle."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from hookz.handlers.float import float_mulratio
from hookz.testing.xahaud_oracle import ORACLE_ENV, XahaudOracle
from hookz.wasm.xahaud_ref import XAHAUD_COMMIT
from host_vectors.float_schema import load_hookz_float_vectors_path

pytestmark = pytest.mark.xahaud_oracle

_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "host_vectors"
    / "hookz_float_vectors.json"
)
_SEED = 0x5841484155  # "XAHAU"


def _as_signed_u64(value: int) -> int:
    return value if value < (1 << 63) else value - (1 << 64)


@pytest.fixture(scope="module")
def oracle() -> XahaudOracle:
    loaded = XahaudOracle.from_env()
    if loaded is None:
        pytest.skip(f"set {ORACLE_ENV} to run live Xahau differential tests")
    assert loaded.git_commit == XAHAUD_COMMIT, (
        f"oracle was built from {loaded.git_commit}, hookz pins {XAHAUD_COMMIT}"
    )
    return loaded


def _assert_same(
    oracle: XahaudOracle,
    *,
    index: int | str,
    xfl: int,
    round_up: int,
    numerator: int,
    denominator: int,
) -> None:
    host = oracle.float_mulratio(xfl, round_up, numerator, denominator)
    hookz = float_mulratio(
        None,
        _as_signed_u64(xfl),
        round_up,
        numerator,
        denominator,
    )
    assert hookz == host, (
        f"float_mulratio divergence at case={index} seed={_SEED}: "
        f"xfl={xfl} round_up={round_up} numerator={numerator} "
        f"denominator={denominator} xahaud={host} hookz={hookz}; "
        "xahaud:src/libxrpl/protocol/IOUAmount.cpp:183-315"
    )


def test_live_oracle_matches_host_vectors(oracle: XahaudOracle):
    vectors = load_hookz_float_vectors_path(_FIXTURE)
    for case in vectors.float_mulratio:
        host = oracle.float_mulratio(
            case.a.as_int(),
            case.round_up.as_int(),
            case.numerator.as_int(),
            case.denominator.as_int(),
        )
        assert host == case.result.as_int_or_error(), (
            f"live oracle disagrees with frozen host vector {case.note}: "
            f"live={host} frozen={case.result.as_int_or_error()}"
        )
        _assert_same(
            oracle,
            index=case.note,
            xfl=case.a.as_int(),
            round_up=case.round_up.as_int(),
            numerator=case.numerator.as_int(),
            denominator=case.denominator.as_int(),
        )


def test_live_oracle_deterministic_sweep(oracle: XahaudOracle):
    """A cheap reproducible sweep beyond the frozen host cases."""
    rng = random.Random(_SEED)
    for index in range(1_000):
        exponent = rng.randint(-96, 80)
        mantissa = rng.randint(1_000_000_000_000_000, 9_999_999_999_999_999)
        # Construct a valid XFL directly so the oracle input does not depend
        # on the Python float_set implementation under test elsewhere.
        xfl = ((exponent + 97) << 54) | mantissa
        if not rng.getrandbits(1):
            xfl |= 1 << 62  # sign bit set means positive

        _assert_same(
            oracle,
            index=index,
            xfl=xfl,
            round_up=rng.getrandbits(1),
            numerator=rng.getrandbits(32),
            denominator=0 if index % 97 == 0 else rng.getrandbits(32),
        )
