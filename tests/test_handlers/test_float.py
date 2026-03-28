"""Tests for HookRuntime host function implementations.

These test the Python implementations of hook API functions directly,
without needing to compile and run WASM. Catches precision/encoding
bugs before they surface as mysterious hook failures.
"""

import struct

import pytest

from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl, xfl_to_float
from hookz.handlers.float import (
    float_sto_set, float_sto, float_multiply, float_invert,
    float_sign, float_mantissa, float_log, float_root, float_mulratio,
)


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    # Give it a fake store/memory for host functions that need them
    import wasmtime
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r


class TestFloatStoSet:
    """float_sto_set: deserialize XRPL amount bytes → XFL."""

    def _call(self, rt, data: bytes) -> int:
        """Write data to WASM memory and call float_sto_set."""
        rt._write_memory(0, data)
        return float_sto_set(rt, 0, len(data))

    def test_xah_100_drops(self, rt):
        """100 drops of XAH (no header, 8 raw bytes)."""
        drops = 100
        buf = struct.pack(">Q", (0x40 << 56) | drops)
        xfl = self._call(rt, buf)
        assert xfl > 0
        assert xfl_to_float(xfl) == pytest.approx(100.0, rel=1e-10)

    def test_xah_1m_drops(self, rt):
        """1,000,000 drops = 1 XAH (no header)."""
        drops = 1_000_000
        buf = struct.pack(">Q", (0x40 << 56) | drops)
        xfl = self._call(rt, buf)
        assert xfl_to_float(xfl) == pytest.approx(1_000_000.0, rel=1e-10)

    def test_xah_100m_drops(self, rt):
        """100,000,000 drops = 100 XAH (no header)."""
        drops = 100_000_000
        buf = struct.pack(">Q", (0x40 << 56) | drops)
        xfl = self._call(rt, buf)
        assert xfl_to_float(xfl) == pytest.approx(100_000_000.0, rel=1e-10)

    def test_xah_with_sfamount_header(self, rt):
        """9-byte XAH amount with sfAmount header (0x61)."""
        drops = 50_000_000  # 50 XAH
        buf = bytearray(9)
        buf[0] = 0x61  # sfAmount: type=6, field=1
        struct.pack_into(">Q", buf, 1, (0x40 << 56) | drops)
        xfl = self._call(rt, bytes(buf))
        assert xfl_to_float(xfl) == pytest.approx(50_000_000.0, rel=1e-10)

    def test_xah_zero_drops(self, rt):
        """Zero drops → XFL 0."""
        buf = struct.pack(">Q", 0x40 << 56)  # positive zero
        xfl = self._call(rt, buf)
        assert xfl == 0

    def test_known_xah_bytes(self, rt):
        """Verify against known encoding: 50 XAH = 50M drops."""
        # 50,000,000 drops encoded as big-endian with positive bit
        drops = 50_000_000
        buf = struct.pack(">Q", (0x40 << 56) | drops)
        xfl = self._call(rt, buf)
        val = xfl_to_float(xfl)
        # float_sto_set returns XFL for the raw drops integer
        assert val == pytest.approx(50_000_000.0, rel=1e-10)
        # Hook then divides by 1M to get XAH: 50M / 1M = 50
        xfl_1m = float_to_xfl(1_000_000.0)
        xah = xfl_to_float(xfl) / xfl_to_float(xfl_1m)
        assert xah == pytest.approx(50.0, rel=1e-10)

    def test_too_short_returns_error(self, rt):
        """Buffer shorter than 8 bytes → error."""
        xfl = self._call(rt, b"\x00" * 5)
        assert xfl < 0  # error code


class TestFloatMultiply:
    """float_multiply: XFL * XFL → XFL."""

    def test_basic(self, rt):
        result = float_multiply(rt, float_to_xfl(3.0), float_to_xfl(4.0))
        assert xfl_to_float(result) == pytest.approx(12.0)

    def test_zero_a(self, rt):
        assert float_multiply(rt, 0, float_to_xfl(5.0)) == 0

    def test_zero_b(self, rt):
        assert float_multiply(rt, float_to_xfl(5.0), 0) == 0

    def test_both_zero(self, rt):
        assert float_multiply(rt, 0, 0) == 0

    def test_negative(self, rt):
        result = float_multiply(rt, float_to_xfl(-3.0), float_to_xfl(4.0))
        assert xfl_to_float(result) == pytest.approx(-12.0)

    def test_both_negative(self, rt):
        result = float_multiply(rt, float_to_xfl(-3.0), float_to_xfl(-4.0))
        assert xfl_to_float(result) == pytest.approx(12.0)

    def test_fractional(self, rt):
        result = float_multiply(rt, float_to_xfl(0.5), float_to_xfl(0.25))
        assert xfl_to_float(result) == pytest.approx(0.125)

    def test_large(self, rt):
        result = float_multiply(rt, float_to_xfl(1_000_000.0), float_to_xfl(1_000_000.0))
        assert xfl_to_float(result) == pytest.approx(1e12)


class TestFloatInvert:
    """float_invert: 1/x for XFL values."""

    def test_basic(self, rt):
        result = float_invert(rt, float_to_xfl(4.0))
        assert xfl_to_float(result) == pytest.approx(0.25)

    def test_one(self, rt):
        xfl_one = float_to_xfl(1.0)
        result = float_invert(rt, xfl_one)
        assert xfl_to_float(result) == pytest.approx(1.0)

    def test_zero_returns_division_by_zero(self, rt):
        from hookz import hookapi
        assert float_invert(rt, 0) == hookapi.DIVISION_BY_ZERO

    def test_negative(self, rt):
        result = float_invert(rt, float_to_xfl(-2.0))
        assert xfl_to_float(result) == pytest.approx(-0.5)

    def test_fractional(self, rt):
        result = float_invert(rt, float_to_xfl(0.5))
        assert xfl_to_float(result) == pytest.approx(2.0)

    def test_large(self, rt):
        result = float_invert(rt, float_to_xfl(1_000_000.0))
        assert xfl_to_float(result) == pytest.approx(1e-6)


class TestFloatSign:
    """float_sign: return 1 if negative, 0 if positive."""

    def test_positive(self, rt):
        assert float_sign(rt, float_to_xfl(42.0)) == 0

    def test_negative(self, rt):
        assert float_sign(rt, float_to_xfl(-42.0)) == 1

    def test_zero(self, rt):
        assert float_sign(rt, 0) == 0

    def test_small_negative(self, rt):
        assert float_sign(rt, float_to_xfl(-0.001)) == 1

    def test_large_positive(self, rt):
        assert float_sign(rt, float_to_xfl(1e12)) == 0


class TestFloatMantissa:
    """float_mantissa: extract mantissa from XFL."""

    def test_zero(self, rt):
        assert float_mantissa(rt, 0) == 0

    def test_one(self, rt):
        xfl = float_to_xfl(1.0)
        m = float_mantissa(rt, xfl)
        assert m == 1_000_000_000_000_000

    def test_negative(self, rt):
        # Mantissa is the same regardless of sign
        xfl_pos = float_to_xfl(42.0)
        xfl_neg = float_to_xfl(-42.0)
        assert float_mantissa(rt, xfl_pos) == float_mantissa(rt, xfl_neg)

    def test_fractional(self, rt):
        xfl = float_to_xfl(0.5)
        m = float_mantissa(rt, xfl)
        assert m == 5_000_000_000_000_000


class TestFloatLog:
    """float_log: log10-based log matching xahaud behavior."""

    def test_one(self, rt):
        # log10(mantissa_of_1) + exponent_of_1 = log10(1e15) + (-15) = 15 + (-15) = 0
        result = float_log(rt, float_to_xfl(1.0))
        assert xfl_to_float(result) == pytest.approx(0.0, abs=1e-10)

    def test_ten(self, rt):
        # log10(mantissa) + exp for 10.0 should give 1.0
        result = float_log(rt, float_to_xfl(10.0))
        assert xfl_to_float(result) == pytest.approx(1.0, rel=1e-10)

    def test_hundred(self, rt):
        result = float_log(rt, float_to_xfl(100.0))
        assert xfl_to_float(result) == pytest.approx(2.0, rel=1e-10)

    def test_zero_returns_error(self, rt):
        from hookz import hookapi
        assert float_log(rt, 0) == hookapi.INVALID_ARGUMENT

    def test_negative_returns_error(self, rt):
        from hookz import hookapi
        assert float_log(rt, float_to_xfl(-5.0)) == hookapi.COMPLEX_NOT_SUPPORTED


class TestFloatRoot:
    """float_root: square root as XFL."""

    def test_four(self, rt):
        result = float_root(rt, float_to_xfl(4.0))
        assert xfl_to_float(result) == pytest.approx(2.0)

    def test_one(self, rt):
        result = float_root(rt, float_to_xfl(1.0))
        assert xfl_to_float(result) == pytest.approx(1.0)

    def test_zero(self, rt):
        assert float_root(rt, 0) == 0

    def test_large(self, rt):
        result = float_root(rt, float_to_xfl(1_000_000.0))
        assert xfl_to_float(result) == pytest.approx(1000.0)

    def test_negative_returns_error(self, rt):
        from hookz import hookapi
        assert float_root(rt, float_to_xfl(-4.0)) == hookapi.COMPLEX_NOT_SUPPORTED

    def test_fractional(self, rt):
        result = float_root(rt, float_to_xfl(0.25))
        assert xfl_to_float(result) == pytest.approx(0.5)


class TestFloatMulratio:
    """float_mulratio: multiply XFL by numer/denom."""

    def test_basic(self, rt):
        # 10 * 3/2 = 15
        result = float_mulratio(rt, float_to_xfl(10.0), 0, 3, 2)
        assert xfl_to_float(result) == pytest.approx(15.0)

    def test_zero(self, rt):
        assert float_mulratio(rt, 0, 0, 3, 2) == 0

    def test_division_by_zero(self, rt):
        from hookz import hookapi
        assert float_mulratio(rt, float_to_xfl(10.0), 0, 3, 0) == hookapi.DIVISION_BY_ZERO

    def test_identity(self, rt):
        # 42 * 1/1 = 42
        result = float_mulratio(rt, float_to_xfl(42.0), 0, 1, 1)
        assert xfl_to_float(result) == pytest.approx(42.0)

    def test_halve(self, rt):
        result = float_mulratio(rt, float_to_xfl(100.0), 0, 1, 2)
        assert xfl_to_float(result) == pytest.approx(50.0)

    def test_negative_input(self, rt):
        result = float_mulratio(rt, float_to_xfl(-10.0), 0, 3, 2)
        assert xfl_to_float(result) == pytest.approx(-15.0)

    def test_large_ratio(self, rt):
        result = float_mulratio(rt, float_to_xfl(1.0), 0, 1_000_000, 1)
        assert xfl_to_float(result) == pytest.approx(1_000_000.0)
