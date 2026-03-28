"""Tests for HookRuntime host function implementations.

These test the Python implementations of hook API functions directly,
without needing to compile and run WASM. Catches precision/encoding
bugs before they surface as mysterious hook failures.
"""

import struct

import pytest

from hookz import hookapi
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


# ---------------------------------------------------------------------------
# float_sto / float_sto_set roundtrip tests
# ---------------------------------------------------------------------------

# The known XFL for 1234567.0 from xahaud tests
XFL_1234567 = 6198187654261802496

ISSUER_20 = b"\x01" * 20
USD_CURRENCY_3 = b"USD"
USD_CURRENCY_20 = b"\x00" * 12 + b"USD" + b"\x00" * 5
CUSTOM_CURRENCY_20 = bytes(range(20))


class TestFloatStoXahaudVectors:
    """float_sto tests matching xahaud SetHook_test.cpp vectors."""

    def test_iou_sfamount_3char_currency(self, rt):
        """IOU with 3-char currency + sfAmount → 49 bytes (1 header + 8 amt + 20 cur + 20 iss)."""
        rt._write_memory(100, USD_CURRENCY_3)
        rt._write_memory(200, ISSUER_20)
        result = float_sto(rt, 0, 50, 100, 3, 200, 20, XFL_1234567, hookapi.sfAmount)
        assert result == 49

        # Header should be 0x61 (sfAmount: type=6, field=1)
        output = rt._read_memory(0, 49)
        assert output[0] == 0x61

    def test_iou_sfamount_20byte_currency(self, rt):
        """IOU with full 20-byte currency."""
        rt._write_memory(100, CUSTOM_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        result = float_sto(rt, 0, 50, 100, 20, 200, 20, XFL_1234567, hookapi.sfAmount)
        assert result == 49

        output = rt._read_memory(0, 49)
        # Currency bytes at offset 9 (1 header + 8 amount)
        assert output[9:29] == CUSTOM_CURRENCY_20
        # Issuer bytes at offset 29
        assert output[29:49] == ISSUER_20

    def test_iou_sfdeliveredamount_2byte_header(self, rt):
        """sfDeliveredAmount (field=18, type=6) → 2-byte header → 50 bytes total."""
        # sfDeliveredAmount = (6 << 16) | 18 = 0x60012
        rt._write_memory(100, CUSTOM_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        result = float_sto(rt, 0, 50, 100, 20, 200, 20, XFL_1234567, 0x60012)
        assert result == 50

        output = rt._read_memory(0, 50)
        # 2-byte header: type=6 field=18 → [0x60, 0x12]
        assert output[0] == 0x60
        assert output[1] == 0x12

    def test_short_mode_no_header_no_tail(self, rt):
        """field_code=0xFFFFFFFF → just 8 amount bytes, no header or currency/issuer."""
        result = float_sto(rt, 0, 50, 0, 0, 0, 0, XFL_1234567, 0xFFFFFFFF)
        assert result == 8

    def test_xrp_mode_no_header(self, rt):
        """field_code=0 → XRP amount, 8 bytes, no header."""
        result = float_sto(rt, 0, 50, 0, 0, 0, 0, XFL_1234567, 0)
        assert result == 8

    def test_iou_roundtrip(self, rt):
        """float_sto then float_sto_set should recover the original XFL."""
        rt._write_memory(100, CUSTOM_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        float_sto(rt, 0, 50, 100, 20, 200, 20, XFL_1234567, hookapi.sfAmount)
        recovered = float_sto_set(rt, 0, 49)
        assert recovered == XFL_1234567

    def test_iou_zero_roundtrip(self, rt):
        """Zero XFL → serialize → deserialize → zero."""
        rt._write_memory(100, CUSTOM_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        float_sto(rt, 0, 50, 100, 20, 200, 20, 0, hookapi.sfAmount)
        recovered = float_sto_set(rt, 0, 49)
        assert recovered == 0

    def test_short_mode_roundtrip(self, rt):
        """Serialize with 0xFFFFFFFF, prepend sfAmount header, deserialize."""
        float_sto(rt, 2, 8, 0, 0, 0, 0, XFL_1234567, 0xFFFFFFFF)
        # Write sfAmount header before the 8 amount bytes
        # The xahaud test writes buf[0]=0x61 before calling float_sto_set on the full buffer
        # But our test: just prepend the header
        rt._write_memory(0, b"\x60\x12")  # sfDeliveredAmount 2-byte header
        recovered = float_sto_set(rt, 0, 10)  # 2 header + 8 amount
        assert recovered == XFL_1234567


class TestFloatStoComposed:
    """float_sto/float_sto_set beyond xahaud vectors."""

    def test_xrp_known_drops(self, rt):
        """Serialize 1 XAH (1e6 drops) as XRP amount and verify bytes."""
        xfl_1m = float_to_xfl(1_000_000.0)
        float_sto(rt, 0, 50, 0, 0, 0, 0, xfl_1m, 0)
        output = rt._read_memory(0, 8)
        # Positive XRP: bit 62 set, no bit 63
        assert (output[0] & 0x80) == 0  # is_xrp
        assert (output[0] & 0x40) != 0  # positive

    def test_xrp_100_drops(self, rt):
        """XFL 100.0 serialized as XRP → 100 drops."""
        xfl_100 = float_to_xfl(100.0)
        float_sto(rt, 0, 50, 0, 0, 0, 0, xfl_100, 0)
        output = rt._read_memory(0, 8)
        # Parse back the drops
        val = int.from_bytes(output, "big")
        drops = val & 0x3FFFFFFFFFFFFFFF  # mask off top 2 bits
        # XFL 100.0 → mantissa=1e17, exponent=-15 → drops = 1e17 / 1e15 = 100
        assert drops == 100

    def test_xrp_roundtrip_various_amounts(self, rt):
        """Roundtrip XRP amounts through float_sto + float_sto_set."""
        for drops in [1, 100, 1_000_000, 50_000_000, 99_999_999_999]:
            xfl = float_to_xfl(float(drops))
            float_sto(rt, 0, 50, 0, 0, 0, 0, xfl, 0)
            # Add a header byte so float_sto_set can parse
            amt_bytes = rt._read_memory(0, 8)
            rt._write_memory(0, b"\x61" + amt_bytes)
            recovered = float_sto_set(rt, 0, 9)
            recovered_float = xfl_to_float(recovered)
            assert recovered_float == pytest.approx(float(drops), rel=1e-10), \
                f"Failed for {drops} drops"

    def test_iou_negative_amount(self, rt):
        """Negative IOU amount roundtrip."""
        xfl_neg = float_to_xfl(-42.5)
        rt._write_memory(100, USD_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        float_sto(rt, 0, 50, 100, 20, 200, 20, xfl_neg, hookapi.sfAmount)
        recovered = float_sto_set(rt, 0, 49)
        assert xfl_to_float(recovered) == pytest.approx(-42.5, rel=1e-10)

    def test_iou_very_small_amount(self, rt):
        """Very small IOU amount."""
        xfl = float_to_xfl(0.000001)
        rt._write_memory(100, USD_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        float_sto(rt, 0, 50, 100, 20, 200, 20, xfl, hookapi.sfAmount)
        recovered = float_sto_set(rt, 0, 49)
        assert xfl_to_float(recovered) == pytest.approx(0.000001, rel=1e-6)

    def test_iou_large_amount(self, rt):
        """Large IOU amount."""
        xfl = float_to_xfl(9.999999e14)
        rt._write_memory(100, USD_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        float_sto(rt, 0, 50, 100, 20, 200, 20, xfl, hookapi.sfAmount)
        recovered = float_sto_set(rt, 0, 49)
        assert xfl_to_float(recovered) == pytest.approx(9.999999e14, rel=1e-6)

    def test_zero_currency_and_issuer_means_xrp(self, rt):
        """Null currency+issuer with non-zero field code → XRP mode."""
        xfl = float_to_xfl(1000.0)
        result = float_sto(rt, 0, 50, 0, 0, 0, 0, xfl, hookapi.sfAmount)
        # sfAmount header (1 byte) + 8 amount bytes = 9, but with no currency/issuer
        # Actually with field_code != 0 and no currency/issuer → it's "not has_iou"
        # but is_xrp = (field_code == 0), so is_xrp is false here
        # The code path: not is_xrp and not is_short and not has_iou → XRP-style encoding
        assert result == 9  # 1-byte header + 8 amount bytes

    def test_all_zero_currency_issuer_means_xrp(self, rt):
        """Currency=0x00*20 and issuer=0x00*20 → treated as XRP."""
        xfl = float_to_xfl(1000.0)
        rt._write_memory(100, b"\x00" * 20)
        rt._write_memory(200, b"\x00" * 20)
        result = float_sto(rt, 0, 50, 100, 20, 200, 20, xfl, hookapi.sfAmount)
        # All-zero currency+issuer → has_iou=False → XRP encoding → 9 bytes
        assert result == 9


class TestFloatStoSetEdgeCases:
    """float_sto_set edge cases."""

    def test_8_byte_raw_xrp(self, rt):
        """Raw 8-byte XRP amount without header."""
        import struct
        drops = 50_000_000
        buf = struct.pack(">Q", (0x40 << 56) | drops)
        rt._write_memory(0, buf)
        xfl = float_sto_set(rt, 0, 8)
        assert xfl_to_float(xfl) == pytest.approx(50_000_000.0, rel=1e-10)

    def test_negative_xrp(self, rt):
        """Negative XRP amount (bit 62 clear)."""
        import struct
        drops = 100
        buf = struct.pack(">Q", drops)  # no bit 62 set → negative
        rt._write_memory(0, buf)
        xfl = float_sto_set(rt, 0, 8)
        assert xfl_to_float(xfl) == pytest.approx(-100.0, rel=1e-10)

    def test_iou_with_1byte_header(self, rt):
        """IOU amount with 1-byte field header (type<16, field<16)."""
        # sfAmount header 0x61, then 8-byte IOU amount, then 20+20 currency+issuer
        xfl = float_to_xfl(42.0)
        rt._write_memory(100, USD_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        float_sto(rt, 0, 50, 100, 20, 200, 20, xfl, hookapi.sfAmount)
        recovered = float_sto_set(rt, 0, 49)
        assert xfl_to_float(recovered) == pytest.approx(42.0, rel=1e-10)

    def test_iou_with_2byte_header(self, rt):
        """IOU amount with 2-byte field header (field>=16)."""
        xfl = float_to_xfl(42.0)
        rt._write_memory(100, USD_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        float_sto(rt, 0, 50, 100, 20, 200, 20, xfl, 0x60012)  # sfDeliveredAmount
        recovered = float_sto_set(rt, 0, 50)
        assert xfl_to_float(recovered) == pytest.approx(42.0, rel=1e-10)

    def test_too_short(self, rt):
        """Less than 8 bytes → INVALID_ARGUMENT."""
        rt._write_memory(0, b"\x00" * 5)
        assert float_sto_set(rt, 0, 5) == hookapi.INVALID_ARGUMENT

    def test_iou_zero_mantissa(self, rt):
        """IOU with zero mantissa → 0."""
        # Build IOU header: bit 63 set (IOU), zero mantissa
        buf = b"\x80" + b"\x00" * 7
        rt._write_memory(0, buf)
        assert float_sto_set(rt, 0, 8) == 0

    def test_3byte_header_skip(self, rt):
        """3-byte header (type>=16, field>=16) should be skipped correctly."""
        # 3-byte header: [0x00, type, field] where both >= 16
        header = bytes([0x00, 0x10, 0x10])
        # IOU amount bytes
        xfl = float_to_xfl(100.0)
        rt._write_memory(200, USD_CURRENCY_20)
        rt._write_memory(300, ISSUER_20)
        float_sto(rt, 0, 50, 200, 20, 300, 20, xfl, hookapi.sfAmount)
        # Get the raw 8 IOU amount bytes (skip 1-byte header)
        amt_bytes = rt._read_memory(1, 8)

        # Now prepend a 3-byte header + amount bytes (total 11 bytes, > 8 triggers header skip)
        rt._write_memory(500, header + amt_bytes + USD_CURRENCY_20 + ISSUER_20)
        recovered = float_sto_set(rt, 500, 3 + 8 + 40)
        assert xfl_to_float(recovered) == pytest.approx(100.0, rel=1e-10)


class TestFloatStoRoundtrip:
    """Stress-test float_sto ↔ float_sto_set roundtrips."""

    @pytest.mark.parametrize("value", [
        1.0, -1.0, 0.5, -0.5, 100.0, 1234567.0,
        0.000001, 9.999999e14, -42.5, 1e-10, 1e10,
    ])
    def test_iou_roundtrip(self, rt, value):
        """Serialize as IOU, deserialize, compare."""
        xfl = float_to_xfl(value)
        rt._write_memory(100, USD_CURRENCY_20)
        rt._write_memory(200, ISSUER_20)
        nbytes = float_sto(rt, 0, 50, 100, 20, 200, 20, xfl, hookapi.sfAmount)
        recovered = float_sto_set(rt, 0, nbytes)
        assert xfl_to_float(recovered) == pytest.approx(value, rel=1e-6)

    @pytest.mark.parametrize("drops", [
        1, 10, 100, 1000, 10_000, 100_000, 1_000_000,
        50_000_000, 1_000_000_000, 99_999_999_999,
    ])
    def test_xrp_roundtrip(self, rt, drops):
        """Serialize as XRP, add header, deserialize, compare drops."""
        xfl = float_to_xfl(float(drops))
        float_sto(rt, 1, 8, 0, 0, 0, 0, xfl, 0)  # XRP mode, write at offset 1
        rt._write_memory(0, b"\x61")  # prepend sfAmount header
        recovered = float_sto_set(rt, 0, 9)
        assert xfl_to_float(recovered) == pytest.approx(float(drops), rel=1e-10)
