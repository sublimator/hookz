"""Tests for slot_float and slot_size handlers."""

import struct

import pytest

from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl, xfl_to_float
from hookz.handlers.slot import slot_float, slot_size, slot_clear, slot_type, xpop_slot, meta_slot
from hookz import hookapi


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    import wasmtime
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r


class TestSlotFloat:
    """slot_float: read XFL from slot data."""

    def test_missing_slot_returns_doesnt_exist(self, rt):
        """Slot not populated -> DOESNT_EXIST."""
        assert slot_float(rt, 1) == hookapi.DOESNT_EXIST

    def test_empty_data_returns_internal_error(self, rt):
        """Empty bytes in slot -> INTERNAL_ERROR."""
        rt._slot_overrides["slot_data:1"] = b""
        assert slot_float(rt, 1) == hookapi.INTERNAL_ERROR

    def test_zero_drops(self, rt):
        """Zero amount -> XFL 0."""
        buf = struct.pack(">Q", 0x40 << 56)  # positive zero
        rt._slot_overrides["slot_data:1"] = buf
        assert slot_float(rt, 1) == 0

    def test_100_drops(self, rt):
        """100 drops -> XFL for 100."""
        drops = 100
        buf = struct.pack(">Q", (0x40 << 56) | drops)
        rt._slot_overrides["slot_data:1"] = buf
        xfl = slot_float(rt, 1)
        assert xfl > 0
        assert xfl_to_float(xfl) == pytest.approx(100.0, rel=1e-10)

    def test_1m_drops(self, rt):
        """1,000,000 drops."""
        drops = 1_000_000
        buf = struct.pack(">Q", (0x40 << 56) | drops)
        rt._slot_overrides["slot_data:2"] = buf
        xfl = slot_float(rt, 2)
        assert xfl_to_float(xfl) == pytest.approx(1_000_000.0, rel=1e-10)

    def test_50m_drops(self, rt):
        """50,000,000 drops = 50 XAH worth of drops."""
        drops = 50_000_000
        buf = struct.pack(">Q", (0x40 << 56) | drops)
        rt._slot_overrides["slot_data:0"] = buf
        xfl = slot_float(rt, 0)
        assert xfl_to_float(xfl) == pytest.approx(50_000_000.0, rel=1e-10)

    def test_different_slot_numbers(self, rt):
        """Each slot number is independent."""
        rt._slot_overrides["slot_data:3"] = struct.pack(">Q", (0x40 << 56) | 500)
        rt._slot_overrides["slot_data:7"] = struct.pack(">Q", (0x40 << 56) | 999)
        assert xfl_to_float(slot_float(rt, 3)) == pytest.approx(500.0, rel=1e-10)
        assert xfl_to_float(slot_float(rt, 7)) == pytest.approx(999.0, rel=1e-10)


class TestSlotSize:
    """slot_size: return size of slot data."""

    def test_missing_slot_returns_doesnt_exist(self, rt):
        """Slot not populated -> DOESNT_EXIST."""
        assert slot_size(rt, 1) == hookapi.DOESNT_EXIST

    def test_empty_data_returns_internal_error(self, rt):
        """Empty bytes in slot -> INTERNAL_ERROR."""
        rt._slot_overrides["slot_data:1"] = b""
        assert slot_size(rt, 1) == hookapi.INTERNAL_ERROR

    def test_8_byte_amount(self, rt):
        """8-byte XAH amount."""
        buf = struct.pack(">Q", (0x40 << 56) | 100)
        rt._slot_overrides["slot_data:1"] = buf
        assert slot_size(rt, 1) == 8

    def test_48_byte_iou(self, rt):
        """48-byte IOU amount."""
        data = b"\x00" * 48
        rt._slot_overrides["slot_data:2"] = data
        assert slot_size(rt, 2) == 48

    def test_arbitrary_length(self, rt):
        """Arbitrary serialized object."""
        data = b"\xab" * 123
        rt._slot_overrides["slot_data:5"] = data
        assert slot_size(rt, 5) == 123

    def test_different_slots_different_sizes(self, rt):
        """Each slot tracks its own data independently."""
        rt._slot_overrides["slot_data:0"] = b"\x00" * 8
        rt._slot_overrides["slot_data:1"] = b"\x00" * 32
        assert slot_size(rt, 0) == 8
        assert slot_size(rt, 1) == 32


class TestSlotClear:
    """slot_clear: remove a slot."""

    def test_clear_existing_slot(self, rt):
        """Clearing a populated slot returns 1."""
        rt._slot_overrides["slot_data:1"] = b"\xab" * 8
        assert slot_clear(rt, 1) == 1

    def test_clear_removes_data(self, rt):
        """After clearing, the slot data key should be gone."""
        rt._slot_overrides["slot_data:3"] = b"\x00" * 8
        slot_clear(rt, 3)
        assert "slot_data:3" not in rt._slot_overrides

    def test_clear_nonexistent_returns_doesnt_exist(self, rt):
        """Clearing a slot that was never set -> DOESNT_EXIST."""
        assert slot_clear(rt, 99) == hookapi.DOESNT_EXIST

    def test_clear_removes_related_keys(self, rt):
        """All keys ending with the slot number should be removed."""
        rt._slot_overrides["slot_data:5"] = b"\x00" * 8
        rt._slot_overrides["slot_count:5"] = 3
        slot_clear(rt, 5)
        assert "slot_data:5" not in rt._slot_overrides
        assert "slot_count:5" not in rt._slot_overrides

    def test_clear_does_not_affect_other_slots(self, rt):
        """Clearing slot 1 should not touch slot 2."""
        rt._slot_overrides["slot_data:1"] = b"\xaa" * 8
        rt._slot_overrides["slot_data:2"] = b"\xbb" * 8
        slot_clear(rt, 1)
        assert "slot_data:2" in rt._slot_overrides


class TestSlotType:
    """slot_type: return serialized field type of a slot."""

    def test_nonexistent_slot_returns_doesnt_exist(self, rt):
        """Slot not populated -> DOESNT_EXIST."""
        assert slot_type(rt, 1, 0) == hookapi.DOESNT_EXIST

    def test_existing_slot_returns_int(self, rt):
        """Populated slot returns a non-negative integer (stub: 0)."""
        rt._slot_overrides["slot_data:1"] = b"\x00" * 8
        result = slot_type(rt, 1, 0)
        assert isinstance(result, int)
        assert result >= 0

    def test_with_flags(self, rt):
        """Flags parameter accepted without error."""
        rt._slot_overrides["slot_data:1"] = b"\x00" * 8
        result = slot_type(rt, 1, 1)
        assert isinstance(result, int)


class TestXpopSlot:
    """xpop_slot: load XPOP proof into slot (stub)."""

    def test_returns_doesnt_exist(self, rt):
        """Default stub always returns DOESNT_EXIST."""
        assert xpop_slot(rt, 0, 0) == hookapi.DOESNT_EXIST

    def test_with_nonzero_args(self, rt):
        """Still returns DOESNT_EXIST regardless of arguments."""
        assert xpop_slot(rt, 1, 2) == hookapi.DOESNT_EXIST


class TestMetaSlot:
    """meta_slot: load transaction metadata into a slot."""

    def test_returns_slot_no(self, rt):
        """Stub returns the slot number passed in."""
        assert meta_slot(rt, 1) == 1
        assert meta_slot(rt, 5) == 5
        assert meta_slot(rt, 0) == 0

    def test_different_slot_numbers(self, rt):
        """Each slot number is returned as-is."""
        for i in range(10):
            assert meta_slot(rt, i) == i
