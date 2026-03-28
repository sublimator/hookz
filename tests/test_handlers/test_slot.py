"""Tests for slot_float and slot_size handlers."""

import struct

import pytest

from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl, xfl_to_float
from hookz.handlers.slot import (
    slot, slot_set, slot_float, slot_size, slot_clear, slot_type,
    slot_subfield, slot_count, slot_subarray, xpop_slot, meta_slot,
)
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


# ---------------------------------------------------------------------------
# slot (read from slot)
# ---------------------------------------------------------------------------

class TestSlot:
    """slot: read data from a slot into WASM memory."""

    def test_missing_slot(self, rt):
        assert slot(rt, 0, 32, 99) == hookapi.DOESNT_EXIST

    def test_basic_read(self, rt):
        data = b"\xDE\xAD\xBE\xEF" * 4
        rt._slot_overrides["slot_data:1"] = data
        result = slot(rt, 100, 32, 1)
        assert result == len(data)
        assert rt._read_memory(100, len(data)) == data

    def test_truncates_to_write_len(self, rt):
        data = b"\xAB" * 32
        rt._slot_overrides["slot_data:1"] = data
        result = slot(rt, 100, 8, 1)
        assert result == 8
        assert rt._read_memory(100, 8) == data[:8]

    def test_empty_slot_returns_zero(self, rt):
        """Explicitly empty slot returns 0 via data_as_int64."""
        rt._slot_overrides["slot_data:2"] = b""
        assert slot(rt, 0, 0, 2) == 0

    def test_return_as_int64(self, rt):
        """write_ptr=0, write_len=0 → returns data as big-endian int64."""
        rt._slot_overrides["slot_data:1"] = b"\x00\x00\x00\x00\x00\x00\x00\x64"  # 100
        assert slot(rt, 0, 0, 1) == 100

    def test_return_as_int64_short_data(self, rt):
        """Less than 8 bytes still works."""
        rt._slot_overrides["slot_data:1"] = b"\x01"  # 1
        assert slot(rt, 0, 0, 1) == 1

    def test_return_as_int64_nonzero_write_len_is_error(self, rt):
        """write_ptr=0 but write_len!=0 → INVALID_ARGUMENT."""
        rt._slot_overrides["slot_data:1"] = b"\x00" * 8
        assert slot(rt, 0, 32, 1) == hookapi.INVALID_ARGUMENT

    def test_return_as_int64_too_big(self, rt):
        """Bit 63 set → TOO_BIG."""
        rt._slot_overrides["slot_data:1"] = b"\x80" + b"\x00" * 7  # bit 63 set
        assert slot(rt, 0, 0, 1) == hookapi.TOO_BIG

    def test_write_at_offset(self, rt):
        data = b"\x01\x02\x03\x04"
        rt._slot_overrides["slot_data:0"] = data
        rt._write_memory(0, b"\xFF" * 100)
        slot(rt, 50, 4, 0)
        assert rt._read_memory(0, 50) == b"\xFF" * 50
        assert rt._read_memory(50, 4) == data


# ---------------------------------------------------------------------------
# slot_set (write to slot)
# ---------------------------------------------------------------------------

class TestSlotSet:
    """slot_set: write data from WASM memory into a slot."""

    def test_basic_set(self, rt):
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        rt._write_memory(0, data)
        result = slot_set(rt, 0, len(data), 5)
        assert result == 5
        assert rt._slot_overrides["slot_data:5"] == data

    def test_returns_slot_no(self, rt):
        rt._write_memory(0, b"\x00" * 8)
        assert slot_set(rt, 0, 8, 3) == 3
        assert slot_set(rt, 0, 8, 99) == 99

    def test_overwrite_existing(self, rt):
        rt._slot_overrides["slot_data:1"] = b"\xAA" * 8
        rt._write_memory(0, b"\xBB" * 8)
        slot_set(rt, 0, 8, 1)
        assert rt._slot_overrides["slot_data:1"] == b"\xBB" * 8

    def test_roundtrip_slot_set_then_slot(self, rt):
        """Write via slot_set, read back via slot."""
        data = b"\xDE\xAD\xBE\xEF"
        rt._write_memory(0, data)
        slot_set(rt, 0, len(data), 7)
        result = slot(rt, 100, 32, 7)
        assert result == len(data)
        assert rt._read_memory(100, len(data)) == data


# ---------------------------------------------------------------------------
# slot_subfield
# ---------------------------------------------------------------------------

class TestSlotSubfield:
    """slot_subfield: look up a subfield override."""

    def test_missing_returns_doesnt_exist(self, rt):
        assert slot_subfield(rt, 1, 0x60001, 2) == hookapi.DOESNT_EXIST

    def test_with_override(self, rt):
        rt._slot_overrides["slot_subfield:1:393217"] = 42  # 0x60001 = 393217
        assert slot_subfield(rt, 1, 393217, 2) == 42


# ---------------------------------------------------------------------------
# slot_count
# ---------------------------------------------------------------------------

class TestSlotCount:
    """slot_count: return count override or 0."""

    def test_missing_slot_returns_doesnt_exist(self, rt):
        """No data in slot → DOESNT_EXIST."""
        assert slot_count(rt, 1) == hookapi.DOESNT_EXIST

    def test_with_override(self, rt):
        rt._slot_overrides["slot_count:5"] = 3
        assert slot_count(rt, 5) == 3


# ---------------------------------------------------------------------------
# slot_subarray
# ---------------------------------------------------------------------------

class TestSlotSubarray:
    """slot_subarray: extract array element into new slot."""

    def test_missing_parent_returns_doesnt_exist(self, rt):
        assert slot_subarray(rt, 1, 0, 5) == hookapi.DOESNT_EXIST

    def test_override_still_works(self, rt):
        rt._slot_overrides["slot_subarray:2:0"] = 3
        assert slot_subarray(rt, 2, 0, 3) == 3


# ---------------------------------------------------------------------------
# Real parsing tests — slot_subfield + slot_count + slot_subarray on actual data
# ---------------------------------------------------------------------------

from hookz.xrpl.xrpl_patch import patch_xahau_definitions
patch_xahau_definitions()
from xrpl.core.binarycodec import encode


class TestSlotRealParsing:
    """Test the slot system with actual serialized XRPL data — no overrides."""

    PAYMENT = {
        "TransactionType": "Payment",
        "Account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
        "Destination": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
        "Amount": "1000000",
        "Fee": "12",
        "Sequence": 1,
        "Flags": 0,
    }

    PAYMENT_WITH_MEMOS = {
        **PAYMENT,
        "Memos": [
            {"Memo": {"MemoData": "AABB", "MemoType": "746578742F706C61696E"}},
            {"Memo": {"MemoData": "CCDD", "MemoType": "746578742F706C61696E"}},
        ],
    }

    def test_subfield_finds_account(self, rt):
        """Load a payment into slot 1, extract sfAccount into slot 2."""
        data = bytes.fromhex(encode(self.PAYMENT))
        rt._slot_overrides["slot_data:1"] = data

        result = slot_subfield(rt, 1, hookapi.sfAccount, 2)
        assert result == 2

        # Slot 2 should now have 20 bytes (the account ID)
        assert slot_size(rt, 2) == 20

    def test_subfield_finds_amount(self, rt):
        """Extract sfAmount — 8 bytes for native XAH."""
        data = bytes.fromhex(encode(self.PAYMENT))
        rt._slot_overrides["slot_data:1"] = data

        result = slot_subfield(rt, 1, hookapi.sfAmount, 2)
        assert result == 2
        assert slot_size(rt, 2) == 8

    def test_subfield_missing_field(self, rt):
        """sfOfferSequence not in payment → DOESNT_EXIST."""
        data = bytes.fromhex(encode(self.PAYMENT))
        rt._slot_overrides["slot_data:1"] = data

        result = slot_subfield(rt, 1, hookapi.sfOfferSequence, 2)
        assert result == hookapi.DOESNT_EXIST

    def test_subfield_no_parent(self, rt):
        """Slot 1 not populated → DOESNT_EXIST."""
        assert slot_subfield(rt, 1, hookapi.sfAccount, 2) == hookapi.DOESNT_EXIST

    def test_subfield_array_returns_full_field(self, rt):
        """sfMemos is an array — subfield returns the whole array including header."""
        data = bytes.fromhex(encode(self.PAYMENT_WITH_MEMOS))
        rt._slot_overrides["slot_data:1"] = data

        result = slot_subfield(rt, 1, hookapi.sfMemos, 2)
        assert result == 2

        # Array data should be in slot 2
        arr_data = rt._slot_overrides["slot_data:2"]
        assert len(arr_data) > 0

    def test_count_on_array(self, rt):
        """slot_count on a Memos array with 2 elements → 2."""
        data = bytes.fromhex(encode(self.PAYMENT_WITH_MEMOS))
        rt._slot_overrides["slot_data:1"] = data

        # Get the Memos array into slot 2
        slot_subfield(rt, 1, hookapi.sfMemos, 2)

        # Count should be 2
        assert slot_count(rt, 2) == 2

    def test_count_on_non_array(self, rt):
        """slot_count on an sfAccount (not an array) → NOT_AN_ARRAY or 0."""
        data = bytes.fromhex(encode(self.PAYMENT))
        rt._slot_overrides["slot_data:1"] = data

        # Extract Account into slot 2
        slot_subfield(rt, 1, hookapi.sfAccount, 2)

        # Account is 20 raw bytes, not a parseable array
        result = slot_count(rt, 2)
        # The parser will either fail or count 0 elements
        assert result <= 0

    def test_subarray_extracts_element(self, rt):
        """Extract first memo from Memos array."""
        data = bytes.fromhex(encode(self.PAYMENT_WITH_MEMOS))
        rt._slot_overrides["slot_data:1"] = data

        slot_subfield(rt, 1, hookapi.sfMemos, 2)
        result = slot_subarray(rt, 2, 0, 3)
        assert result == 3

        # Slot 3 should have some bytes (the first Memo object)
        assert slot_size(rt, 3) > 0

    def test_subarray_second_element(self, rt):
        """Extract second memo."""
        data = bytes.fromhex(encode(self.PAYMENT_WITH_MEMOS))
        rt._slot_overrides["slot_data:1"] = data

        slot_subfield(rt, 1, hookapi.sfMemos, 2)
        result = slot_subarray(rt, 2, 1, 4)
        assert result == 4
        assert slot_size(rt, 4) > 0

    def test_subarray_out_of_range(self, rt):
        """Index 5 in a 2-element array → DOESNT_EXIST."""
        data = bytes.fromhex(encode(self.PAYMENT_WITH_MEMOS))
        rt._slot_overrides["slot_data:1"] = data

        slot_subfield(rt, 1, hookapi.sfMemos, 2)
        assert slot_subarray(rt, 2, 5, 3) == hookapi.DOESNT_EXIST

    def test_full_navigation_chain(self, rt):
        """otxn_slot(1) → slot_subfield → slot_count → slot_subarray → slot() read.

        This mimics the top.c flow:
            otxn_slot(1)
            slot_subfield(1, sfAmounts, 2)
            slot_count(2) == 1
            slot_subarray(2, 0, 3)
            slot(buf, size, 3)
        """
        # Build a minimal transaction with a single-element Amounts-like array
        # Use Memos since Amounts isn't in standard xrpl-py
        txn = {
            "TransactionType": "Payment",
            "Account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
            "Destination": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            "Amount": "1000000",
            "Fee": "12",
            "Sequence": 1,
            "Memos": [
                {"Memo": {"MemoData": "DEADBEEF", "MemoType": "746578742F706C61696E"}},
            ],
        }
        data = bytes.fromhex(encode(txn))
        rt._slot_overrides["slot_data:1"] = data

        # Navigate: subfield → count → subarray → read
        assert slot_subfield(rt, 1, hookapi.sfMemos, 2) == 2
        assert slot_count(rt, 2) == 1
        assert slot_subarray(rt, 2, 0, 3) == 3

        # Read the element bytes
        size = slot_size(rt, 3)
        assert size > 0
        result = slot(rt, 100, 256, 3)
        assert result == size
        element_data = rt._read_memory(100, result)
        assert len(element_data) == size

    def test_override_beats_real_data(self, rt):
        """Override takes priority even when real data exists."""
        data = bytes.fromhex(encode(self.PAYMENT))
        rt._slot_overrides["slot_data:1"] = data

        # Override says sfAccount doesn't exist (even though it does)
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfAccount}"] = hookapi.DOESNT_EXIST
        assert slot_subfield(rt, 1, hookapi.sfAccount, 2) == hookapi.DOESNT_EXIST

    def test_override_count_beats_real_data(self, rt):
        """slot_count override takes priority."""
        data = bytes.fromhex(encode(self.PAYMENT_WITH_MEMOS))
        rt._slot_overrides["slot_data:1"] = data
        slot_subfield(rt, 1, hookapi.sfMemos, 2)

        # Real count is 2, override says 99
        rt._slot_overrides["slot_count:2"] = 99
        assert slot_count(rt, 2) == 99
