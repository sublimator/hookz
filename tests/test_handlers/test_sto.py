"""Tests for STO (Serialized Transaction Object) handlers."""

import pytest
import wasmtime

from hookz.runtime import HookRuntime
from hookz import hookapi
from hookz.xrpl.xrpl_patch import patch_xahau_definitions
from hookz.handlers.sto import (
    sto_subfield,
    sto_subarray,
    sto_emplace,
    sto_erase,
    sto_validate,
)

patch_xahau_definitions()

from xrpl.core.binarycodec import encode


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(2, None)))
    r._store = store
    r._memory = memory
    return r


# A simple Payment transaction for testing
PAYMENT_TXN = {
    "TransactionType": "Payment",
    "Account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
    "Destination": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
    "Amount": "1000000",
    "Fee": "12",
    "Sequence": 1,
    "Flags": 0,
}
PAYMENT_HEX = encode(PAYMENT_TXN)
PAYMENT_BYTES = bytes.fromhex(PAYMENT_HEX)


class TestStoSubfield:
    """sto_subfield: find a field in a serialized object."""

    def test_find_amount(self, rt):
        rt._write_memory(0, PAYMENT_BYTES)
        # sfAmount = 0x60001
        result = sto_subfield(rt, 0, len(PAYMENT_BYTES), hookapi.sfAmount)
        assert result > 0
        offset = (result >> 32) & 0xFFFFFFFF
        length = result & 0xFFFFFFFF
        assert length == 8  # Amount payload is 8 bytes
        payload = rt._read_memory(offset, length)
        assert len(payload) == 8

    def test_find_fee(self, rt):
        rt._write_memory(0, PAYMENT_BYTES)
        result = sto_subfield(rt, 0, len(PAYMENT_BYTES), hookapi.sfFee)
        assert result > 0
        offset = (result >> 32) & 0xFFFFFFFF
        length = result & 0xFFFFFFFF
        assert length == 8  # Fee payload is 8 bytes

    def test_find_sequence(self, rt):
        rt._write_memory(0, PAYMENT_BYTES)
        result = sto_subfield(rt, 0, len(PAYMENT_BYTES), hookapi.sfSequence)
        assert result > 0
        offset = (result >> 32) & 0xFFFFFFFF
        length = result & 0xFFFFFFFF
        assert length == 4  # UInt32 is 4 bytes

    def test_find_account(self, rt):
        rt._write_memory(0, PAYMENT_BYTES)
        result = sto_subfield(rt, 0, len(PAYMENT_BYTES), hookapi.sfAccount)
        assert result > 0
        offset = (result >> 32) & 0xFFFFFFFF
        length = result & 0xFFFFFFFF
        assert length == 20  # Account ID is 20 bytes

    def test_doesnt_exist(self, rt):
        rt._write_memory(0, PAYMENT_BYTES)
        # sfOfferSequence is not in this transaction
        result = sto_subfield(rt, 0, len(PAYMENT_BYTES), hookapi.sfOfferSequence)
        assert result == hookapi.DOESNT_EXIST

    def test_too_small(self, rt):
        rt._write_memory(0, b"\x12")
        result = sto_subfield(rt, 0, 1, hookapi.sfAmount)
        assert result == hookapi.TOO_SMALL

    def test_parse_error(self, rt):
        rt._write_memory(0, b"\xFF\xFF")
        result = sto_subfield(rt, 0, 2, hookapi.sfAmount)
        assert result == hookapi.PARSE_ERROR


class TestStoSubarray:
    """sto_subarray: find element at index in a serialized array."""

    def _make_array_with_memos(self):
        """Create a transaction with Memos array and return its serialized Memos field."""
        txn = {
            "TransactionType": "Payment",
            "Account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
            "Destination": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            "Amount": "1000000",
            "Fee": "12",
            "Sequence": 1,
            "Flags": 0,
            "Memos": [
                {"Memo": {"MemoData": "AABB", "MemoType": "746578742F706C61696E"}},
                {"Memo": {"MemoData": "CCDD", "MemoType": "746578742F706C61696E"}},
            ],
        }
        txn_hex = encode(txn)
        txn_bytes = bytes.fromhex(txn_hex)

        # Extract the Memos array field using sto_subfield
        # sfMemos = 0xF0009 (type=0xF, field=9)
        # For arrays, sto_subfield returns the full field including header
        return txn_bytes

    def test_find_first_element(self, rt):
        txn_bytes = self._make_array_with_memos()
        rt._write_memory(0, txn_bytes)

        # First get the Memos array
        result = sto_subfield(rt, 0, len(txn_bytes), hookapi.sfMemos)
        assert result > 0
        arr_offset = (result >> 32) & 0xFFFFFFFF
        arr_len = result & 0xFFFFFFFF

        # Now find first element in the array
        result2 = sto_subarray(rt, arr_offset, arr_len, 0)
        assert result2 > 0

    def test_find_second_element(self, rt):
        txn_bytes = self._make_array_with_memos()
        rt._write_memory(0, txn_bytes)

        result = sto_subfield(rt, 0, len(txn_bytes), hookapi.sfMemos)
        assert result > 0
        arr_offset = (result >> 32) & 0xFFFFFFFF
        arr_len = result & 0xFFFFFFFF

        result2 = sto_subarray(rt, arr_offset, arr_len, 1)
        assert result2 > 0

    def test_index_out_of_range(self, rt):
        txn_bytes = self._make_array_with_memos()
        rt._write_memory(0, txn_bytes)

        result = sto_subfield(rt, 0, len(txn_bytes), hookapi.sfMemos)
        assert result > 0
        arr_offset = (result >> 32) & 0xFFFFFFFF
        arr_len = result & 0xFFFFFFFF

        # Only 2 memos, index 5 doesn't exist
        result2 = sto_subarray(rt, arr_offset, arr_len, 5)
        assert result2 == hookapi.DOESNT_EXIST

    def test_too_small(self, rt):
        rt._write_memory(0, b"\xF9")
        result = sto_subarray(rt, 0, 1, 0)
        assert result == hookapi.TOO_SMALL


class TestStoEmplace:
    """sto_emplace: insert/replace a field in a serialized object."""

    def test_replace_existing_field(self, rt):
        """Replace the Fee field with a new value."""
        source = PAYMENT_BYTES

        # Build a new Fee field: header byte (0x68) + 8 bytes of amount
        # sfFee type=6, field=8 -> header byte = 0x68
        new_fee = b"\x68" + (0x4000000000000064).to_bytes(8, "big")  # 100 drops

        rt._write_memory(0, source)
        rt._write_memory(1000, new_fee)

        result = sto_emplace(
            rt, 2000, 200, 0, len(source), 1000, len(new_fee), hookapi.sfFee
        )
        assert result > 0

        # The output should be a valid serialized object
        output = rt._read_memory(2000, result)
        rt._write_memory(3000, output)
        assert sto_validate(rt, 3000, len(output)) == 1

    def test_insert_new_field(self, rt):
        """Insert a field that doesn't exist yet."""
        source = PAYMENT_BYTES

        # Build SourceTag field: sfSourceTag = 0x20003, type=2(UInt32), field=3
        # header byte = 0x23
        new_field = b"\x23" + (42).to_bytes(4, "big")

        rt._write_memory(0, source)
        rt._write_memory(1000, new_field)

        result = sto_emplace(
            rt, 2000, 300, 0, len(source), 1000, len(new_field), hookapi.sfSourceTag
        )
        assert result > 0
        assert result > len(source)  # Should be larger (added a field)

        # Verify the new field exists
        output = rt._read_memory(2000, result)
        rt._write_memory(3000, output)
        found = sto_subfield(rt, 3000, len(output), hookapi.sfSourceTag)
        assert found > 0

    def test_delete_field(self, rt):
        """Delete a field by passing fread_ptr=0, fread_len=0."""
        source = PAYMENT_BYTES
        rt._write_memory(0, source)

        result = sto_emplace(
            rt, 2000, 200, 0, len(source), 0, 0, hookapi.sfFee
        )
        assert result > 0
        assert result < len(source)  # Should be smaller (removed a field)

        # Verify the field is gone
        output = rt._read_memory(2000, result)
        rt._write_memory(3000, output)
        found = sto_subfield(rt, 3000, len(output), hookapi.sfFee)
        assert found == hookapi.DOESNT_EXIST

    def test_too_small_source(self, rt):
        rt._write_memory(0, b"\x12")
        result = sto_emplace(rt, 2000, 200, 0, 1, 100, 5, hookapi.sfFee)
        assert result == hookapi.TOO_SMALL

    def test_too_big_source(self, rt):
        result = sto_emplace(rt, 2000, 200, 0, 1024 * 16 + 1, 100, 5, hookapi.sfFee)
        assert result == hookapi.TOO_BIG

    def test_too_small_field(self, rt):
        rt._write_memory(0, PAYMENT_BYTES)
        rt._write_memory(1000, b"\x68")
        result = sto_emplace(
            rt, 2000, 200, 0, len(PAYMENT_BYTES), 1000, 1, hookapi.sfFee
        )
        assert result == hookapi.TOO_SMALL

    def test_too_big_field(self, rt):
        rt._write_memory(0, PAYMENT_BYTES)
        result = sto_emplace(
            rt, 2000, 200, 0, len(PAYMENT_BYTES), 1000, 4097, hookapi.sfFee
        )
        assert result == hookapi.TOO_BIG

    def test_write_buf_too_small(self, rt):
        source = PAYMENT_BYTES
        new_field = b"\x23" + (42).to_bytes(4, "big")
        rt._write_memory(0, source)
        rt._write_memory(1000, new_field)
        result = sto_emplace(
            rt, 2000, 5, 0, len(source), 1000, len(new_field), hookapi.sfSourceTag
        )
        assert result == hookapi.TOO_SMALL


class TestStoErase:
    """sto_erase: remove a field from a serialized object."""

    def test_erase_existing_field(self, rt):
        source = PAYMENT_BYTES
        rt._write_memory(0, source)

        result = sto_erase(rt, 2000, 200, 0, len(source), hookapi.sfFee)
        assert result > 0
        assert result < len(source)

        output = rt._read_memory(2000, result)
        rt._write_memory(3000, output)
        found = sto_subfield(rt, 3000, len(output), hookapi.sfFee)
        assert found == hookapi.DOESNT_EXIST

    def test_erase_nonexistent_field(self, rt):
        source = PAYMENT_BYTES
        rt._write_memory(0, source)

        result = sto_erase(rt, 2000, 200, 0, len(source), hookapi.sfOfferSequence)
        assert result == hookapi.DOESNT_EXIST

    def test_erase_preserves_other_fields(self, rt):
        source = PAYMENT_BYTES
        rt._write_memory(0, source)

        result = sto_erase(rt, 2000, 200, 0, len(source), hookapi.sfFee)
        assert result > 0

        output = rt._read_memory(2000, result)
        rt._write_memory(3000, output)

        # Amount should still be there
        found = sto_subfield(rt, 3000, len(output), hookapi.sfAmount)
        assert found > 0

        # Account should still be there
        found = sto_subfield(rt, 3000, len(output), hookapi.sfAccount)
        assert found > 0


class TestStoValidate:
    """sto_validate: check if bytes are well-formed serialized object."""

    def test_valid_payment(self, rt):
        rt._write_memory(0, PAYMENT_BYTES)
        assert sto_validate(rt, 0, len(PAYMENT_BYTES)) == 1

    def test_invalid_bytes(self, rt):
        rt._write_memory(0, b"\xFF\xFF\xFF\xFF")
        assert sto_validate(rt, 0, 4) == 0

    def test_too_small(self, rt):
        rt._write_memory(0, b"\x12")
        assert sto_validate(rt, 0, 1) == hookapi.TOO_SMALL

    def test_truncated_object(self, rt):
        """An object cut short should fail validation."""
        truncated = PAYMENT_BYTES[:10]
        rt._write_memory(0, truncated)
        assert sto_validate(rt, 0, len(truncated)) == 0

    def test_valid_with_memos(self, rt):
        txn = {
            "TransactionType": "Payment",
            "Account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
            "Destination": "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
            "Amount": "1000000",
            "Fee": "12",
            "Sequence": 1,
            "Memos": [
                {"Memo": {"MemoData": "AABB", "MemoType": "746578742F706C61696E"}},
            ],
        }
        data = bytes.fromhex(encode(txn))
        rt._write_memory(0, data)
        assert sto_validate(rt, 0, len(data)) == 1


class TestStoRoundtrip:
    """Integration tests combining multiple STO operations."""

    def test_emplace_then_subfield(self, rt):
        """Emplace a field and verify it can be found with subfield."""
        source = PAYMENT_BYTES
        # SourceTag: type=2, field=3, header=0x23, UInt32
        new_field = b"\x23" + (999).to_bytes(4, "big")

        rt._write_memory(0, source)
        rt._write_memory(1000, new_field)

        result = sto_emplace(
            rt, 2000, 300, 0, len(source), 1000, len(new_field), hookapi.sfSourceTag
        )
        assert result > 0

        # Find the new field
        found = sto_subfield(rt, 2000, result, hookapi.sfSourceTag)
        assert found > 0
        offset = (found >> 32) & 0xFFFFFFFF
        length = found & 0xFFFFFFFF
        assert length == 4
        value = int.from_bytes(rt._read_memory(offset + 2000, length), "big")
        assert value == 999

    def test_erase_then_validate(self, rt):
        """Erase a field and verify the result is still valid."""
        source = PAYMENT_BYTES
        rt._write_memory(0, source)

        result = sto_erase(rt, 2000, 200, 0, len(source), hookapi.sfFlags)
        assert result > 0

        assert sto_validate(rt, 2000, result) == 1
