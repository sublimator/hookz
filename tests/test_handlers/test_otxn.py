"""Tests for otxn/hook_param handlers."""

import pytest
import wasmtime

from hookz.runtime import HookRuntime
from hookz import hookapi
from hookz.handlers.otxn import (
    otxn_field, otxn_param, otxn_id, otxn_slot, hook_param, hook_param_set,
)


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r


# ---------------------------------------------------------------------------
# otxn_field
# ---------------------------------------------------------------------------

class TestOtxnField:
    """otxn_field: read originating transaction fields."""

    def test_sfaccount_returns_20(self, rt):
        rt.otxn_account = b"\x01" * 20
        result = otxn_field(rt, 100, 32, hookapi.sfAccount)
        assert result == 20
        assert rt._read_memory(100, 20) == b"\x01" * 20

    def test_sfaccount_too_small(self, rt):
        rt.otxn_account = b"\x01" * 20
        result = otxn_field(rt, 100, 10, hookapi.sfAccount)
        assert result == hookapi.TOO_SMALL

    def test_sftransactiontype_returns_2(self, rt):
        rt.otxn_type = 0  # ttPAYMENT
        result = otxn_field(rt, 100, 32, hookapi.sfTransactionType)
        assert result == 2
        assert rt._read_memory(100, 2) == b"\x00\x00"

    def test_sftransactiontype_invoke(self, rt):
        rt.otxn_type = hookapi.ttINVOKE
        result = otxn_field(rt, 100, 32, hookapi.sfTransactionType)
        assert result == 2
        val = int.from_bytes(rt._read_memory(100, 2), "big")
        assert val == hookapi.ttINVOKE

    def test_return_as_int64(self, rt):
        """write_ptr=0, write_len=0 → returns value as int64."""
        rt.otxn_type = hookapi.ttINVOKE
        result = otxn_field(rt, 0, 0, hookapi.sfTransactionType)
        assert result == hookapi.ttINVOKE

    def test_unknown_field_returns_doesnt_exist(self, rt):
        result = otxn_field(rt, 100, 32, hookapi.sfFee)
        assert result == hookapi.DOESNT_EXIST

    def test_write_at_offset(self, rt):
        rt.otxn_account = b"\xAB" * 20
        rt._write_memory(0, b"\xFF" * 100)
        otxn_field(rt, 50, 20, hookapi.sfAccount)
        assert rt._read_memory(0, 50) == b"\xFF" * 50
        assert rt._read_memory(50, 20) == b"\xAB" * 20


# ---------------------------------------------------------------------------
# otxn_param
# ---------------------------------------------------------------------------

class TestOtxnParam:
    """otxn_param: read originating transaction parameters."""

    def test_basic_lookup(self, rt):
        key = b"amount"
        val = b"\x00\x01\x02\x03"
        rt.params[key] = val
        rt._write_memory(200, key)
        result = otxn_param(rt, 0, 128, 200, len(key))
        assert result == len(val)
        assert rt._read_memory(0, len(val)) == val

    def test_missing_key(self, rt):
        rt._write_memory(200, b"nokey")
        result = otxn_param(rt, 0, 128, 200, 5)
        assert result == hookapi.DOESNT_EXIST

    def test_truncates_to_write_len(self, rt):
        key = b"k"
        rt.params[key] = b"longvalue_here"
        rt._write_memory(200, key)
        result = otxn_param(rt, 0, 4, 200, 1)
        assert result == 4
        assert rt._read_memory(0, 4) == b"long"

    def test_empty_value(self, rt):
        key = b"flag"
        rt.params[key] = b""
        rt._write_memory(200, key)
        result = otxn_param(rt, 0, 128, 200, len(key))
        assert result == 0

    def test_binary_key(self, rt):
        key = b"\x00\x01\x02"
        rt.params[key] = b"\xFF"
        rt._write_memory(200, key)
        result = otxn_param(rt, 0, 128, 200, 3)
        assert result == 1

    def test_multiple_params(self, rt):
        rt.params[b"a"] = b"val_a"
        rt.params[b"b"] = b"val_b"
        rt._write_memory(200, b"a")
        assert otxn_param(rt, 0, 128, 200, 1) == 5
        assert rt._read_memory(0, 5) == b"val_a"
        rt._write_memory(200, b"b")
        assert otxn_param(rt, 0, 128, 200, 1) == 5
        assert rt._read_memory(0, 5) == b"val_b"

    def test_kread_len_zero_returns_too_small(self, rt):
        """kread_len=0 -> TOO_SMALL."""
        assert otxn_param(rt, 0, 128, 200, 0) == hookapi.TOO_SMALL

    def test_kread_len_33_returns_too_big(self, rt):
        """kread_len=33 -> TOO_BIG."""
        rt._write_memory(200, b"A" * 33)
        assert otxn_param(rt, 0, 128, 200, 33) == hookapi.TOO_BIG


# ---------------------------------------------------------------------------
# otxn_id
# ---------------------------------------------------------------------------

class TestOtxnId:
    """otxn_id: write 32-byte transaction ID."""

    def test_returns_32(self, rt):
        assert otxn_id(rt, 0, 32, 0) == 32

    def test_writes_32_bytes(self, rt):
        otxn_id(rt, 0, 32, 0)
        data = rt._read_memory(0, 32)
        assert len(data) == 32
        assert data == b"\xAB" * 32

    def test_truncates_to_write_len(self, rt):
        rt._write_memory(0, b"\xFF" * 32)
        otxn_id(rt, 0, 16, 0)
        assert rt._read_memory(0, 16) == b"\xAB" * 16

    def test_with_flags(self, rt):
        """Flags parameter is accepted without error."""
        assert otxn_id(rt, 0, 32, 1) == 32


# ---------------------------------------------------------------------------
# otxn_slot
# ---------------------------------------------------------------------------

class TestOtxnSlot:
    """otxn_slot: load originating transaction into slot."""

    def test_returns_slot_no(self, rt):
        assert otxn_slot(rt, 0) == 0
        assert otxn_slot(rt, 5) == 5
        assert otxn_slot(rt, 255) == 255


# ---------------------------------------------------------------------------
# hook_param (existing tests below)
# ---------------------------------------------------------------------------

class TestHookParam:
    """hook_param: read a hook parameter by key."""

    def test_empty_key_returns_too_small(self, rt):
        """kread_len=0 -> TOO_SMALL."""
        result = hook_param(rt, 0, 128, 200, 0)
        assert result == hookapi.TOO_SMALL

    def test_basic_from_params(self, rt):
        """Reads from rt.params when no overrides exist."""
        key = b"mykey"
        val = b"myvalue"
        rt.params[key] = val
        rt._write_memory(200, key)
        result = hook_param(rt, 0, 128, 200, len(key))
        assert result == len(val)
        assert rt._read_memory(0, len(val)) == val

    def test_missing_key_returns_doesnt_exist(self, rt):
        rt._write_memory(200, b"nokey")
        result = hook_param(rt, 0, 128, 200, 5)
        assert result == hookapi.DOESNT_EXIST

    def test_override_takes_priority(self, rt):
        """Overrides from hook_param_set should be checked first."""
        key = b"k"
        rt.params[key] = b"original"
        rt._param_overrides = {b"\x00" * 32: {key: b"overridden"}}
        rt._write_memory(200, key)
        result = hook_param(rt, 0, 128, 200, len(key))
        assert result == len(b"overridden")
        assert rt._read_memory(0, result) == b"overridden"

    def test_empty_override_means_deleted(self, rt):
        """An empty override value means the parameter is 'deleted'."""
        key = b"k"
        rt.params[key] = b"original"
        rt._param_overrides = {b"\x00" * 32: {key: b""}}
        rt._write_memory(200, key)
        result = hook_param(rt, 0, 128, 200, len(key))
        assert result == hookapi.DOESNT_EXIST

    def test_write_len_truncates(self, rt):
        """Output is truncated to write_len."""
        key = b"k"
        rt.params[key] = b"longvalue"
        rt._write_memory(200, key)
        result = hook_param(rt, 0, 4, 200, len(key))
        assert result == 4
        assert rt._read_memory(0, 4) == b"long"


class TestHookParamSet:
    """hook_param_set: set a parameter override for another hook."""

    def test_basic_set(self, rt):
        key = b"mykey"
        val = b"myval"
        hook_hash = b"\xAA" * 32
        rt._write_memory(0, val)
        rt._write_memory(100, key)
        rt._write_memory(200, hook_hash)
        result = hook_param_set(rt, 0, len(val), 100, len(key), 200, 32)
        assert result == len(val)
        assert rt._param_overrides[hook_hash][key] == val

    def test_kread_len_too_small(self, rt):
        rt._write_memory(200, b"\xAA" * 32)
        result = hook_param_set(rt, 0, 5, 100, 0, 200, 32)
        assert result == hookapi.TOO_SMALL

    def test_kread_len_too_big(self, rt):
        rt._write_memory(200, b"\xAA" * 32)
        result = hook_param_set(rt, 0, 5, 100, 33, 200, 32)
        assert result == hookapi.TOO_BIG

    def test_hread_len_not_32(self, rt):
        result = hook_param_set(rt, 0, 5, 100, 5, 200, 31)
        assert result == hookapi.INVALID_ARGUMENT

    def test_read_len_too_big(self, rt):
        rt._write_memory(200, b"\xAA" * 32)
        result = hook_param_set(rt, 0, 257, 100, 5, 200, 32)
        assert result == hookapi.TOO_BIG

    def test_empty_value_allowed(self, rt):
        """Setting an empty value (delete) is valid."""
        key = b"k"
        hook_hash = b"\xBB" * 32
        rt._write_memory(100, key)
        rt._write_memory(200, hook_hash)
        result = hook_param_set(rt, 0, 0, 100, len(key), 200, 32)
        assert result == 0
        assert rt._param_overrides[hook_hash][key] == b""

    def test_roundtrip_with_hook_param(self, rt):
        """Set via hook_param_set, read via hook_param."""
        key = b"testkey"
        val = b"testval"
        hook_hash = b"\xCC" * 32
        rt._write_memory(0, val)
        rt._write_memory(100, key)
        rt._write_memory(200, hook_hash)
        hook_param_set(rt, 0, len(val), 100, len(key), 200, 32)

        # Now read it back
        rt._write_memory(300, key)
        result = hook_param(rt, 400, 128, 300, len(key))
        assert result == len(val)
        assert rt._read_memory(400, len(val)) == val


class TestHookParamMultiHook:
    """hook_param with multiple hook hashes and overrides."""

    def test_override_from_different_hashes(self, rt):
        """Overrides from multiple hook hashes are all searchable."""
        key = b"shared_key"
        hash_a = b"\xAA" * 32
        hash_b = b"\xBB" * 32

        # Set override from hash_a
        rt._write_memory(0, b"val_a")
        rt._write_memory(100, key)
        rt._write_memory(200, hash_a)
        hook_param_set(rt, 0, 5, 100, len(key), 200, 32)

        # hook_param should find it
        rt._write_memory(300, key)
        result = hook_param(rt, 400, 128, 300, len(key))
        assert result == 5
        assert rt._read_memory(400, 5) == b"val_a"

    def test_override_wins_over_params(self, rt):
        """Override always takes priority over rt.params."""
        key = b"k"
        rt.params[key] = b"from_params"

        hook_hash = b"\xDD" * 32
        rt._write_memory(0, b"from_override")
        rt._write_memory(100, key)
        rt._write_memory(200, hook_hash)
        hook_param_set(rt, 0, 13, 100, 1, 200, 32)

        rt._write_memory(300, key)
        result = hook_param(rt, 400, 128, 300, 1)
        assert rt._read_memory(400, result) == b"from_override"

    def test_delete_override_exposes_params(self, rt):
        """Empty override deletes, but rt.params should still have the original.

        However, hook_param checks overrides first and treats empty as deleted,
        returning DOESNT_EXIST even though rt.params has the key.
        """
        key = b"k"
        rt.params[key] = b"original"

        hook_hash = b"\xEE" * 32
        rt._write_memory(100, key)
        rt._write_memory(200, hook_hash)
        hook_param_set(rt, 0, 0, 100, 1, 200, 32)  # empty = delete

        rt._write_memory(300, key)
        result = hook_param(rt, 400, 128, 300, 1)
        # Empty override means "deleted" — DOESNT_EXIST even though params has it
        assert result == hookapi.DOESNT_EXIST

    def test_max_key_length(self, rt):
        """32-byte key is the max allowed."""
        key = b"A" * 32
        val = b"value"
        hook_hash = b"\xFF" * 32
        rt._write_memory(0, val)
        rt._write_memory(100, key)
        rt._write_memory(200, hook_hash)
        result = hook_param_set(rt, 0, len(val), 100, 32, 200, 32)
        assert result == len(val)

    def test_max_value_length(self, rt):
        """256-byte value is the max allowed."""
        val = b"\xAB" * 256
        key = b"k"
        hook_hash = b"\xFF" * 32
        rt._write_memory(0, val)
        rt._write_memory(500, key)
        rt._write_memory(600, hook_hash)
        result = hook_param_set(rt, 0, 256, 500, 1, 600, 32)
        assert result == 256
