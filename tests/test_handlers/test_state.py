"""Tests for state and state_foreign handlers."""

import pytest
import wasmtime

from hookz.runtime import HookRuntime
from hookz import hookapi
from hookz.handlers.state import state, state_set, state_foreign, state_foreign_set


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
# state / state_set (local state)
# ---------------------------------------------------------------------------

class TestState:
    """state: read from local state_db."""

    def test_basic_read(self, rt):
        key = b"balance"
        val = b"\x00\x00\x00\x64"
        rt.state_db[key] = val
        rt._write_memory(100, key)
        result = state(rt, 0, 128, 100, len(key))
        assert result == len(val)
        assert rt._read_memory(0, len(val)) == val

    def test_missing_key(self, rt):
        rt._write_memory(100, b"nokey")
        assert state(rt, 0, 128, 100, 5) == hookapi.DOESNT_EXIST

    def test_truncates_to_write_len(self, rt):
        rt.state_db[b"k"] = b"longvalue"
        rt._write_memory(100, b"k")
        result = state(rt, 0, 4, 100, 1)
        assert result == 4
        assert rt._read_memory(0, 4) == b"long"

    def test_binary_key_and_value(self, rt):
        key = b"\x00\x01\x02\x03"
        val = b"\xFF\xFE\xFD"
        rt.state_db[key] = val
        rt._write_memory(100, key)
        result = state(rt, 0, 128, 100, len(key))
        assert result == len(val)
        assert rt._read_memory(0, len(val)) == val

    def test_key_at_ptr_zero(self, rt):
        """Key stored at memory address 0 should work."""
        key = b"k"
        rt.state_db[key] = b"v"
        rt._write_memory(0, key)
        result = state(rt, 100, 128, 0, 1)
        assert result == 1
        assert rt._read_memory(100, 1) == b"v"

    def test_empty_value(self, rt):
        rt.state_db[b"k"] = b""
        rt._write_memory(100, b"k")
        result = state(rt, 0, 128, 100, 1)
        assert result == 0


class TestStateSet:
    """state_set: write to local state_db."""

    def test_basic_set(self, rt):
        rt._write_memory(0, b"myval")
        rt._write_memory(100, b"mykey")
        result = state_set(rt, 0, 5, 100, 5)
        assert result == 5
        assert rt.state_db[b"mykey"] == b"myval"

    def test_overwrite(self, rt):
        rt.state_db[b"k"] = b"old"
        rt._write_memory(0, b"new")
        rt._write_memory(100, b"k")
        state_set(rt, 0, 3, 100, 1)
        assert rt.state_db[b"k"] == b"new"

    def test_delete_with_zero_ptr_and_len(self, rt):
        rt.state_db[b"k"] = b"val"
        rt._write_memory(100, b"k")
        result = state_set(rt, 0, 0, 100, 1)
        assert result == 0
        assert b"k" not in rt.state_db

    def test_delete_nonexistent_key(self, rt):
        rt._write_memory(100, b"nokey")
        result = state_set(rt, 0, 0, 100, 5)
        assert result == 0  # No error, just no-op

    def test_set_at_ptr_zero(self, rt):
        """Value at memory address 0 should work."""
        rt._write_memory(0, b"val")
        rt._write_memory(100, b"k")
        state_set(rt, 0, 3, 100, 1)
        assert rt.state_db[b"k"] == b"val"

    def test_roundtrip(self, rt):
        """Set then read."""
        rt._write_memory(0, b"\xDE\xAD")
        rt._write_memory(100, b"key")
        state_set(rt, 0, 2, 100, 3)
        result = state(rt, 200, 128, 100, 3)
        assert result == 2
        assert rt._read_memory(200, 2) == b"\xDE\xAD"

    def test_32_byte_key(self, rt):
        """Max key length (32 bytes) should work."""
        key = b"A" * 32
        val = b"V" * 128
        rt._write_memory(0, val)
        rt._write_memory(200, key)
        state_set(rt, 0, len(val), 200, 32)
        assert rt.state_db[key] == val


ACCOUNT_A = b"\x01" * 20
ACCOUNT_B = b"\x02" * 20
NAMESPACE = b"\xAA" * 32


class TestStateForeign:
    """state_foreign: read state from another account."""

    def test_basic_read(self, rt):
        key = b"mykey"
        val = b"myvalue"
        rt._foreign_state_db = {(ACCOUNT_A, NAMESPACE, key): val}
        rt._write_memory(100, key)
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign(rt, 0, 128, 100, len(key), 200, 32, 300, 20)
        assert result == len(val)
        assert rt._read_memory(0, len(val)) == val

    def test_missing_key_returns_doesnt_exist(self, rt):
        rt._write_memory(100, b"nokey")
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign(rt, 0, 128, 100, 5, 200, 32, 300, 20)
        assert result == hookapi.DOESNT_EXIST

    def test_different_accounts_isolated(self, rt):
        key = b"k"
        rt._foreign_state_db = {(ACCOUNT_A, NAMESPACE, key): b"val_a"}
        rt._write_memory(100, key)
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_B)
        result = state_foreign(rt, 0, 128, 100, len(key), 200, 32, 300, 20)
        assert result == hookapi.DOESNT_EXIST

    def test_kread_len_too_small(self, rt):
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign(rt, 0, 128, 100, 0, 200, 32, 300, 20)
        assert result == hookapi.TOO_SMALL

    def test_kread_len_too_big(self, rt):
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign(rt, 0, 128, 100, 33, 200, 32, 300, 20)
        assert result == hookapi.TOO_BIG

    def test_invalid_ns_len(self, rt):
        result = state_foreign(rt, 0, 128, 100, 5, 200, 16, 300, 20)
        assert result == hookapi.INVALID_ARGUMENT

    def test_invalid_aread_len(self, rt):
        result = state_foreign(rt, 0, 128, 100, 5, 200, 32, 300, 10)
        assert result == hookapi.INVALID_ARGUMENT

    def test_zero_ns_len_defaults(self, rt):
        """ns_len=0 should use zero namespace."""
        key = b"k"
        default_ns = b"\x00" * 32
        rt._foreign_state_db = {(ACCOUNT_A, default_ns, key): b"val"}
        rt._write_memory(100, key)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign(rt, 0, 128, 100, len(key), 200, 0, 300, 20)
        assert result == 3

    def test_write_len_truncates(self, rt):
        key = b"k"
        rt._foreign_state_db = {(ACCOUNT_A, NAMESPACE, key): b"longvalue"}
        rt._write_memory(100, key)
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign(rt, 0, 4, 100, len(key), 200, 32, 300, 20)
        assert result == 4
        assert rt._read_memory(0, 4) == b"long"


class TestStateForeignSet:
    """state_foreign_set: write state to another account."""

    def test_basic_set(self, rt):
        key = b"mykey"
        val = b"myval"
        rt._write_memory(0, val)
        rt._write_memory(100, key)
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign_set(rt, 0, len(val), 100, len(key), 200, 32, 300, 20)
        assert result == len(val)
        assert rt._foreign_state_db[(ACCOUNT_A, NAMESPACE, key)] == val

    def test_delete_operation(self, rt):
        key = b"k"
        rt._foreign_state_db = {(ACCOUNT_A, NAMESPACE, key): b"old"}
        rt._write_memory(100, key)
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign_set(rt, 0, 0, 100, len(key), 200, 32, 300, 20)
        assert result == 0
        assert (ACCOUNT_A, NAMESPACE, key) not in rt._foreign_state_db

    def test_kread_len_too_small(self, rt):
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign_set(rt, 0, 5, 100, 0, 200, 32, 300, 20)
        assert result == hookapi.TOO_SMALL

    def test_kread_len_too_big(self, rt):
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        result = state_foreign_set(rt, 0, 5, 100, 33, 200, 32, 300, 20)
        assert result == hookapi.TOO_BIG

    def test_invalid_ns_len(self, rt):
        result = state_foreign_set(rt, 0, 5, 100, 5, 200, 16, 300, 20)
        assert result == hookapi.INVALID_ARGUMENT

    def test_invalid_aread_len(self, rt):
        result = state_foreign_set(rt, 0, 5, 100, 5, 200, 32, 300, 10)
        assert result == hookapi.INVALID_ARGUMENT

    def test_roundtrip(self, rt):
        """Set via state_foreign_set, read via state_foreign."""
        key = b"roundtrip"
        val = b"hello"
        rt._write_memory(0, val)
        rt._write_memory(100, key)
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        state_foreign_set(rt, 0, len(val), 100, len(key), 200, 32, 300, 20)

        result = state_foreign(rt, 400, 128, 100, len(key), 200, 32, 300, 20)
        assert result == len(val)
        assert rt._read_memory(400, len(val)) == val

    def test_different_accounts_isolated(self, rt):
        """Writing to account A should not affect account B."""
        key = b"k"
        val = b"v"
        rt._write_memory(0, val)
        rt._write_memory(100, key)
        rt._write_memory(200, NAMESPACE)
        rt._write_memory(300, ACCOUNT_A)
        state_foreign_set(rt, 0, len(val), 100, len(key), 200, 32, 300, 20)

        rt._write_memory(300, ACCOUNT_B)
        result = state_foreign(rt, 400, 128, 100, len(key), 200, 32, 300, 20)
        assert result == hookapi.DOESNT_EXIST
