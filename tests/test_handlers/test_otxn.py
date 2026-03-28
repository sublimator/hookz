"""Tests for hook_param and hook_param_set handlers."""

import pytest
import wasmtime

from hookz.runtime import HookRuntime
from hookz import hookapi
from hookz.handlers.otxn import hook_param, hook_param_set


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r


class TestHookParam:
    """hook_param: read a hook parameter by key."""

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
