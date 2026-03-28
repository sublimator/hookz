"""Tests for etxn_nonce handler."""

import pytest
import wasmtime

from hookz.runtime import HookRuntime
from hookz.handlers.emit import etxn_nonce, prepare
from hookz import hookapi


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r


class TestEtxnNonce:
    """etxn_nonce: write a unique 32-byte nonce."""

    def test_returns_32(self, rt):
        """Should return 32 on success."""
        assert etxn_nonce(rt, 0, 32) == 32

    def test_writes_32_bytes(self, rt):
        """Should write exactly 32 bytes."""
        etxn_nonce(rt, 0, 32)
        data = rt._read_memory(0, 32)
        assert len(data) == 32

    def test_too_small(self, rt):
        """write_len < 32 -> TOO_SMALL."""
        assert etxn_nonce(rt, 0, 31) == hookapi.TOO_SMALL

    def test_successive_nonces_differ(self, rt):
        """Each call should produce a different nonce."""
        etxn_nonce(rt, 0, 32)
        first = rt._read_memory(0, 32)
        etxn_nonce(rt, 100, 32)
        second = rt._read_memory(100, 32)
        assert first != second

    def test_counter_increments(self, rt):
        """Internal counter should increment with each call."""
        etxn_nonce(rt, 0, 32)
        assert rt._emit_nonce_counter == 1
        etxn_nonce(rt, 0, 32)
        assert rt._emit_nonce_counter == 2

    def test_nonce_is_deterministic(self, rt):
        """Same counter value should produce same nonce across runs."""
        etxn_nonce(rt, 0, 32)
        first = rt._read_memory(0, 32)

        rt2 = HookRuntime()
        rt2._store = rt._store
        rt2._memory = rt._memory
        etxn_nonce(rt2, 0, 32)
        second = rt2._read_memory(0, 32)

        assert first == second


class TestPrepare:
    """prepare: copy input transaction bytes to output buffer."""

    def test_basic_copy(self, rt):
        """Input bytes are copied to output buffer, returns length."""
        blob = b"\x12\x00\x00\x22\x00\x00\x00\x01"  # minimal tx-like blob
        rt._write_memory(100, blob)
        result = prepare(rt, 0, 256, 100, len(blob))
        assert result == len(blob)
        assert rt._read_memory(0, len(blob)) == blob

    def test_empty_input(self, rt):
        """Zero-length read -> TOO_SMALL."""
        assert prepare(rt, 0, 256, 100, 0) == hookapi.TOO_SMALL

    def test_write_buf_too_small(self, rt):
        """write_len smaller than input -> TOO_SMALL."""
        blob = b"\xAB" * 20
        rt._write_memory(100, blob)
        assert prepare(rt, 0, 10, 100, 20) == hookapi.TOO_SMALL

    def test_exact_fit(self, rt):
        """write_len exactly equals input length."""
        blob = b"\xCD" * 50
        rt._write_memory(200, blob)
        result = prepare(rt, 0, 50, 200, 50)
        assert result == 50
        assert rt._read_memory(0, 50) == blob

    def test_preserves_existing_memory(self, rt):
        """Only the written region is affected."""
        rt._write_memory(0, b"\xFF" * 100)
        blob = b"\x00" * 10
        rt._write_memory(200, blob)
        prepare(rt, 50, 100, 200, 10)
        # Before the write region is untouched
        assert rt._read_memory(0, 50) == b"\xFF" * 50
        # Written region has the blob
        assert rt._read_memory(50, 10) == blob
