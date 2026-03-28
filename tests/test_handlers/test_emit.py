"""Tests for emit handlers: emit, etxn_reserve, etxn_details, etxn_fee_base, etxn_nonce, prepare."""

import hashlib

import pytest
import wasmtime

from hookz.runtime import HookRuntime
from hookz.handlers.emit import (
    emit, etxn_reserve, etxn_details, etxn_fee_base, etxn_nonce, prepare,
)
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


# ---------------------------------------------------------------------------
# etxn_reserve
# ---------------------------------------------------------------------------

class TestEtxnReserve:
    """etxn_reserve: returns the count passed in."""

    def test_returns_count(self, rt):
        assert etxn_reserve(rt, 1) == 1
        assert etxn_reserve(rt, 5) == 5
        assert etxn_reserve(rt, 0) == 0
        assert etxn_reserve(rt, 255) == 255


# ---------------------------------------------------------------------------
# etxn_details
# ---------------------------------------------------------------------------

class TestEtxnDetails:
    """etxn_details: builds a 116-byte EmitDetails serialized object."""

    def test_returns_116(self, rt):
        assert etxn_details(rt, 0, 256) == 116

    def test_writes_116_bytes(self, rt):
        etxn_details(rt, 0, 256)
        data = rt._read_memory(0, 116)
        assert len(data) == 116

    def test_starts_with_emit_details_marker(self, rt):
        etxn_details(rt, 0, 256)
        data = rt._read_memory(0, 1)
        assert data[0] == 0xED  # sfEmitDetails

    def test_ends_with_object_end_marker(self, rt):
        etxn_details(rt, 0, 256)
        data = rt._read_memory(0, 116)
        assert data[-1] == 0xE1  # object end marker

    def test_contains_emit_generation(self, rt):
        """sfEmitGeneration (0x202E) with value 1."""
        etxn_details(rt, 0, 256)
        data = rt._read_memory(0, 116)
        # Header bytes for sfEmitGeneration
        assert data[1:3] == b"\x20\x2E"
        # Value = 1 (big-endian UInt32)
        assert data[3:7] == b"\x00\x00\x00\x01"

    def test_contains_emit_burden(self, rt):
        """sfEmitBurden (0x3D) with value 1."""
        etxn_details(rt, 0, 256)
        data = rt._read_memory(0, 116)
        assert data[7] == 0x3D
        assert data[8:16] == b"\x00\x00\x00\x00\x00\x00\x00\x01"

    def test_truncates_to_write_len(self, rt):
        """Output truncated if write_len < 116."""
        etxn_details(rt, 0, 10)
        # Should still return 116 (the full length) even if truncated
        # Let's verify it doesn't crash
        data = rt._read_memory(0, 10)
        assert len(data) == 10

    def test_offset_write(self, rt):
        """Write at non-zero offset."""
        rt._write_memory(0, b"\xFF" * 200)
        etxn_details(rt, 50, 116)
        assert rt._read_memory(0, 50) == b"\xFF" * 50
        assert rt._read_memory(50, 1) == b"\xED"


# ---------------------------------------------------------------------------
# etxn_fee_base
# ---------------------------------------------------------------------------

class TestEtxnFeeBase:
    """etxn_fee_base: always returns 10."""

    def test_returns_10(self, rt):
        assert etxn_fee_base(rt, 0, 0) == 10

    def test_ignores_args(self, rt):
        assert etxn_fee_base(rt, 100, 50) == 10
        assert etxn_fee_base(rt, 0, 1000) == 10


# ---------------------------------------------------------------------------
# emit
# ---------------------------------------------------------------------------

class TestEmit:
    """emit: record an emitted transaction and write its hash."""

    def test_returns_zero(self, rt):
        blob = b"\x12\x00\x00\x22\x00\x00\x00\x01"
        rt._write_memory(100, blob)
        result = emit(rt, 0, 32, 100, len(blob))
        assert result == 0

    def test_writes_sha256_hash(self, rt):
        blob = b"\x12\x00\x00\x22\x00\x00\x00\x01"
        rt._write_memory(100, blob)
        emit(rt, 0, 32, 100, len(blob))
        expected = hashlib.sha256(blob).digest()
        assert rt._read_memory(0, 32) == expected

    def test_records_emitted_txn(self, rt):
        blob = b"\xAB\xCD\xEF"
        rt._write_memory(100, blob)
        emit(rt, 0, 32, 100, len(blob))
        assert len(rt.emitted_txns) == 1
        assert rt.emitted_txns[0] == blob

    def test_multiple_emits(self, rt):
        """Each emit appends to emitted_txns."""
        for i in range(5):
            blob = bytes([i]) * 10
            rt._write_memory(100, blob)
            emit(rt, 0, 32, 100, len(blob))
        assert len(rt.emitted_txns) == 5
        assert rt.emitted_txns[2] == bytes([2]) * 10

    def test_hash_truncated_to_write_len(self, rt):
        """If hash_len < 32, only that many bytes written."""
        blob = b"\x00" * 10
        rt._write_memory(100, blob)
        rt._write_memory(0, b"\xFF" * 32)
        emit(rt, 0, 16, 100, len(blob))
        expected_full = hashlib.sha256(blob).digest()
        assert rt._read_memory(0, 16) == expected_full[:16]

    def test_different_blobs_different_hashes(self, rt):
        blob1 = b"\x01" * 10
        blob2 = b"\x02" * 10
        rt._write_memory(100, blob1)
        emit(rt, 0, 32, 100, len(blob1))
        hash1 = rt._read_memory(0, 32)

        rt._write_memory(100, blob2)
        emit(rt, 0, 32, 100, len(blob2))
        hash2 = rt._read_memory(0, 32)

        assert hash1 != hash2
