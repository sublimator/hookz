"""Tests for util_accid, util_raddr, hook_skip, and ledger_keylet handlers."""

import pytest
import wasmtime

from hookz.account import to_accid, to_raddr
from hookz.runtime import HookRuntime
from hookz import hookapi
from hookz.handlers.util import (
    util_sha512h, util_keylet, hook_account, ledger_seq, ledger_nonce,
    util_accid, util_raddr, hook_hash, ledger_last_hash, util_verify,
    hook_skip, ledger_keylet,
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


RADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
ACCID = to_accid(RADDR)  # 20 bytes


# ---------------------------------------------------------------------------
# util_sha512h
# ---------------------------------------------------------------------------

class TestUtilSha512h:
    """util_sha512h: SHA-512 half (first 32 bytes)."""

    def test_returns_32(self, rt):
        rt._write_memory(100, b"hello")
        assert util_sha512h(rt, 0, 32, 100, 5) == 32

    def test_correct_hash(self, rt):
        import hashlib
        data = b"hello"
        expected = hashlib.sha512(data).digest()[:32]
        rt._write_memory(100, data)
        util_sha512h(rt, 0, 32, 100, len(data))
        assert rt._read_memory(0, 32) == expected

    def test_empty_input(self, rt):
        import hashlib
        expected = hashlib.sha512(b"").digest()[:32]
        result = util_sha512h(rt, 0, 32, 100, 0)
        assert result == 32
        assert rt._read_memory(0, 32) == expected

    def test_too_small_write_len(self, rt):
        """write_len < 32 should return TOO_SMALL."""
        rt._write_memory(100, b"test")
        assert util_sha512h(rt, 0, 16, 100, 4) == hookapi.TOO_SMALL

    def test_different_inputs_different_hashes(self, rt):
        rt._write_memory(100, b"aaa")
        util_sha512h(rt, 0, 32, 100, 3)
        h1 = rt._read_memory(0, 32)
        rt._write_memory(100, b"bbb")
        util_sha512h(rt, 0, 32, 100, 3)
        h2 = rt._read_memory(0, 32)
        assert h1 != h2


# ---------------------------------------------------------------------------
# util_keylet
# ---------------------------------------------------------------------------

class TestUtilKeylet:
    """util_keylet: construct a keylet (stub)."""

    def test_returns_34(self, rt):
        assert util_keylet(rt, 0, 34) == 34

    def test_writes_34_zero_bytes(self, rt):
        util_keylet(rt, 0, 34)
        assert rt._read_memory(0, 34) == b"\x00" * 34


# ---------------------------------------------------------------------------
# hook_account
# ---------------------------------------------------------------------------

class TestHookAccount:
    """hook_account: write the 20-byte hook account."""

    def test_returns_20(self, rt):
        assert hook_account(rt, 0, 20) == 20

    def test_writes_hook_account(self, rt):
        rt.hook_account = b"\xAB" * 20
        hook_account(rt, 0, 20)
        assert rt._read_memory(0, 20) == b"\xAB" * 20

    def test_too_small(self, rt):
        assert hook_account(rt, 0, 19) == hookapi.TOO_SMALL

    def test_at_ptr_zero(self, rt):
        rt.hook_account = b"\x01" * 20
        hook_account(rt, 0, 20)
        assert rt._read_memory(0, 20) == b"\x01" * 20


# ---------------------------------------------------------------------------
# ledger_seq
# ---------------------------------------------------------------------------

class TestLedgerSeq:
    """ledger_seq: return current ledger sequence."""

    def test_default(self, rt):
        assert ledger_seq(rt) == rt.ledger_seq_val

    def test_custom_value(self, rt):
        rt.ledger_seq_val = 42
        assert ledger_seq(rt) == 42

    def test_large_value(self, rt):
        rt.ledger_seq_val = 99_999_999
        assert ledger_seq(rt) == 99_999_999


# ---------------------------------------------------------------------------
# ledger_nonce
# ---------------------------------------------------------------------------

class TestLedgerNonce:
    """ledger_nonce: write 32-byte nonce."""

    def test_returns_32(self, rt):
        assert ledger_nonce(rt, 0, 32) == 32

    def test_writes_32_bytes(self, rt):
        ledger_nonce(rt, 0, 32)
        data = rt._read_memory(0, 32)
        assert len(data) == 32
        assert data == b"\xCD" * 32

    def test_too_small(self, rt):
        assert ledger_nonce(rt, 0, 31) == hookapi.TOO_SMALL


class TestUtilAccid:
    """util_accid: r-address string -> 20-byte account ID."""

    def test_basic(self, rt):
        raddr_bytes = RADDR.encode("ascii")
        rt._write_memory(100, raddr_bytes)
        result = util_accid(rt, 0, 20, 100, len(raddr_bytes))
        assert result == 20
        assert rt._read_memory(0, 20) == ACCID

    def test_too_small_write_buf(self, rt):
        raddr_bytes = RADDR.encode("ascii")
        rt._write_memory(100, raddr_bytes)
        result = util_accid(rt, 0, 19, 100, len(raddr_bytes))
        assert result == hookapi.TOO_SMALL

    def test_too_big_read_len(self, rt):
        result = util_accid(rt, 0, 20, 100, 50)
        assert result == hookapi.TOO_BIG

    def test_invalid_raddr(self, rt):
        bad = b"notAnAddress"
        rt._write_memory(100, bad)
        result = util_accid(rt, 0, 20, 100, len(bad))
        assert result == hookapi.INVALID_ARGUMENT

    def test_null_terminated(self, rt):
        """r-address followed by null byte should still decode."""
        raddr_bytes = RADDR.encode("ascii") + b"\x00"
        rt._write_memory(100, raddr_bytes)
        result = util_accid(rt, 0, 20, 100, len(raddr_bytes))
        assert result == 20
        assert rt._read_memory(0, 20) == ACCID


class TestUtilRaddr:
    """util_raddr: 20-byte account ID -> r-address string."""

    def test_basic(self, rt):
        rt._write_memory(100, ACCID)
        result = util_raddr(rt, 0, 50, 100, 20)
        assert result == len(RADDR)
        assert rt._read_memory(0, result) == RADDR.encode("ascii")

    def test_too_small_write_buf(self, rt):
        rt._write_memory(100, ACCID)
        result = util_raddr(rt, 0, 5, 100, 20)
        assert result == hookapi.TOO_SMALL

    def test_invalid_accid_wrong_length(self, rt):
        bad = b"\x00" * 10
        rt._write_memory(100, bad)
        result = util_raddr(rt, 0, 50, 100, 10)
        assert result == hookapi.INVALID_ARGUMENT

    def test_roundtrip(self, rt):
        """accid -> raddr -> accid roundtrip."""
        rt._write_memory(100, ACCID)
        rlen = util_raddr(rt, 0, 50, 100, 20)
        assert rlen > 0
        result = util_accid(rt, 200, 20, 0, rlen)
        assert result == 20
        assert rt._read_memory(200, 20) == ACCID


class TestHookHash:
    """hook_hash: write 32-byte hook hash."""

    def test_returns_32(self, rt):
        assert hook_hash(rt, 0, 32, -1) == 32

    def test_writes_32_zero_bytes(self, rt):
        hook_hash(rt, 0, 32, -1)
        assert rt._read_memory(0, 32) == b"\x00" * 32

    def test_too_small(self, rt):
        assert hook_hash(rt, 0, 31, -1) == hookapi.TOO_SMALL

    def test_different_hook_no(self, rt):
        """hook_no parameter accepted without error."""
        assert hook_hash(rt, 0, 32, 0) == 32
        assert hook_hash(rt, 0, 32, 5) == 32


class TestLedgerLastHash:
    """ledger_last_hash: write 32-byte ledger hash."""

    def test_returns_32(self, rt):
        assert ledger_last_hash(rt, 0, 32) == 32

    def test_writes_32_bytes(self, rt):
        ledger_last_hash(rt, 0, 32)
        data = rt._read_memory(0, 32)
        assert len(data) == 32
        assert data != b"\x00" * 32  # deterministic but non-zero

    def test_too_small(self, rt):
        assert ledger_last_hash(rt, 0, 31) == hookapi.TOO_SMALL

    def test_deterministic(self, rt):
        """Same value every call."""
        ledger_last_hash(rt, 0, 32)
        first = rt._read_memory(0, 32)
        ledger_last_hash(rt, 100, 32)
        second = rt._read_memory(100, 32)
        assert first == second


class TestUtilVerify:
    """util_verify: verify a signature against data and a public key."""

    def test_default_returns_valid(self, rt):
        """Default stub returns 1 (valid) when args are well-formed."""
        rt._write_memory(0, b"\xAB" * 50)     # data
        rt._write_memory(100, b"\xCD" * 72)    # sig (DER sigs are ~70-72 bytes)
        rt._write_memory(200, b"\x02" + b"\x00" * 32)  # 33-byte key
        result = util_verify(rt, 0, 50, 100, 72, 200, 33)
        assert result == 1

    def test_invalid_key_length(self, rt):
        """Key must be exactly 33 bytes."""
        result = util_verify(rt, 0, 10, 100, 30, 200, 32)
        assert result == hookapi.INVALID_KEY

    def test_empty_data(self, rt):
        """Empty data -> TOO_SMALL."""
        result = util_verify(rt, 0, 0, 100, 30, 200, 33)
        assert result == hookapi.TOO_SMALL

    def test_short_signature(self, rt):
        """Signature < 30 bytes -> TOO_SMALL."""
        result = util_verify(rt, 0, 10, 100, 29, 200, 33)
        assert result == hookapi.TOO_SMALL

    def test_sig_exactly_30_bytes(self, rt):
        """Signature of exactly 30 bytes should pass validation."""
        rt._write_memory(0, b"\xAB" * 10)
        rt._write_memory(100, b"\xCD" * 30)
        rt._write_memory(200, b"\x02" + b"\x00" * 32)
        result = util_verify(rt, 0, 10, 100, 30, 200, 33)
        assert result == 1

    def test_override_returns_invalid(self, rt):
        """rt.handlers override can return 0 (invalid)."""
        rt.handlers = {"util_verify": lambda data, sig, key: 0}
        rt._write_memory(0, b"\xAB" * 10)
        rt._write_memory(100, b"\xCD" * 30)
        rt._write_memory(200, b"\x02" + b"\x00" * 32)
        result = util_verify(rt, 0, 10, 100, 30, 200, 33)
        assert result == 0

    def test_override_receives_correct_bytes(self, rt):
        """Override callable receives the exact memory slices."""
        captured = {}

        def spy(data, sig, key):
            captured["data"] = data
            captured["sig"] = sig
            captured["key"] = key
            return 1

        rt.handlers = {"util_verify": spy}
        rt._write_memory(0, b"\x01\x02\x03")
        rt._write_memory(100, b"\xAA" * 30)
        rt._write_memory(200, b"\xBB" * 33)
        util_verify(rt, 0, 3, 100, 30, 200, 33)
        assert captured["data"] == b"\x01\x02\x03"
        assert captured["sig"] == b"\xAA" * 30
        assert captured["key"] == b"\xBB" * 33


class TestHookSkip:
    """hook_skip: skip execution of another hook."""

    def test_returns_1(self, rt):
        rt._write_memory(0, b"\xAA" * 32)
        assert hook_skip(rt, 0, 32, 0) == 1

    def test_delete_flag_returns_1(self, rt):
        rt._write_memory(0, b"\xAA" * 32)
        assert hook_skip(rt, 0, 32, 1) == 1

    def test_invalid_hash_len(self, rt):
        assert hook_skip(rt, 0, 31, 0) == hookapi.INVALID_ARGUMENT
        assert hook_skip(rt, 0, 33, 0) == hookapi.INVALID_ARGUMENT

    def test_invalid_flags(self, rt):
        rt._write_memory(0, b"\xAA" * 32)
        assert hook_skip(rt, 0, 32, 2) == hookapi.INVALID_ARGUMENT


class TestLedgerKeylet:
    """ledger_keylet: construct a keylet from components."""

    def test_returns_34(self, rt):
        rt._write_memory(100, b"\x00" * 34)
        rt._write_memory(200, b"\x00" * 34)
        result = ledger_keylet(rt, 0, 34, 100, 34, 200, 34)
        assert result == 34

    def test_writes_34_zero_bytes(self, rt):
        rt._write_memory(100, b"\x00" * 34)
        rt._write_memory(200, b"\x00" * 34)
        ledger_keylet(rt, 0, 34, 100, 34, 200, 34)
        assert rt._read_memory(0, 34) == b"\x00" * 34

    def test_too_small_write(self, rt):
        assert ledger_keylet(rt, 0, 33, 100, 34, 200, 34) == hookapi.TOO_SMALL

    def test_too_small_lread(self, rt):
        assert ledger_keylet(rt, 0, 34, 100, 33, 200, 34) == hookapi.TOO_SMALL

    def test_too_small_hread(self, rt):
        assert ledger_keylet(rt, 0, 34, 100, 34, 200, 33) == hookapi.TOO_SMALL

    def test_too_big_write(self, rt):
        assert ledger_keylet(rt, 0, 35, 100, 34, 200, 34) == hookapi.TOO_BIG

    def test_too_big_lread(self, rt):
        assert ledger_keylet(rt, 0, 34, 100, 35, 200, 34) == hookapi.TOO_BIG

    def test_too_big_hread(self, rt):
        assert ledger_keylet(rt, 0, 34, 100, 34, 200, 35) == hookapi.TOO_BIG
