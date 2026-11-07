"""Tests for accept() / rollback() — the host's HOOK_EXIT macro.

xahaud:include/xrpl/hook/Macro.h:235-276, entered from
xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1770 (accept) and :1784
(rollback).
"""

import pytest
import wasmtime

from hookz import hookapi
from hookz.handlers.core import accept, rollback
from hookz.runtime import HookAccepted, HookRejected, HookRuntime


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r


EXITS = [(accept, HookAccepted), (rollback, HookRejected)]
EXIT_IDS = ["accept", "rollback"]

# xahaud:src/test/app/SetHook_test.cpp:3627 / :3639
OOB_PTR = 0xFFFFFF00


def _memory_end(rt) -> int:
    return rt._memory.data_len(rt._store)


class TestReasonOutOfBounds:
    """A reason buffer outside memory, either side of fix20260929
    (xahaud:include/xrpl/hook/Macro.h:241-253)."""

    @pytest.mark.parametrize("fn,_exc", EXITS, ids=EXIT_IDS)
    def test_with_fix_it_ends_the_hook_as_a_rollback(self, rt, fn, _exc):
        """Whichever was called, the hook ends as ROLLBACK with exit code
        OUT_OF_BOUNDS and no reason."""
        assert "fix20260929" in rt.amendments, "mainnet default carries the fix"
        with pytest.raises(HookRejected) as e:
            fn(rt, OOB_PTR, 32, 42)
        assert e.value.code == hookapi.OUT_OF_BOUNDS
        assert e.value.msg == b""

    @pytest.mark.parametrize("fn,_exc", EXITS, ids=EXIT_IDS)
    def test_without_fix_the_call_returns_and_the_hook_runs_on(self, rt, fn, _exc):
        rt.amendments.discard("fix20260929")
        assert fn(rt, OOB_PTR, 32, 42) == hookapi.OUT_OF_BOUNDS

    @pytest.mark.parametrize("fn,_exc", EXITS, ids=EXIT_IDS)
    def test_a_signed_pointer_is_compared_unsigned(self, rt, fn, _exc):
        """0xFFFFFF00 can reach a handler as -256."""
        rt.amendments.discard("fix20260929")
        assert fn(rt, -256, 32, 42) == hookapi.OUT_OF_BOUNDS

    @pytest.mark.parametrize("fn,_exc", EXITS, ids=EXIT_IDS)
    def test_straddling_the_end_is_out_of_bounds(self, rt, fn, _exc):
        """wasmtime's Memory.read clamps; the host does not. A reason running
        past the end used to be accepted, truncated."""
        rt.amendments.discard("fix20260929")
        assert fn(rt, _memory_end(rt) - 4, 8, 42) == hookapi.OUT_OF_BOUNDS


class TestReasonShape:
    """What becomes the exit reason (xahaud:include/xrpl/hook/Macro.h:237-269)."""

    @pytest.mark.parametrize("fn,exc", EXITS, ids=EXIT_IDS)
    def test_the_reason_and_code(self, rt, fn, exc):
        rt._write_memory(100, b"done")
        with pytest.raises(exc) as e:
            fn(rt, 100, 4, 7)
        assert (e.value.msg, e.value.code) == (b"done", 7)

    @pytest.mark.parametrize("fn,exc", EXITS, ids=EXIT_IDS)
    def test_a_null_pointer_is_no_reason_whatever_the_length(self, rt, fn, exc):
        """Macro.h:239 — not a read of address 0, and no bounds test, so even
        a length past the end of memory exits normally."""
        rt._write_memory(0, b"not a reason")
        with pytest.raises(exc) as e:
            fn(rt, 0, 12, 7)
        assert (e.value.msg, e.value.code) == (b"", 7)
        with pytest.raises(exc) as e:
            fn(rt, 0, 0xFFFFFFFF, 7)
        assert (e.value.msg, e.value.code) == (b"", 7)

    @pytest.mark.parametrize("fn,exc", EXITS, ids=EXIT_IDS)
    def test_the_reason_is_capped_at_256(self, rt, fn, exc):
        rt._write_memory(100, bytes(range(1, 256)) + b"\x41" * 45)
        with pytest.raises(exc) as e:
            fn(rt, 100, 300, 7)
        assert len(e.value.msg) == 256

    @pytest.mark.parametrize("fn,exc", EXITS, ids=EXIT_IDS)
    def test_the_cap_comes_before_the_bounds_test(self, rt, fn, exc):
        """Macro.h:237 shortens read_len before :241 tests it, so a long
        length ending past memory is fine if its first 256 bytes are not."""
        start = _memory_end(rt) - 256
        rt._write_memory(start, b"\x41" * 256)
        with pytest.raises(exc) as e:
            fn(rt, start, 1000, 7)
        assert e.value.msg == b"\x41" * 256

    @pytest.mark.parametrize("fn,exc", EXITS, ids=EXIT_IDS)
    def test_utf16le_collapses_to_its_even_bytes(self, rt, fn, exc):
        """AssemblyScript strings (Macro.h:257-265)."""
        rt._write_memory(100, "oops".encode("utf-16-le"))
        with pytest.raises(exc) as e:
            fn(rt, 100, 8, 7)
        assert e.value.msg == b"oops"

    @pytest.mark.parametrize("raw", [
        b"o\x00o\x00p",        # odd length
        b"o\x00\x00\x00",      # a zero even byte
        b"oo",                 # a non-zero odd byte
    ], ids=["odd-length", "zero-even-byte", "nonzero-odd-byte"])
    def test_not_utf16le_is_kept_as_is(self, rt, raw):
        """The heuristic (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:714)."""
        rt._write_memory(100, raw)
        with pytest.raises(HookAccepted) as e:
            accept(rt, 100, len(raw), 7)
        assert e.value.msg == raw


class TestExitOutOfBoundsVector:
    """xahaud:src/test/app/SetHook_test.cpp:3613-3684 (test_exit_out_of_bounds):
    `accept`/`rollback(0xFFFFFF00, 32, 42)`, then fall through.

    With fix20260929 the execution is a ROLLBACK, exit code OUT_OF_BOUNDS, no
    reason. Without it the call returns OUT_OF_BOUNDS and the hook carries
    on — here it returns what the call returned, so that is visible.
    (Upstream records that fall-through as UNSET with the default exit code
    -1; hookz records the hook's own return value.)
    """

    WAT = """
    (module
      (import "env" "_g" (func $_g (param i32 i32) (result i32)))
      (import "env" "{fn}" (func $exit (param i32 i32 i64) (result i64)))
      (memory 1)
      (export "memory" (memory 0))
      (func (export "hook") (param i32) (result i64)
        (drop (call $_g (i32.const 1) (i32.const 1)))
        (call $exit (i32.const 0xFFFFFF00) (i32.const 32) (i64.const 42))))
    """

    def _run(self, fn: str, fix: bool):
        rt = HookRuntime()
        if not fix:
            rt.amendments.discard("fix20260929")
        return rt.run(bytes(wasmtime.wat2wasm(self.WAT.format(fn=fn))))

    @pytest.mark.parametrize("fn", EXIT_IDS)
    def test_with_fix(self, fn):
        r = self._run(fn, fix=True)
        assert r.error is None
        assert r.rejected and not r.accepted
        assert r.return_code == hookapi.OUT_OF_BOUNDS
        assert r.return_msg == b""

    @pytest.mark.parametrize("fn", EXIT_IDS)
    def test_without_fix(self, fn):
        r = self._run(fn, fix=False)
        assert r.error is None
        assert not r.rejected and not r.accepted
        assert r.return_code == hookapi.OUT_OF_BOUNDS
