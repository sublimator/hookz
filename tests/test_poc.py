"""Proof of concept — run inline WASM hooks from Python."""

import subprocess
from pathlib import Path

import pytest

from hookz.runtime import HookRuntime
from location_consts import WASI_SDK

pytestmark = pytest.mark.skipif(WASI_SDK is None, reason="wasi-sdk not found")


INLINE_HOOK_ACCEPT = r"""
#include <stdint.h>
extern int32_t _g(uint32_t, uint32_t);
extern int64_t accept(uint32_t, uint32_t, int64_t);
int64_t hook(uint32_t r) {
    _g(1, 1);
    return accept(0, 0, 42);
}
"""

INLINE_HOOK_STATE = r"""
#include <stdint.h>
extern int32_t _g(uint32_t, uint32_t);
extern int64_t accept(uint32_t, uint32_t, int64_t);
extern int64_t rollback(uint32_t, uint32_t, int64_t);
extern int64_t state(uint32_t, uint32_t, uint32_t, uint32_t);
extern int64_t state_set(uint32_t, uint32_t, uint32_t, uint32_t);
int64_t hook(uint32_t r) {
    _g(1, 1);
    uint8_t key[4] = "test";
    uint8_t val[8];
    int64_t len = state((uint32_t)val, 8, (uint32_t)key, 4);
    if (len < 0)
        return rollback("no state", 8, len);
    return accept("ok", 2, len);
}
"""


def _compile_inline(source: str) -> bytes:
    """Compile inline C source to WASM."""
    clang = WASI_SDK / "bin" / "clang"
    sysroot = WASI_SDK / "share" / "wasi-sysroot"
    cmd = [
        str(clang), "--target=wasm32-wasip1", f"--sysroot={sysroot}",
        "-nostdlib", "-g", "-O0",
        "-Wno-incompatible-pointer-types", "-Wno-int-conversion",
        "-Wl,--allow-undefined", "-Wl,--no-entry", "-Wl,--export=hook",
        "-x", "c", "/dev/stdin", "-o", "/dev/stdout",
    ]
    r = subprocess.run(cmd, input=source.encode(), capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"Compilation failed:\n{r.stderr.decode()}")
    return r.stdout


class TestBasicExecution:
    """Verify that we can execute WASM hooks from Python."""

    def test_inline_hook_accept(self):
        wasm = _compile_inline(INLINE_HOOK_ACCEPT)
        rt = HookRuntime()
        result = rt.run(wasm)
        assert result.accepted
        assert result.return_code == 42

    def test_inline_hook_state_missing(self):
        wasm = _compile_inline(INLINE_HOOK_STATE)
        rt = HookRuntime()
        result = rt.run(wasm)
        assert result.rejected
        assert b"no state" in result.return_msg

    def test_inline_hook_state_present(self):
        wasm = _compile_inline(INLINE_HOOK_STATE)
        rt = HookRuntime()
        rt.state_db[b"test"] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        result = rt.run(wasm)
        assert result.accepted
        assert result.return_code == 8

    def test_call_log(self):
        wasm = _compile_inline(INLINE_HOOK_ACCEPT)
        rt = HookRuntime()
        result = rt.run(wasm)
        names = [c.name for c in result.call_log]
        assert "_g" in names
        assert "accept" in names
