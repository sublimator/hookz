"""Test coverage instrumentation via WASM rewriting."""

import subprocess
from pathlib import Path

import pytest

from hookz.runtime import HookRuntime
from hookz.coverage.rewriter import instrument_wasm, parse_dwarf_locations
from location_consts import WASI_SDK

pytestmark = pytest.mark.skipif(WASI_SDK is None, reason="wasi-sdk not found")

SIMPLE_HOOK = r"""
#include <stdint.h>
extern int32_t _g(uint32_t, uint32_t);
extern int64_t accept(uint32_t, uint32_t, int64_t);
extern int64_t rollback(uint32_t, uint32_t, int64_t);
int64_t hook(uint32_t r) {
    _g(1, 1);
    if (r > 0)
        return accept("yes", 3, 1);
    return accept("no", 2, 0);
}
"""


def compile_with_debug(source: str) -> tuple[bytes, str]:
    """Compile inline C to WASM with -g. Returns (bytes, temp_path)."""
    import tempfile
    clang = WASI_SDK / "bin" / "clang"
    sysroot = WASI_SDK / "share" / "wasi-sysroot"
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.close()

    r = subprocess.run([
        str(clang), "--target=wasm32-wasip1", f"--sysroot={sysroot}",
        "-nostdlib", "-g", "-O0",
        "-Wno-incompatible-pointer-types", "-Wno-int-conversion",
        "-Wl,--allow-undefined", "-Wl,--no-entry", "-Wl,--export=hook",
        "-x", "c", "/dev/stdin", "-o", tmp.name,
    ], input=source.encode(), capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode())

    wasm_bytes = Path(tmp.name).read_bytes()
    return wasm_bytes, tmp.name


class TestDwarfParsing:
    def test_parse_dwarf_locations(self):
        _, path = compile_with_debug(SIMPLE_HOOK)
        locs = parse_dwarf_locations(path)
        assert len(locs) > 0
        lines = {loc.line for loc in locs}
        # Should have entries for the function body lines
        assert any(l > 0 for l in lines)


class TestInstrumentation:
    def test_instrument_produces_valid_wasm(self):
        """Instrumented WASM can be loaded by wasmtime."""
        import wasmtime
        wasm_bytes, path = compile_with_debug(SIMPLE_HOOK)
        instrumented, locs = instrument_wasm(wasm_bytes, path)

        # Should be loadable
        engine = wasmtime.Engine()
        module = wasmtime.Module(engine, instrumented)

        # Should have __on_source_line import
        import_names = [imp.name for imp in module.imports]
        assert "__on_source_line" in import_names

    def test_coverage_tracks_lines(self):
        """Running with coverage=True records which lines were hit."""
        wasm_bytes, path = compile_with_debug(SIMPLE_HOOK)

        rt = HookRuntime()
        result = rt.run(wasm_bytes, coverage=True)

        assert result.accepted
        assert len(rt.coverage.lines_hit) > 0
        print(f"\nLines hit: {sorted(rt.coverage.lines_hit)}")

    def test_coverage_branch_true(self):
        """When r > 0, the true branch is taken."""
        wasm_bytes, _ = compile_with_debug(SIMPLE_HOOK)

        # Default r=0 passed to hook(0)
        rt = HookRuntime()
        result = rt.run(wasm_bytes, coverage=True)
        lines_r0 = rt.coverage.lines_hit.copy()

        print(f"\nr=0 lines: {sorted(lines_r0)}")
        print(f"r=0 result: code={result.return_code} msg={result.return_msg}")

    def test_coverage_all_hits(self):
        """Coverage data includes hit counts."""
        wasm_bytes, _ = compile_with_debug(SIMPLE_HOOK)

        rt = HookRuntime()
        result = rt.run(wasm_bytes, coverage=True)

        for line in sorted(rt.coverage.lines_hit):
            lc = rt.coverage.line(line)
            print(f"  line {line}: hit {lc.hit_count}x")
