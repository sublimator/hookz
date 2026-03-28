"""Test marker-based coverage assertions."""

import subprocess
import tempfile
from pathlib import Path

import pytest

from hookz.coverage.markers import parse_markers
from hookz.runtime import HookRuntime
from hookz.coverage.rewriter import instrument_wasm
from location_consts import WASI_SDK, FIXTURES

pytestmark = pytest.mark.skipif(WASI_SDK is None, reason="wasi-sdk not found")


def _compile(source: Path) -> tuple[bytes, str]:
    clang = WASI_SDK / "bin" / "clang"
    sysroot = WASI_SDK / "share" / "wasi-sysroot"
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.close()
    r = subprocess.run([
        str(clang), "--target=wasm32-wasip1", f"--sysroot={sysroot}",
        "-nostdlib", "-g", "-O0",
        "-Wno-incompatible-pointer-types", "-Wno-int-conversion",
        "-Wl,--allow-undefined", "-Wl,--no-entry", "-Wl,--export=hook",
        "-x", "c", str(source), "-o", tmp.name,
    ], capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode())
    return Path(tmp.name).read_bytes(), tmp.name


class TestParseMarkers:
    def test_finds_all_markers(self):
        markers = parse_markers(FIXTURES / "marked_hook.c")
        names = [m.name for m in markers]
        assert "hook_entry" in names
        assert "state_read" in names
        assert "no_state" in names
        assert "big_value" in names
        assert "small_value" in names

    def test_regions_have_ranges(self):
        markers = parse_markers(FIXTURES / "marked_hook.c")
        by_name = {m.name: m for m in markers}

        # hook_entry should span the whole function
        he = by_name["hook_entry"]
        assert he.region_end > he.region_start

        # no_state is an if — should include the rollback line
        ns = by_name["no_state"]
        assert ns.region_end > ns.region_start

        for m in markers:
            print(f"  {m.name:20s} lines {m.region_start}-{m.region_end} [{m.node_type}] {m.context}")


class TestMarkerCoverage:
    @pytest.fixture
    def wasm(self):
        wasm_bytes, path = _compile(FIXTURES / "marked_hook.c")
        instrumented, _ = instrument_wasm(wasm_bytes, path)
        return instrumented

    def _run_with_markers(self, wasm, state_db=None):
        rt = HookRuntime()
        rt.coverage.load_source_markers(FIXTURES / "marked_hook.c")
        if state_db:
            rt.state_db.update(state_db)
        result = rt.run(wasm)
        return rt, result

    def test_render_all_paths(self, wasm):
        """Visualize coverage for each code path."""
        for label, state_db in [
            ("no state", {}),
            ("small (4 bytes)", {b"test": b"\x01\x02\x03\x04"}),
            ("big (8 bytes)", {b"test": b"\x01\x02\x03\x04\x05\x06\x07\x08"}),
        ]:
            rt, result = self._run_with_markers(wasm, state_db)
            status = "ACCEPT" if result.accepted else "REJECT"
            print(f"\n{'='*60}")
            print(f"Path: {label} → {status} msg={result.return_msg}")
            print(f"{'='*60}")
            print(rt.coverage.render_source(FIXTURES / "marked_hook.c"))
            print()
            print(rt.coverage.render_markers())

    def test_state_missing_path(self, wasm):
        """When state is missing, no_state region is entered."""
        rt, result = self._run_with_markers(wasm)
        assert result.rejected
        print(f"\n{rt.coverage.render_region('no_state')}")
        print(f"\n{rt.coverage.render_region('big_value')}")
        assert rt.coverage.region("hook_entry").entered
        assert rt.coverage.region("no_state").entered
        assert rt.coverage.region("big_value").not_entered

    def test_small_value_path(self, wasm):
        """With 4 bytes of state, small_value is hit."""
        rt, result = self._run_with_markers(wasm, {b"test": b"\x01\x02\x03\x04"})
        assert result.accepted
        print(f"\n{rt.coverage.render_region('no_state')}")
        print(f"\n{rt.coverage.render_region('small_value')}")
        assert rt.coverage.region("hook_entry").entered
        assert rt.coverage.marker("small_value").hit

    def test_big_value_path(self, wasm):
        """With 8 bytes of state, big_value region is entered."""
        rt, result = self._run_with_markers(wasm, {b"test": b"\x01\x02\x03\x04\x05\x06\x07\x08"})
        assert result.accepted
        print(f"\n{rt.coverage.render_region('big_value')}")
        assert rt.coverage.region("big_value").entered
        assert rt.coverage.marker("small_value").not_hit
