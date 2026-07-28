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


# ---------------------------------------------------------------------------
# //@@start … //@@end spans
# ---------------------------------------------------------------------------

class TestBlockMarkers:
    """Paired span markers, read from comment tokens rather than lines."""

    @staticmethod
    def _write(tmp_path, body: str):
        src = tmp_path / "h.c"
        src.write_text(body)
        return src

    def test_a_pair_becomes_one_region(self, tmp_path):
        from hookz.coverage.markers import parse_block_markers

        src = self._write(tmp_path, """
int64_t hook(uint32_t r) {
    //@@start pay
    int a = 1;
    //@@end pay
    return 0;
}
""")
        (block,) = parse_block_markers(src)
        assert block.name == "pay"
        assert block.region_start == 3
        assert block.region_end == 5

    def test_blocks_nest(self, tmp_path):
        from hookz.coverage.markers import parse_block_markers

        src = self._write(tmp_path, """
int64_t hook(uint32_t r) {
    //@@start outer
    //@@start inner
    int a = 1;
    //@@end inner
    int b = 2;
    //@@end outer
    return 0;
}
""")
        spans = {b.name: (b.region_start, b.region_end)
                 for b in parse_block_markers(src)}
        assert spans == {"inner": (4, 6), "outer": (3, 8)}

    def test_a_half_open_span_is_dropped(self, tmp_path):
        """A start with no end would otherwise run to the end of the file and
        claim every line after it."""
        from hookz.coverage.markers import parse_block_markers

        src = self._write(tmp_path, """
int64_t hook(uint32_t r) {
    //@@start never_closed
    int a = 1;
    return 0;
}
""")
        assert parse_block_markers(src) == []

    def test_an_end_with_no_start_is_dropped(self, tmp_path):
        from hookz.coverage.markers import parse_block_markers

        src = self._write(tmp_path, "int64_t hook(uint32_t r) { //@@end orphan\n return 0; }\n")
        assert parse_block_markers(src) == []

    def test_a_marker_inside_a_string_is_not_one(self, tmp_path):
        """The reason these come from tree-sitter comment nodes.

        A line scan matches this and opens a span that never closes, silently
        swallowing the rest of the file into a region nobody wrote.
        """
        from hookz.coverage.markers import parse_block_markers

        src = self._write(tmp_path, """
int64_t hook(uint32_t r) {
    char *s = "//@@start not_a_marker";
    //@@start real
    int a = 1;
    //@@end real
    return 0;
}
""")
        assert [b.name for b in parse_block_markers(src)] == ["real"]

    def test_a_marker_inside_a_block_comment_is_not_one(self, tmp_path):
        from hookz.coverage.markers import parse_block_markers

        src = self._write(tmp_path, """
int64_t hook(uint32_t r) {
    /* disabled for now:
       //@@start commented_out
    */
    return 0;
}
""")
        assert parse_block_markers(src) == []

    def test_a_label_must_be_a_single_word(self, tmp_path):
        from hookz.coverage.markers import parse_block_markers

        src = self._write(tmp_path, """
int64_t hook(uint32_t r) {
    //@@start two words
    int a = 1;
    //@@end two words
    return 0;
}
""")
        assert parse_block_markers(src) == []

    def test_both_marker_spellings_reach_region(self, tmp_path):
        from hookz.coverage.markers import parse_markers

        src = self._write(tmp_path, """
int64_t hook(uint32_t r) {
    //@@start span
    int a = 1; //@point
    //@@end span
    return 0;
}
""")
        assert {m.name for m in parse_markers(src)} == {"span", "point"}


class TestRegionRanking:
    """`regions()` turns a list of line numbers into a list of blocks."""

    def test_worst_first_and_unentered_is_visible(self, tmp_path):
        from hookz.coverage.markers import parse_block_markers
        from hookz.coverage.tracker import CoverageTracker

        src = tmp_path / "h.c"
        src.write_text("""
int64_t hook(uint32_t r) {
    //@@start touched
    int a = 1;
    int b = 2;
    //@@end touched
    //@@start never
    int c = 3;
    int d = 4;
    int e = 5;
    //@@end never
    return 0;
}
""")
        t = CoverageTracker()
        t._markers = parse_block_markers(src)
        # every line in both blocks is executable; only the first block ran
        for ln in (4, 5, 8, 9, 10):
            t._line_hits[ln] = 0
        t._line_hits[4] = 1
        t._line_hits[5] = 1

        ranked = t.regions()
        assert [r.name for r in ranked] == ["never", "touched"], "worst first"
        assert ranked[0].not_entered
        assert ranked[1].completed
        assert "NONE" in t.render_regions()


class TestRegionDenominator:
    """A region's total is the executable lines in its span, not the hits.

    Counting only lines that were hit makes every entered region 100%
    complete and every unentered one 0/0 — so `completed` is true whenever
    anything ran, and a region can never report the gap it exists to report.
    """

    @staticmethod
    def _tracker(tmp_path):
        from hookz.coverage.markers import parse_block_markers
        from hookz.coverage.tracker import CoverageTracker

        src = tmp_path / "h.c"
        src.write_text("""
int64_t hook(uint32_t r) {
    //@@start half
    int a = 1;
    int b = 2;
    int c = 3;
    int d = 4;
    //@@end half
    return 0;
}
""")
        t = CoverageTracker()
        t._markers = parse_block_markers(src)
        t._executable_lines = {4, 5, 6, 7}
        return t

    def test_a_partly_run_region_is_not_complete(self, tmp_path):
        t = self._tracker(tmp_path)
        t.hit(4)
        t.hit(5)

        region = t.region("half")
        assert region.entered
        assert not region.completed, "two of its four lines never ran"
        assert len(region.lines_total) == 4
        assert region.coverage_pct == 50.0

    def test_a_fully_run_region_is_complete(self, tmp_path):
        t = self._tracker(tmp_path)
        for ln in (4, 5, 6, 7):
            t.hit(ln)

        assert t.region("half").completed

    def test_an_unentered_region_still_knows_its_size(self, tmp_path):
        """0/0 reads as "nothing to cover"; 0/4 reads as "nobody ran it"."""
        region = self._tracker(tmp_path).region("half")

        assert region.not_entered
        assert len(region.lines_total) == 4
