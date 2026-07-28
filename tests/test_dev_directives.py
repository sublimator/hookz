"""Tests for `hookz:` dev directives — observing a hook's own locals.

A hook's interesting values are often locals: an intermediate sum, a bound
that was clamped, the delta a reconciliation decided to absorb. None of that
is reachable from outside, so a test can only assert on the ends and hope the
middle was right.

Directives put named observation points inside the hook, in comments, so
production builds are byte-identical and only `compile_hook_dev` unwraps them.
Each `HOOKZ_CHECK` closes a Checkpoint of everything observed since the last.

Recording only — this module never asserts on what a value *should* be. That
belongs to whoever placed the directive.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from hookz.compiler import compile_hook, compile_hook_dev
from hookz.config import load_config
from hookz.coverage.rewriter import parse_dwarf_locations
from hookz.dev_directives import extract_hookz_directives, render_dev_source
from hookz.runtime import HookRuntime
from location_consts import WASI_SDK


SOURCE = r"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{
    uint64_t count = 40;
    uint64_t before = count;
    count++;
    uint8_t buf[2] = {0xAA, 0xBB};

    /* hookz:
    HOOKZ_U64("before", before);
    HOOKZ_U64("count", count);
    HOOKZ_BYTES("buf", buf, 2);
    HOOKZ_CHECK("after_increment");
    */

    return accept(0, 0, (int64_t)count);
}
"""

TWO_CHECKPOINTS = r"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{
    for (uint64_t i = 0; i < 3; ++i) {
        /* hookz:
        HOOKZ_U64("i", i);
        HOOKZ_CHECK("loop");
        */
    }
    return accept(0, 0, 0);
}
"""


needs_sdk = pytest.mark.skipif(WASI_SDK is None, reason="wasi-sdk not found")


def _compile_dev(tmp_path: Path, text: str, name: str = "dev_hook.c") -> bytes:
    source = tmp_path / name
    source.write_text(text)
    config = replace(load_config(source_file=source), exports=["hook"])
    return compile_hook_dev(source, config=config)


class TestExtraction:
    def test_finds_the_block_directive(self):
        directives = extract_hookz_directives(SOURCE)
        assert len(directives) == 1
        assert "HOOKZ_CHECK" in directives[0].code
        assert directives[0].line > 0

    def test_render_emits_prelude_and_unwraps_the_body(self):
        rendered = render_dev_source(SOURCE)
        assert "extern int64_t hookz_dev_check" in rendered
        assert 'HOOKZ_U64("count", count);' in rendered
        assert "hookz:" not in rendered  # the comment wrapper is gone

    def test_line_directive_keeps_original_numbering(self):
        """Diagnostics must point at the real file, not the temp copy."""
        assert '#line 1 "<hookz-dev-source>"' in render_dev_source(SOURCE)

    def test_source_without_directives_is_left_alone(self):
        plain = "int64_t hook(uint32_t r) { return 0; }\n"
        assert extract_hookz_directives(plain) == []
        assert "hookz_dev_check" not in render_dev_source(plain)


class TestProductionBuildsAreUnaffected:
    @needs_sdk
    def test_normal_compile_ignores_directives(self, tmp_path):
        """The whole point: what you audit is what you deploy."""
        source = tmp_path / "dev_hook.c"
        source.write_text(SOURCE)
        config = replace(load_config(source_file=source), exports=["hook"])

        prod = compile_hook(source, config=config)
        mod = __import__("hookz.wasm.decode", fromlist=["decode_module"])
        imports = {i.name for i in mod.decode_module(prod).imports}
        assert not any(n.startswith("hookz_dev") for n in imports)

    @needs_sdk
    def test_dev_compile_does_import_the_host_calls(self, tmp_path):
        wasm = _compile_dev(tmp_path, SOURCE)
        mod = __import__("hookz.wasm.decode", fromlist=["decode_module"])
        imports = {i.name for i in mod.decode_module(wasm).imports}
        assert "hookz_dev_check" in imports

    @needs_sdk
    def test_source_file_is_never_modified(self, tmp_path):
        source = tmp_path / "dev_hook.c"
        source.write_text(SOURCE)
        config = replace(load_config(source_file=source), exports=["hook"])
        compile_hook_dev(source, config=config)
        assert source.read_text() == SOURCE

    @needs_sdk
    def test_dwarf_lines_stay_within_the_original_file(self, tmp_path):
        """Injected code must not push line numbers past the real source."""
        wasm = _compile_dev(tmp_path, SOURCE)
        lines = {loc.line for loc in parse_dwarf_locations(wasm)}
        assert lines
        assert max(lines) <= len(SOURCE.splitlines())


class TestRecording:
    @needs_sdk
    def test_checkpoint_captures_the_observed_values(self, tmp_path):
        rt = HookRuntime()
        result = rt.run(_compile_dev(tmp_path, SOURCE))

        assert result.accepted
        cp = result.checkpoint("after_increment")
        assert cp is not None
        assert cp["before"] == 40
        assert cp["count"] == 41
        assert cp["buf"] == b"\xAA\xBB"

    @needs_sdk
    def test_values_are_scoped_to_their_own_checkpoint(self, tmp_path):
        """Each CHECK takes only what was observed since the previous one."""
        rt = HookRuntime()
        result = rt.run(_compile_dev(tmp_path, TWO_CHECKPOINTS))

        loops = result.checkpoints_for("loop")
        assert [c["i"] for c in loops] == [0, 1, 2]
        assert all(set(c.values) == {"i"} for c in loops)

    @needs_sdk
    def test_repeated_tag_refuses_the_singular_accessor(self, tmp_path):
        rt = HookRuntime()
        result = rt.run(_compile_dev(tmp_path, TWO_CHECKPOINTS))
        with pytest.raises(ValueError, match="reached 3 times"):
            result.checkpoint("loop")

    @needs_sdk
    def test_unknown_tag_is_none_not_an_error(self, tmp_path):
        rt = HookRuntime()
        result = rt.run(_compile_dev(tmp_path, SOURCE))
        assert result.checkpoint("never_placed") is None

    @needs_sdk
    def test_checkpoints_reset_between_runs(self, tmp_path):
        wasm = _compile_dev(tmp_path, SOURCE)
        rt = HookRuntime()
        rt.run(wasm)
        second = rt.run(wasm)
        assert len(second.checkpoints) == 1

    @needs_sdk
    def test_observers_see_each_checkpoint_as_it_closes(self, tmp_path):
        """The live hook: consume checkpoints during the run, not only after."""
        seen = []
        rt = HookRuntime()
        rt.checkpoint_observers.append(lambda cp, _rt: seen.append(cp.tag))
        rt.run(_compile_dev(tmp_path, TWO_CHECKPOINTS))
        assert seen == ["loop", "loop", "loop"]
