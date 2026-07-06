"""Development-only hookz comment directives."""

from dataclasses import replace

import pytest

from hookz.compiler import compile_hook_dev
from hookz.config import load_config
from hookz.coverage.rewriter import parse_dwarf_locations
from hookz.dev_directives import (
    extract_hookz_directives,
    render_dev_source,
)
from hookz.dev_lean import DevLeanError, dispatch_dev_lean_checks, lean_available, render_dev_lean_checks
from hookz.runtime import HookRuntime
from location_consts import WASI_SDK


DEV_DIRECTIVE_SOURCE = r"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{
    uint64_t count = 40;
    uint64_t before_count = count;
    count++;
    uint8_t buf[2] = {0xAA, 0xBB};

    /* hookz:
    HOOKZ_LEAN4_U64("before_count", before_count);
    HOOKZ_LEAN4_U64("count", count);
    HOOKZ_LEAN4_BYTES("buf", buf, 2);
    HOOKZ_LEAN4_CHECK("state_counter.after_increment");
    */

    return accept(0, 0, (int64_t)count);
}
"""

DEV_DIRECTIVE_FAILING_SOURCE = r"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{
    uint64_t before_count = 40;
    uint64_t count = 42;

    /* hookz:
    HOOKZ_LEAN4_U64("before_count", before_count);
    HOOKZ_LEAN4_U64("count", count);
    HOOKZ_LEAN4_CHECK("state_counter.after_increment");
    */

    return accept(0, 0, (int64_t)count);
}
"""

LEGACY_LEAN4_METADATA_SOURCE = r"""
// hookz: lean4 adapter=state_counter model=Hookz.Contracts.StateCounter.expected
int64_t hook(uint32_t reserved)
{
    return 0;
}
"""


def test_extracts_block_directive():
    directives = extract_hookz_directives(DEV_DIRECTIVE_SOURCE)

    assert len(directives) == 1
    assert "HOOKZ_LEAN4_U64" in directives[0].code
    assert directives[0].line > 0
    assert directives[0].end_line >= directives[0].line


def test_renders_dev_source_with_prelude_and_unwrapped_code():
    rendered = render_dev_source(DEV_DIRECTIVE_SOURCE)

    assert "extern int64_t hookz_dev_check" in rendered
    assert "HOOKZ_LEAN4_U64(\"count\", count);" in rendered
    assert "#line 1 \"<hookz-dev-source>\"" in rendered
    assert "hookz:" not in rendered


def test_legacy_lean4_metadata_is_not_unwrapped():
    directives = extract_hookz_directives(LEGACY_LEAN4_METADATA_SOURCE)
    rendered = render_dev_source(LEGACY_LEAN4_METADATA_SOURCE)

    assert directives == []
    assert "hookz: lean4 adapter=state_counter" in rendered
    assert "extern int64_t hookz_dev_check" not in rendered


@pytest.mark.skipif(WASI_SDK is None, reason="wasi-sdk not found")
def test_dev_compile_dwarf_lines_stay_in_original_source_range(tmp_path):
    source = tmp_path / "dev_directive_hook.c"
    source.write_text(DEV_DIRECTIVE_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    wasm = compile_hook_dev(source, config=config)
    locs = parse_dwarf_locations(wasm)
    source_lines = DEV_DIRECTIVE_SOURCE.splitlines()
    post_directive_line = next(
        index
        for index, line in enumerate(source_lines, start=1)
        if "return accept" in line
    )
    dwarf_lines = {loc.line for loc in locs}

    assert locs
    assert post_directive_line in dwarf_lines
    assert max(dwarf_lines) <= len(source_lines)


@pytest.mark.skipif(WASI_SDK is None or not lean_available(), reason="wasi-sdk/lake not found")
def test_dev_compile_records_unwrapped_hook_events(tmp_path, monkeypatch):
    source = tmp_path / "dev_directive_hook.c"
    source.write_text(DEV_DIRECTIVE_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    lean_out = tmp_path / "lean"
    monkeypatch.setenv("HOOKZ_LEAN_DEV_DIR", str(lean_out))
    wasm = compile_hook_dev(source, config=config)
    rt = HookRuntime()
    result = rt.run(wasm)

    assert result.accepted
    assert result.return_code == 41
    assert result.dev_events == [
        {"kind": "u64", "name": "before_count", "value": 40, "line": None},
        {"kind": "u64", "name": "count", "value": 41, "line": None},
        {"kind": "bytes", "name": "buf", "value": b"\xAA\xBB", "line": None},
        {"kind": "check", "tag": "state_counter.after_increment", "line": None},
    ]
    assert list(lean_out.glob("*.lean"))


@pytest.mark.skipif(WASI_SDK is None or not lean_available(), reason="wasi-sdk/lake not found")
def test_dev_compile_fails_fast_when_lean_checkpoint_fails(tmp_path, monkeypatch):
    source = tmp_path / "dev_directive_hook_fails.c"
    source.write_text(DEV_DIRECTIVE_FAILING_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    monkeypatch.setenv("HOOKZ_LEAN_DEV_DIR", str(tmp_path / "lean"))
    wasm = compile_hook_dev(source, config=config)
    rt = HookRuntime()
    result = rt.run(wasm)

    assert not result.accepted
    assert isinstance(result.error, DevLeanError)
    assert "state_counter.after_increment" in str(result.error)


def test_renders_dev_events_to_lean_check():
    events = [
        {"kind": "u64", "name": "before_count", "value": 40},
        {"kind": "u64", "name": "count", "value": 41},
        {"kind": "check", "tag": "state_counter.after_increment"},
    ]

    rendered = render_dev_lean_checks(events)

    assert len(rendered) == 1
    tag, lean_source = rendered[0]
    assert tag == "state_counter.after_increment"
    assert "Hookz.Contracts.StateCounter.expected" in lean_source
    assert "counterState := some 40" in lean_source
    assert "counterState := some 41" in lean_source


@pytest.mark.skipif(not lean_available(), reason="lake not found")
def test_dispatches_dev_events_to_lean(tmp_path):
    events = [
        {"kind": "u64", "name": "before_count", "value": 40},
        {"kind": "u64", "name": "count", "value": 41},
        {"kind": "check", "tag": "state_counter.after_increment"},
    ]

    results = dispatch_dev_lean_checks(events, out_dir=tmp_path)

    assert len(results) == 1
    assert results[0].tag == "state_counter.after_increment"
    assert results[0].lean_file.exists()
