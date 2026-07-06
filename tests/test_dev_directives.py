"""Development-only hookz comment directives."""

from dataclasses import replace

import pytest

from hookz.compiler import compile_hook_dev
from hookz.config import load_config
from hookz.dev_directives import extract_hookz_directives, render_dev_source
from hookz.runtime import HookRuntime
from location_consts import WASI_SDK


DEV_DIRECTIVE_SOURCE = r"""
#include <stdint.h>
extern int64_t accept(uint32_t, uint32_t, int64_t);

int64_t hook(uint32_t reserved)
{
    uint64_t count = 41;
    uint8_t buf[2] = {0xAA, 0xBB};

    /* hookz:
    HOOKZ_LEAN4_U64("count", count);
    HOOKZ_LEAN4_BYTES("buf", buf, 2);
    HOOKZ_LEAN4_CHECK("state_counter.after_increment");
    */

    return accept(0, 0, (int64_t)count);
}
"""


def test_extracts_block_directive():
    directives = extract_hookz_directives(DEV_DIRECTIVE_SOURCE)

    assert len(directives) == 1
    assert "HOOKZ_LEAN4_U64" in directives[0].code
    assert directives[0].line > 0


def test_renders_dev_source_with_prelude_and_unwrapped_code():
    rendered = render_dev_source(DEV_DIRECTIVE_SOURCE)

    assert "extern int64_t hookz_dev_check" in rendered
    assert "HOOKZ_LEAN4_U64(\"count\", count);" in rendered
    assert "hookz:" not in rendered


@pytest.mark.skipif(WASI_SDK is None, reason="wasi-sdk not found")
def test_dev_compile_records_unwrapped_hook_events(tmp_path):
    source = tmp_path / "dev_directive_hook.c"
    source.write_text(DEV_DIRECTIVE_SOURCE)
    config = replace(load_config(source_file=source), exports=["hook"])

    wasm = compile_hook_dev(source, config=config)
    rt = HookRuntime()
    result = rt.run(wasm)

    assert result.accepted
    assert result.return_code == 41
    assert result.dev_events == [
        {"kind": "u64", "name": "count", "value": 41, "line": None},
        {"kind": "bytes", "name": "buf", "value": b"\xAA\xBB", "line": None},
        {"kind": "check", "tag": "state_counter.after_increment", "line": None},
    ]
